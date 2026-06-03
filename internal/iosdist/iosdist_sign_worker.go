package iosdist

// Sign worker — single goroutine consuming task IDs from
// p.iosdistSignQueue. Per task it stages the source IPA + cert + profile
// to a temp dir, decrypts the cert password, runs zsign, parses the
// output IPA, uploads it via chatStorage, creates a new IOSVersion row,
// and marks the task success/failed.
//
// One worker is intentional: zsign is CPU-heavy and we don't want
// concurrent jobs thrashing disk + CDN egress on a small box. If we
// outgrow this, swap to a Redis Stream + N consumer goroutines.

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	iosdistSignTimeout = 5 * time.Minute
	iosdistSignLogCap  = 4 << 10 // 4 KiB
)

func (p *Plugin) runIOSSignWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case taskID, ok := <-p.iosdistSignQueue:
			if !ok {
				return
			}
			p.processIOSSignTask(ctx, taskID)
		}
	}
}

// processIOSSignTask is the per-task entrypoint. Failures inside this
// function never leak — they are persisted to the task row so the UI
// can surface them. Panics in zsign / file IO are caught and recorded.
func (p *Plugin) processIOSSignTask(ctx context.Context, taskID int64) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[iosdist sign-worker] task=%d panic: %v", taskID, r)
			_ = p.markIOSSignTaskFailed(taskID, fmt.Sprintf("worker panic: %v", r), "")
		}
	}()

	if p.iosdistZsignPath == "" {
		_ = p.markIOSSignTaskFailed(taskID, "服务器未安装 zsign，无法签名", "")
		log.Printf("[iosdist sign-worker] task=%d aborted: zsign not installed", taskID)
		return
	}

	task, err := p.getIOSSignTask(taskID)
	if err != nil || task == nil {
		log.Printf("[iosdist sign-worker] task=%d not found: %v", taskID, err)
		return
	}
	if task.Status != "pending" {
		log.Printf("[iosdist sign-worker] task=%d skipping — status=%s", taskID, task.Status)
		return
	}

	source, err := p.getIOSVersion(task.SourceVersionID)
	if err != nil || source == nil {
		_ = p.markIOSSignTaskFailed(taskID, "源版本不存在", "")
		return
	}
	app, err := p.getIOSAppByID(task.AppID)
	if err != nil || app == nil {
		_ = p.markIOSSignTaskFailed(taskID, "应用不存在", "")
		return
	}
	cert, err := p.getIOSCertificate(task.CertID, app.WorkspaceID)
	if err != nil || cert == nil {
		_ = p.markIOSSignTaskFailed(taskID, "证书不存在或无权访问", "")
		return
	}
	profile, err := p.getIOSProfileForOwner(task.ProfileID, app.WorkspaceID)
	if err != nil || profile == nil {
		_ = p.markIOSSignTaskFailed(taskID, "Profile 不存在或无权访问", "")
		return
	}

	if err := p.markIOSSignTaskRunning(taskID); err != nil {
		log.Printf("[iosdist sign-worker] task=%d markRunning failed: %v", taskID, err)
		return
	}
	log.Printf("[iosdist sign-worker] task=%d running app=%d source_version=%d cert=%d profile=%d", taskID, app.ID, source.ID, cert.ID, profile.ID)
	p.logSignEvent(app.WorkspaceID, taskID, "started", "开始签名", LogLevelInfo, map[string]any{
		"app_id":      app.ID,
		"app_name":    app.Name,
		"source_ver":  source.ID,
		"cert_id":     cert.ID,
		"profile_id":  profile.ID,
		"task_status": task.Status,
	})

	// Defer the terminal outcome log: re-read the task and emit
	// success/failed depending on what the worker landed on. This
	// wraps every early failure path (and the panic recovery) in
	// a single audit entry without touching each markFailed site.
	// Phase 3: also record the terminal outcome on the build counter
	// so the operator dashboard can track success rate / failure mode.
	defer func() {
		final, ferr := p.getIOSSignTask(taskID)
		if ferr != nil || final == nil {
			return
		}
		switch final.Status {
		case "success":
			p.logSignEvent(app.WorkspaceID, taskID, "completed", "签名成功", LogLevelInfo, map[string]any{
				"output_version_id": final.OutputVersionID,
			})
			p.metricsRegistry.recordIOSDistBuild("zsign", "success")
		case "failed":
			msg := final.ErrorMessage
			if msg == "" {
				msg = "签名失败"
			}
			p.logSignEvent(app.WorkspaceID, taskID, "failed", msg, LogLevelError, map[string]any{
				"log_text_preview": truncateForLog(final.LogText, 400),
			})
			p.metricsRegistry.recordIOSDistBuild("zsign", "failed")
		}
	}()

	workDir, err := os.MkdirTemp("", fmt.Sprintf("iosdist-sign-%d-", taskID))
	if err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "无法创建临时目录", err.Error())
		return
	}
	defer os.RemoveAll(workDir)

	sourceIPA := filepath.Join(workDir, "source.ipa")
	if err := p.fetchAttachmentToFile(ctx, source.IPAUrl, sourceIPA); err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "下载源 IPA 失败", err.Error())
		return
	}
	certFile := filepath.Join(workDir, "cert.p12")
	if err := p.fetchAttachmentToFile(ctx, cert.FileURL, certFile); err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "下载证书失败", err.Error())
		return
	}
	profileFile := filepath.Join(workDir, "profile.mobileprovision")
	if err := p.fetchAttachmentToFile(ctx, profile.FileURL, profileFile); err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "下载 Profile 失败", err.Error())
		return
	}

	password := cert.passwordCipher
	if cert.PasswordEncrypted {
		decrypted, err := p.decryptIOSDistSecret(cert.passwordCipher)
		if err != nil {
			_ = p.markIOSSignTaskFailed(taskID, "解密证书密码失败", err.Error())
			return
		}
		password = decrypted
	}

	outIPA := filepath.Join(workDir, "signed.ipa")
	cmdCtx, cancel := context.WithTimeout(ctx, iosdistSignTimeout)
	defer cancel()

	args := []string{"-k", certFile}
	if password != "" {
		args = append(args, "-p", password)
	}
	args = append(args, "-m", profileFile)
	// Optional rewrites. zsign cascades -b to embedded extensions
	// (the suffix after the original prefix is preserved).
	if task.NewBundleID != "" {
		args = append(args, "-b", task.NewBundleID)
	}
	if task.NewAppName != "" {
		args = append(args, "-n", task.NewAppName)
	}
	args = append(args, "-o", outIPA, "-z", "9", sourceIPA)
	log.Printf("[iosdist sign-worker] task=%d zsign args: %v", task.ID, redactPasswordArg(args))
	cmd := exec.CommandContext(cmdCtx, p.iosdistZsignPath, args...)
	combined, runErr := cmd.CombinedOutput()
	logText := truncateForLog(string(combined), iosdistSignLogCap)

	if runErr != nil {
		errMsg := fmt.Sprintf("zsign 退出非零: %v", runErr)
		// Pull the last meaningful line out of zsign output as a hint.
		if hint := lastNonEmptyLine(string(combined)); hint != "" {
			errMsg = fmt.Sprintf("zsign 失败: %s", hint)
		}
		_ = p.markIOSSignTaskFailed(taskID, errMsg, logText)
		log.Printf("[iosdist sign-worker] task=%d zsign failed: %v", taskID, runErr)
		return
	}

	stat, err := os.Stat(outIPA)
	if err != nil || stat.Size() == 0 {
		_ = p.markIOSSignTaskFailed(taskID, "zsign 完成但输出 IPA 不存在或为空", logText)
		return
	}

	sum, err := sha256File(outIPA)
	if err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "校验输出 IPA 失败", logText)
		return
	}

	// Re-introspect the signed IPA — the embedded.mobileprovision
	// changes, possibly the bundle id (if the profile uses a wildcard
	// that overlaps), and we want the new metadata on the output row.
	parsed, parseErr := parseIPA(outIPA)
	if parseErr != nil {
		log.Printf("[iosdist sign-worker] task=%d output IPA parse failed (continuing): %v", taskID, parseErr)
	}

	storedName := fmt.Sprintf("iosdist_signed_%d_%s.ipa", taskID, generateSessionID()[:8])
	signedMeta, err := p.uploadIOSBlobAsset(outIPA, "package", "iosdist/ipa/"+iosdistRandHex(6)+".ipa", "application/octet-stream", "public")
	if err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "上传签名 IPA 失败", logText+"\n"+err.Error())
		return
	}
	publicURL := fmt.Sprintf("asset://%d", signedMeta.ID)

	// Compose the new version row from the source + parsed output.
	newVersion := &IOSVersion{
		AppID:            app.ID,
		Version:          source.Version,
		BuildNumber:      source.BuildNumber,
		IPAUrl:           publicURL,
		IPAFilename:      storedName,
		IPASize:          stat.Size(),
		IPASHA256:        sum,
		ReleaseNotes:     fmt.Sprintf("Resigned from version %d (cert #%d, profile #%d)", source.ID, cert.ID, profile.ID),
		IsSigned:         true,
		DistributionType: pickDistTypeForSign(profile.Kind, source.DistributionType),
	}
	if parsed != nil {
		newVersion.IPABundleID = parsed.BundleID
		newVersion.IPAShortVersion = parsed.BundleShortVersion
		newVersion.IPABuildNumber = parsed.BundleVersion
		newVersion.IPADisplayName = parsed.BundleDisplayName
		newVersion.IPAMinOS = parsed.MinimumOSVersion
		newVersion.IPAHasEmbeddedPP = parsed.HasEmbeddedProvProf
	}
	if err := p.createIOSVersion(newVersion); err != nil {
		_ = p.markIOSSignTaskFailed(taskID, "写入新版本记录失败", logText+"\n"+err.Error())
		return
	}
	_ = p.touchIOSApp(app.ID)

	if err := p.markIOSSignTaskSuccess(taskID, newVersion.ID, logText); err != nil {
		log.Printf("[iosdist sign-worker] task=%d markSuccess failed: %v", taskID, err)
	}
	log.Printf("[iosdist sign-worker] task=%d ok → version_id=%d url=%s", taskID, newVersion.ID, publicURL)
}

// pickDistTypeForSign maps the profile kind onto the distribution_type
// enum we expose on iosdist_versions. ASC profiles map cleanly; if the
// profile's kind is empty or unrecognized we fall back to the source
// version's existing distribution_type so OTA install rules stay
// consistent.
func pickDistTypeForSign(profileKind, sourceDist string) string {
	switch profileKind {
	case "ad_hoc", "enterprise", "development", "app_store":
		return profileKind
	}
	if sourceDist != "" {
		return sourceDist
	}
	return "ad_hoc"
}

// fetchAttachmentToFile copies an attachment URL to a local file. We
// handle two kinds of URLs:
//   - "/uploads/<key>" — local AttachmentStorage; copy from the upload dir
//   - http(s)://       — remote (R2 public, mzstatic, etc.); HTTP GET
func (p *Plugin) fetchAttachmentToFile(ctx context.Context, srcURL, dstPath string) error {
	// Catalog-backed blob (single-write): fetch via internal AssetDownload.
	if id, ok := parseAssetRef(srcURL); ok {
		return p.fetchAssetToFile(ctx, id, dstPath)
	}
	if strings.HasPrefix(srcURL, "/uploads/") && p.BlobDir != "" {
		return copyFile(filepath.Join(p.BlobDir, strings.TrimPrefix(srcURL, "/uploads/")), dstPath)
	}
	if !strings.HasPrefix(srcURL, "http://") && !strings.HasPrefix(srcURL, "https://") {
		return fmt.Errorf("unsupported attachment URL: %q", srcURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srcURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %q: HTTP %d", srcURL, resp.StatusCode)
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	return nil
}

// redactPasswordArg returns a copy of args with the value following -p
// replaced by "***" so we can log the zsign invocation safely.
func redactPasswordArg(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-p" {
			out[i+1] = "***"
		}
	}
	return out
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}
