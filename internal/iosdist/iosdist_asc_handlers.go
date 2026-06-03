package iosdist

// HTTP handlers for the App Store Connect bridge.
//
// Five endpoints; all owner-scoped:
//   GET    /api/iosdist/asc/config                  → status (no secrets in body)
//   POST   /api/iosdist/asc/config                  → multipart: issuer_id, key_id, p8 file
//   DELETE /api/iosdist/asc/config                  → wipe
//   GET    /api/iosdist/asc/apps?bundle_id=…        → forward to ASC for the picker
//   GET    /api/iosdist/asc/beta-groups?asc_app_id= → forward to ASC for the picker
//   PUT    /api/iosdist/apps/:id/asc-binding        → set asc_app_id + asc_beta_group_id
//   POST   /api/iosdist/apps/:id/invite-tester      → email invite, ASC handles the email send

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// ---- Config CRUD ---------------------------------------------------------

func (p *Plugin) handleIOSASCConfigGet(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	cfg, err := p.getIOSASCConfig(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	if cfg == nil {
		c.JSON(http.StatusOK, gin.H{
			"configured":       false,
			"encryption_ready": len(p.iosdistResourceKey) == iosdistResourceKeyBytes,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"configured":       true,
		"config":           cfg,
		"encryption_ready": len(p.iosdistResourceKey) == iosdistResourceKeyBytes,
	})
}

func (p *Plugin) handleIOSASCConfigUpsert(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := requireUserID(c)
	if !ok {
		return
	}
	issuer := sanitizeASCIDInput(c.PostForm("issuer_id"))
	keyID := sanitizeASCIDInput(c.PostForm("key_id"))
	if issuer == "" || keyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Issuer ID 与 Key ID 不能为空"})
		return
	}
	// Apple Key IDs are 10 alphanumeric chars; if anything snuck through
	// after sanitize (e.g. zero-width chars), reject loudly so the user
	// fixes the paste rather than ending up with a silent 401 later.
	if len(keyID) != 10 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Key ID 必须是 10 位字符（实际 %d 位）。检查复制时是否带了多余的引号 / 空格 / 冒号。", len(keyID)),
		})
		return
	}
	file, err := c.FormFile("p8")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择 .p8 私钥文件"})
		return
	}
	if file.Size > int64(64<<10) { // 64 KiB — Apple p8 files are ~250 bytes
		c.JSON(http.StatusBadRequest, gin.H{"error": "p8 文件过大"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "文件读取失败"})
		return
	}
	defer src.Close()
	// io.ReadAll guarantees all bytes are consumed regardless of how
	// the underlying multipart.File chunks reads. Cap is paranoid.
	pemBytes, err := io.ReadAll(io.LimitReader(src, int64(64<<10)))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "文件读取失败"})
		return
	}
	if len(pemBytes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": ".p8 文件为空"})
		return
	}

	// Sanity-check the PEM by parsing through the same code path the
	// ASC client would. This way a bad upload fails fast with a clear
	// 400 instead of silently breaking later invite calls.
	probe := &IOSASCConfig{p8Cipher: string(pemBytes)}
	if _, _, err := p.loadASCConfigPrivateKey(probe); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "p8 解析失败：" + err.Error()})
		return
	}

	cipher, encrypted, err := p.encryptIOSDistSecret(string(pemBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "p8 加密失败"})
		return
	}
	stored := cipher
	if !encrypted {
		stored = string(pemBytes)
	}

	cfg := &IOSASCConfig{
		OwnerUserID: userID,
		WorkspaceID: workspaceID,
		IssuerID:    issuer,
		KeyID:       keyID,
		P8Filename:  file.Filename,
		P8Encrypted: encrypted,
		p8Cipher:    stored,
	}
	if err := p.upsertIOSASCConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}

	// Best-effort: pull the team's account holder email so the topbar
	// pill can show "ASC 已配置 · me@example.com". Failures here just
	// mean the email stays empty — the config itself is already saved
	// and the operator can re-trigger via re-upload.
	if users, err := p.ascListUsers(c.Request.Context(), cfg); err == nil {
		email := ascAccountHolderEmail(users)
		log.Printf("[iosdist asc-config] workspace=%s saved config; resolved account holder email=%q (%d users total)", workspaceID, email, len(users))
		if email != "" {
			if dbErr := p.setIOSASCConfigAccountInfo(workspaceID, email, ""); dbErr == nil {
				cfg.AccountHolderEmail = email
			}
		}
	} else {
		log.Printf("[iosdist asc-config] workspace=%s saved config but ascListUsers failed: %v", workspaceID, err)
	}

	c.JSON(http.StatusOK, gin.H{"config": cfg})
}

func (p *Plugin) handleIOSASCConfigDelete(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	if err := p.deleteIOSASCConfig(workspaceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---- Discovery helpers ---------------------------------------------------

func (p *Plugin) handleIOSASCAppList(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		return
	}
	bundleID := strings.TrimSpace(c.Query("bundle_id"))
	log.Printf("[iosdist asc-apps] workspace=%s issuer=%s key_id=%s bundle_id=%q", workspaceID, cfg.IssuerID, cfg.KeyID, bundleID)
	apps, err := p.ascListApps(c.Request.Context(), cfg, bundleID)
	if err != nil {
		log.Printf("[iosdist asc-apps] workspace=%s ascListApps failed: %v", workspaceID, err)
		p.respondASCError(c, err)
		return
	}
	log.Printf("[iosdist asc-apps] workspace=%s ascListApps ok: %d match(es)", workspaceID, len(apps))
	c.JSON(http.StatusOK, gin.H{"apps": apps})
}

func (p *Plugin) handleIOSASCBetaGroupList(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		return
	}
	groups, err := p.ascListBetaGroups(c.Request.Context(), cfg, strings.TrimSpace(c.Query("asc_app_id")))
	if err != nil {
		p.respondASCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"beta_groups": groups})
}

// ---- Bundle ID + App creation (Phase 3 of iOS pipeline closed loop) -----

type iosASCCreateBundleIDRequest struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Platform   string `json:"platform"` // IOS / MAC_OS / UNIVERSAL — defaults to IOS
}

// handleIOSASCBundleIDCreate registers a new bundle id with ASC.
// Idempotent at this layer: if the identifier already exists,
// re-fetches it and returns the existing record (no 409 to UI).
func (p *Plugin) handleIOSASCBundleIDCreate(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		return
	}
	var req iosASCCreateBundleIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	name := strings.TrimSpace(req.Name)
	platform := strings.TrimSpace(req.Platform)
	if identifier == "" || name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "identifier and name are required"})
		return
	}
	if platform == "" {
		platform = "IOS"
	}
	// Idempotency probe.
	existing, err := p.ascListBundleIDs(c.Request.Context(), cfg, identifier)
	if err != nil {
		p.respondASCError(c, err)
		return
	}
	for _, b := range existing {
		if b.Identifier == identifier {
			c.JSON(http.StatusOK, gin.H{"bundle_id": b, "reused": true})
			return
		}
	}
	created, err := p.ascCreateBundleID(c.Request.Context(), cfg, identifier, name, platform)
	if err != nil {
		p.respondASCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"bundle_id": created, "reused": false})
}

type iosASCCreateAppRequest struct {
	BundleIDResourceID string `json:"bundle_id_resource_id"`
	Name               string `json:"name"`
	SKU                string `json:"sku"`
	PrimaryLocale      string `json:"primary_locale"`
}

// handleIOSASCAppCreate creates an ASC app record. Idempotent at
// this layer: if an app with the same bundle id already exists,
// returns it without trying to recreate (Apple would 409).
func (p *Plugin) handleIOSASCAppCreate(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		return
	}
	var req iosASCCreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}
	bidResource := strings.TrimSpace(req.BundleIDResourceID)
	name := strings.TrimSpace(req.Name)
	sku := strings.TrimSpace(req.SKU)
	primary := strings.TrimSpace(req.PrimaryLocale)
	if bidResource == "" || name == "" || sku == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bundle_id_resource_id, name, sku are required"})
		return
	}
	if primary == "" {
		primary = "en-US"
	}
	created, err := p.ascCreateApp(c.Request.Context(), cfg, bidResource, name, sku, primary)
	if err != nil {
		p.respondASCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"app": created})
}

// ---- Per-app binding + invite -------------------------------------------

type iosASCBindingRequest struct {
	ASCAppID       string `json:"asc_app_id"`
	ASCBetaGroupID string `json:"asc_beta_group_id"`
}

func (p *Plugin) handleIOSAppASCBindingUpdate(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	id, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	app, err := p.getIOSApp(id, workspaceID)
	if err != nil || app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "应用不存在"})
		return
	}
	var req iosASCBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的输入数据"})
		return
	}
	if err := p.setIOSAppASCBinding(app.ID, workspaceID, strings.TrimSpace(req.ASCAppID), strings.TrimSpace(req.ASCBetaGroupID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	updated, _ := p.getIOSApp(app.ID, workspaceID)
	c.JSON(http.StatusOK, gin.H{"app": updated})
}

type iosASCInviteRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (p *Plugin) handleIOSAppInviteTester(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	id, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	app, err := p.getIOSApp(id, workspaceID)
	if err != nil || app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "应用不存在"})
		return
	}
	if app.ASCBetaGroupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "尚未绑定 ASC Beta Group，请先在「App Store Connect 集成」配置"})
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		return
	}

	var req iosASCInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的输入数据"})
		return
	}
	email := strings.TrimSpace(req.Email)
	if _, err := mail.ParseAddress(email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱格式无效"})
		return
	}

	if err := p.ascCreateTester(c.Request.Context(), cfg, email, strings.TrimSpace(req.FirstName), strings.TrimSpace(req.LastName), []string{app.ASCBetaGroupID}); err != nil {
		p.respondASCError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---- Sync app meta from ASC ---------------------------------------------

// handleIOSAppASCSyncMeta pulls the ASC app's name + primary-locale
// description + latest-build icon and writes them onto the local row.
// Manual icon overrides (icon_source='manual') are preserved; everything
// else is overwritten from ASC since the user explicitly clicked sync.
//
// When asc_app_id is empty we auto-resolve via bundle_id (ASC bundle ids
// are unique within an Apple Dev account) and auto-pick the first Beta
// Group. This lets users skip the "选 ASC App / 保存绑定" step entirely
// for the common case.
func (p *Plugin) handleIOSAppASCSyncMeta(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	id, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	app, err := p.getIOSApp(id, workspaceID)
	if err != nil || app == nil {
		log.Printf("[iosdist asc-sync] app %d not found in workspace %s: %v", id, workspaceID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "应用不存在"})
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		log.Printf("[iosdist asc-sync] app %d (bundle %s): no ASC config for workspace %s — aborting", app.ID, app.BundleID, workspaceID)
		return
	}
	log.Printf("[iosdist asc-sync] app=%d bundle=%q name=%q workspace=%s asc_app_id=%q asc_beta_group_id=%q icon_source=%q",
		app.ID, app.BundleID, app.Name, workspaceID, app.ASCAppID, app.ASCBetaGroupID, app.IconSource)
	log.Printf("[iosdist asc-sync] using ASC config issuer=%s key_id=%s p8_encrypted=%v", cfg.IssuerID, cfg.KeyID, cfg.P8Encrypted)

	ctx := c.Request.Context()

	// Auto-resolve ASC App via bundle_id match when no binding is set yet.
	// Same Apple Dev account can't have two apps with the same bundle id,
	// so the lookup is unambiguous.
	autoBound := false
	if app.ASCAppID == "" {
		if strings.TrimSpace(app.BundleID) == "" {
			log.Printf("[iosdist asc-sync] app=%d auto-bind aborted: empty bundle_id", app.ID)
			c.JSON(http.StatusBadRequest, gin.H{"error": "应用没有 bundle_id，无法自动绑定 ASC App"})
			return
		}
		log.Printf("[iosdist asc-sync] app=%d auto-binding via bundle_id lookup: %s", app.ID, app.BundleID)
		ascApps, lookupErr := p.ascListApps(ctx, cfg, app.BundleID)
		if lookupErr != nil {
			log.Printf("[iosdist asc-sync] app=%d ascListApps failed: %v", app.ID, lookupErr)
			p.respondASCError(c, lookupErr)
			return
		}
		log.Printf("[iosdist asc-sync] app=%d ascListApps returned %d match(es)", app.ID, len(ascApps))
		if len(ascApps) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("ASC 中找不到 bundle_id 为 %s 的 App。请确认该 App 已在你的 App Store Connect 账号下创建。", app.BundleID),
			})
			return
		}
		app.ASCAppID = ascApps[0].ID
		autoBound = true
		log.Printf("[iosdist asc-sync] app=%d auto-bound to asc_app_id=%s (name=%q)", app.ID, app.ASCAppID, ascApps[0].Name)
		if err := p.setIOSAppASCBinding(app.ID, workspaceID, app.ASCAppID, app.ASCBetaGroupID); err != nil {
			log.Printf("[iosdist asc-sync] app=%d setIOSAppASCBinding failed: %v", app.ID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
			return
		}
	}

	// 1. App-level attributes (name, primary locale).
	log.Printf("[iosdist asc-sync] app=%d GET /v1/apps/%s", app.ID, app.ASCAppID)
	detail, err := p.ascGetApp(ctx, cfg, app.ASCAppID)
	if err != nil {
		log.Printf("[iosdist asc-sync] app=%d ascGetApp failed: %v", app.ID, err)
		p.respondASCError(c, err)
		return
	}
	log.Printf("[iosdist asc-sync] app=%d ascGetApp ok: name=%q primaryLocale=%q sku=%q", app.ID, detail.Name, detail.PrimaryLocale, detail.SKU)

	// 2. Pick the best-matching locale and grab the full metainfo
	//    bundle. Prefer the app's primaryLocale; fall back to any "en"
	//    variant; finally first row.
	var pickedLoc *ascAppLocalization
	locs, locErr := p.ascGetLatestVersionLocalizations(ctx, cfg, app.ASCAppID)
	if locErr != nil {
		log.Printf("[iosdist asc-sync] app=%d ascGetLatestVersionLocalizations failed (continuing): %v", app.ID, locErr)
	} else {
		log.Printf("[iosdist asc-sync] app=%d ascGetLatestVersionLocalizations ok: %d locale(s)", app.ID, len(locs))
	}
	if len(locs) > 0 {
		for i := range locs {
			if strings.EqualFold(locs[i].Locale, detail.PrimaryLocale) {
				pickedLoc = &locs[i]
				break
			}
		}
		if pickedLoc == nil {
			for i := range locs {
				if strings.HasPrefix(strings.ToLower(locs[i].Locale), "en") {
					pickedLoc = &locs[i]
					break
				}
			}
		}
		if pickedLoc == nil {
			pickedLoc = &locs[0]
		}
		log.Printf("[iosdist asc-sync] app=%d picked locale=%q description_len=%d keywords_len=%d whatsnew_len=%d",
			app.ID, pickedLoc.Locale, len(pickedLoc.Description), len(pickedLoc.Keywords), len(pickedLoc.WhatsNew))
	}

	// 3. Compose the meta update. Anything ASC returned non-empty wins;
	//    empty falls back to whatever's already on the row so we don't
	//    accidentally clear fields ASC didn't include this round.
	updatedFields := []string{}
	if autoBound {
		updatedFields = append(updatedFields, "ASC 绑定")
	}
	newName := strings.TrimSpace(detail.Name)
	meta := IOSAppMetaUpdate{
		Name:            firstNonEmpty(newName, app.Name),
		Description:     app.Description,
		Keywords:        app.Keywords,
		WhatsNew:        app.WhatsNew,
		PromotionalText: app.PromotionalText,
		MarketingURL:    app.MarketingURL,
		SupportURL:      app.SupportURL,
	}
	if pickedLoc != nil {
		meta.Description = firstNonEmpty(pickedLoc.Description, app.Description)
		meta.Keywords = firstNonEmpty(pickedLoc.Keywords, app.Keywords)
		meta.WhatsNew = firstNonEmpty(pickedLoc.WhatsNew, app.WhatsNew)
		meta.PromotionalText = firstNonEmpty(pickedLoc.PromotionalText, app.PromotionalText)
		meta.MarketingURL = firstNonEmpty(pickedLoc.MarketingURL, app.MarketingURL)
		meta.SupportURL = firstNonEmpty(pickedLoc.SupportURL, app.SupportURL)
	}

	if meta.Name != app.Name {
		updatedFields = append(updatedFields, "名称")
	}
	if meta.Description != app.Description {
		updatedFields = append(updatedFields, "描述")
	}
	if meta.Keywords != app.Keywords {
		updatedFields = append(updatedFields, "关键词")
	}
	if meta.WhatsNew != app.WhatsNew {
		updatedFields = append(updatedFields, "What's New")
	}
	if meta.PromotionalText != app.PromotionalText {
		updatedFields = append(updatedFields, "推广文本")
	}
	if meta.MarketingURL != app.MarketingURL {
		updatedFields = append(updatedFields, "Marketing URL")
	}
	if meta.SupportURL != app.SupportURL {
		updatedFields = append(updatedFields, "Support URL")
	}

	if len(updatedFields) > 0 || autoBound {
		// Skip the write when only autoBound is true (binding was
		// already saved earlier) and no other field changed.
		hasMetaChange := false
		for _, f := range updatedFields {
			if f != "ASC 绑定" {
				hasMetaChange = true
				break
			}
		}
		if hasMetaChange {
			log.Printf("[iosdist asc-sync] app=%d writing meta updated_fields=%v", app.ID, updatedFields)
			if err := p.setIOSAppMeta(app.ID, workspaceID, meta); err != nil {
				log.Printf("[iosdist asc-sync] app=%d setIOSAppMeta failed: %v", app.ID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
				return
			}
		} else {
			log.Printf("[iosdist asc-sync] app=%d only auto-binding updated, no meta write", app.ID)
		}
	} else {
		log.Printf("[iosdist asc-sync] app=%d meta unchanged", app.ID)
	}

	// Icon: only overwrite when ASC has one AND user hasn't manually
	// uploaded one. Manual uploads pin forever.
	if app.IconSource == "manual" {
		log.Printf("[iosdist asc-sync] app=%d skipping icon: icon_source=manual (operator-pinned)", app.ID)
	} else {
		build, buildErr := p.ascLatestBuildForApp(ctx, cfg, app.ASCAppID)
		if buildErr != nil {
			log.Printf("[iosdist asc-sync] app=%d ascLatestBuildForApp failed: %v", app.ID, buildErr)
		} else if build == nil {
			log.Printf("[iosdist asc-sync] app=%d no builds yet on ASC", app.ID)
		} else if build.IconAssetToken == nil {
			log.Printf("[iosdist asc-sync] app=%d build %s has no iconAssetToken (processingState=%s)", app.ID, build.ID, build.ProcessingState)
		} else {
			iconURLs := resolveASCIconURLs(build.IconAssetToken)
			if len(iconURLs) > 0 {
				log.Printf("[iosdist asc-sync] app=%d build=%s trying %d icon URL variant(s); first=%s", app.ID, build.ID, len(iconURLs), iconURLs[0])
			} else {
				log.Printf("[iosdist asc-sync] app=%d resolveASCIconURLs produced no URLs", app.ID)
			}
			if len(iconURLs) > 0 {
				data, ct, dlErr := p.downloadASCIconWithFallback(ctx, iconURLs)
				if dlErr != nil {
					log.Printf("[iosdist asc-sync] app=%d downloadASCIcon failed all variants: %v", app.ID, dlErr)
				} else {
					log.Printf("[iosdist asc-sync] app=%d downloaded icon %d bytes (%s)", app.ID, len(data), ct)
					assetID, persistErr := p.persistIOSDownloadedIcon(c, app.ID, data, ct)
					if persistErr != nil {
						log.Printf("[iosdist asc-sync] app=%d persistIOSDownloadedIcon failed: %v", app.ID, persistErr)
					} else {
						if err := p.setIOSAppIconAsset(app.ID, workspaceID, assetID, "asc"); err != nil {
							log.Printf("[iosdist asc-sync] app=%d setIOSAppIconAsset failed: %v", app.ID, err)
						} else {
							log.Printf("[iosdist asc-sync] app=%d icon updated → asset:%d (route /iosdist/icon/%d)", app.ID, assetID, app.ID)
							updatedFields = append(updatedFields, "图标")
						}
					}
				}
			}
		}
	}

	log.Printf("[iosdist asc-sync] app=%d done updated_fields=%v", app.ID, updatedFields)
	updated, _ := p.getIOSApp(app.ID, workspaceID)
	c.JSON(http.StatusOK, gin.H{"app": updated, "updated_fields": updatedFields})
}

// persistIOSDownloadedIcon single-writes raw icon bytes (fetched from ASC)
// into the assets catalog and returns the catalog asset id. Mirrors
// persistIOSExtractedIcon; the staged temp file is transient.
func (p *Plugin) persistIOSDownloadedIcon(_ *gin.Context, appID int64, data []byte, contentType string) (int64, error) {
	if p.BlobDir == "" {
		return 0, fmt.Errorf("upload dir not configured")
	}
	if err := os.MkdirAll(p.BlobDir, 0o755); err != nil {
		return 0, err
	}
	ext := ".png"
	if strings.Contains(contentType, "jpeg") || strings.Contains(contentType, "jpg") {
		ext = ".jpg"
	}
	storedName := fmt.Sprintf("iosdist_appicon_%d_%s%s", appID, generateSessionID()[:8], ext)
	dstPath := filepath.Join(p.BlobDir, storedName)
	if err := os.WriteFile(dstPath, data, 0o644); err != nil {
		return 0, err
	}
	mime := contentType
	if mime == "" {
		mime = "image/png"
	}
	meta, err := p.uploadIOSBlobAsset(dstPath, "media", "iosdist/icon/"+iosdistRandHex(6)+ext, mime, "public")
	removeLocalFile(dstPath)
	if err != nil {
		return 0, err
	}
	return meta.ID, nil
}

// sanitizeASCIDInput strips common copy-paste artifacts (whitespace, ASCII
// quotes, curly quotes, backticks, surrounding angle brackets) from an
// Issuer ID / Key ID. Real Apple identifiers contain only [A-Za-z0-9-]
// so anything else is almost certainly a paste contaminant.
func sanitizeASCIDInput(s string) string {
	s = strings.TrimSpace(s)
	// Strip a known set of wrapping characters first; the second
	// TrimSpace catches whitespace inside the wrappers. Curly quotes
	// expressed via escapes to keep the source ASCII-clean.
	s = strings.Trim(s, "\"'`<>“”‘’")
	s = strings.TrimSpace(s)
	// Some users paste values prefixed with the field label, e.g.
	// "Key ID: ABCDE12345" — strip a single leading word + colon.
	if i := strings.Index(s, ":"); i > 0 && i < len(s)-1 {
		// Only do this when the prefix looks like a label: short, no
		// dashes, no spaces in the value portion. Anything else, leave alone.
		prefix := strings.TrimSpace(s[:i])
		if len(prefix) <= 16 && !strings.ContainsAny(prefix, "-") {
			s = strings.TrimSpace(s[i+1:])
		}
	}
	return s
}

// ---- shared helpers ------------------------------------------------------

func (p *Plugin) requireASCConfig(c *gin.Context, workspaceID string) (*IOSASCConfig, error) {
	cfg, err := p.getIOSASCConfig(workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return nil, err
	}
	if cfg == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "尚未配置 ASC API Key（Issuer ID + Key ID + .p8）"})
		return nil, nil
	}
	return cfg, nil
}

func (p *Plugin) respondASCError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), errIOSASCClient.Error()) {
		// Trim the "asc client error: " prefix the caller wrapped on, so
		// the user sees just Apple's message.
		msg := strings.TrimPrefix(err.Error(), "asc client error: ")
		c.JSON(http.StatusBadRequest, gin.H{"error": "ASC API 拒绝请求：" + msg})
		return
	}
	c.JSON(http.StatusBadGateway, gin.H{"error": "调用 ASC API 失败：" + err.Error()})
}

// handleIOSAppStatusGet returns the cached snapshot. 200 with body
// {"status": null} when no snapshot exists yet — the UI shows "等待
// 首次同步". Workspace-scoped; cross-tenant id returns 404.
func (p *Plugin) handleIOSAppStatusGet(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	id, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	app, err := p.getIOSApp(id, workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	if app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "应用不存在"})
		return
	}
	st, err := p.getIOSAppStatus(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": st})
}

// handleIOSAppStatusSync forces a single-app refresh and returns the
// freshly-written snapshot. 400 when the app has no ASC binding (the
// worker would skip it anyway, but a user-triggered call deserves a
// clear error). 502 on ASC failure — the row's sync_error is still
// updated so the next GET shows the failure.
func (p *Plugin) handleIOSAppStatusSync(c *gin.Context) {
	workspaceID, ok := requireWorkspaceID(c)
	if !ok {
		return
	}
	id, ok := parseInt64Param(c, "id")
	if !ok {
		return
	}
	app, err := p.getIOSApp(id, workspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	if app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "应用不存在"})
		return
	}
	if strings.TrimSpace(app.ASCAppID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "应用尚未绑定 ASC App ID，无法同步"})
		return
	}
	cfg, _ := p.requireASCConfig(c, workspaceID)
	if cfg == nil {
		return
	}
	if err := p.syncOneIOSAppStatus(c.Request.Context(), app, cfg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "同步失败：" + err.Error()})
		return
	}
	st, err := p.getIOSAppStatus(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": st})
}
