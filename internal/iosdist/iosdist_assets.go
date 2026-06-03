package iosdist

// Blob → central-assets migration (single-write).
// See doc/arch/blob-storage-to-assets-migration.md in polar-dock.
//
// iosdist stores four kinds of blobs: the IPA (iosdist_versions.ipa_url),
// the signing cert (iosdist_certificates.file_url), the provisioning
// profile (iosdist_profiles.file_url), and the app icon
// (iosdist_apps.icon_url). The first three are consumed only by the OTA
// install manifest (IPA) and the sign worker (cert/profile/IPA) — never
// fetched directly by a browser with a session — so we store an
// "asset://<id>" marker in the existing *_url column and resolve it at
// read time (signed URL for the manifest, internal AssetDownload for the
// worker).
//
// The icon is different: it's an <img src> rendered both on the public
// plaza/share pages and in the admin UI (same-origin as iosdist-svc). To
// keep every render site working unchanged we point icon_url at a stable
// public redirect route (/iosdist/icon/<appID>) and stash the asset id in
// a new icon_asset_id column; the route 302s to a fresh signed URL on
// each load (so the short-lived signed URL never goes stale in a cached
// page).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	sdk "github.com/networkextension/polar-sdk"
)

func iosdistRandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// parseAssetRef extracts the catalog asset id from an "asset://<id>"
// marker stored in a *_url column. Returns (0,false) for legacy local /
// remote URLs.
func parseAssetRef(s string) (int64, bool) {
	const pfx = "asset://"
	if !strings.HasPrefix(s, pfx) {
		return 0, false
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(s, pfx), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// ensureIOSDistAssetSchema adds the one new column the migration needs.
// Idempotent; called from New().
func (p *Plugin) ensureIOSDistAssetSchema(ctx context.Context) error {
	_, err := p.DB.ExecContext(ctx,
		`ALTER TABLE iosdist_apps ADD COLUMN IF NOT EXISTS icon_asset_id BIGINT`)
	return err
}

// uploadIOSBlobAsset streams a staged on-disk file straight into the
// central assets catalog (platform-owned) and returns the asset meta.
// No permanent local copy is kept — the caller removes its staged temp.
func (p *Plugin) uploadIOSBlobAsset(stagedPath, kind, name, mime, visibility string) (*sdk.AssetMeta, error) {
	f, err := os.Open(stagedPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return p.Dock.AssetUpload(sdk.AssetUploadInput{
		Kind:       kind,
		Name:       name,
		Version:    "v1",
		Visibility: visibility,
		Mime:       mime,
	}, f)
}

// fetchAssetToFile downloads an asset's bytes (internal, dock-authed) to a
// local temp file — used by the sign worker, which needs random-access
// local copies of the source IPA / cert / profile for zsign.
func (p *Plugin) fetchAssetToFile(ctx context.Context, assetID int64, dstPath string) error {
	resp, err := p.Dock.AssetDownload(&sdk.AssetMeta{ID: assetID})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asset download %d: HTTP %d", assetID, resp.StatusCode)
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

// setIOSAppIconAsset points icon_url at the stable redirect route and
// records the backing asset id + source in one UPDATE.
func (p *Plugin) setIOSAppIconAsset(appID int64, workspaceID string, assetID int64, source string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps SET icon_url = $1, icon_asset_id = $2, icon_source = $3, updated_at = now()
		 WHERE id = $4 AND workspace_id = $5`,
		iconRouteFor(appID), assetID, source, appID, workspaceID,
	)
	return err
}

// iconRouteFor is the stable, same-origin redirect path stored in
// icon_url for asset-backed icons. Relative so it resolves against the
// iosdist host for both the public pages and the (same-origin) admin UI.
func iconRouteFor(appID int64) string {
	return "/iosdist/icon/" + strconv.FormatInt(appID, 10)
}

// getIOSAppIconRef returns the icon's backing asset id (0 if none) plus
// the raw icon_url (legacy /uploads or http for un-migrated apps). Narrow
// read used by the redirect route only.
func (p *Plugin) getIOSAppIconRef(appID int64) (assetID int64, iconURL string, err error) {
	var aid sql.NullInt64
	var u sql.NullString
	err = p.DB.QueryRow(
		`SELECT COALESCE(icon_asset_id, 0), COALESCE(icon_url, '') FROM iosdist_apps WHERE id = $1`,
		appID,
	).Scan(&aid, &u)
	if err != nil {
		return 0, "", err
	}
	return aid.Int64, u.String, nil
}

// handleIOSAppIconRedirect is the public, no-auth icon route. It 302s to a
// fresh signed asset URL for migrated icons, or to the legacy absolute
// URL for icons not yet backfilled.
func (p *Plugin) handleIOSAppIconRedirect(c *gin.Context) {
	appID, ok := parseInt64Param(c, "appID")
	if !ok {
		return
	}
	assetID, legacy, err := p.getIOSAppIconRef(appID)
	if err != nil || (assetID == 0 && legacy == "") {
		c.Status(http.StatusNotFound)
		return
	}
	if assetID > 0 {
		signed, serr := p.Dock.AssetDownloadURL(assetID)
		if serr != nil || signed == "" {
			log.Printf("iosdist: icon redirect app=%d asset=%d sign failed: %v", appID, assetID, serr)
			c.Status(http.StatusBadGateway)
			return
		}
		c.Redirect(http.StatusFound, signed)
		return
	}
	// Legacy icon (pre-migration): bounce to its existing absolute URL.
	c.Redirect(http.StatusFound, absolutizeURL(p.installPublicBaseURL(c), legacy))
}

// backfillIOSDistAssetsOnce self-migrates any legacy local/remote blobs
// into the assets catalog on boot (idempotent goroutine from Start()).
// Each row whose blob still lives outside the catalog is fetched, uploaded
// once, and its column rewritten to the asset reference.
func (p *Plugin) backfillIOSDistAssetsOnce(ctx context.Context) {
	n := 0
	n += p.backfillIOSBlobColumn(ctx, "iosdist_versions", "ipa_url", "package", "ipa", "application/octet-stream", "public")
	n += p.backfillIOSBlobColumn(ctx, "iosdist_certificates", "file_url", "package", "cert", "application/octet-stream", "private")
	n += p.backfillIOSBlobColumn(ctx, "iosdist_profiles", "file_url", "package", "profile", "application/octet-stream", "private")
	n += p.backfillIOSIcons(ctx)
	if n > 0 {
		log.Printf("iosdist: asset backfill migrated %d blob(s) to the catalog", n)
	}
}

// backfillIOSBlobColumn migrates marker-less rows of one *_url column.
func (p *Plugin) backfillIOSBlobColumn(ctx context.Context, table, col, kind, label, mime, visibility string) int {
	rows, err := p.DB.QueryContext(ctx,
		`SELECT id, `+col+` FROM `+table+`
		 WHERE `+col+` <> '' AND `+col+` NOT LIKE 'asset://%'`)
	if err != nil {
		log.Printf("iosdist: backfill %s.%s query: %v", table, col, err)
		return 0
	}
	type row struct {
		id  int64
		url string
	}
	var pending []row
	for rows.Next() {
		var r row
		var u sql.NullString
		if err := rows.Scan(&r.id, &u); err != nil {
			continue
		}
		r.url = u.String
		pending = append(pending, r)
	}
	rows.Close()

	migrated := 0
	for _, r := range pending {
		tmp, err := os.CreateTemp("", "iosdist-backfill-*")
		if err != nil {
			continue
		}
		tmpPath := tmp.Name()
		tmp.Close()
		if err := p.fetchAttachmentToFile(ctx, r.url, tmpPath); err != nil {
			os.Remove(tmpPath)
			log.Printf("iosdist: backfill %s id=%d fetch %q: %v (skip)", table, r.id, r.url, err)
			continue
		}
		meta, err := p.uploadIOSBlobAsset(tmpPath, kind, "iosdist/"+label+"/"+iosdistRandHex(6), mime, visibility)
		os.Remove(tmpPath)
		if err != nil {
			log.Printf("iosdist: backfill %s id=%d upload: %v (skip)", table, r.id, err)
			continue
		}
		marker := "asset://" + strconv.FormatInt(meta.ID, 10)
		if _, err := p.DB.ExecContext(ctx,
			`UPDATE `+table+` SET `+col+` = $2 WHERE id = $1`, r.id, marker); err != nil {
			log.Printf("iosdist: backfill %s id=%d update: %v", table, r.id, err)
			continue
		}
		migrated++
	}
	return migrated
}

// backfillIOSIcons migrates app icons (which use the redirect route, not
// the asset:// marker): any app with a legacy icon_url and no
// icon_asset_id yet.
func (p *Plugin) backfillIOSIcons(ctx context.Context) int {
	rows, err := p.DB.QueryContext(ctx,
		`SELECT id, COALESCE(workspace_id, ''), icon_url, icon_source FROM iosdist_apps
		 WHERE icon_url <> '' AND icon_url NOT LIKE '/iosdist/icon/%' AND COALESCE(icon_asset_id, 0) = 0`)
	if err != nil {
		log.Printf("iosdist: backfill icons query: %v", err)
		return 0
	}
	type row struct {
		id     int64
		ws     string
		url    string
		source string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ws, &r.url, &r.source); err != nil {
			continue
		}
		pending = append(pending, r)
	}
	rows.Close()

	migrated := 0
	for _, r := range pending {
		tmp, err := os.CreateTemp("", "iosdist-icon-*")
		if err != nil {
			continue
		}
		tmpPath := tmp.Name()
		tmp.Close()
		if err := p.fetchAttachmentToFile(ctx, r.url, tmpPath); err != nil {
			os.Remove(tmpPath)
			log.Printf("iosdist: backfill icon app=%d fetch %q: %v (skip)", r.id, r.url, err)
			continue
		}
		meta, err := p.uploadIOSBlobAsset(tmpPath, "media", "iosdist/icon/"+iosdistRandHex(6), "image/png", "public")
		os.Remove(tmpPath)
		if err != nil {
			log.Printf("iosdist: backfill icon app=%d upload: %v (skip)", r.id, err)
			continue
		}
		src := r.source
		if src == "" {
			src = "manual"
		}
		if err := p.setIOSAppIconAsset(r.id, r.ws, meta.ID, src); err != nil {
			log.Printf("iosdist: backfill icon app=%d set: %v", r.id, err)
			continue
		}
		migrated++
	}
	return migrated
}
