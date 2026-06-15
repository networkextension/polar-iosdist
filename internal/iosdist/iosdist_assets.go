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

// iconURLBase returns the absolute origin to prefix the icon redirect
// route with, so icon_url is a fully-qualified URL that resolves from ANY
// page (the iOS app, a shared link, another subdomain) — not just from
// iosdist's own same-origin pages. Empty (IOSDIST_PUBLIC_BASE_URL unset)
// falls back to a relative path, which only works same-origin.
func (p *Plugin) iconURLBase() string {
	return strings.TrimRight(p.publicBaseURL, "/")
}

// setIOSAppIconAsset points icon_url at the stable redirect route — keyed
// by the app's opaque public_slug, NOT its sequential db id, so the public
// URL doesn't leak record ids/counts — and records the backing asset id +
// source in one UPDATE. public_slug is computed from the same row, so no
// extra round-trip; createIOSApp guarantees every app has one. The URL is
// absolute (publicBaseURL prefix) so it works cross-origin.
func (p *Plugin) setIOSAppIconAsset(appID int64, workspaceID string, assetID int64, source string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps
		 SET icon_url = $1 || '/iosdist/icon/' || public_slug, icon_asset_id = $2, icon_source = $3, updated_at = now()
		 WHERE id = $4 AND workspace_id = $5 AND public_slug <> ''`,
		p.iconURLBase(), assetID, source, appID, workspaceID,
	)
	return err
}

// getIOSAppIconRef returns the icon's backing asset id (0 if none) plus
// the raw icon_url (legacy /uploads or http for un-migrated apps), keyed
// by the opaque public_slug. Narrow read used by the redirect route only.
func (p *Plugin) getIOSAppIconRef(slug string) (assetID int64, iconURL string, err error) {
	var aid sql.NullInt64
	var u sql.NullString
	err = p.DB.QueryRow(
		`SELECT COALESCE(icon_asset_id, 0), COALESCE(icon_url, '') FROM iosdist_apps WHERE public_slug = $1`,
		slug,
	).Scan(&aid, &u)
	if err != nil {
		return 0, "", err
	}
	return aid.Int64, u.String, nil
}

// handleIOSAppIconRedirect is the public, no-auth icon route, keyed by the
// app's opaque public_slug. It 302s to a fresh signed asset URL (icons live
// exclusively in the central catalog post-cutover).
func (p *Plugin) handleIOSAppIconRedirect(c *gin.Context) {
	slug := c.Param("slug")
	if slug == "" {
		c.Status(http.StatusNotFound)
		return
	}
	assetID, _, err := p.getIOSAppIconRef(slug)
	if err != nil || assetID == 0 {
		c.Status(http.StatusNotFound)
		return
	}
	signed, serr := p.Dock.AssetDownloadURL(assetID)
	if serr != nil || signed == "" {
		log.Printf("iosdist: icon redirect slug=%s asset=%d sign failed: %v", slug, assetID, serr)
		c.Status(http.StatusBadGateway)
		return
	}
	c.Redirect(http.StatusFound, signed)
}

