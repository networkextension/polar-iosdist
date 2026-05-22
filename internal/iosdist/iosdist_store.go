package iosdist

// Storage layer for the iOS distribution module. Tables are declared in
// store.go schema (iosdist_apps, iosdist_versions, iosdist_install_tokens).

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type IOSApp struct {
	ID              int64     `json:"id"`
	OwnerUserID     string    `json:"owner_user_id"`
	WorkspaceID     string    `json:"workspace_id"`
	Name            string    `json:"name"`
	BundleID        string    `json:"bundle_id"`
	Description     string    `json:"description"`
	IconURL         string    `json:"icon_url"`
	IconSource      string    `json:"icon_source"`     // '' | 'ipa' | 'manual' | 'asc'
	TestFlightURL   string    `json:"testflight_url"`  // empty means not configured
	ASCAppID        string    `json:"asc_app_id"`      // App Store Connect app id
	ASCBetaGroupID  string    `json:"asc_beta_group_id"`
	PublicSlug      string    `json:"public_slug"`
	IsPublic        bool      `json:"is_public"`
	Keywords        string    `json:"keywords"`         // comma-separated, ASC localization
	WhatsNew        string    `json:"whats_new"`        // latest ASC version's "what's new"
	PromotionalText string    `json:"promotional_text"` // ASC localization
	MarketingURL    string    `json:"marketing_url"`    // ASC localization
	SupportURL      string    `json:"support_url"`      // ASC localization
	// Multi-language overrides. JSONB keyed by BCP-47-ish locale code
	// ("zh-CN" / "en" / "ja" / "ko"). Empty / nil = no override; public
	// page falls back to the plain Name/Description/PromotionalText
	// fields. Honored by the public plaza + share page based on
	// ?lang= query param or Accept-Language header.
	NameI18N            map[string]string `json:"name_i18n,omitempty"`
	DescriptionI18N     map[string]string `json:"description_i18n,omitempty"`
	PromotionalTextI18N map[string]string `json:"promotional_text_i18n,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// IOSSignTask is one re-signing job (zsign run). Status transitions:
// pending → running → success (output_version_id set) | failed (error_message).
type IOSSignTask struct {
	ID              int64      `json:"id"`
	AppID           int64      `json:"app_id"`
	SourceVersionID int64      `json:"source_version_id"`
	OutputVersionID *int64     `json:"output_version_id,omitempty"`
	CertID          int64      `json:"cert_id"`
	ProfileID       int64      `json:"profile_id"`
	NewBundleID     string     `json:"new_bundle_id"` // empty = preserve
	NewAppName      string     `json:"new_app_name"`  // empty = preserve
	IdempotencyKey  string     `json:"idempotency_key"`
	Status          string     `json:"status"` // pending|running|success|failed
	ErrorMessage    string     `json:"error_message"`
	LogText         string     `json:"log_text"`
	SubmittedBy     string     `json:"submitted_by"`
	SubmittedAt     time.Time  `json:"submitted_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// IOSTestRequest is one "申请测试" submission from the public app page.
type IOSTestRequest struct {
	ID          int64      `json:"id"`
	AppID       int64      `json:"app_id"`
	Email       string     `json:"email"`
	FirstName   string     `json:"first_name"`
	LastName    string     `json:"last_name"`
	Status      string     `json:"status"` // pending|sent|failed
	ASCResponse string     `json:"asc_response"`
	SourceIP    string     `json:"source_ip"`
	UserAgent   string     `json:"user_agent"`
	CreatedAt   time.Time  `json:"created_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
}

// IOSASCConfig is the per-owner App Store Connect API key set. The
// p8_cipher field stays plain on the struct (we don't want it spilled
// into JSON responses) — see store funcs for read/write helpers.
type IOSASCConfig struct {
	OwnerUserID        string    `json:"owner_user_id"`
	WorkspaceID        string    `json:"workspace_id"`
	IssuerID           string    `json:"issuer_id"`
	KeyID              string    `json:"key_id"`
	P8Filename         string    `json:"p8_filename"`
	P8Encrypted        bool      `json:"p8_encrypted"`
	AccountHolderEmail string    `json:"account_holder_email"`
	TeamName           string    `json:"team_name"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`

	// p8Cipher mirrors the DB column. Unexported to keep secrets out of
	// JSON; the ASC client reads it through getIOSASCConfigSecret.
	p8Cipher string
}

type IOSVersion struct {
	ID               int64     `json:"id"`
	AppID            int64     `json:"app_id"`
	Version          string    `json:"version"`
	BuildNumber      string    `json:"build_number"`
	IPAUrl           string    `json:"ipa_url"`
	IPAFilename      string    `json:"ipa_filename"`
	IPASize          int64     `json:"ipa_size"`
	IPASHA256        string    `json:"ipa_sha256"`
	ReleaseNotes     string    `json:"release_notes"`
	IsSigned         bool      `json:"is_signed"`
	DistributionType string    `json:"distribution_type"` // app_store|enterprise|ad_hoc|development
	IPABundleID      string    `json:"ipa_bundle_id"`
	IPAShortVersion  string    `json:"ipa_short_version"`
	IPABuildNumber   string    `json:"ipa_build_number"`
	IPADisplayName   string    `json:"ipa_display_name"`
	IPAMinOS         string    `json:"ipa_min_os"`
	IPAHasEmbeddedPP bool      `json:"ipa_has_embedded_profile"`
	CreatedAt        time.Time `json:"created_at"`
}

// IOSCertificate is a user-supplied .p12 (or other-format) signing cert.
// The actual file is stored via AttachmentStorage and only referenced by URL;
// the password (if any) is encrypted at rest when IOSDIST_RESOURCE_KEY is set.
type IOSCertificate struct {
	ID                int64      `json:"id"`
	OwnerUserID       string     `json:"owner_user_id"`
	WorkspaceID       string     `json:"workspace_id"`
	Name              string     `json:"name"`
	Kind              string     `json:"kind"` // distribution|development|enterprise|adhoc
	FileURL           string     `json:"file_url"`
	FileFilename      string     `json:"file_filename"`
	FileSize          int64      `json:"file_size"`
	PasswordEncrypted bool       `json:"password_encrypted"`
	HasPassword       bool       `json:"has_password"`
	TeamID            string     `json:"team_id"`
	CommonName        string     `json:"common_name"`
	Notes             string     `json:"notes"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`

	// passwordCipher is the at-rest password column. Unexported so it
	// never ships to API consumers; the signing pipeline (M3) reads
	// this through decryptIOSDistSecret.
	passwordCipher string
}

// IOSProvisioningProfile is a user-supplied .mobileprovision file.
// We don't parse the embedded plist here yet (CMS unwrap + plist) —
// metadata fields are filled in from the upload form for now.
type IOSProvisioningProfile struct {
	ID           int64      `json:"id"`
	OwnerUserID  string     `json:"owner_user_id"`
	WorkspaceID  string     `json:"workspace_id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"` // app_store|ad_hoc|enterprise|development
	FileURL      string     `json:"file_url"`
	FileFilename string     `json:"file_filename"`
	FileSize     int64      `json:"file_size"`
	AppID        string     `json:"app_id"`
	TeamID       string     `json:"team_id"`
	UDIDCount    int        `json:"udid_count"`
	Notes        string     `json:"notes"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type IOSInstallToken struct {
	Token          string     `json:"token"`
	VersionID      int64      `json:"version_id"`
	CreatedBy      string     `json:"created_by"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	LastAccessedAt *time.Time `json:"last_accessed_at,omitempty"`
	AccessCount    int        `json:"access_count"`
}

func (p *Plugin) createIOSApp(app *IOSApp) error {
	if app == nil {
		return errors.New("ios app is nil")
	}
	now := time.Now()
	app.CreatedAt = now
	app.UpdatedAt = now
	if app.PublicSlug == "" {
		slug, err := p.generateUniqueIOSAppSlug()
		if err != nil {
			return err
		}
		app.PublicSlug = slug
	}
	return p.DB.QueryRow(
		`INSERT INTO iosdist_apps (owner_user_id, workspace_id, name, bundle_id, description, icon_url, public_slug, is_public, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9) RETURNING id`,
		app.OwnerUserID, app.WorkspaceID, app.Name, app.BundleID, app.Description, app.IconURL, app.PublicSlug, app.IsPublic, now,
	).Scan(&app.ID)
}

// backfillIOSAppSlugs assigns a public_slug to legacy rows that pre-date
// the column. Idempotent and cheap — typical instance has < 100 apps.
func (p *Plugin) backfillIOSAppSlugs() error {
	rows, err := p.DB.Query(`SELECT id FROM iosdist_apps WHERE public_slug = ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		slug, err := p.generateUniqueIOSAppSlug()
		if err != nil {
			return err
		}
		if _, err := p.DB.Exec(`UPDATE iosdist_apps SET public_slug = $1 WHERE id = $2`, slug, id); err != nil {
			return err
		}
	}
	return nil
}

// generateUniqueIOSAppSlug returns a URL-safe ~10-char id that doesn't
// collide with an existing row. Collision space is ~62^10 ≈ 8e17 so a
// single retry round is overkill in practice — we still do it because
// the unique index would surface a confusing error otherwise.
func (p *Plugin) generateUniqueIOSAppSlug() (string, error) {
	for attempts := 0; attempts < 5; attempts++ {
		candidate := generateSessionID()
		// Strip URL-unsafe chars and clip to 10. base64url already
		// avoids '/' and '+', so this is just length normalization.
		clean := make([]byte, 0, 10)
		for i := 0; i < len(candidate) && len(clean) < 10; i++ {
			c := candidate[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				clean = append(clean, c)
			}
		}
		slug := string(clean)
		if len(slug) < 8 {
			continue
		}
		var existing int64
		err := p.DB.QueryRow(`SELECT id FROM iosdist_apps WHERE public_slug = $1 LIMIT 1`, slug).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			return slug, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not generate unique app slug after 5 attempts")
}

// listPublicIOSApps powers the plaza page. Sorted by updated_at so
// recently-touched apps surface first. Caller paginates via limit/offset.
func (p *Plugin) listPublicIOSApps(limit, offset int) ([]IOSApp, error) {
	if limit <= 0 || limit > 100 {
		limit = 24
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := p.DB.Query(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, bundle_id, description, icon_url, icon_source, testflight_url, asc_app_id, asc_beta_group_id, public_slug, is_public, keywords, whats_new, promotional_text, marketing_url, support_url, name_i18n, description_i18n, promotional_text_i18n, created_at, updated_at
		 FROM iosdist_apps WHERE is_public = TRUE ORDER BY updated_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOSApp
	for rows.Next() {
		var a IOSApp
		var nameI18N, descI18N, promoI18N sql.NullString
		if err := rows.Scan(&a.ID, &a.OwnerUserID, &a.WorkspaceID, &a.Name, &a.BundleID, &a.Description, &a.IconURL, &a.IconSource, &a.TestFlightURL, &a.ASCAppID, &a.ASCBetaGroupID, &a.PublicSlug, &a.IsPublic, &a.Keywords, &a.WhatsNew, &a.PromotionalText, &a.MarketingURL, &a.SupportURL, &nameI18N, &descI18N, &promoI18N, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		a.NameI18N = parseI18N(nameI18N)
		a.DescriptionI18N = parseI18N(descI18N)
		a.PromotionalTextI18N = parseI18N(promoI18N)
		out = append(out, a)
	}
	return out, rows.Err()
}

// parseI18N decodes a JSONB column scanned as sql.NullString into a
// locale → text map. Returns nil for empty / invalid input — callers
// fall back to the plain single-language field.
func parseI18N(s sql.NullString) map[string]string {
	if !s.Valid || strings.TrimSpace(s.String) == "" {
		return nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(s.String), &out); err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p *Plugin) countPublicIOSApps() (int, error) {
	var n int
	err := p.DB.QueryRow(`SELECT COUNT(*) FROM iosdist_apps WHERE is_public = TRUE`).Scan(&n)
	return n, err
}

// getIOSAppBySlug is the public-page lookup. Owner check is intentionally
// absent — the slug is the auth token. Caller still gates on is_public.
func (p *Plugin) getIOSAppBySlug(slug string) (*IOSApp, error) {
	if slug == "" {
		return nil, nil
	}
	var a IOSApp
	var nameI18N, descI18N, promoI18N sql.NullString
	err := p.DB.QueryRow(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, bundle_id, description, icon_url, icon_source, testflight_url, asc_app_id, asc_beta_group_id, public_slug, is_public, keywords, whats_new, promotional_text, marketing_url, support_url, name_i18n, description_i18n, promotional_text_i18n, created_at, updated_at
		 FROM iosdist_apps WHERE public_slug = $1`,
		slug,
	).Scan(&a.ID, &a.OwnerUserID, &a.WorkspaceID, &a.Name, &a.BundleID, &a.Description, &a.IconURL, &a.IconSource, &a.TestFlightURL, &a.ASCAppID, &a.ASCBetaGroupID, &a.PublicSlug, &a.IsPublic, &a.Keywords, &a.WhatsNew, &a.PromotionalText, &a.MarketingURL, &a.SupportURL, &nameI18N, &descI18N, &promoI18N, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.NameI18N = parseI18N(nameI18N)
	a.DescriptionI18N = parseI18N(descI18N)
	a.PromotionalTextI18N = parseI18N(promoI18N)
	return &a, nil
}

// setIOSAppNameAndDescription writes name + description without touching
// other fields. Used by the ASC meta sync. Empty strings overwrite (so
// caller must guard if it doesn't want that).
func (p *Plugin) setIOSAppNameAndDescription(id int64, workspaceID, name, description string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps SET name = $1, description = $2, updated_at = $3
		 WHERE id = $4 AND workspace_id = $5`,
		name, description, time.Now(), id, workspaceID,
	)
	return err
}

// IOSAppMetaUpdate is the bundle of metadata fields that the ASC sync
// can refresh. Empty fields are written — callers should pass through
// existing values for fields ASC didn't return.
type IOSAppMetaUpdate struct {
	Name            string
	Description     string
	Keywords        string
	WhatsNew        string
	PromotionalText string
	MarketingURL    string
	SupportURL      string
}

func (p *Plugin) setIOSAppMeta(id int64, workspaceID string, m IOSAppMetaUpdate) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps
		 SET name = $1, description = $2, keywords = $3, whats_new = $4, promotional_text = $5,
		     marketing_url = $6, support_url = $7, updated_at = $8
		 WHERE id = $9 AND workspace_id = $10`,
		m.Name, m.Description, m.Keywords, m.WhatsNew, m.PromotionalText, m.MarketingURL, m.SupportURL,
		time.Now(), id, workspaceID,
	)
	return err
}

func (p *Plugin) setIOSAppPublicVisibility(id int64, workspaceID string, isPublic bool) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps SET is_public = $1, updated_at = $2
		 WHERE id = $3 AND workspace_id = $4`,
		isPublic, time.Now(), id, workspaceID,
	)
	return err
}

func (p *Plugin) listIOSApps(workspaceID string) ([]IOSApp, error) {
	rows, err := p.DB.Query(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, bundle_id, description, icon_url, icon_source, testflight_url, asc_app_id, asc_beta_group_id, public_slug, is_public, keywords, whats_new, promotional_text, marketing_url, support_url, created_at, updated_at
		 FROM iosdist_apps WHERE workspace_id = $1 ORDER BY updated_at DESC`,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []IOSApp
	for rows.Next() {
		var a IOSApp
		if err := rows.Scan(&a.ID, &a.OwnerUserID, &a.WorkspaceID, &a.Name, &a.BundleID, &a.Description, &a.IconURL, &a.IconSource, &a.TestFlightURL, &a.ASCAppID, &a.ASCBetaGroupID, &a.PublicSlug, &a.IsPublic, &a.Keywords, &a.WhatsNew, &a.PromotionalText, &a.MarketingURL, &a.SupportURL, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// getIOSAppByID fetches an app without a workspace check. Only callers
// that have already authorized via a separate channel (e.g. an install
// token bound to a specific version, or the public share page using
// public_slug) should use this — keep the workspace-scoped getIOSApp
// for the user-facing handlers.
func (p *Plugin) getIOSAppByID(id int64) (*IOSApp, error) {
	var a IOSApp
	err := p.DB.QueryRow(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, bundle_id, description, icon_url, icon_source, testflight_url, asc_app_id, asc_beta_group_id, public_slug, is_public, keywords, whats_new, promotional_text, marketing_url, support_url, created_at, updated_at
		 FROM iosdist_apps WHERE id = $1`,
		id,
	).Scan(&a.ID, &a.OwnerUserID, &a.WorkspaceID, &a.Name, &a.BundleID, &a.Description, &a.IconURL, &a.IconSource, &a.TestFlightURL, &a.ASCAppID, &a.ASCBetaGroupID, &a.PublicSlug, &a.IsPublic, &a.Keywords, &a.WhatsNew, &a.PromotionalText, &a.MarketingURL, &a.SupportURL, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (p *Plugin) getIOSApp(id int64, workspaceID string) (*IOSApp, error) {
	var a IOSApp
	err := p.DB.QueryRow(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, bundle_id, description, icon_url, icon_source, testflight_url, asc_app_id, asc_beta_group_id, public_slug, is_public, keywords, whats_new, promotional_text, marketing_url, support_url, created_at, updated_at
		 FROM iosdist_apps WHERE id = $1 AND workspace_id = $2`,
		id, workspaceID,
	).Scan(&a.ID, &a.OwnerUserID, &a.WorkspaceID, &a.Name, &a.BundleID, &a.Description, &a.IconURL, &a.IconSource, &a.TestFlightURL, &a.ASCAppID, &a.ASCBetaGroupID, &a.PublicSlug, &a.IsPublic, &a.Keywords, &a.WhatsNew, &a.PromotionalText, &a.MarketingURL, &a.SupportURL, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (p *Plugin) deleteIOSApp(id int64, workspaceID string) error {
	_, err := p.DB.Exec(`DELETE FROM iosdist_apps WHERE id = $1 AND workspace_id = $2`, id, workspaceID)
	return err
}

func (p *Plugin) touchIOSApp(id int64) error {
	_, err := p.DB.Exec(`UPDATE iosdist_apps SET updated_at = $1 WHERE id = $2`, time.Now(), id)
	return err
}

// setIOSAppIcon writes the icon URL + source. The source field guards
// against future IPA uploads silently overwriting a manual icon — see
// the icon-resolution note on IOSApp.
func (p *Plugin) setIOSAppIcon(id int64, workspaceID, iconURL, source string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps SET icon_url = $1, icon_source = $2, updated_at = $3
		 WHERE id = $4 AND workspace_id = $5`,
		iconURL, source, time.Now(), id, workspaceID,
	)
	return err
}

func (p *Plugin) setIOSAppTestFlightURL(id int64, workspaceID, url string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps SET testflight_url = $1, updated_at = $2
		 WHERE id = $3 AND workspace_id = $4`,
		url, time.Now(), id, workspaceID,
	)
	return err
}

func (p *Plugin) setIOSAppASCBinding(id int64, workspaceID, ascAppID, ascBetaGroupID string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_apps SET asc_app_id = $1, asc_beta_group_id = $2, updated_at = $3
		 WHERE id = $4 AND workspace_id = $5`,
		ascAppID, ascBetaGroupID, time.Now(), id, workspaceID,
	)
	return err
}

// ---- ASC config ---------------------------------------------------------

// upsertIOSASCConfig writes the per-workspace ASC API key. T6-B
// flipped the conflict target from owner_user_id (legacy per-user)
// to workspace_id (team-scoped: one ASC config per workspace).
// owner_user_id is still required by the table's PRIMARY KEY but
// downgrades semantically to "who uploaded this".
//
// Important: existing rows whose owner_user_id collides with
// cfg.OwnerUserID will be hit by the PK first, even if their
// workspace_id differs. T6-D will rename owner_user_id to
// creator_user_id and drop its PK status, fully decoupling. For
// now upserts that come from a different user in the same
// workspace will fail on PK collision — surface as an error.
func (p *Plugin) upsertIOSASCConfig(cfg *IOSASCConfig) error {
	if cfg == nil {
		return errors.New("asc config is nil")
	}
	if cfg.WorkspaceID == "" {
		return errors.New("asc config workspace_id is empty")
	}
	now := time.Now()
	cfg.UpdatedAt = now
	_, err := p.DB.Exec(
		`INSERT INTO iosdist_asc_configs (owner_user_id, workspace_id, issuer_id, key_id, p8_cipher, p8_filename, p8_encrypted, account_holder_email, team_name, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		 ON CONFLICT (workspace_id) WHERE workspace_id IS NOT NULL DO UPDATE
		   SET owner_user_id        = EXCLUDED.owner_user_id,
		       issuer_id            = EXCLUDED.issuer_id,
		       key_id               = EXCLUDED.key_id,
		       p8_cipher            = EXCLUDED.p8_cipher,
		       p8_filename          = EXCLUDED.p8_filename,
		       p8_encrypted         = EXCLUDED.p8_encrypted,
		       account_holder_email = EXCLUDED.account_holder_email,
		       team_name            = EXCLUDED.team_name,
		       updated_at           = EXCLUDED.updated_at`,
		cfg.OwnerUserID, cfg.WorkspaceID, cfg.IssuerID, cfg.KeyID, cfg.p8Cipher, cfg.P8Filename, cfg.P8Encrypted, cfg.AccountHolderEmail, cfg.TeamName, now,
	)
	if err == nil && cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = now
	}
	return err
}

func (p *Plugin) setIOSASCConfigAccountInfo(workspaceID, email, teamName string) error {
	_, err := p.DB.Exec(
		`UPDATE iosdist_asc_configs SET account_holder_email = $1, team_name = $2, updated_at = $3
		 WHERE workspace_id = $4`,
		email, teamName, time.Now(), workspaceID,
	)
	return err
}

func (p *Plugin) getIOSASCConfig(workspaceID string) (*IOSASCConfig, error) {
	var c IOSASCConfig
	err := p.DB.QueryRow(
		`SELECT owner_user_id, COALESCE(workspace_id, ''), issuer_id, key_id, p8_cipher, p8_filename, p8_encrypted, account_holder_email, team_name, created_at, updated_at
		 FROM iosdist_asc_configs WHERE workspace_id = $1`,
		workspaceID,
	).Scan(&c.OwnerUserID, &c.WorkspaceID, &c.IssuerID, &c.KeyID, &c.p8Cipher, &c.P8Filename, &c.P8Encrypted, &c.AccountHolderEmail, &c.TeamName, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ---- Test requests -------------------------------------------------------

func (p *Plugin) createIOSTestRequest(r *IOSTestRequest) error {
	if r == nil {
		return errors.New("test request is nil")
	}
	r.CreatedAt = time.Now()
	if r.Status == "" {
		r.Status = "pending"
	}
	return p.DB.QueryRow(
		`INSERT INTO iosdist_test_requests
			(app_id, email, first_name, last_name, status, asc_response, source_ip, user_agent, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		r.AppID, r.Email, r.FirstName, r.LastName, r.Status, r.ASCResponse, r.SourceIP, r.UserAgent, r.CreatedAt,
	).Scan(&r.ID)
}

func (p *Plugin) markIOSTestRequest(id int64, status, ascResponse string) error {
	now := time.Now()
	_, err := p.DB.Exec(
		`UPDATE iosdist_test_requests SET status = $1, asc_response = $2, processed_at = $3 WHERE id = $4`,
		status, ascResponse, now, id,
	)
	return err
}

func (p *Plugin) listIOSTestRequests(appID int64, limit int) ([]IOSTestRequest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := p.DB.Query(
		`SELECT id, app_id, email, first_name, last_name, status, asc_response, source_ip, user_agent, created_at, processed_at
		 FROM iosdist_test_requests WHERE app_id = $1 ORDER BY created_at DESC LIMIT $2`,
		appID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOSTestRequest
	for rows.Next() {
		var r IOSTestRequest
		if err := rows.Scan(&r.ID, &r.AppID, &r.Email, &r.FirstName, &r.LastName, &r.Status, &r.ASCResponse, &r.SourceIP, &r.UserAgent, &r.CreatedAt, &r.ProcessedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Sign tasks ----------------------------------------------------------

const iosSignTaskColumns = `id, app_id, source_version_id, output_version_id, cert_id, profile_id,
	new_bundle_id, new_app_name, idempotency_key, status, error_message, log_text,
	submitted_by, submitted_at, started_at, completed_at`

func scanIOSSignTask(rs interface {
	Scan(dest ...any) error
}, t *IOSSignTask) error {
	return rs.Scan(
		&t.ID, &t.AppID, &t.SourceVersionID, &t.OutputVersionID, &t.CertID, &t.ProfileID,
		&t.NewBundleID, &t.NewAppName, &t.IdempotencyKey, &t.Status, &t.ErrorMessage, &t.LogText,
		&t.SubmittedBy, &t.SubmittedAt, &t.StartedAt, &t.CompletedAt,
	)
}

func (p *Plugin) createIOSSignTask(t *IOSSignTask) error {
	if t == nil {
		return errors.New("sign task is nil")
	}
	t.SubmittedAt = time.Now()
	if t.Status == "" {
		t.Status = "pending"
	}
	return p.DB.QueryRow(
		`INSERT INTO iosdist_sign_tasks
			(app_id, source_version_id, cert_id, profile_id, new_bundle_id, new_app_name,
			 idempotency_key, status, submitted_by, submitted_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		t.AppID, t.SourceVersionID, t.CertID, t.ProfileID, t.NewBundleID, t.NewAppName,
		t.IdempotencyKey, t.Status, t.SubmittedBy, t.SubmittedAt,
	).Scan(&t.ID)
}

func (p *Plugin) getIOSSignTask(id int64) (*IOSSignTask, error) {
	var t IOSSignTask
	row := p.DB.QueryRow(`SELECT `+iosSignTaskColumns+` FROM iosdist_sign_tasks WHERE id = $1`, id)
	if err := scanIOSSignTask(row, &t); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// findIOSSuccessfulSignTaskByKey returns the most recent succeeded task
// for an idempotency key, used by the handler to skip a redundant
// re-sign and just return the existing result.
func (p *Plugin) findIOSSuccessfulSignTaskByKey(key string) (*IOSSignTask, error) {
	if key == "" {
		return nil, nil
	}
	var t IOSSignTask
	row := p.DB.QueryRow(
		`SELECT `+iosSignTaskColumns+`
		 FROM iosdist_sign_tasks
		 WHERE idempotency_key = $1 AND status = 'success'
		 ORDER BY submitted_at DESC LIMIT 1`,
		key,
	)
	if err := scanIOSSignTask(row, &t); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (p *Plugin) listIOSSignTasksForApp(appID int64, limit int) ([]IOSSignTask, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := p.DB.Query(
		`SELECT `+iosSignTaskColumns+`
		 FROM iosdist_sign_tasks WHERE app_id = $1 ORDER BY submitted_at DESC LIMIT $2`,
		appID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOSSignTask
	for rows.Next() {
		var t IOSSignTask
		if err := scanIOSSignTask(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *Plugin) markIOSSignTaskRunning(id int64) error {
	now := time.Now()
	_, err := p.DB.Exec(
		`UPDATE iosdist_sign_tasks SET status = 'running', started_at = $1 WHERE id = $2`,
		now, id,
	)
	return err
}

func (p *Plugin) markIOSSignTaskSuccess(id, outputVersionID int64, logText string) error {
	now := time.Now()
	_, err := p.DB.Exec(
		`UPDATE iosdist_sign_tasks
		 SET status = 'success', output_version_id = $1, log_text = $2, completed_at = $3
		 WHERE id = $4`,
		outputVersionID, logText, now, id,
	)
	return err
}

func (p *Plugin) markIOSSignTaskFailed(id int64, errMsg, logText string) error {
	now := time.Now()
	_, err := p.DB.Exec(
		`UPDATE iosdist_sign_tasks
		 SET status = 'failed', error_message = $1, log_text = $2, completed_at = $3
		 WHERE id = $4`,
		errMsg, logText, now, id,
	)
	return err
}

// recoverIOSSignTasks runs at server startup. Rows stuck in 'running'
// imply a crash mid-job; mark them failed with a clear message. Rows
// in 'pending' get re-enqueued so they get a chance after restart.
func (p *Plugin) recoverIOSSignTasks() ([]int64, error) {
	now := time.Now()
	if _, err := p.DB.Exec(
		`UPDATE iosdist_sign_tasks
		 SET status = 'failed', error_message = '服务在签名中途重启，任务已中止', completed_at = $1
		 WHERE status = 'running'`,
		now,
	); err != nil {
		return nil, err
	}
	rows, err := p.DB.Query(`SELECT id FROM iosdist_sign_tasks WHERE status = 'pending' ORDER BY submitted_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// countIOSTestRequestsByEmail is the rate-limit primitive: how many
// requests for this app + email arrived in the trailing window.
func (p *Plugin) countIOSTestRequestsByEmail(appID int64, email string, since time.Time) (int, error) {
	var n int
	err := p.DB.QueryRow(
		`SELECT COUNT(*) FROM iosdist_test_requests WHERE app_id = $1 AND email = $2 AND created_at >= $3`,
		appID, email, since,
	).Scan(&n)
	return n, err
}

func (p *Plugin) deleteIOSASCConfig(workspaceID string) error {
	_, err := p.DB.Exec(`DELETE FROM iosdist_asc_configs WHERE workspace_id = $1`, workspaceID)
	return err
}

const iosVersionColumns = `id, app_id, version, build_number, ipa_url, ipa_filename, ipa_size, ipa_sha256, release_notes, is_signed, distribution_type,
	ipa_bundle_id, ipa_short_version, ipa_build_number, ipa_display_name, ipa_min_os, ipa_has_embedded_profile, created_at`

func scanIOSVersion(rs interface {
	Scan(dest ...any) error
}, v *IOSVersion) error {
	return rs.Scan(
		&v.ID, &v.AppID, &v.Version, &v.BuildNumber, &v.IPAUrl, &v.IPAFilename, &v.IPASize, &v.IPASHA256, &v.ReleaseNotes, &v.IsSigned, &v.DistributionType,
		&v.IPABundleID, &v.IPAShortVersion, &v.IPABuildNumber, &v.IPADisplayName, &v.IPAMinOS, &v.IPAHasEmbeddedPP, &v.CreatedAt,
	)
}

func (p *Plugin) createIOSVersion(v *IOSVersion) error {
	if v == nil {
		return errors.New("ios version is nil")
	}
	v.CreatedAt = time.Now()
	return p.DB.QueryRow(
		`INSERT INTO iosdist_versions (app_id, version, build_number, ipa_url, ipa_filename, ipa_size, ipa_sha256, release_notes, is_signed, distribution_type,
			ipa_bundle_id, ipa_short_version, ipa_build_number, ipa_display_name, ipa_min_os, ipa_has_embedded_profile, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING id`,
		v.AppID, v.Version, v.BuildNumber, v.IPAUrl, v.IPAFilename, v.IPASize, v.IPASHA256, v.ReleaseNotes, v.IsSigned, v.DistributionType,
		v.IPABundleID, v.IPAShortVersion, v.IPABuildNumber, v.IPADisplayName, v.IPAMinOS, v.IPAHasEmbeddedPP, v.CreatedAt,
	).Scan(&v.ID)
}

func (p *Plugin) listIOSVersions(appID int64) ([]IOSVersion, error) {
	rows, err := p.DB.Query(
		`SELECT `+iosVersionColumns+`
		 FROM iosdist_versions WHERE app_id = $1 ORDER BY created_at DESC`,
		appID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOSVersion
	for rows.Next() {
		var v IOSVersion
		if err := scanIOSVersion(rows, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (p *Plugin) getIOSVersion(id int64) (*IOSVersion, error) {
	var v IOSVersion
	row := p.DB.QueryRow(`SELECT `+iosVersionColumns+` FROM iosdist_versions WHERE id = $1`, id)
	if err := scanIOSVersion(row, &v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

func (p *Plugin) deleteIOSVersion(id int64) error {
	_, err := p.DB.Exec(`DELETE FROM iosdist_versions WHERE id = $1`, id)
	return err
}

func (p *Plugin) createIOSInstallToken(t *IOSInstallToken) error {
	if t == nil {
		return errors.New("install token is nil")
	}
	t.CreatedAt = time.Now()
	_, err := p.DB.Exec(
		`INSERT INTO iosdist_install_tokens (token, version_id, created_by, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		t.Token, t.VersionID, t.CreatedBy, t.ExpiresAt, t.CreatedAt,
	)
	return err
}

func (p *Plugin) getIOSInstallToken(token string) (*IOSInstallToken, error) {
	var t IOSInstallToken
	err := p.DB.QueryRow(
		`SELECT token, version_id, created_by, expires_at, created_at, last_accessed_at, access_count
		 FROM iosdist_install_tokens WHERE token = $1`,
		token,
	).Scan(&t.Token, &t.VersionID, &t.CreatedBy, &t.ExpiresAt, &t.CreatedAt, &t.LastAccessedAt, &t.AccessCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (p *Plugin) bumpIOSInstallTokenAccess(token string) error {
	now := time.Now()
	_, err := p.DB.Exec(
		`UPDATE iosdist_install_tokens
		 SET last_accessed_at = $1, access_count = access_count + 1
		 WHERE token = $2`,
		now, token,
	)
	return err
}

// ---- Certificates ---------------------------------------------------------

func (p *Plugin) createIOSCertificate(c *IOSCertificate) error {
	if c == nil {
		return errors.New("ios certificate is nil")
	}
	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now
	return p.DB.QueryRow(
		`INSERT INTO iosdist_certificates
			(owner_user_id, workspace_id, name, kind, file_url, file_filename, file_size, password_cipher, password_encrypted, team_id, common_name, notes, expires_at, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
		 RETURNING id`,
		c.OwnerUserID, c.WorkspaceID, c.Name, c.Kind, c.FileURL, c.FileFilename, c.FileSize,
		c.passwordCipher, c.PasswordEncrypted,
		c.TeamID, c.CommonName, c.Notes, c.ExpiresAt, now,
	).Scan(&c.ID)
}

func (p *Plugin) listIOSCertificates(workspaceID string) ([]IOSCertificate, error) {
	rows, err := p.DB.Query(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, kind, file_url, file_filename, file_size,
			password_cipher, password_encrypted, team_id, common_name, notes, expires_at, created_at, updated_at
		 FROM iosdist_certificates WHERE workspace_id = $1 ORDER BY updated_at DESC`,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOSCertificate
	for rows.Next() {
		var c IOSCertificate
		if err := rows.Scan(
			&c.ID, &c.OwnerUserID, &c.WorkspaceID, &c.Name, &c.Kind, &c.FileURL, &c.FileFilename, &c.FileSize,
			&c.passwordCipher, &c.PasswordEncrypted, &c.TeamID, &c.CommonName, &c.Notes, &c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		c.HasPassword = c.passwordCipher != ""
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Plugin) getIOSCertificate(id int64, workspaceID string) (*IOSCertificate, error) {
	var c IOSCertificate
	err := p.DB.QueryRow(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, kind, file_url, file_filename, file_size,
			password_cipher, password_encrypted, team_id, common_name, notes, expires_at, created_at, updated_at
		 FROM iosdist_certificates WHERE id = $1 AND workspace_id = $2`,
		id, workspaceID,
	).Scan(
		&c.ID, &c.OwnerUserID, &c.WorkspaceID, &c.Name, &c.Kind, &c.FileURL, &c.FileFilename, &c.FileSize,
		&c.passwordCipher, &c.PasswordEncrypted, &c.TeamID, &c.CommonName, &c.Notes, &c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.HasPassword = c.passwordCipher != ""
	return &c, nil
}

func (p *Plugin) deleteIOSCertificate(id int64, workspaceID string) error {
	_, err := p.DB.Exec(`DELETE FROM iosdist_certificates WHERE id = $1 AND workspace_id = $2`, id, workspaceID)
	return err
}

// ---- Provisioning profiles -----------------------------------------------

func (p *Plugin) createIOSProfile(prof *IOSProvisioningProfile) error {
	if prof == nil {
		return errors.New("ios profile is nil")
	}
	now := time.Now()
	prof.CreatedAt = now
	prof.UpdatedAt = now
	return p.DB.QueryRow(
		`INSERT INTO iosdist_profiles
			(owner_user_id, workspace_id, name, kind, file_url, file_filename, file_size, app_id, team_id, udid_count, notes, expires_at, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)
		 RETURNING id`,
		prof.OwnerUserID, prof.WorkspaceID, prof.Name, prof.Kind, prof.FileURL, prof.FileFilename, prof.FileSize,
		prof.AppID, prof.TeamID, prof.UDIDCount, prof.Notes, prof.ExpiresAt, now,
	).Scan(&prof.ID)
}

func (p *Plugin) listIOSProfiles(workspaceID string) ([]IOSProvisioningProfile, error) {
	rows, err := p.DB.Query(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, kind, file_url, file_filename, file_size,
			app_id, team_id, udid_count, notes, expires_at, created_at, updated_at
		 FROM iosdist_profiles WHERE workspace_id = $1 ORDER BY updated_at DESC`,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOSProvisioningProfile
	for rows.Next() {
		var prof IOSProvisioningProfile
		if err := rows.Scan(
			&prof.ID, &prof.OwnerUserID, &prof.WorkspaceID, &prof.Name, &prof.Kind, &prof.FileURL, &prof.FileFilename, &prof.FileSize,
			&prof.AppID, &prof.TeamID, &prof.UDIDCount, &prof.Notes, &prof.ExpiresAt, &prof.CreatedAt, &prof.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, prof)
	}
	return out, rows.Err()
}

func (p *Plugin) getIOSProfileForOwner(id int64, workspaceID string) (*IOSProvisioningProfile, error) {
	var prof IOSProvisioningProfile
	err := p.DB.QueryRow(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, kind, file_url, file_filename, file_size,
			app_id, team_id, udid_count, notes, expires_at, created_at, updated_at
		 FROM iosdist_profiles WHERE id = $1 AND workspace_id = $2`,
		id, workspaceID,
	).Scan(
		&prof.ID, &prof.OwnerUserID, &prof.WorkspaceID, &prof.Name, &prof.Kind, &prof.FileURL, &prof.FileFilename, &prof.FileSize,
		&prof.AppID, &prof.TeamID, &prof.UDIDCount, &prof.Notes, &prof.ExpiresAt, &prof.CreatedAt, &prof.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &prof, nil
}

func (p *Plugin) deleteIOSProfile(id int64, workspaceID string) error {
	_, err := p.DB.Exec(`DELETE FROM iosdist_profiles WHERE id = $1 AND workspace_id = $2`, id, workspaceID)
	return err
}

// ---- iosdist_app_status: ASC snapshot cache ----

type IOSAppStatus struct {
	AppID               int64      `json:"app_id"`
	AppStoreVersion     string     `json:"appstore_version"`
	AppStoreState       string     `json:"appstore_state"`
	AppStoreSubmittedAt *time.Time `json:"appstore_submitted_at,omitempty"`
	AppStoreReleasedAt  *time.Time `json:"appstore_released_at,omitempty"`
	TFBuildVersion      string     `json:"tf_build_version"`
	TFProcessingState   string     `json:"tf_processing_state"`
	TFBetaState         string     `json:"tf_beta_state"`
	TFUploadedAt        *time.Time `json:"tf_uploaded_at,omitempty"`
	TFExpiresAt         *time.Time `json:"tf_expires_at,omitempty"`
	BetaTesterCount     int        `json:"beta_tester_count"`
	SyncedAt            time.Time  `json:"synced_at"`
	SyncError           string     `json:"sync_error"`
}

func (p *Plugin) getIOSAppStatus(appID int64) (*IOSAppStatus, error) {
	var st IOSAppStatus
	var submittedAt, releasedAt, uploadedAt, expiresAt sql.NullTime
	err := p.DB.QueryRow(
		`SELECT app_id, appstore_version, appstore_state, appstore_submitted_at, appstore_released_at,
		        tf_build_version, tf_processing_state, tf_beta_state, tf_uploaded_at, tf_expires_at,
		        beta_tester_count, synced_at, sync_error
		   FROM iosdist_app_status WHERE app_id = $1`,
		appID,
	).Scan(
		&st.AppID, &st.AppStoreVersion, &st.AppStoreState, &submittedAt, &releasedAt,
		&st.TFBuildVersion, &st.TFProcessingState, &st.TFBetaState, &uploadedAt, &expiresAt,
		&st.BetaTesterCount, &st.SyncedAt, &st.SyncError,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if submittedAt.Valid {
		t := submittedAt.Time
		st.AppStoreSubmittedAt = &t
	}
	if releasedAt.Valid {
		t := releasedAt.Time
		st.AppStoreReleasedAt = &t
	}
	if uploadedAt.Valid {
		t := uploadedAt.Time
		st.TFUploadedAt = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		st.TFExpiresAt = &t
	}
	return &st, nil
}

// upsertIOSAppStatus writes the snapshot. When syncErr is non-empty we
// still store the metric fields the caller managed to fetch — stale
// values beat blank ones when one of the 3 ASC calls hiccups.
func (p *Plugin) upsertIOSAppStatus(st *IOSAppStatus) error {
	if st == nil || st.AppID == 0 {
		return errors.New("upsertIOSAppStatus: nil or zero app id")
	}
	_, err := p.DB.Exec(
		`INSERT INTO iosdist_app_status
		   (app_id, appstore_version, appstore_state, appstore_submitted_at, appstore_released_at,
		    tf_build_version, tf_processing_state, tf_beta_state, tf_uploaded_at, tf_expires_at,
		    beta_tester_count, synced_at, sync_error)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (app_id) DO UPDATE SET
		    appstore_version = EXCLUDED.appstore_version,
		    appstore_state = EXCLUDED.appstore_state,
		    appstore_submitted_at = EXCLUDED.appstore_submitted_at,
		    appstore_released_at = EXCLUDED.appstore_released_at,
		    tf_build_version = EXCLUDED.tf_build_version,
		    tf_processing_state = EXCLUDED.tf_processing_state,
		    tf_beta_state = EXCLUDED.tf_beta_state,
		    tf_uploaded_at = EXCLUDED.tf_uploaded_at,
		    tf_expires_at = EXCLUDED.tf_expires_at,
		    beta_tester_count = EXCLUDED.beta_tester_count,
		    synced_at = EXCLUDED.synced_at,
		    sync_error = EXCLUDED.sync_error`,
		st.AppID, st.AppStoreVersion, st.AppStoreState, st.AppStoreSubmittedAt, st.AppStoreReleasedAt,
		st.TFBuildVersion, st.TFProcessingState, st.TFBetaState, st.TFUploadedAt, st.TFExpiresAt,
		st.BetaTesterCount, st.SyncedAt, st.SyncError,
	)
	return err
}

// listIOSAppsWithASC: input set for the status sync worker. Apps without
// asc_app_id can't be synced, so we skip them. No workspace filter —
// the worker is platform-wide.
func (p *Plugin) listIOSAppsWithASC() ([]IOSApp, error) {
	rows, err := p.DB.Query(
		`SELECT id, owner_user_id, COALESCE(workspace_id, ''), name, bundle_id, description, icon_url, icon_source, testflight_url, asc_app_id, asc_beta_group_id, public_slug, is_public, keywords, whats_new, promotional_text, marketing_url, support_url, created_at, updated_at
		   FROM iosdist_apps WHERE asc_app_id <> '' ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IOSApp, 0)
	for rows.Next() {
		var a IOSApp
		if err := rows.Scan(&a.ID, &a.OwnerUserID, &a.WorkspaceID, &a.Name, &a.BundleID, &a.Description, &a.IconURL, &a.IconSource, &a.TestFlightURL, &a.ASCAppID, &a.ASCBetaGroupID, &a.PublicSlug, &a.IsPublic, &a.Keywords, &a.WhatsNew, &a.PromotionalText, &a.MarketingURL, &a.SupportURL, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
