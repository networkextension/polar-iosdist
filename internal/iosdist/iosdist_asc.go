package iosdist

// App Store Connect API integration.
//
// What's here:
//   - Loading the operator's .p8 (PEM-wrapped PKCS#8 EC P-256) private key.
//   - Signing the ES256 JWT that ASC requires on every call (header
//     {alg:ES256,kid,typ:JWT}; claims {iss,iat,exp,aud:appstoreconnect-v1}).
//   - A tiny in-memory token cache so we don't re-sign for every request —
//     ASC tokens are valid for up to 20 minutes, we keep ours at 18 to
//     leave clock-skew margin.
//   - Thin HTTP client around the three calls the iosdist module needs:
//     list apps, list beta groups, create+invite a tester.
//
// Failure mode mapping is deliberate: 401/403/422 errors come back as
// errIOSASCClient (caller surfaces a 400 to the user). Network errors and
// 5xx come back as wrapped errors (caller returns 502).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ascAPIBase    = "https://api.appstoreconnect.apple.com"
	ascAudience   = "appstoreconnect-v1"
	ascTokenTTL   = 18 * time.Minute // <20m to allow clock skew
	ascHTTPTimeout = 30 * time.Second
)

var errIOSASCClient = errors.New("asc client error")

type ascCachedToken struct {
	token     string
	expiresAt time.Time
}

// ascTokenCache is keyed by sha256(issuer || key_id || p8_pem). Rotating
// the key invalidates the cache automatically because the fingerprint
// changes.
var (
	ascTokenCacheMu sync.Mutex
	ascTokenCache   = map[string]ascCachedToken{}
)

// loadASCConfigPrivateKey decrypts the stored p8 cipher (when the server
// has an IOSDIST_RESOURCE_KEY) and parses it into an ECDSA key. The .p8
// Apple emits is a PEM block of type "PRIVATE KEY" wrapping a PKCS#8
// structure that holds the EC P-256 key.
func (p *Plugin) loadASCConfigPrivateKey(cfg *IOSASCConfig) (*ecdsa.PrivateKey, []byte, error) {
	if cfg == nil {
		return nil, nil, errors.New("asc config nil")
	}
	pemBytes := []byte(cfg.p8Cipher)
	if cfg.P8Encrypted {
		plain, err := p.decryptIOSDistSecret(cfg.p8Cipher)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt p8: %w", err)
		}
		pemBytes = []byte(plain)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, errors.New("p8: not PEM-encoded")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Some legacy exports use PKCS#1; try EC explicitly as a fallback
		// before bailing out.
		if k2, e2 := x509.ParseECPrivateKey(block.Bytes); e2 == nil {
			return k2, pemBytes, nil
		}
		return nil, nil, fmt.Errorf("p8 parse: %w", err)
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("p8 key is not ECDSA")
	}
	return ec, pemBytes, nil
}

func (p *Plugin) ascSignToken(cfg *IOSASCConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("asc config nil")
	}
	priv, pemBytes, err := p.loadASCConfigPrivateKey(cfg)
	if err != nil {
		return "", err
	}
	cacheKey := ascCacheFingerprint(cfg.IssuerID, cfg.KeyID, pemBytes)

	ascTokenCacheMu.Lock()
	if cached, ok := ascTokenCache[cacheKey]; ok && time.Until(cached.expiresAt) > 60*time.Second {
		ascTokenCacheMu.Unlock()
		return cached.token, nil
	}
	ascTokenCacheMu.Unlock()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": cfg.IssuerID,
		"iat": now.Unix(),
		"exp": now.Add(ascTokenTTL).Unix(),
		"aud": ascAudience,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = cfg.KeyID
	tok.Header["typ"] = "JWT"
	signed, err := tok.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	// Diagnostic log: dump JWT header + claims (everything except the
	// signature) so we can cross-check against Apple's expectations.
	// Also log a short fingerprint of the .p8 so the operator can
	// confirm we're using the file they think we are.
	logASCSigningContext(cfg, pemBytes, signed, now)

	ascTokenCacheMu.Lock()
	ascTokenCache[cacheKey] = ascCachedToken{token: signed, expiresAt: now.Add(ascTokenTTL)}
	ascTokenCacheMu.Unlock()
	return signed, nil
}

// logASCSigningContext prints what we just signed in a form the operator
// can paste back to verify against Apple's expectations.
//
// We log:
//   - kid + iss + aud + iat + exp (the JWT header + claims)
//   - the first 12 chars of the .p8 SHA-256 (so multiple uploads can be
//     distinguished without revealing the key)
//   - the JWT prefix (header.payload — public, signature stripped)
//
// Signature is omitted to keep secrets out of logs.
func logASCSigningContext(cfg *IOSASCConfig, pemBytes []byte, signed string, now time.Time) {
	sum := sha256.Sum256(pemBytes)
	pemFP := hex.EncodeToString(sum[:])[:12]
	parts := strings.SplitN(signed, ".", 3)
	prefix := signed
	if len(parts) == 3 {
		prefix = parts[0] + "." + parts[1] + ".<sig>"
	}
	log.Printf("[iosdist asc-jwt] signed: kid=%s iss=%s aud=%s iat=%d exp=%d (ttl=%dm) p8_sha256_prefix=%s jwt=%s",
		cfg.KeyID, cfg.IssuerID, ascAudience, now.Unix(), now.Add(ascTokenTTL).Unix(), int(ascTokenTTL.Minutes()),
		pemFP, prefix,
	)
}

func ascCacheFingerprint(issuer, kid string, pemBytes []byte) string {
	h := sha256.New()
	h.Write([]byte(issuer))
	h.Write([]byte{0})
	h.Write([]byte(kid))
	h.Write([]byte{0})
	h.Write(pemBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// ---- HTTP client wrappers ------------------------------------------------

type ascAppSummary struct {
	ID       string `json:"id"`
	BundleID string `json:"bundle_id"`
	Name     string `json:"name"`
	SKU      string `json:"sku"`
}

type ascBetaGroup struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IsInternal    bool   `json:"is_internal"`
	PublicLink    string `json:"public_link"`
	PublicEnabled bool   `json:"public_link_enabled"`
}

func (p *Plugin) ascListApps(ctx context.Context, cfg *IOSASCConfig, bundleIDFilter string) ([]ascAppSummary, error) {
	q := url.Values{}
	q.Set("limit", "200")
	if bundleIDFilter != "" {
		q.Set("filter[bundleId]", bundleIDFilter)
	}
	body, err := p.ascDoGET(ctx, cfg, "/v1/apps?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				BundleID string `json:"bundleId"`
				Name     string `json:"name"`
				SKU      string `json:"sku"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc list apps decode: %w", err)
	}
	out := make([]ascAppSummary, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, ascAppSummary{
			ID:       d.ID,
			BundleID: d.Attributes.BundleID,
			Name:     d.Attributes.Name,
			SKU:      d.Attributes.SKU,
		})
	}
	return out, nil
}

// ascAppDetail mirrors the subset of /v1/apps/:id we care about for the
// "Sync Meta" button.
type ascAppDetail struct {
	ID            string
	BundleID      string
	Name          string
	SKU           string
	PrimaryLocale string
}

func (p *Plugin) ascGetApp(ctx context.Context, cfg *IOSASCConfig, appID string) (*ascAppDetail, error) {
	body, err := p.ascDoGET(ctx, cfg, "/v1/apps/"+url.PathEscape(appID))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				BundleID      string `json:"bundleId"`
				Name          string `json:"name"`
				SKU           string `json:"sku"`
				PrimaryLocale string `json:"primaryLocale"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc app detail decode: %w", err)
	}
	return &ascAppDetail{
		ID:            resp.Data.ID,
		BundleID:      resp.Data.Attributes.BundleID,
		Name:          resp.Data.Attributes.Name,
		SKU:           resp.Data.Attributes.SKU,
		PrimaryLocale: resp.Data.Attributes.PrimaryLocale,
	}, nil
}

// ascAppLocalization is the description-side metadata, scoped to one
// locale. Only the primary one matters for our sync button.
type ascAppLocalization struct {
	Locale          string
	Description     string
	Keywords        string
	WhatsNew        string
	PromotionalText string
	MarketingURL    string
	SupportURL      string
}

// ascGetLatestVersionLocalizations grabs the appStoreVersionLocalizations
// for the most-recent appStoreVersion. Returns nil + nil error when the
// app has no submitted versions yet (a freshly-created ASC app).
//
// We can't sort on the nested /v1/apps/{id}/appStoreVersions endpoint —
// ASC rejects it ("The parameter 'sort' can not be used with this
// request"). Workaround: fetch a small page (10 versions covers any
// realistic scenario) and pick the latest by createdDate client-side.
func (p *Plugin) ascGetLatestVersionLocalizations(ctx context.Context, cfg *IOSASCConfig, appID string) ([]ascAppLocalization, error) {
	q := url.Values{}
	q.Set("limit", "10")
	q.Set("include", "appStoreVersionLocalizations")
	q.Set("fields[appStoreVersions]", "createdDate,versionString,appStoreVersionLocalizations")
	body, err := p.ascDoGET(ctx, cfg, "/v1/apps/"+url.PathEscape(appID)+"/appStoreVersions?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				CreatedDate   time.Time `json:"createdDate"`
				VersionString string    `json:"versionString"`
			} `json:"attributes"`
			Relationships struct {
				AppStoreVersionLocalizations struct {
					Data []struct {
						ID string `json:"id"`
					} `json:"data"`
				} `json:"appStoreVersionLocalizations"`
			} `json:"relationships"`
		} `json:"data"`
		Included []struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Locale          string `json:"locale"`
				Description     string `json:"description"`
				Keywords        string `json:"keywords"`
				WhatsNew        string `json:"whatsNew"`
				PromotionalText string `json:"promotionalText"`
				MarketingURL    string `json:"marketingUrl"`
				SupportURL      string `json:"supportUrl"`
			} `json:"attributes"`
		} `json:"included"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc localizations decode: %w", err)
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	// Pick the latest version by createdDate (descending). When the
	// timestamp is zero (rare, e.g. fresh empty version), fall back to
	// the first row Apple gave us.
	latestIdx := 0
	for i := 1; i < len(resp.Data); i++ {
		if resp.Data[i].Attributes.CreatedDate.After(resp.Data[latestIdx].Attributes.CreatedDate) {
			latestIdx = i
		}
	}
	wanted := make(map[string]struct{}, len(resp.Data[latestIdx].Relationships.AppStoreVersionLocalizations.Data))
	for _, d := range resp.Data[latestIdx].Relationships.AppStoreVersionLocalizations.Data {
		wanted[d.ID] = struct{}{}
	}
	out := make([]ascAppLocalization, 0, len(wanted))
	for _, inc := range resp.Included {
		if inc.Type != "appStoreVersionLocalizations" {
			continue
		}
		if _, ok := wanted[inc.ID]; !ok {
			continue
		}
		out = append(out, ascAppLocalization{
			Locale:          inc.Attributes.Locale,
			Description:     inc.Attributes.Description,
			Keywords:        inc.Attributes.Keywords,
			WhatsNew:        inc.Attributes.WhatsNew,
			PromotionalText: inc.Attributes.PromotionalText,
			MarketingURL:    inc.Attributes.MarketingURL,
			SupportURL:      inc.Attributes.SupportURL,
		})
	}
	return out, nil
}

// ascBuildIcon is the iconAssetToken structure ASC returns. The
// templateUrl has {c}, {w}, {h}, {f} placeholders that the caller
// substitutes to produce a real download URL.
type ascBuildIcon struct {
	TemplateURL string `json:"templateUrl"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
}

type ascBuildSummary struct {
	ID              string
	Version         string
	ProcessingState string
	UploadedDate    time.Time
	IconAssetToken  *ascBuildIcon
}

// ascLatestBuildForApp returns the most-recently-uploaded build for the
// app. We use this just to lift its iconAssetToken — TestFlight build
// status sync is a separate roadmap item (M4).
func (p *Plugin) ascLatestBuildForApp(ctx context.Context, cfg *IOSASCConfig, appID string) (*ascBuildSummary, error) {
	q := url.Values{}
	q.Set("limit", "1")
	q.Set("sort", "-uploadedDate")
	q.Set("filter[app]", appID)
	body, err := p.ascDoGET(ctx, cfg, "/v1/builds?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Version         string        `json:"version"`
				ProcessingState string        `json:"processingState"`
				UploadedDate    time.Time     `json:"uploadedDate"`
				IconAssetToken  *ascBuildIcon `json:"iconAssetToken"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc builds decode: %w", err)
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	d := resp.Data[0]
	return &ascBuildSummary{
		ID:              d.ID,
		Version:         d.Attributes.Version,
		ProcessingState: d.Attributes.ProcessingState,
		UploadedDate:    d.Attributes.UploadedDate,
		IconAssetToken:  d.Attributes.IconAssetToken,
	}, nil
}

// resolveASCIconURLs returns the icon URL variants to try, in priority
// order. ASC URLs have placeholders {w}, {h}, {f}, {c} — we sub real
// values for w/h/f and try multiple `c` crop variants because some
// assets only have a subset prepared on the CDN. mzstatic frequently
// returns 403 (instead of 404) when a given crop doesn't exist for
// that asset, hence the fallback chain.
//
// Width/height: respect what Apple says was uploaded (may be 256 for
// macOS app icons, 1024 for iOS marketing). Falling back to 1024 if
// Apple returned 0 or missing dims.
func resolveASCIconURLs(icon *ascBuildIcon) []string {
	if icon == nil || icon.TemplateURL == "" {
		return nil
	}
	w, h := icon.Width, icon.Height
	if w <= 0 {
		w = 1024
	}
	if h <= 0 {
		h = 1024
	}
	// Try multiple crop variants. "bb" = blurred background (what App
	// Store storefront uses for iOS), "sr" = square render, empty = no
	// variant suffix (some legacy assets), "r" = simple rounded.
	variants := []string{"bb", "sr", "", "r"}
	out := make([]string, 0, len(variants))
	for _, c := range variants {
		u := icon.TemplateURL
		u = strings.ReplaceAll(u, "{w}", fmt.Sprintf("%d", w))
		u = strings.ReplaceAll(u, "{h}", fmt.Sprintf("%d", h))
		u = strings.ReplaceAll(u, "{f}", "png")
		u = strings.ReplaceAll(u, "{c}", c)
		out = append(out, u)
	}
	return out
}

// resolveASCIconURL keeps the legacy single-URL signature for callers
// that expect one URL (e.g. logging). Returns the highest-priority
// variant; downloadASCIcon iterates the full list internally.
func resolveASCIconURL(icon *ascBuildIcon) string {
	urls := resolveASCIconURLs(icon)
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

// downloadASCIcon fetches one of the resolved iconAssetToken URLs.
// We add a browser-like User-Agent + Referer because mzstatic.com
// hot-link-blocks default Go HTTP UA → 403. We iterate crop variants
// because some assets have only a subset of crops prepared.
func (p *Plugin) downloadASCIcon(ctx context.Context, iconURL string) ([]byte, string, error) {
	// Backwards-compat: if caller passes a single URL string, just try
	// that one.
	return p.downloadASCIconWithFallback(ctx, []string{iconURL})
}

func (p *Plugin) downloadASCIconWithFallback(ctx context.Context, urls []string) ([]byte, string, error) {
	if len(urls) == 0 {
		return nil, "", fmt.Errorf("no icon urls to try")
	}
	client := &http.Client{Timeout: ascHTTPTimeout}
	const maxIconBytes = int64(8 << 20)
	var lastErr error
	for i, u := range urls {
		if u == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		// Browser-like headers — mzstatic returns 403 for default Go UA.
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15")
		req.Header.Set("Referer", "https://apps.apple.com/")
		req.Header.Set("Accept", "image/png,image/*;q=0.9,*/*;q=0.5")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("asc icon variant %d (%s): HTTP %d", i+1, u, resp.StatusCode)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxIconBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if int64(len(data)) > maxIconBytes {
			lastErr = fmt.Errorf("asc icon too large")
			continue
		}
		ct := resp.Header.Get("Content-Type")
		if ct == "" {
			ct = "image/png"
		}
		return data, ct, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("asc icon: no variant succeeded")
	}
	return nil, "", lastErr
}

// ascUser is the subset of /v1/users we use to identify the team's
// account holder (whose email is what the operator typically wants
// surfaced as "logged-in account").
type ascUser struct {
	ID        string
	Username  string // ASC stores the email here
	FirstName string
	LastName  string
	Roles     []string
}

func (p *Plugin) ascListUsers(ctx context.Context, cfg *IOSASCConfig) ([]ascUser, error) {
	body, err := p.ascDoGET(ctx, cfg, "/v1/users?limit=200")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Username  string   `json:"username"`
				FirstName string   `json:"firstName"`
				LastName  string   `json:"lastName"`
				Roles     []string `json:"roles"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc list users decode: %w", err)
	}
	out := make([]ascUser, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, ascUser{
			ID:        d.ID,
			Username:  d.Attributes.Username,
			FirstName: d.Attributes.FirstName,
			LastName:  d.Attributes.LastName,
			Roles:     d.Attributes.Roles,
		})
	}
	return out, nil
}

// ascAccountHolderEmail returns the email of the user with the
// ACCOUNT_HOLDER role. Falls back to the first ADMIN if no holder is
// returned (some Apple Dev configurations hide the holder from non-holder
// keys), and finally to the first user. Empty string when no users at all.
func ascAccountHolderEmail(users []ascUser) string {
	var firstAdmin string
	for _, u := range users {
		for _, r := range u.Roles {
			if r == "ACCOUNT_HOLDER" {
				return u.Username
			}
			if firstAdmin == "" && r == "ADMIN" {
				firstAdmin = u.Username
			}
		}
	}
	if firstAdmin != "" {
		return firstAdmin
	}
	if len(users) > 0 {
		return users[0].Username
	}
	return ""
}

func (p *Plugin) ascListBetaGroups(ctx context.Context, cfg *IOSASCConfig, ascAppID string) ([]ascBetaGroup, error) {
	q := url.Values{}
	q.Set("limit", "200")
	if ascAppID != "" {
		q.Set("filter[app]", ascAppID)
	}
	body, err := p.ascDoGET(ctx, cfg, "/v1/betaGroups?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name              string `json:"name"`
				IsInternalGroup   bool   `json:"isInternalGroup"`
				PublicLink        string `json:"publicLink"`
				PublicLinkEnabled bool   `json:"publicLinkEnabled"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc list beta groups decode: %w", err)
	}
	out := make([]ascBetaGroup, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, ascBetaGroup{
			ID:            d.ID,
			Name:          d.Attributes.Name,
			IsInternal:    d.Attributes.IsInternalGroup,
			PublicLink:    d.Attributes.PublicLink,
			PublicEnabled: d.Attributes.PublicLinkEnabled,
		})
	}
	return out, nil
}

// ascCreateTester both creates a betaTesters resource AND associates it
// with the supplied beta groups in one round-trip. ASC's own UI does it
// the same way.
//
// firstName / lastName are optional — ASC accepts empty strings but the
// tester profile in the App Store Connect web UI looks nicer with them.
func (p *Plugin) ascCreateTester(ctx context.Context, cfg *IOSASCConfig, email, firstName, lastName string, betaGroupIDs []string) error {
	type relRef struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	type rel struct {
		Data []relRef `json:"data"`
	}
	type rels struct {
		BetaGroups rel `json:"betaGroups"`
	}
	type attrs struct {
		Email     string `json:"email"`
		FirstName string `json:"firstName,omitempty"`
		LastName  string `json:"lastName,omitempty"`
	}
	type data struct {
		Type          string `json:"type"`
		Attributes    attrs  `json:"attributes"`
		Relationships rels   `json:"relationships"`
	}
	groups := make([]relRef, 0, len(betaGroupIDs))
	for _, id := range betaGroupIDs {
		if id == "" {
			continue
		}
		groups = append(groups, relRef{Type: "betaGroups", ID: id})
	}
	if len(groups) == 0 {
		return fmt.Errorf("%w: at least one beta group is required", errIOSASCClient)
	}
	payload := struct {
		Data data `json:"data"`
	}{
		Data: data{
			Type:       "betaTesters",
			Attributes: attrs{Email: email, FirstName: firstName, LastName: lastName},
			Relationships: rels{
				BetaGroups: rel{Data: groups},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("asc payload: %w", err)
	}
	_, err = p.ascDo(ctx, cfg, http.MethodPost, "/v1/betaTesters", "application/json", bytes.NewReader(raw))
	return err
}

// ---- bundle ID + app creation (Phase 3 of iOS pipeline closed loop) ----

type ascBundleID struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	SeedID     string `json:"seed_id,omitempty"`
}

// ascListBundleIDs queries /v1/bundleIds, optionally filtered by
// identifier (exact match — Apple's API supports this filter).
// Used both as a "does this identifier already exist?" probe and
// as a picker for the project bind UI.
func (p *Plugin) ascListBundleIDs(ctx context.Context, cfg *IOSASCConfig, identifierFilter string) ([]ascBundleID, error) {
	q := url.Values{}
	q.Set("limit", "200")
	if identifierFilter != "" {
		q.Set("filter[identifier]", identifierFilter)
	}
	body, err := p.ascDoGET(ctx, cfg, "/v1/bundleIds?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
				Platform   string `json:"platform"`
				SeedID     string `json:"seedId"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc list bundle ids decode: %w", err)
	}
	out := make([]ascBundleID, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, ascBundleID{
			ID:         d.ID,
			Identifier: d.Attributes.Identifier,
			Name:       d.Attributes.Name,
			Platform:   d.Attributes.Platform,
			SeedID:     d.Attributes.SeedID,
		})
	}
	return out, nil
}

// ascCreateBundleID registers a new identifier with Apple. Platform
// must be "IOS" / "MAC_OS" / "UNIVERSAL". Idempotent at the caller's
// level: if the identifier already exists, Apple returns 409 — caller
// should ascListBundleIDs(identifier) first and reuse if found.
func (p *Plugin) ascCreateBundleID(ctx context.Context, cfg *IOSASCConfig, identifier, name, platform string) (*ascBundleID, error) {
	type attrs struct {
		Identifier string `json:"identifier"`
		Name       string `json:"name"`
		Platform   string `json:"platform"`
		SeedID     string `json:"seedId,omitempty"`
	}
	type data struct {
		Type       string `json:"type"`
		Attributes attrs  `json:"attributes"`
	}
	payload := struct {
		Data data `json:"data"`
	}{
		Data: data{
			Type: "bundleIds",
			Attributes: attrs{
				Identifier: identifier,
				Name:       name,
				Platform:   platform,
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("asc bundle id payload: %w", err)
	}
	body, err := p.ascDo(ctx, cfg, http.MethodPost, "/v1/bundleIds", "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
				Platform   string `json:"platform"`
				SeedID     string `json:"seedId"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc bundle id decode: %w", err)
	}
	return &ascBundleID{
		ID:         resp.Data.ID,
		Identifier: resp.Data.Attributes.Identifier,
		Name:       resp.Data.Attributes.Name,
		Platform:   resp.Data.Attributes.Platform,
		SeedID:     resp.Data.Attributes.SeedID,
	}, nil
}

// ascCreateApp creates an App Store Connect app record. The bundle
// id must already exist (call ascCreateBundleID first if needed).
// SKU is Apple's internal app identifier — not shown to users; we
// recommend using the bundle identifier itself for clarity.
func (p *Plugin) ascCreateApp(ctx context.Context, cfg *IOSASCConfig, bundleIDResourceID, name, sku, primaryLocale string) (*ascAppSummary, error) {
	type relRef struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	type relData struct {
		Data relRef `json:"data"`
	}
	type rels struct {
		BundleID relData `json:"bundleId"`
	}
	type attrs struct {
		Name          string `json:"name"`
		SKU           string `json:"sku"`
		PrimaryLocale string `json:"primaryLocale,omitempty"`
	}
	type data struct {
		Type          string `json:"type"`
		Attributes    attrs  `json:"attributes"`
		Relationships rels   `json:"relationships"`
	}
	payload := struct {
		Data data `json:"data"`
	}{
		Data: data{
			Type: "apps",
			Attributes: attrs{
				Name:          name,
				SKU:           sku,
				PrimaryLocale: primaryLocale,
			},
			Relationships: rels{
				BundleID: relData{Data: relRef{Type: "bundleIds", ID: bundleIDResourceID}},
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("asc app payload: %w", err)
	}
	body, err := p.ascDo(ctx, cfg, http.MethodPost, "/v1/apps", "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				BundleID string `json:"bundleId"`
				Name     string `json:"name"`
				SKU      string `json:"sku"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc app decode: %w", err)
	}
	return &ascAppSummary{
		ID:       resp.Data.ID,
		BundleID: resp.Data.Attributes.BundleID,
		Name:     resp.Data.Attributes.Name,
		SKU:      resp.Data.Attributes.SKU,
	}, nil
}

// ---- low-level HTTP -----------------------------------------------------

func (p *Plugin) ascDoGET(ctx context.Context, cfg *IOSASCConfig, pathQuery string) ([]byte, error) {
	return p.ascDo(ctx, cfg, http.MethodGet, pathQuery, "", nil)
}

func (p *Plugin) ascDo(ctx context.Context, cfg *IOSASCConfig, method, pathQuery, contentType string, body io.Reader) ([]byte, error) {
	token, err := p.ascSignToken(cfg)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: ascHTTPTimeout}
	var lastErr error
	// Three attempts with simple exponential backoff for transient failures
	// (429 + 5xx + transport hiccups). Max wait between tries: 1.5s + 3s.
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1500*(1<<(attempt-1))) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, ascAPIBase+pathQuery, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, nil
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("asc %s %s: %d %s", method, pathQuery, resp.StatusCode, summarizeASCError(respBody))
			// retryable: rewind body if seekable, otherwise we can't
			// retry with a non-seekable reader so abort.
			if seeker, ok := body.(io.Seeker); ok && body != nil {
				_, _ = seeker.Seek(0, io.SeekStart)
			} else if body != nil {
				return nil, lastErr
			}
			continue
		}
		// 4xx that isn't 429 is the user's problem (auth, validation).
		return nil, fmt.Errorf("%w: %d %s", errIOSASCClient, resp.StatusCode, summarizeASCError(respBody))
	}
	if lastErr == nil {
		lastErr = errors.New("asc request failed after retries")
	}
	return nil, lastErr
}

// summarizeASCError pulls the human-readable bit out of the JSON:API
// error envelope ASC returns. Falls back to the raw body when we can't
// decode it.
func summarizeASCError(body []byte) string {
	var env struct {
		Errors []struct {
			Status string `json:"status"`
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err == nil && len(env.Errors) > 0 {
		parts := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			parts = append(parts, strings.TrimSpace(strings.Join([]string{e.Title, e.Detail}, ": ")))
		}
		return strings.Join(parts, "; ")
	}
	if len(body) > 200 {
		return string(body[:200]) + "..."
	}
	return string(body)
}

// ---- M-iosdist-status: ops snapshot pulls ----
//
// Three thin reads used by the iosdist status sync worker. Each returns
// nil + nil when the app has nothing to report (no submitted version, no
// build uploaded, no testers configured) — caller treats nil as "empty
// but successful" and stores blank fields in the snapshot row.

// ascLatestAppStoreVersionState is the App-Store-side review/release
// state. It folds three ASC concepts into one snapshot:
//   - versionString of the most recently created appStoreVersion
//   - appStoreState enum (READY_FOR_SALE, IN_REVIEW, REJECTED, ...)
//   - createdDate (when it was first submitted to Apple) +
//     earliestReleaseDate / releaseDate (when it actually went live, if
//     applicable — null while still in review)
type ascLatestAppStoreVersionState struct {
	Version     string
	State       string
	SubmittedAt *time.Time
	ReleasedAt  *time.Time
}

func (p *Plugin) ascLatestAppStoreVersionState(ctx context.Context, cfg *IOSASCConfig, appID string) (*ascLatestAppStoreVersionState, error) {
	q := url.Values{}
	q.Set("limit", "10") // ASC rejects sort on the nested route; pick latest client-side
	// AppStoreVersion has no `releaseDate` attribute — only earliestReleaseDate.
	// The actual go-live time is computed from appStoreState transitions or
	// from appStoreVersionPhasedReleases; for the ops panel earliestReleaseDate
	// is a sufficient proxy (developer-requested release date).
	q.Set("fields[appStoreVersions]", "createdDate,versionString,appStoreState,earliestReleaseDate")
	body, err := p.ascDoGET(ctx, cfg, "/v1/apps/"+url.PathEscape(appID)+"/appStoreVersions?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			Attributes struct {
				VersionString       string     `json:"versionString"`
				AppStoreState       string     `json:"appStoreState"`
				CreatedDate         time.Time  `json:"createdDate"`
				EarliestReleaseDate *time.Time `json:"earliestReleaseDate"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc appStoreVersions decode: %w", err)
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	latest := 0
	for i := 1; i < len(resp.Data); i++ {
		if resp.Data[i].Attributes.CreatedDate.After(resp.Data[latest].Attributes.CreatedDate) {
			latest = i
		}
	}
	attr := resp.Data[latest].Attributes
	out := &ascLatestAppStoreVersionState{
		Version: attr.VersionString,
		State:   attr.AppStoreState,
	}
	if !attr.CreatedDate.IsZero() {
		t := attr.CreatedDate
		out.SubmittedAt = &t
	}
	// earliestReleaseDate is the developer-requested release date; it's the
	// closest thing to "上架时间" available on the AppStoreVersion resource.
	if attr.EarliestReleaseDate != nil && !attr.EarliestReleaseDate.IsZero() {
		out.ReleasedAt = attr.EarliestReleaseDate
	}
	return out, nil
}

// ascLatestBuildStatus is the TestFlight-side state of the most-recent
// build: processingState (PROCESSING / VALID / INVALID), external beta
// review state (IN_BETA_REVIEW / BETA_APPROVED / BETA_REJECTED / ...),
// uploadedDate, expirationDate (= uploadedDate + 90d for TF). The beta
// state comes from the buildBetaDetail relationship — one extra ASC
// call per app per cycle. Returns nil when the app has no builds.
type ascLatestBuildStatus struct {
	Version         string
	ProcessingState string
	BetaState       string
	UploadedAt      *time.Time
	ExpiresAt       *time.Time
}

func (p *Plugin) ascLatestBuildStatus(ctx context.Context, cfg *IOSASCConfig, appID string) (*ascLatestBuildStatus, error) {
	q := url.Values{}
	q.Set("limit", "1")
	q.Set("sort", "-uploadedDate")
	q.Set("filter[app]", appID)
	q.Set("include", "buildBetaDetail")
	q.Set("fields[builds]", "version,processingState,uploadedDate,expirationDate,buildBetaDetail")
	q.Set("fields[buildBetaDetails]", "externalBuildState,internalBuildState")
	body, err := p.ascDoGET(ctx, cfg, "/v1/builds?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			Attributes struct {
				Version         string     `json:"version"`
				ProcessingState string     `json:"processingState"`
				UploadedDate    *time.Time `json:"uploadedDate"`
				ExpirationDate  *time.Time `json:"expirationDate"`
			} `json:"attributes"`
			Relationships struct {
				BuildBetaDetail struct {
					Data *struct {
						ID string `json:"id"`
					} `json:"data"`
				} `json:"buildBetaDetail"`
			} `json:"relationships"`
		} `json:"data"`
		Included []struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			Attributes struct {
				ExternalBuildState string `json:"externalBuildState"`
				InternalBuildState string `json:"internalBuildState"`
			} `json:"attributes"`
		} `json:"included"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("asc latest build decode: %w", err)
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	d := resp.Data[0]
	out := &ascLatestBuildStatus{
		Version:         d.Attributes.Version,
		ProcessingState: d.Attributes.ProcessingState,
		UploadedAt:      d.Attributes.UploadedDate,
		ExpiresAt:       d.Attributes.ExpirationDate,
	}
	if d.Relationships.BuildBetaDetail.Data != nil {
		wantID := d.Relationships.BuildBetaDetail.Data.ID
		for _, inc := range resp.Included {
			if inc.Type == "buildBetaDetails" && inc.ID == wantID {
				// External state is what public testers see. Internal is
				// only relevant when no external state is set yet (build
				// not submitted to external review).
				out.BetaState = inc.Attributes.ExternalBuildState
				if out.BetaState == "" {
					out.BetaState = inc.Attributes.InternalBuildState
				}
				break
			}
		}
	}
	return out, nil
}

// ascCountBetaTesters returns the public-test participant count. Prefers
// the bound Beta Group's testers (/v1/betaGroups/:id/betaTesters), where
// 99% of testers actually live: the standard ASC workflow is "create
// Beta Group → add testers to group → invite". Falls back to the
// app-direct list (/v1/apps/:id/betaTesters) when no group is bound —
// that endpoint only returns individually-attached testers (the rare
// "Individual Testers" tab in ASC). Pre-fix this counted app-direct
// only and almost always showed 0.
//
// 0 is a valid result; errors propagate. Reads meta.paging.total via
// limit=1 so we don't paginate.
func (p *Plugin) ascCountBetaTesters(ctx context.Context, cfg *IOSASCConfig, appID, betaGroupID string) (int, error) {
	var path string
	if strings.TrimSpace(betaGroupID) != "" {
		path = "/v1/betaGroups/" + url.PathEscape(betaGroupID) + "/betaTesters"
	} else {
		path = "/v1/apps/" + url.PathEscape(appID) + "/betaTesters"
	}
	q := url.Values{}
	q.Set("limit", "1")
	q.Set("fields[betaTesters]", "email") // smallest field to minimise payload
	body, err := p.ascDoGET(ctx, cfg, path+"?"+q.Encode())
	if err != nil {
		return 0, err
	}
	var resp struct {
		Meta struct {
			Paging struct {
				Total int `json:"total"`
			} `json:"paging"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("asc betaTesters count decode: %w", err)
	}
	return resp.Meta.Paging.Total, nil
}
