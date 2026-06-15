// Package iosdist is the iOS Distribution control plane plugin.
//
// Phase 2-W1 iosdist-skeleton ships the architecture, not the
// handlers. Dock still owns the /api/iosdist/* + /iosdist/* surface;
// iosdist-svc stands up alongside, owns polar_iosdist + its own
// blob root, and proves the layout end-to-end (heartbeat back to
// dock via /internal/v1/plugin-registry/heartbeat).
//
// Next PR moves the 7K LOC of handlers (iosdist_handlers.go,
// iosdist_asc_handlers.go, iosdist_public.go, iosdist_sign_worker.go,
// iosdist_status_sync.go, iosdist_agent_handlers.go, iosdist_store.go,
// iosdist_asc.go, iosdist_ipa.go, iosdist_crypto.go, iosdist_parsers.go)
// across, mirroring Phase 1-D-1's wg move.
//
// The Plugin owns:
//   - DB pool to polar_iosdist
//   - Dock SDK client for cross-domain user/team lookups
//   - Local blob roots: $IOSDIST_BLOB_DIR/{ipa,certs,profiles,asc-keys,icons}
//   - Encryption key for cert passwords + ASC .p8 contents
//     (IOSDIST_RESOURCE_KEY env, AES-GCM, mirrors dock's existing
//      iosdist_crypto.go)
//   - Heartbeat goroutine (60s cadence → dock's plugin registry)
package iosdist

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/networkextension/polar-sdk"
)

type Plugin struct {
	DB         *sql.DB
	Dock       *sdk.Client
	Name       string
	Listen     string
	Ver        string
	BlobDir    string // $IOSDIST_BLOB_DIR — ipa/, certs/, profiles/, asc-keys/, icons/
	MetricsTok string

	// SystemWorkspaceID — dock's "system" user personal team. iosdist
	// platform-wide rows (e.g. ASC config global fallback) stamp this
	// when no workspace is implied. Resolved once at New() via
	// /internal/v1/users/system/workspace.
	SystemWorkspaceID string

	// chatStorage — AttachmentStorage backend for blob persistence.
	// Either LocalAttachmentStorage (default) writing under BlobDir, or
	// R2AttachmentStorage when R2_* env vars are configured.
	chatStorage AttachmentStorage

	// publicBaseURL — base URL for install/manifest links served back
	// to iOS clients (e.g. https://iosdist.example.com). Empty falls
	// back to gin's request host.
	publicBaseURL string

	// iosdistResourceKey — AES-256 key for at-rest encryption of cert
	// passwords + ASC .p8 contents. Loaded from IOSDIST_RESOURCE_KEY
	// env at New(). Empty → handlers fall back to plaintext + flag.
	iosdistResourceKey []byte

	// iosdistSignQueue — buffered task-ID channel feeding the single
	// runIOSSignWorker goroutine. Capacity is intentionally small
	// (zsign is CPU heavy; back-pressure is the right answer).
	iosdistSignQueue chan int64

	// iosdistZsignPath — resolved zsign binary path. Empty → handlers
	// reject sign requests with a clear "zsign not installed" message.
	iosdistZsignPath string

	// metricsRegistry — domain-flavored metrics handle. Carries small
	// helper methods like recordIOSDistBuild that the sign worker
	// invokes. Backed by a prometheus.Registry under the hood.
	metricsRegistry *iosdistMetricsRegistry

	// ASC fallback env config (used when an ASC config row hasn't been
	// uploaded yet). Each is read once at boot from ASC_* env vars.
	ascFallbackKeyID          string
	ascFallbackIssuerID       string
	ascFallbackPrivateKeyPath string

	metrics   *iosdistMetrics
	startedAt time.Time
}

type Config struct {
	DBDSN        string
	DockBase     string
	PluginName   string
	PluginToken  string
	Listen       string
	BuildVersion string
	BlobDir      string
	MetricsToken string

	// Domain secrets (see cmd/iosdist-svc/main.go for env mapping).
	ResourceKey       string // IOSDIST_RESOURCE_KEY (hex or base64; 32 bytes)
	R2AccountID       string
	R2Bucket          string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2PublicURL       string
	ASCKeyID          string
	ASCIssuerID       string
	ASCPrivateKeyPath string
}

func New(ctx context.Context, cfg Config) (*Plugin, error) {
	cfg.PluginName = strings.TrimSpace(cfg.PluginName)
	if cfg.PluginName == "" {
		cfg.PluginName = "iosdist"
	}
	if strings.TrimSpace(cfg.DBDSN) == "" {
		return nil, errors.New("iosdist.New: DBDSN required")
	}
	if strings.TrimSpace(cfg.DockBase) == "" {
		return nil, errors.New("iosdist.New: DockBase required")
	}
	if strings.TrimSpace(cfg.PluginToken) == "" {
		return nil, errors.New("iosdist.New: PluginToken required (plaintext from /admin-plugins.html)")
	}
	if strings.TrimSpace(cfg.BlobDir) == "" {
		return nil, errors.New("iosdist.New: BlobDir required (iosdist-svc-local data root)")
	}

	db, err := sql.Open("postgres", cfg.DBDSN)
	if err != nil {
		return nil, fmt.Errorf("open polar_iosdist: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping polar_iosdist: %w", err)
	}

	dock := sdk.NewClient(cfg.DockBase, cfg.PluginName, sdk.DeriveHMACKey(cfg.PluginToken))
	resp, err := dock.Do(http.MethodGet, "/internal/v1/ping", nil)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dock ping: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = db.Close()
		return nil, fmt.Errorf("dock /ping rejected: HTTP %d (check PLUGIN_TOKEN + plugin_modules row)", resp.StatusCode)
	}

	// Pre-fetch the system workspace ID. Mirrors packtunnel — iosdist
	// occasionally needs to stamp a workspace_id when none is implied.
	// Cold-box failure is non-fatal; first POST will surface a clean
	// DB error.
	sysWSResp, sysErr := dock.Do(http.MethodGet, "/internal/v1/users/system/workspace", nil)
	systemWorkspaceID := ""
	if sysErr == nil {
		var body struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if jerr := readJSON(sysWSResp, &body); jerr == nil {
			systemWorkspaceID = body.WorkspaceID
		}
	}
	if systemWorkspaceID == "" {
		log.Printf("iosdist: WARN system workspace lookup failed; some handlers may 500 until dock bootstraps system user (err=%v)", sysErr)
	}

	// Decode the at-rest encryption key. Empty / bad key → handlers
	// flag rows as plaintext rather than crashing the boot.
	var iosKey []byte
	if k := strings.TrimSpace(cfg.ResourceKey); k != "" {
		decoded, decErr := decodeIOSDistResourceKey(k)
		if decErr != nil {
			log.Printf("iosdist: WARN IOSDIST_RESOURCE_KEY invalid (%v) — secrets will be stored plaintext", decErr)
		} else {
			iosKey = decoded
		}
	} else {
		log.Print("iosdist: WARN IOSDIST_RESOURCE_KEY unset — secrets will be stored plaintext (set a 32-byte hex/base64 key for prod)")
	}

	// Blob storage backend: R2 when all R2_* env vars set, else local
	// LocalAttachmentStorage rooted under BlobDir.
	storage, sterr := newAttachmentStorage(cfg.BlobDir, cfg.R2AccountID, cfg.R2AccessKeyID, cfg.R2SecretAccessKey, cfg.R2Bucket, cfg.R2PublicURL)
	if sterr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("attachment storage: %w", sterr)
	}

	// Resolve zsign binary path (env override or $PATH lookup). Empty
	// path is OK — handlers reject sign requests with a clean message.
	zsignPath := strings.TrimSpace(os.Getenv("IOSDIST_ZSIGN_PATH"))
	if zsignPath == "" {
		if p, lerr := execLookPath("zsign"); lerr == nil {
			zsignPath = p
		}
	}
	if zsignPath == "" {
		log.Print("iosdist: WARN zsign not found on PATH (set IOSDIST_ZSIGN_PATH); sign tasks will be rejected")
	}

	p := &Plugin{
		DB:                        db,
		Dock:                      dock,
		Name:                      cfg.PluginName,
		Listen:                    cfg.Listen,
		Ver:                       cfg.BuildVersion,
		BlobDir:                   cfg.BlobDir,
		MetricsTok:                cfg.MetricsToken,
		SystemWorkspaceID:         systemWorkspaceID,
		chatStorage:               storage,
		publicBaseURL:             strings.TrimSpace(os.Getenv("IOSDIST_PUBLIC_BASE_URL")),
		iosdistResourceKey:        iosKey,
		iosdistSignQueue:          make(chan int64, 16),
		iosdistZsignPath:          zsignPath,
		ascFallbackKeyID:          cfg.ASCKeyID,
		ascFallbackIssuerID:       cfg.ASCIssuerID,
		ascFallbackPrivateKeyPath: cfg.ASCPrivateKeyPath,
		metrics:                   newIOSDistMetrics(),
		metricsRegistry:           newIOSDistMetricsRegistry(),
		startedAt:                 time.Now(),
	}
	// Blob→assets migration column — run synchronously so the icon
	// redirect route can read icon_asset_id from the first request.
	if err := p.ensureIOSDistAssetSchema(ctx); err != nil {
		log.Printf("iosdist: ensure asset schema: %v", err)
	}
	return p, nil
}

// execLookPath wraps exec.LookPath. Kept as a thin wrapper so tests
// can stub the zsign discovery without touching $PATH.
func execLookPath(bin string) (string, error) { return exec.LookPath(bin) }

// readJSON — minimal JSON unmarshaller used during boot (system
// workspace lookup). SDK has the same helper but it's unexported.
func readJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// RegisterRoutes attaches the iosdist plugin's HTTP surface. Mirrors
// dock's /api/iosdist/* + /iosdist/* (public) routing so nginx can
// flip with a single proxy_pass redirect (see scripts/nginx/
// iosdist-svc-snippet.conf).
//
// Routes NOT moved here:
//
//	/api/iosdist/agent/* — still served by dock (iosdist_agent_handlers.go)
//	    because those hit dock's PolarAgentAuthMiddleware.
func (p *Plugin) RegisterRoutes(r gin.IRouter) {
	r.GET("/healthz", p.handleHealthz)
	r.GET("/metrics", p.handleMetricsExposition)

	// ── public surface (no auth — slug / token IS the auth) ──
	r.GET("/iosdist/install/:token", p.handleIOSInstallPage)
	r.GET("/iosdist/manifest/:token", p.handleIOSInstallManifest)
	r.GET("/iosdist/icon/:slug", p.handleIOSAppIconRedirect)
	r.GET("/iosdist/share/:slug", p.handleIOSPublicShareHTML)
	r.POST("/iosdist/share/:slug/install", p.handleIOSPublicShareInstall)
	r.POST("/iosdist/share/:slug/test-request", p.handleIOSPublicShareTestRequest)
	r.GET("/iosdist/plaza", p.handleIOSPublicPlaza)

	// ── authed admin surface (dock-introspected Bearer token) ──
	api := r.Group("/api")
	authed := api.Group("", p.requireAuthViaDock())
	{
		// apps
		authed.GET("/iosdist/apps", p.handleIOSAppList)
		authed.POST("/iosdist/apps", p.handleIOSAppCreate)
		authed.GET("/iosdist/apps/:id", p.handleIOSAppDetail)
		authed.DELETE("/iosdist/apps/:id", p.handleIOSAppDelete)
		authed.POST("/iosdist/apps/:id/icon", p.handleIOSAppIconUpload)
		authed.PUT("/iosdist/apps/:id/testflight", p.handleIOSAppTestFlightUpdate)
		authed.PUT("/iosdist/apps/:id/visibility", p.handleIOSAppVisibilityUpdate)
		authed.GET("/iosdist/apps/:id/test-requests", p.handleIOSAppTestRequestList)
		authed.GET("/iosdist/apps/:id/status", p.handleIOSAppStatusGet)
		authed.POST("/iosdist/apps/:id/status/sync", p.handleIOSAppStatusSync)

		// versions
		authed.POST("/iosdist/apps/:id/versions", p.handleIOSVersionUpload)
		authed.DELETE("/iosdist/apps/:id/versions/:versionId", p.handleIOSVersionDelete)
		authed.POST("/iosdist/apps/:id/versions/:versionId/install-token", p.handleIOSVersionInstallToken)
		authed.POST("/iosdist/apps/:id/versions/:versionId/sign", p.handleIOSVersionSign)

		// sign tasks
		authed.GET("/iosdist/apps/:id/sign-tasks", p.handleIOSAppSignTaskList)
		authed.GET("/iosdist/sign-tasks/:id", p.handleIOSSignTaskDetail)

		// certs / profiles
		authed.GET("/iosdist/certificates", p.handleIOSCertificateList)
		authed.POST("/iosdist/certificates", p.handleIOSCertificateUpload)
		authed.DELETE("/iosdist/certificates/:id", p.handleIOSCertificateDelete)
		authed.GET("/iosdist/profiles", p.handleIOSProfileList)
		authed.POST("/iosdist/profiles", p.handleIOSProfileUpload)
		authed.DELETE("/iosdist/profiles/:id", p.handleIOSProfileDelete)

		// ASC
		authed.GET("/iosdist/asc/config", p.handleIOSASCConfigGet)
		authed.POST("/iosdist/asc/config", p.handleIOSASCConfigUpsert)
		authed.DELETE("/iosdist/asc/config", p.handleIOSASCConfigDelete)
		authed.GET("/iosdist/asc/apps", p.handleIOSASCAppList)
		authed.POST("/iosdist/asc/apps", p.handleIOSASCAppCreate)
		authed.POST("/iosdist/asc/bundle-ids", p.handleIOSASCBundleIDCreate)
		authed.GET("/iosdist/asc/beta-groups", p.handleIOSASCBetaGroupList)
		authed.PUT("/iosdist/apps/:id/asc-binding", p.handleIOSAppASCBindingUpdate)
		authed.POST("/iosdist/apps/:id/invite-tester", p.handleIOSAppInviteTester)
		authed.POST("/iosdist/apps/:id/asc-sync", p.handleIOSAppASCSyncMeta)
	}
}

func (p *Plugin) Start(ctx context.Context) {
	go p.heartbeatLoop(ctx)
	go p.runIOSSignWorker(ctx)
	p.startIOSDistStatusSync(ctx)
}

func (p *Plugin) Close() error {
	if p.DB != nil {
		return p.DB.Close()
	}
	return nil
}

func (p *Plugin) handleHealthz(c *gin.Context) {
	dbOK := true
	if err := p.DB.PingContext(c.Request.Context()); err != nil {
		dbOK = false
	}
	status := http.StatusOK
	if !dbOK {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{
		"plugin":         p.Name,
		"version":        p.Ver,
		"uptime_seconds": int64(time.Since(p.startedAt).Seconds()),
		"db_ok":          dbOK,
		"blob_dir":       p.BlobDir,
		"go":             runtime.Version(),
	})
}

func (p *Plugin) handleMetricsExposition(c *gin.Context) {
	if p.MetricsTok == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if c.GetHeader("Authorization") != "Bearer "+p.MetricsTok {
		c.Header("WWW-Authenticate", `Bearer realm="metrics"`)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	promhttp.HandlerFor(p.metrics.registry, promhttp.HandlerOpts{}).ServeHTTP(c.Writer, c.Request)
}

func (p *Plugin) heartbeatLoop(ctx context.Context) {
	p.beat(ctx)
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.beat(ctx)
		}
	}
}

// iosdistUIRoutes — sidebar entries this plugin contributes. Heartbeated
// up to dock; aggregated into /api/plugin-ui-routes for polar-dock-ui's
// dynamic sidebar. See task #196.
var iosdistUIRoutes = []sdk.UIRoute{
	{Path: "/iosdist.html", Label: "iOS 分发", Icon: "smartphone", AdminOnly: true, Order: 65},
}

func (p *Plugin) beat(_ context.Context) {
	err := p.Dock.Heartbeat(sdk.HeartbeatOpts{
		Version:       p.Ver,
		Endpoint:      p.Listen,
		UptimeSeconds: int64(time.Since(p.startedAt).Seconds()),
		UIRoutes:      iosdistUIRoutes,
	})
	if err != nil {
		log.Printf("iosdist: heartbeat failed: %v", err)
	}
}

// ── metrics — placeholder set; handler migration adds more ─────────

type iosdistMetrics struct {
	registry *prometheus.Registry
	upGauge  prometheus.Gauge
}

func newIOSDistMetrics() *iosdistMetrics {
	m := &iosdistMetrics{registry: prometheus.NewRegistry()}
	m.upGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "polar_iosdist_up",
		Help: "Always 1 while iosdist-svc is serving. Phase 2-W1 placeholder.",
	})
	m.registry.MustRegister(m.upGauge)
	m.upGauge.Set(1)
	return m
}
