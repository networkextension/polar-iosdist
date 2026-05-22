// Command iosdist-svc is the iOS Distribution control plane plugin binary.
//
// Env vars:
//
//	POLAR_IOSDIST_DB_DSN     postgres://ideamesh:test123456@127.0.0.1:5432/polar_iosdist?sslmode=disable
//	POLAR_DOCK_BASE          http://127.0.0.1:8080
//	POLAR_PLUGIN_NAME        iosdist
//	POLAR_PLUGIN_TOKEN       polar_plugin_…   (plaintext from /admin-plugins.html)
//	POLAR_IOSDIST_LISTEN     127.0.0.1:8091
//	POLAR_IOSDIST_VERSION    git-sha or "0.0.1"
//	POLAR_IOSDIST_BLOB_DIR   /Users/local/iosdist-svc-data (ipa/ + certs/ + profiles/ + asc-keys/ + icons/)
//	POLAR_IOSDIST_METRICS_TOKEN bearer for /metrics; unset = 404
//
// Domain secrets (encryption + Cloudflare R2 + App Store Connect):
//
//	IOSDIST_RESOURCE_KEY     AES-GCM key (base64) for at-rest cert pw + ASC .p8
//	R2_ACCOUNT_ID            Cloudflare account ID
//	R2_BUCKET                Cloudflare R2 bucket name (signed/unsigned IPAs)
//	R2_ACCESS_KEY_ID         R2 access key
//	R2_SECRET_ACCESS_KEY     R2 secret key
//	ASC_KEY_ID               App Store Connect key id (fallback / legacy)
//	ASC_ISSUER_ID            App Store Connect issuer id
//	ASC_PRIVATE_KEY_PATH     Path to .p8 (fallback when row not set)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"github.com/networkextension/polar-iosdist/internal/iosdist"
)

func main() {
	cfg := iosdist.Config{
		DBDSN:        envOrDefault("POLAR_IOSDIST_DB_DSN", "postgres://ideamesh:test123456@127.0.0.1:5432/polar_iosdist?sslmode=disable"),
		DockBase:     envOrDefault("POLAR_DOCK_BASE", "http://127.0.0.1:8080"),
		PluginName:   envOrDefault("POLAR_PLUGIN_NAME", "iosdist"),
		PluginToken:  os.Getenv("POLAR_PLUGIN_TOKEN"),
		Listen:       envOrDefault("POLAR_IOSDIST_LISTEN", "127.0.0.1:8091"),
		BuildVersion: envOrDefault("POLAR_IOSDIST_VERSION", "0.0.1"),
		BlobDir:      envOrDefault("POLAR_IOSDIST_BLOB_DIR", "/Users/local/iosdist-svc-data"),
		MetricsToken: os.Getenv("POLAR_IOSDIST_METRICS_TOKEN"),

		ResourceKey:       os.Getenv("IOSDIST_RESOURCE_KEY"),
		R2AccountID:       os.Getenv("R2_ACCOUNT_ID"),
		R2Bucket:          os.Getenv("R2_BUCKET"),
		R2AccessKeyID:     os.Getenv("R2_ACCESS_KEY_ID"),
		R2SecretAccessKey: os.Getenv("R2_SECRET_ACCESS_KEY"),
		R2PublicURL:       os.Getenv("R2_PUBLIC_URL"),
		ASCKeyID:          os.Getenv("ASC_KEY_ID"),
		ASCIssuerID:       os.Getenv("ASC_ISSUER_ID"),
		ASCPrivateKeyPath: os.Getenv("ASC_PRIVATE_KEY_PATH"),
	}
	if strings.TrimSpace(cfg.PluginToken) == "" {
		log.Fatal("POLAR_PLUGIN_TOKEN unset — get plaintext from /admin-plugins.html (one-time print at row creation)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	plugin, err := iosdist.New(ctx, cfg)
	if err != nil {
		log.Fatalf("iosdist.New: %v", err)
	}
	defer plugin.Close()

	gin.SetMode(envOrDefault("GIN_MODE", gin.ReleaseMode))
	r := gin.New()
	r.Use(gin.Recovery())
	plugin.RegisterRoutes(r)
	plugin.Start(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("iosdist-svc listening on %s (dock=%s, name=%s, ver=%s, blob=%s)",
			cfg.Listen, cfg.DockBase, cfg.PluginName, cfg.BuildVersion, cfg.BlobDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("iosdist-svc: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("iosdist-svc: shutdown: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}
