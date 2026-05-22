package iosdist

// Background sync of iOS-distribution ASC status snapshots.
//
// Every IOSDIST_STATUS_SYNC_INTERVAL_SEC (default 900s = 15min) iterates
// every iosdist_apps row that has asc_app_id set and refreshes its
// cached App Store / TestFlight metrics into iosdist_app_status. Apps
// without ASC binding are skipped — they can't be queried.
//
// Per-app failure isolation: one bad ASC config or rate-limit hiccup
// doesn't kill the loop or the other apps. Errors are stored on the
// row's sync_error column so the UI can surface "last sync failed at X".
//
// Manual force-sync: handlers/syncIOSAppStatusNow exposes the same
// per-app refresh path the worker uses, so the "立即同步" button
// behaves identically to a tick.

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

const iosdistStatusSyncIntervalDefault = 15 * time.Minute

func iosdistStatusSyncInterval() time.Duration {
	if n := envIntDefault("IOSDIST_STATUS_SYNC_INTERVAL_SEC", 0); n > 0 {
		return time.Duration(n) * time.Second
	}
	return iosdistStatusSyncIntervalDefault
}

// startIOSDistStatusSync launches the worker; returns immediately.
// Single goroutine per process. First tick fires after a 30s grace
// period so we don't compete with bootstrap DB chatter.
func (p *Plugin) startIOSDistStatusSync(ctx context.Context) {
	if p.DB == nil {
		return
	}
	interval := iosdistStatusSyncInterval()
	log.Printf("iosdist: starting status sync (interval=%s)", interval)
	go func() {
		// Initial delay; then a real ticker.
		grace := time.NewTimer(30 * time.Second)
		defer grace.Stop()
		select {
		case <-ctx.Done():
			return
		case <-grace.C:
		}
		p.syncAllIOSAppStatuses(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.syncAllIOSAppStatuses(ctx)
			}
		}
	}()
}

// syncAllIOSAppStatuses runs one full pass over apps with asc_app_id.
// Sequential within a single ASC config (rate-limit friendly); parallel
// across configs would help if many workspaces are bound, but in
// practice one ASC config per workspace and ≤5 workspaces is the
// expected scale. Revisit if that changes.
func (p *Plugin) syncAllIOSAppStatuses(ctx context.Context) {
	apps, err := p.listIOSAppsWithASC()
	if err != nil {
		log.Printf("iosdist: status sync list apps failed: %v", err)
		return
	}
	if len(apps) == 0 {
		return
	}
	// Group by workspace so we can reuse the ASC config + token cache
	// per group without re-loading from DB.
	cfgByWorkspace := map[string]*IOSASCConfig{}
	var mu sync.Mutex
	loadCfg := func(workspaceID string) *IOSASCConfig {
		mu.Lock()
		defer mu.Unlock()
		if cfg, ok := cfgByWorkspace[workspaceID]; ok {
			return cfg
		}
		cfg, err := p.getIOSASCConfig(workspaceID)
		if err != nil {
			log.Printf("iosdist: status sync load cfg ws=%s: %v", workspaceID, err)
			cfgByWorkspace[workspaceID] = nil
			return nil
		}
		cfgByWorkspace[workspaceID] = cfg
		return cfg
	}

	start := time.Now()
	ok, fail := 0, 0
	for _, app := range apps {
		if ctx.Err() != nil {
			return
		}
		cfg := loadCfg(app.WorkspaceID)
		if cfg == nil {
			// No ASC config but app has asc_app_id — record so the UI
			// can flag the misconfiguration.
			_ = p.upsertIOSAppStatus(&IOSAppStatus{
				AppID:     app.ID,
				SyncedAt:  time.Now().UTC(),
				SyncError: "workspace has no ASC config",
			})
			fail++
			continue
		}
		if err := p.syncOneIOSAppStatus(ctx, &app, cfg); err != nil {
			log.Printf("iosdist: status sync app=%d ws=%s: %v", app.ID, app.WorkspaceID, err)
			fail++
			continue
		}
		ok++
	}
	log.Printf("iosdist: status sync done: ok=%d fail=%d elapsed=%s", ok, fail, time.Since(start))
}

// syncOneIOSAppStatus does the 3-call pull and writes the snapshot.
// Partial success is OK — if e.g. betaTesters returns 401 but the
// version + build calls succeed, we store what we got and put the
// betaTesters error in sync_error.
func (p *Plugin) syncOneIOSAppStatus(ctx context.Context, app *IOSApp, cfg *IOSASCConfig) error {
	if app == nil || cfg == nil || strings.TrimSpace(app.ASCAppID) == "" {
		return errors.New("syncOneIOSAppStatus: missing app or asc config")
	}
	st := &IOSAppStatus{
		AppID:    app.ID,
		SyncedAt: time.Now().UTC(),
	}
	var errParts []string

	if asv, err := p.ascLatestAppStoreVersionState(ctx, cfg, app.ASCAppID); err != nil {
		errParts = append(errParts, "appstore: "+err.Error())
	} else if asv != nil {
		st.AppStoreVersion = asv.Version
		st.AppStoreState = asv.State
		st.AppStoreSubmittedAt = asv.SubmittedAt
		st.AppStoreReleasedAt = asv.ReleasedAt
	}

	if b, err := p.ascLatestBuildStatus(ctx, cfg, app.ASCAppID); err != nil {
		errParts = append(errParts, "build: "+err.Error())
	} else if b != nil {
		st.TFBuildVersion = b.Version
		st.TFProcessingState = b.ProcessingState
		st.TFBetaState = b.BetaState
		st.TFUploadedAt = b.UploadedAt
		st.TFExpiresAt = b.ExpiresAt
	}

	if n, err := p.ascCountBetaTesters(ctx, cfg, app.ASCAppID, app.ASCBetaGroupID); err != nil {
		errParts = append(errParts, "testers: "+err.Error())
	} else {
		st.BetaTesterCount = n
	}

	st.SyncError = strings.Join(errParts, "; ")
	return p.upsertIOSAppStatus(st)
}
