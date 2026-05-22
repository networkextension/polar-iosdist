package iosdist

// stubs.go — placeholder shims for dock-internal helpers that the
// extracted iosdist code references. The extraction PR keeps these as
// log-only no-ops + TODOs so the package compiles + boots; the
// follow-up PR wires real SDK calls or migrates the underlying tables.
//
// Each block names which dock function/type it stubs and what the real
// wiring will look like.

import (
	"log"
)

// ── log levels (dock/logs_store.go) ─────────────────────────────────
//
// Mirrors dock's LogLevelInfo / LogLevelError. We don't ship the full
// LogEntry / appendLog plumbing because iosdist-svc emits to stdout
// today; the follow-up PR routes these through the SDK to dock's
// /internal/v1/logs ingest endpoint.

const (
	LogLevelInfo  = "info"
	LogLevelError = "error"
)

// ── iosdistMetricsRegistry (dock/metrics.go) ─────────────────────────
//
// Original was dock's `metrics` struct carrying recordIOSDistBuild +
// recordLLMCall + etc. The extracted module only consumes
// recordIOSDistBuild today; the underlying Prometheus counter is
// stubbed to a no-op + counter so the boot path doesn't drag in the
// full dock metric surface.
//
// TODO(extract): swap in a real prometheus.CounterVec once the
// follow-up PR decides where iosdist metrics live (own scrape vs.
// dock relay).

type iosdistMetricsRegistry struct{}

func newIOSDistMetricsRegistry() *iosdistMetricsRegistry { return &iosdistMetricsRegistry{} }

// recordIOSDistBuild — invoked by the sign worker on success / failure.
// Stubbed to a log line; replace with a CounterVec.WithLabelValues call
// when the metric is wired.
func (m *iosdistMetricsRegistry) recordIOSDistBuild(tool, result string) {
	log.Printf("[iosdist metric-stub] build tool=%s result=%s", tool, result)
}

// ── logSignEvent (dock/logs_store.go) ────────────────────────────────
//
// Original signature:
//   func (s *Server) logSignEvent(workspaceID string, taskID int64,
//       action, message, level string, details map[string]any)
//
// Persists a structured event to the `logs` table for the operator UI.
// Stubbed to a stderr log line — the follow-up PR adds an SDK method
// `Dock.LogAppend(LogEntry)` and points this here.
//
// TODO(extract): replace with p.Dock.LogAppend(...) once the SDK has it.
func (p *Plugin) logSignEvent(workspaceID string, taskID int64, action, message, level string, details map[string]any) {
	if level == "" {
		level = LogLevelInfo
	}
	log.Printf("[iosdist log-stub] sign-event ws=%s task=%d action=%s level=%s msg=%s details=%v",
		workspaceID, taskID, action, level, message, details)
}
