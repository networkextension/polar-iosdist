# ASC Proxy — Detailed Breakdown

**Status**: design / task breakdown. Some endpoints already
shipped; this doc inventories current state and decomposes the
remaining work.
**Owner**: backlog
**Created**: 2026-05-06
**Companion docs**: [`iosapp.md`](../iosapp.md) (architecture),
[`DEV_PLAN.md`](../DEV_PLAN.md) M4/M5 (high-level plan)

The platform already proxies *some* ASC operations end-to-end (config
upload + app/beta-group discovery + per-app binding + tester invite +
metadata sync). What's missing is everything else from M4/M5 in
DEV_PLAN.md, plus a handful of cross-cutting concerns that none of
the existing handlers address.

This breakdown takes M4 (pull) + M5 (push) from one-paragraph
milestones to concrete, sized sub-tasks with current-state mapping.

---

## Current state inventory

### Schema (already shipped)
- `iosdist_asc_configs` — per-workspace, encrypted `.p8` private key
  + Issuer ID + Key ID (with workspace_id FK to teams)
- `iosdist_apps.asc_app_id` / `asc_beta_group_id` — per-app binding
- `iosdist_invites` — tester invite outbox with status + ascResponse

### Server-side ASC client (`internal/app/dock/iosdist_asc.go`)
| Function | Endpoint | Status |
|---|---|---|
| `ascSignToken` | JWT mint with cached p8 | ✅ |
| `ascListApps` | `GET /v1/apps` (filtered by bundle id) | ✅ |
| `ascGetApp` | `GET /v1/apps/{id}` | ✅ |
| `ascGetLatestVersionLocalizations` | per-locale meta read | ✅ |
| `ascLatestBuildForApp` | `GET /v1/builds` (icon source) | ✅ |
| `ascListUsers` | `GET /v1/users` | ✅ |
| `ascListBetaGroups` | `GET /v1/betaGroups` | ✅ |
| `ascCreateTester` | `POST /v1/betaTesters` | ✅ |

### HTTP handlers (`internal/app/dock/iosdist_asc_handlers.go`)
| Handler | Route | Status |
|---|---|---|
| `handleIOSASCConfigGet` | `GET /api/iosdist/asc/config` | ✅ |
| `handleIOSASCConfigUpsert` | `POST /api/iosdist/asc/config` | ✅ |
| `handleIOSASCConfigDelete` | `DELETE /api/iosdist/asc/config` | ✅ |
| `handleIOSASCAppList` | `GET /api/iosdist/asc/apps` | ✅ |
| `handleIOSASCBetaGroupList` | `GET /api/iosdist/asc/beta-groups` | ✅ |
| `handleIOSAppASCBindingUpdate` | `PUT /api/iosdist/apps/:id/asc-binding` | ✅ |
| `handleIOSAppInviteTester` | `POST /api/iosdist/apps/:id/invite-tester` | ✅ |
| `handleIOSAppASCSyncMeta` | sync app meta from ASC | ✅ |

What's done is **discovery + binding + low-volume one-shot writes**.
What's missing is **bulk read sync, build/version state pulling,
metadata write, build upload, and all cross-cuts**.

---

## Gap analysis vs M4/M5

DEV_PLAN.md M4 promises "TF / metadata / 审核状态展示". Currently
the platform shows nothing of the sort. M5 promises "控制台一键提交
描述/截图/What's New" — none of the write paths exist. Between the
existing functions and that goal there are ~15 distinct tasks.

---

## M4 — Pull side (TestFlight + App Store state)

### M4.1 — TestFlight build state sync
**Goal**: every iosdist build whose IPA was uploaded to ASC shows
its current ASC processing state in the UI:
PROCESSING → VALID → BETA_REVIEW_IN_PROGRESS → APPROVED →
EXTERNAL_RELEASE → INVALID/EXPIRED.

**Current state**: `ascLatestBuildForApp` exists but is only used
to lift an iconAssetToken (single read). No persistence, no
periodic sync, no UI surface.

**Sub-tasks**:
- a. New table `iosdist_asc_builds` (asc_build_id PK, asc_app_id,
     bundle_version, processing_state, expires_at, uploaded_at,
     synced_at).
- b. New ASC client function `ascListBuilds(appID, since)` —
     paginated, supports `filter[expired]=false`.
- c. Periodic sync goroutine: for each `iosdist_asc_configs` row
     with at least one bound app, pull builds every 60s; upsert.
     Backoff on 429.
- d. UI per-app row shows latest build state pill;
     `iosdist.html` already has the slot.
- e. Webhook fallback (Apple's ASC has webhooks for `BUILD` and
     `APP_STORE_VERSION` — adopt where available, polling as
     fallback).

**Estimate**: 1 wk (a-d), +0.5 wk (e).
**Trigger**: first time someone wants to see TF processing
status without opening ASC tab.

### M4.2 — App Store version + review state sync
**Goal**: per-app row shows current App Store version state
(PREPARE_FOR_SUBMISSION → WAITING_FOR_REVIEW → IN_REVIEW →
PENDING_DEVELOPER_RELEASE → READY_FOR_SALE → REJECTED).

**Current state**: zero.

**Sub-tasks**:
- a. ASC client function `ascListAppStoreVersions(appID)`.
- b. New table `iosdist_asc_app_store_versions` (asc_app_id,
     version_string, app_store_state, release_type,
     phased_release_state, rejection_reason).
- c. Pull on the same 60s tick as M4.1.
- d. UI: append a small status pill column on the app card.
- e. Surface rejection reasons (text + checklist) — these are
     critical UX value.

**Estimate**: 1 wk total.
**Trigger**: after M4.1 (same plumbing).

### M4.3 — Bidirectional beta tester / group sync
**Goal**: keep `iosdist_asc_beta_groups` and `iosdist_asc_beta_testers`
mirrored from ASC so the UI can do tester management without going
to ASC.

**Current state**: `ascListBetaGroups` is used as a one-shot
picker; `ascListUsers` exists but nothing persists. `ascCreateTester`
writes to ASC without local mirror.

**Sub-tasks**:
- a. Local tables for groups + testers + group_membership.
- b. `ascListBetaTesters(appID, page)` paginated client.
- c. Two-way sync logic: pull side overrides local; local writes
     queue an ASC mutation, mark `sync_pending` until ASC echo.
- d. UI: tester management page (add / remove / move-between-groups
     / resend-invite).
- e. Soft-delete handling (ASC deletions vs local removals).

**Estimate**: 1.5 wk.
**Trigger**: when team has >50 testers and ASC tab gets unwieldy.

### M4.4 — Metadata pull (per-locale)
**Goal**: app description / keywords / what's new / screenshots
visible in the platform UI for every locale, in read-only form
(write side is M5).

**Current state**: `ascGetLatestVersionLocalizations` exists and
the `handleIOSAppASCSyncMeta` handler uses *one* locale's worth
of data to populate the local app row. Multi-locale not exposed.

**Sub-tasks**:
- a. New table `iosdist_asc_localizations` (asc_app_id, locale,
     description, keywords, whats_new, marketing_url, support_url,
     synced_at).
- b. Sync function pulls all locales (~40 max for an app); upsert.
- c. ASC client function for screenshot URLs:
     `ascListAppScreenshotSets(versionID)` →
     `ascListAppScreenshots(setID)`. Each screenshot has signed
     download URL; cache locally optional.
- d. UI: per-app "Metadata" tab with locale switcher, all fields
     read-only, "edit" button greyed until M5.

**Estimate**: 1 wk.
**Trigger**: bundled with M5.

---

## M5 — Push side (write metadata, submit version, upload build)

### M5.1 — Metadata write per locale
**Goal**: edit description / keywords / what's new / promotional
text / marketing URL / support URL per locale and push to ASC in
one click.

**Current state**: zero write paths.

**Sub-tasks**:
- a. ASC client functions: `ascUpdateAppInfo`,
     `ascUpdateAppInfoLocalization`, `ascUpdateAppStoreVersion`,
     `ascUpdateAppStoreVersionLocalization`. Each is a PATCH against
     `/v1/{resource}/{id}` with sparse JSON:API body.
- b. UI: per-locale form with hard-coded length limits (description
     4000, keywords 100, what's new 4000, etc.) — surface limits
     before the round-trip.
- c. Draft model: local edits are saved against
     `iosdist_asc_localizations.draft_*` columns, submit pushes
     atomically. On success clear draft, on failure surface ASC's
     error JSON.
- d. Bulk locale "fan out": one source locale + auto-translate
     hint to the others (out of scope for v1; just edit each
     manually).

**Estimate**: 1.5 wk.
**Trigger**: first non-trivial app submission where running back
to ASC web is friction.

### M5.2 — Screenshot upload per locale per device size
**Goal**: upload screenshots from the platform UI; ASC takes them
correctly with the right device-size bucket.

**Current state**: zero.

**Sub-tasks**:
- a. ASC API quirks — screenshots are uploaded as
     `appScreenshots` resources; each requires:
     1. `POST` to reserve a slot (returns upload operations array)
     2. parallel `PATCH` chunks to the upload URLs Apple returned
     3. `PATCH` to commit (sets `uploaded=true`)
     4. local sourceFileChecksum stored for idempotency
- b. Server-side dimension validation per device class (iPhone 6.7"
     1290×2796, iPad 12.9" 2048×2732, etc.). Reject with clear
     error before the round-trip.
- c. UI: drag-drop with auto-bucketing by detected dimension.
- d. Reorder support — ASC respects display order; expose via the
     screenshot list endpoint.

**Estimate**: 1.5 wk. Screenshot upload is the most fiddly piece
of the ASC API.
**Trigger**: bundled with M5.1.

### M5.3 — Build upload (replace altool / transporter)
**Goal**: signed IPA from the iosdist sign worker → ASC build
upload, no operator intervention.

**Current state**: zero. Today operators upload builds to ASC
via Xcode Organizer or `xcrun altool` manually.

**Background**: Apple deprecated `altool` in November 2024;
`xcrun notarytool` and the standalone Transporter app / Java
Transporter CLI are the supported paths. The cleanest API path is
ASC's own `POST /v1/buildUploads` (only available via the
delivery API which requires a notarized iTMSTransporter binary
shipped with Xcode).

**Sub-tasks**:
- a. Decide path: (i) ship transporter CLI in the iosdist worker
     image (~500 MB), call as subprocess; or (ii) reverse-engineer
     the protocol (not supported; risky); or (iii) use a
     Mac-side agent that has Xcode + transporter installed
     (consistent with the existing mac-agent direction).
- b. Worker integration: after sign-worker produces signed IPA,
     hand off to transporter; capture output for build_id.
- c. Status hand-off: transporter call returns; build state then
     follows the M4.1 sync path (PROCESSING → VALID).
- d. Error handling: transporter exits non-zero with diagnostic
     plist; parse and surface user-friendly message.
- e. Concurrency: one transporter process per upload; queue if
     multiple builds compete.

**Estimate**: 2 wk. Path decision drives most of the cost — if
mac-agent is the path, this is the same work as the other
mac-agent stories.
**Trigger**: when sign-worker output starts piling up uploaded
manually.
**Dependency**: mac-agent FUTURE_WORK item.

### M5.4 — Submit for review
**Goal**: one-button "submit for review" that creates the
`appStoreVersionSubmissions` resource and tracks the result.

**Current state**: zero.

**Sub-tasks**:
- a. ASC client function `ascSubmitVersionForReview(versionID)`.
- b. Pre-flight check: validate all required locale fields filled,
     screenshots present per device class, build attached. Failures
     listed before the call so user fixes locally.
- c. UI: button only enabled when pre-flight passes.
- d. Post-submit: M4.2 sync picks up the new state.

**Estimate**: 0.5 wk.
**Trigger**: after M5.1 + M5.2 — submit is the end of the
metadata flow.

---

## Cross-cutting tasks (apply to multiple milestones above)

### CC1 — JWT lifecycle hardening
**Current**: `ascSignToken` mints fresh JWT per call. Apple
caps token lifetime ≤20 min; some endpoints want shorter.

**Sub-tasks**:
- Cache signed JWT per `iosdist_asc_configs.id` keyed by
  `(key_id, exp_at - 60s)`. In-memory + Redis for HA.
- Refresh on 401 and re-execute the call once.
- Logging: surface which key_id minted the failing token (already
  done in `logASCSigningContext`, just keep).

**Estimate**: 0.3 wk. Worth doing first — every other M4/M5 task
sees a 5-10% latency drop.

### CC2 — Rate limit + retry policy
**Current**: no retry on 429. Apple's per-team limit is ~3500
requests / hour soft. Easily blown by an unbounded bulk-sync.

**Sub-tasks**:
- Exponential backoff on 429 + 5xx with `Retry-After` honored.
- Per-config token bucket so polling jobs (M4.1, M4.2) don't
  starve interactive calls.
- Cap concurrent in-flight requests per config (5).
- Surface "ASC throttled, will retry" status pill on app rows
  during throttle so user understands stalled syncs.

**Estimate**: 0.5 wk. Required before M4.1 polling lands or the
team's ASC quota gets blown.

### CC3 — Audit log of ASC calls
**Current**: zero. ASC actions on behalf of operators leave no
local trace beyond the result.

**Sub-tasks**:
- New table `iosdist_asc_audit` (config_id, operator_user_id,
  method, path, status, response_summary, requested_at).
- Server-side middleware in `ascDo` writes a row.
- Page in admin UI to filter by operator / time / status.
- Retention: 90 days then purge.

**Estimate**: 0.5 wk.
**Trigger**: when more than one person can use the same ASC
config (workspace shared) — accountability becomes a need.

### CC4 — Per-error mapping (ASC → human)
**Current**: ASC errors bubble up as JSON:API `errors[]` arrays.
Operator sees raw codes like `ENTITY_ERROR.ATTRIBUTE.INVALID`.

**Sub-tasks**:
- A small Go map of ASC error codes → Chinese explanation +
  remediation hint ("description 超过 4000 字符" / "screenshot
  尺寸 1290×2796 不符合 iPhone 6.7" 设备类").
- Wrap `ascDo` to translate before returning to handler.
- Fallback: pass-through raw if code unknown.

**Estimate**: 0.3 wk for an initial set of ~20 error codes;
iterative thereafter.

### CC5 — Multi-credential / multi-team support
**Current**: schema is per-workspace (`iosdist_asc_configs`
unique on workspace_id) — only one Apple Dev account per
workspace. Some operators have multiple Apple Dev accounts
(personal + enterprise + client work).

**Sub-tasks**:
- Drop unique constraint; add `name` + `is_default` columns.
- Per-app `asc_config_id` FK so each app says which credential
  to use.
- UI: config picker on the ASC config page; per-app config
  selector when binding.

**Estimate**: 0.5 wk.
**Trigger**: first request from someone managing apps across
multiple Apple Dev accounts. Don't pre-build.

### CC6 — Webhook receiver (build / version state)
**Current**: zero. M4.1/M4.2 default to polling.

**Sub-tasks**:
- Apple's webhook config (per-team, console UI) → POST to a
  Polar endpoint with HMAC signature.
- Implement `POST /api/iosdist/asc/webhook/:config_id` with
  HMAC verification.
- Process `BUILD` and `APP_STORE_VERSION` events; trigger
  immediate refresh of M4.1/M4.2 state for the affected app.
- Polling stays as fallback (slower interval when webhooks are
  active).

**Estimate**: 0.7 wk.
**Trigger**: when 60s polling latency feels slow — typically
after M4.1 lands and someone notices "TF processed 4 minutes
ago, why does the UI still say PROCESSING?"

---

## Suggested ship order

```
done   →  Config CRUD, app discovery, beta-group discovery,
          per-app binding, single-tester invite, sync-meta one-shot
next   →  CC1 (JWT cache)              ← gates everything else
+1     →  CC2 (rate limit + retry)     ← gates polling
+2     →  M4.1 (TF build state sync)   ← first user-visible win
+3     →  M4.2 (App Store version)     ← same plumbing as M4.1
+4     →  M4.4 (multi-locale meta pull)← read side of M5
+5     →  M5.1 (metadata write)        ← first write path
+6     →  M5.2 (screenshot upload)
+7     →  M5.4 (submit for review)     ← closes the metadata loop
later  →  M4.3 (tester sync), M5.3 (build upload via mac-agent),
          CC3 (audit), CC4 (error map), CC5 (multi-cred), CC6 (webhook)
```

Total to "metadata round-trip via Polar instead of ASC web":
**~6 engineer-weeks** spread over CC1+CC2+M4.1+M4.2+M4.4+M5.1+M5.2+M5.4.

Build upload (M5.3) is gated by mac-agent and is independently
~2 wk on top.

---

## Out of scope (deliberately)

- **Pricing tier management** — ASC API supports it; rare enough
  that one operator can use ASC web.
- **In-app purchase configuration** — large surface area, separate
  story.
- **Sales reports** — read-only consumer of ASC API, but a
  different problem domain (finance dashboard).
- **Apple Developer Program enrollment / membership** — ASC API
  doesn't cover this; there's no Apple-supported automation.
- **TestFlight crash reports** — symbolicated stack uploads come
  from a different API (App Store Connect Diagnostics) and need
  dSYM management; out of scope until v2.

---

## Open questions

1. **Mac-agent shape for M5.3**. Do we ship a dedicated Mac side
   agent for transporter (consistent with existing mac-agent
   direction), or run transporter inside the regular polar-agent
   on a Mac host? Affects M5.3 + M3+ codesign route plumbing.
2. **Webhook auth**. Apple's HMAC signature scheme on ASC webhooks
   — confirm the exact algorithm (HMAC-SHA256 with what shared
   secret?) before implementing CC6. Apple docs ambiguous in
   spots.
3. **Multi-locale UX**. M5.1's "fan out" auto-translate — useful
   feature or scope creep? Defer to user feedback.
4. **Audit log retention**. CC3 says 90 days; legal/compliance
   may want longer. Confirm before shipping.
