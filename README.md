# polar-iosdist

iOS app distribution + re-signing plugin for the [Polar](https://github.com/networkextension/Polar) platform.

Owns the `/api/iosdist/*` admin surface (apps, versions, certificates, provisioning profiles, App Store Connect bindings, sign tasks) plus the `/iosdist/*` public install / share / plaza surface (over-the-air iOS install manifest, public-share landing pages, test-request inbox).

## Status

Phase 2-W1 handler extraction at 2026-05-22; pre-cutover. Dock still double-serves the same routes until ops flips `POLAR_IOSDIST_REMOTE=true`.

**Note**: `iosdist_agent_handlers.go` + `iosdist_agent_store.go` stay in Polar dock — the agent-facing endpoints (`/api/iosdist/agent/*`) depend on dock's `PolarAgentAuthMiddleware` and run in-process with the build agent registry. Phase 3 will canonicalize.

## Install

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o /tmp/iosdist-svc ./cmd/iosdist-svc
rsync -avz /tmp/iosdist-svc local@<deploy-box>:/Users/local/.local/bin/
```

Environment:

Plugin plumbing
- `POLAR_DOCK_BASE` — e.g. `http://127.0.0.1:8080`
- `POLAR_PLUGIN_TOKEN` — plaintext token from `/admin-plugins.html` (one-time print at row creation)
- `POLAR_IOSDIST_DB_DSN` — Postgres DSN for `polar_iosdist`
- `POLAR_IOSDIST_LISTEN` — default `127.0.0.1:8091`
- `POLAR_IOSDIST_BLOB_DIR` — default `/Users/local/iosdist-svc-data` (ipa/, certs/, profiles/, asc-keys/, icons/)
- `POLAR_IOSDIST_METRICS_TOKEN` — Bearer for `/metrics`; unset → 404
- `POLAR_IOSDIST_VERSION` — git-sha or `0.0.1`
- `IOSDIST_PUBLIC_BASE_URL` — base for install / manifest links (optional; falls back to request host)
- `IOSDIST_ZSIGN_PATH` — explicit zsign binary path; unset → `$PATH` lookup

At-rest encryption
- `IOSDIST_RESOURCE_KEY` — 32-byte AES-GCM key (hex or base64). When unset, certificate passwords + ASC `.p8` contents are stored plaintext and the API flags the row.

Cloudflare R2 (IPA / signed-IPA / icon blob storage; if any are unset → local disk fallback)
- `R2_ACCOUNT_ID`
- `R2_BUCKET`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_PUBLIC_URL`

App Store Connect fallback (used when a workspace hasn't uploaded its own ASC config row)
- `ASC_KEY_ID`
- `ASC_ISSUER_ID`
- `ASC_PRIVATE_KEY_PATH`

## Endpoints

Authed admin (Bearer token introspected via dock `/internal/v1/auth/verify`):

Apps
- `GET / POST /api/iosdist/apps`
- `GET / DELETE /api/iosdist/apps/:id`
- `POST /api/iosdist/apps/:id/icon`
- `PUT /api/iosdist/apps/:id/testflight`
- `PUT /api/iosdist/apps/:id/visibility`
- `GET /api/iosdist/apps/:id/test-requests`
- `GET /api/iosdist/apps/:id/status`
- `POST /api/iosdist/apps/:id/status/sync`

Versions + signing
- `POST /api/iosdist/apps/:id/versions`
- `DELETE /api/iosdist/apps/:id/versions/:versionId`
- `POST /api/iosdist/apps/:id/versions/:versionId/install-token`
- `POST /api/iosdist/apps/:id/versions/:versionId/sign`
- `GET /api/iosdist/apps/:id/sign-tasks`
- `GET /api/iosdist/sign-tasks/:id`

Certs / profiles
- `GET / POST /api/iosdist/certificates`
- `DELETE /api/iosdist/certificates/:id`
- `GET / POST /api/iosdist/profiles`
- `DELETE /api/iosdist/profiles/:id`

App Store Connect
- `GET / POST / DELETE /api/iosdist/asc/config`
- `GET /api/iosdist/asc/apps`
- `POST /api/iosdist/asc/apps`
- `POST /api/iosdist/asc/bundle-ids`
- `GET /api/iosdist/asc/beta-groups`
- `PUT /api/iosdist/apps/:id/asc-binding`
- `POST /api/iosdist/apps/:id/invite-tester`
- `POST /api/iosdist/apps/:id/asc-sync`

Public (slug / token IS the auth — no Bearer)
- `GET /iosdist/install/:token` — install landing page
- `GET /iosdist/manifest/:token` — iOS OTA `.plist` manifest
- `GET /iosdist/share/:slug` — public share landing
- `POST /iosdist/share/:slug/install` — issue install token
- `POST /iosdist/share/:slug/test-request` — test-flight request inbox
- `GET /iosdist/plaza` — public app gallery

## Related

- [Polar dock](https://github.com/networkextension/Polar)
- [polar-sdk](https://github.com/networkextension/polar-sdk)

## License

MIT
