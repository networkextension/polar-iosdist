-- ============================================================
-- polar_iosdist schema — end-state (post-T6-B).
--
-- Apply order:
--   1. As cluster superuser:
--        CREATE DATABASE polar_iosdist OWNER ideamesh;
--   2. As `ideamesh` against polar_iosdist:
--        psql -d polar_iosdist -f scripts/migrate/iosdist-schema.sql
--
-- Cross-DB references (no FKs across databases):
--   - owner_user_id, submitted_by, created_by  — resolved via
--     dock SDK /internal/v1/users/:id
--   - workspace_id                             — resolved via
--     dock SDK /internal/v1/teams/:id
--   - project_id (iosdist_agent_builds)        — projects lives in
--     dock; iosdist-svc treats it as an opaque string. dock's
--     projects table no longer has the reverse FK to iosdist_apps
--     either (handled by separate dock-side migration in cutover PR).
--
-- These columns stay TEXT (BIGINT for app_id/version_id/cert_id/
-- profile_id which are owned by polar_iosdist).
--
-- See doc/arch/database-ownership.md for the full map.
-- ============================================================

CREATE TABLE IF NOT EXISTS iosdist_apps (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id TEXT NOT NULL,
    workspace_id TEXT,
    name TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    icon_url TEXT NOT NULL DEFAULT '',
    icon_source TEXT NOT NULL DEFAULT '',
    testflight_url TEXT NOT NULL DEFAULT '',
    asc_app_id TEXT NOT NULL DEFAULT '',
    asc_beta_group_id TEXT NOT NULL DEFAULT '',
    public_slug TEXT NOT NULL DEFAULT '',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    keywords TEXT NOT NULL DEFAULT '',
    whats_new TEXT NOT NULL DEFAULT '',
    promotional_text TEXT NOT NULL DEFAULT '',
    marketing_url TEXT NOT NULL DEFAULT '',
    support_url TEXT NOT NULL DEFAULT '',
    name_i18n JSONB,
    description_i18n JSONB,
    promotional_text_i18n JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iosdist_apps_owner ON iosdist_apps(owner_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_apps_workspace ON iosdist_apps(workspace_id, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_iosdist_apps_public_slug
    ON iosdist_apps(public_slug) WHERE public_slug <> '';

CREATE TABLE IF NOT EXISTS iosdist_app_status (
    app_id BIGINT PRIMARY KEY REFERENCES iosdist_apps(id) ON DELETE CASCADE,
    appstore_version TEXT NOT NULL DEFAULT '',
    appstore_state TEXT NOT NULL DEFAULT '',
    appstore_submitted_at TIMESTAMPTZ,
    appstore_released_at TIMESTAMPTZ,
    tf_build_version TEXT NOT NULL DEFAULT '',
    tf_processing_state TEXT NOT NULL DEFAULT '',
    tf_beta_state TEXT NOT NULL DEFAULT '',
    tf_uploaded_at TIMESTAMPTZ,
    tf_expires_at TIMESTAMPTZ,
    beta_tester_count INTEGER NOT NULL DEFAULT 0,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sync_error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS iosdist_test_requests (
    id BIGSERIAL PRIMARY KEY,
    app_id BIGINT NOT NULL REFERENCES iosdist_apps(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    asc_response TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_iosdist_test_requests_app ON iosdist_test_requests(app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_test_requests_email ON iosdist_test_requests(email, created_at DESC);

-- iosdist_asc_configs: per-workspace ASC API credentials (post-T6-B).
-- Encryption key (IOSDIST_RESOURCE_KEY env on iosdist-svc) AES-GCMs p8_cipher.
CREATE TABLE IF NOT EXISTS iosdist_asc_configs (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id TEXT NOT NULL,
    workspace_id TEXT,
    issuer_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    p8_cipher TEXT NOT NULL,
    p8_filename TEXT NOT NULL DEFAULT '',
    p8_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    account_holder_email TEXT NOT NULL DEFAULT '',
    team_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_iosdist_asc_configs_workspace
    ON iosdist_asc_configs(workspace_id) WHERE workspace_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS iosdist_versions (
    id BIGSERIAL PRIMARY KEY,
    app_id BIGINT NOT NULL REFERENCES iosdist_apps(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    build_number TEXT NOT NULL DEFAULT '',
    ipa_url TEXT NOT NULL DEFAULT '',
    ipa_filename TEXT NOT NULL DEFAULT '',
    ipa_size BIGINT NOT NULL DEFAULT 0,
    ipa_sha256 TEXT NOT NULL DEFAULT '',
    release_notes TEXT NOT NULL DEFAULT '',
    is_signed BOOLEAN NOT NULL DEFAULT TRUE,
    distribution_type TEXT NOT NULL DEFAULT 'ad_hoc',
    ipa_bundle_id TEXT NOT NULL DEFAULT '',
    ipa_short_version TEXT NOT NULL DEFAULT '',
    ipa_build_number TEXT NOT NULL DEFAULT '',
    ipa_display_name TEXT NOT NULL DEFAULT '',
    ipa_min_os TEXT NOT NULL DEFAULT '',
    ipa_has_embedded_profile BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iosdist_versions_app ON iosdist_versions(app_id, created_at DESC);

CREATE TABLE IF NOT EXISTS iosdist_install_tokens (
    token TEXT PRIMARY KEY,
    version_id BIGINT NOT NULL REFERENCES iosdist_versions(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_accessed_at TIMESTAMPTZ,
    access_count INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_iosdist_install_tokens_version ON iosdist_install_tokens(version_id);
CREATE INDEX IF NOT EXISTS idx_iosdist_install_tokens_expires ON iosdist_install_tokens(expires_at);

CREATE TABLE IF NOT EXISTS iosdist_certificates (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id TEXT NOT NULL,
    workspace_id TEXT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'distribution',
    file_url TEXT NOT NULL,
    file_filename TEXT NOT NULL DEFAULT '',
    file_size BIGINT NOT NULL DEFAULT 0,
    password_cipher TEXT NOT NULL DEFAULT '',
    password_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    team_id TEXT NOT NULL DEFAULT '',     -- Apple Developer team id, NOT polar workspace
    common_name TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iosdist_certificates_owner ON iosdist_certificates(owner_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_certificates_workspace ON iosdist_certificates(workspace_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS iosdist_profiles (
    id BIGSERIAL PRIMARY KEY,
    owner_user_id TEXT NOT NULL,
    workspace_id TEXT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'ad_hoc',
    file_url TEXT NOT NULL,
    file_filename TEXT NOT NULL DEFAULT '',
    file_size BIGINT NOT NULL DEFAULT 0,
    app_id TEXT NOT NULL DEFAULT '',      -- bundle id (Apple)
    team_id TEXT NOT NULL DEFAULT '',     -- Apple Developer team id
    udid_count INT NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iosdist_profiles_owner ON iosdist_profiles(owner_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_profiles_workspace ON iosdist_profiles(workspace_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS iosdist_sign_tasks (
    id BIGSERIAL PRIMARY KEY,
    app_id BIGINT NOT NULL REFERENCES iosdist_apps(id) ON DELETE CASCADE,
    source_version_id BIGINT NOT NULL REFERENCES iosdist_versions(id) ON DELETE CASCADE,
    output_version_id BIGINT REFERENCES iosdist_versions(id) ON DELETE SET NULL,
    cert_id BIGINT NOT NULL REFERENCES iosdist_certificates(id) ON DELETE CASCADE,
    profile_id BIGINT NOT NULL REFERENCES iosdist_profiles(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT NOT NULL DEFAULT '',
    log_text TEXT NOT NULL DEFAULT '',
    new_bundle_id TEXT NOT NULL DEFAULT '',
    new_app_name TEXT NOT NULL DEFAULT '',
    submitted_by TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_iosdist_sign_tasks_app ON iosdist_sign_tasks(app_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_sign_tasks_status ON iosdist_sign_tasks(status);
CREATE INDEX IF NOT EXISTS idx_iosdist_sign_tasks_idem ON iosdist_sign_tasks(idempotency_key);

-- iosdist_agent_builds: agent-driven build lifecycle. project_id is a
-- TEXT pointer into dock's projects table (no FK; dock owns it). Lookups
-- of project metadata go via dock SDK.
CREATE TABLE IF NOT EXISTS iosdist_agent_builds (
    id BIGSERIAL PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    project_id TEXT,
    iosdist_app_id BIGINT REFERENCES iosdist_apps(id) ON DELETE SET NULL,
    agent_user_id TEXT,
    status TEXT NOT NULL DEFAULT 'init',
    sign_method TEXT NOT NULL DEFAULT '',
    source_filename TEXT NOT NULL DEFAULT '',
    source_size BIGINT NOT NULL DEFAULT 0,
    source_ipa_url TEXT NOT NULL DEFAULT '',
    signed_ipa_url TEXT NOT NULL DEFAULT '',
    asc_build_id TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    log_text TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_iosdist_agent_builds_workspace ON iosdist_agent_builds(workspace_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_agent_builds_project ON iosdist_agent_builds(project_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_iosdist_agent_builds_app ON iosdist_agent_builds(iosdist_app_id, updated_at DESC);
