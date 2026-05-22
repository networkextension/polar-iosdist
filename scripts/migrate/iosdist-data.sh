#!/usr/bin/env bash
# iosdist-data.sh — copy iosdist_* tables from `ideamesh` (dock's DB)
# into `polar_iosdist` (iosdist-svc's DB). Run AFTER
# scripts/migrate/iosdist-schema.sql has provisioned the target.
#
# Same shape as scripts/migrate/wg-data.sh — read-only on source,
# idempotent on target, TRUNCATE before reload.
#
# Usage:
#   SRC_DSN="postgres://ideamesh:test123456@127.0.0.1:5432/ideamesh"
#   DST_DSN="postgres://ideamesh:test123456@127.0.0.1:5432/polar_iosdist"
#   ./scripts/migrate/iosdist-data.sh              # dry-run: counts only
#   ./scripts/migrate/iosdist-data.sh --apply      # actually copies

set -euo pipefail

SRC_DSN="${SRC_DSN:-postgres://ideamesh:test123456@127.0.0.1:5432/ideamesh}"
DST_DSN="${DST_DSN:-postgres://ideamesh:test123456@127.0.0.1:5432/polar_iosdist}"
PSQL="${PSQL:-/Applications/Postgres.app/Contents/Versions/latest/bin/psql}"
PG_DUMP="${PG_DUMP:-/Applications/Postgres.app/Contents/Versions/latest/bin/pg_dump}"

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
    APPLY=1
fi

# Order matters — parents before children so FKs resolve. Same order
# as the CREATE TABLE blocks in iosdist-schema.sql.
TABLES=(
    iosdist_apps
    iosdist_app_status
    iosdist_test_requests
    iosdist_asc_configs
    iosdist_versions
    iosdist_install_tokens
    iosdist_certificates
    iosdist_profiles
    iosdist_sign_tasks
    iosdist_agent_builds
)

echo "=== iosdist-data.sh — $(if [[ $APPLY -eq 1 ]]; then echo APPLY; else echo DRY-RUN; fi) ==="
echo "source: $SRC_DSN"
echo "target: $DST_DSN"
echo

echo "--- source row counts ---"
for t in "${TABLES[@]}"; do
    n=$("$PSQL" "$SRC_DSN" -At -c "SELECT COUNT(*) FROM $t;" 2>/dev/null || echo "ERR")
    printf "  %-25s %s\n" "$t" "$n"
done
echo

if [[ $APPLY -eq 0 ]]; then
    echo "Dry run — pass --apply to perform the copy."
    echo "Pre-flight: ensure scripts/migrate/iosdist-schema.sql is applied to target."
    exit 0
fi

TMPDIR=$(mktemp -d -t iosmigrate)
trap 'rm -rf "$TMPDIR"' EXIT

echo "--- dumping source data ---"
DUMP="$TMPDIR/iosdist-data.sql"
"$PG_DUMP" "$SRC_DSN" \
    --data-only \
    --column-inserts \
    --no-owner \
    --no-privileges \
    $(printf -- '--table=%s ' "${TABLES[@]}") \
    > "$DUMP"
echo "wrote $(wc -l < "$DUMP") lines to $DUMP"
echo

echo "--- truncating target + loading ---"
# Same approach as wg-data.sh: TRUNCATE CASCADE is the simplest
# idempotent reset; pg_dump's own setval calls re-sync sequences.
{
    echo "BEGIN;"
    for t in "${TABLES[@]}"; do
        echo "TRUNCATE $t RESTART IDENTITY CASCADE;"
    done
    cat "$DUMP"
    echo "COMMIT;"
} | "$PSQL" "$DST_DSN" -v ON_ERROR_STOP=1

echo
echo "--- target row counts (post-load) ---"
for t in "${TABLES[@]}"; do
    n=$("$PSQL" "$DST_DSN" -At -c "SELECT COUNT(*) FROM $t;")
    printf "  %-25s %s\n" "$t" "$n"
done
echo
echo "Done. iosdist-svc can now point POLAR_IOSDIST_DB_DSN at $DST_DSN."
