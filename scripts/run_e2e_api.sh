#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/api"

export AUTH_ENABLED="${AUTH_ENABLED:-true}"
export LOCAL_AUTH_ENABLED="${LOCAL_AUTH_ENABLED:-true}"
export SKIP_MIGRATIONS="${SKIP_MIGRATIONS:-1}"
export PROFILES_AUTO_SEED="${PROFILES_AUTO_SEED:-false}"
export PROFILES_CATALOG_SYNC_ENABLED="${PROFILES_CATALOG_SYNC_ENABLED:-false}"
export NOTIFICATIONS_ENABLED="${NOTIFICATIONS_ENABLED:-false}"
export OBJECT_RBAC_ENABLED="${OBJECT_RBAC_ENABLED:-false}"
export APP_ENV="${APP_ENV:-development}"
export SECRET_KEY="${SECRET_KEY:-ci-test-secret-key-32chars-minimum}"

exec uvicorn app.main:app --host 127.0.0.1 --port 8000
