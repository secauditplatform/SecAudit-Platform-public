#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/frontend"

export VITE_AUTH_ENABLED="${VITE_AUTH_ENABLED:-true}"
export VITE_LOCAL_AUTH_ENABLED="${VITE_LOCAL_AUTH_ENABLED:-true}"
export VITE_API_URL="${VITE_API_URL:-http://127.0.0.1:8000}"

npm run build
exec npm run preview -- --host 127.0.0.1 --port "${E2E_WEB_PORT:-4173}"
