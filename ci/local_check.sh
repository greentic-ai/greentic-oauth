#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
echo "[info] ci/local_check.sh is deprecated. Please use ci/check_local.sh instead." >&2
exec "$SCRIPT_DIR/check_local.sh" "$@"
