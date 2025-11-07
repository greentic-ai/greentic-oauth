#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   LOCAL_CHECK_ONLINE=1 LOCAL_CHECK_STRICT=1 ci/local_check.sh
# Defaults: online, non-strict.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ONLINE="${LOCAL_CHECK_ONLINE:-1}"
STRICT="${LOCAL_CHECK_STRICT:-0}"
VERBOSE="${LOCAL_CHECK_VERBOSE:-0}"
SKIP_EXIT=99
SKIPPED_STEPS=()

if [ "$VERBOSE" = "1" ]; then
  set -x
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[miss] $1" >&2
    return 1
  }
}

step() {
  echo ""
  echo "▶ $*"
}

run_or_skip() {
  local desc="$1"
  shift
  if "$@"; then
    return 0
  fi

  local status=$?
  if [ "$status" -eq "$SKIP_EXIT" ]; then
    echo "[skip] $desc"
    SKIPPED_STEPS+=("$desc")
    return 0
  fi

  echo "[fail] $desc" >&2
  return "$status"
}

require_tool() {
  local tool="$1"
  local desc="$2"
  if need "$tool"; then
    return 0
  fi

  if [ "$STRICT" = "1" ]; then
    echo "[err] Missing required tool '$tool' for ${desc}" >&2
    return 1
  fi

  echo "[info] Missing '$tool'; ${desc} will be skipped." >&2
  return "$SKIP_EXIT"
}

require_online() {
  local desc="$1"
  if [ "$ONLINE" = "1" ]; then
    return 0
  fi

  echo "[info] Offline mode; skipping ${desc}. Set LOCAL_CHECK_ONLINE=1 to enable." >&2
  return "$SKIP_EXIT"
}

require_env_vars() {
  local desc="$1"
  shift
  local missing=()

  for var in "$@"; do
    if [ -z "${!var:-}" ]; then
      missing+=("$var")
    fi
  done

  if [ "${#missing[@]}" -eq 0 ]; then
    return 0
  fi

  echo "[info] Missing environment variables for ${desc}: ${missing[*]}" >&2
  if [ "$STRICT" = "1" ]; then
    return 1
  fi
  return "$SKIP_EXIT"
}

print_env_overview() {
  echo "LOCAL_CHECK_ONLINE=${ONLINE}"
  echo "LOCAL_CHECK_STRICT=${STRICT}"
  echo "LOCAL_CHECK_VERBOSE=${VERBOSE}"
}

print_tool_version() {
  local tool="$1"
  local desc="$2"
  require_tool "$tool" "$desc" || return $?
  "$tool" --version
}

run_cargo_fetch() {
  local desc="cargo fetch --locked"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?
  cargo fetch --locked
}

run_cargo_fmt() {
  local desc="cargo fmt"
  require_tool "cargo" "$desc" || return $?
  require_tool "rustfmt" "$desc" || return $?
  cargo fmt --all -- --check
}

run_cargo_clippy() {
  local desc="cargo clippy"
  require_tool "cargo" "$desc" || return $?
  cargo clippy --workspace --all-targets --all-features -- -D warnings
}

run_cargo_build() {
  local desc="cargo build (workspace)"
  require_tool "cargo" "$desc" || return $?
  cargo build --workspace --all-features
}

run_cargo_test() {
  local desc="cargo test"
  require_tool "cargo" "$desc" || return $?
  cargo test --workspace --all-features -- --nocapture
}

run_broker_release_build() {
  local desc="cargo build -p greentic-oauth-broker --release"
  require_tool "cargo" "$desc" || return $?
  cargo build -p greentic-oauth-broker --release
}

WIT_FILES=()
while IFS= read -r wit_path; do
  WIT_FILES+=("$wit_path")
done < <(find "$ROOT" -type f -name '*.wit' -print | sort)

run_wit_validation() {
  local desc="wasm-tools wit validate"
  if [ "${#WIT_FILES[@]}" -eq 0 ]; then
    echo "[info] No WIT files detected."
    return "$SKIP_EXIT"
  fi

  require_tool "wasm-tools" "$desc" || return $?
  local ok=0
  for wit_path in "${WIT_FILES[@]}"; do
    echo "Validating ${wit_path}"
    wasm-tools wit validate "$wit_path" || ok=$?
  done
  if [ "$ok" -ne 0 ]; then
    return "$ok"
  fi
}

run_conformance_msgraph() {
  local desc="Conformance example (msgraph)"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?
  require_env_vars "$desc" MS_TENANT_ID MS_CLIENT_ID MS_CLIENT_SECRET MS_REFRESH_TOKEN_SEEDED || return $?

  RUST_LOG=info cargo run -p greentic-oauth-broker --example conformance_live -- \
    --provider msgraph \
    --checks discovery,jwks,client_credentials,signed_fetch,refresh,revocation
}

run_conformance_oidc() {
  local desc="Conformance example (oidc)"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?
  require_env_vars "$desc" OIDC_ISSUER OIDC_CLIENT_ID OIDC_CLIENT_SECRET OIDC_REFRESH_TOKEN_SEEDED OIDC_AUDIENCE || return $?

  RUST_LOG=info cargo run -p greentic-oauth-broker --example conformance_live -- \
    --provider oidc \
    --checks discovery,jwks,client_credentials,signed_fetch,refresh,revocation
}

PUBLISH_CRATES=(greentic-oauth-core greentic-oauth-broker greentic-oauth-sdk)

run_publish_dry_run() {
  local desc="cargo publish --dry-run"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?

  for crate in "${PUBLISH_CRATES[@]}"; do
    echo "Dry-running publish for ${crate}"
    cargo publish --dry-run --allow-dirty -p "$crate"
  done
}

main() {
  step "Local check configuration"
  print_env_overview

  step "Tool versions"
  run_or_skip "rustc --version" print_tool_version rustc "rustc version"
  run_or_skip "cargo --version" print_tool_version cargo "cargo version"
  run_or_skip "wasm-tools --version" print_tool_version wasm-tools "wasm-tools version"

  step "Cargo fetch"
  run_or_skip "cargo fetch --locked" run_cargo_fetch

  step "Formatting"
  run_or_skip "cargo fmt --all -- --check" run_cargo_fmt

  step "Clippy"
  run_or_skip "cargo clippy --workspace --all-targets --all-features -- -D warnings" run_cargo_clippy

  step "Workspace build"
  run_or_skip "cargo build --workspace --all-features" run_cargo_build

  step "Workspace tests"
  run_or_skip "cargo test --workspace --all-features -- --nocapture" run_cargo_test

  step "Broker release build"
  run_or_skip "cargo build -p greentic-oauth-broker --release" run_broker_release_build

  step "WIT validation"
  run_or_skip "wasm-tools wit validate" run_wit_validation

  step "Publish dry-runs"
  run_or_skip "cargo publish --dry-run (workspace crates)" run_publish_dry_run

  step "Conformance example (msgraph)"
  run_or_skip "cargo run --example conformance_live --provider msgraph" run_conformance_msgraph

  step "Conformance example (oidc)"
  run_or_skip "cargo run --example conformance_live --provider oidc" run_conformance_oidc

  echo ""
  echo "All requested checks completed."
  if [ "${#SKIPPED_STEPS[@]}" -gt 0 ]; then
    echo "Skipped:"
    for s in "${SKIPPED_STEPS[@]}"; do
      echo " - $s"
    done
  fi
}

main "$@"
