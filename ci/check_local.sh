#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
cd "$ROOT"

ONLINE="${LOCAL_CHECK_ONLINE:-1}"
STRICT="${LOCAL_CHECK_STRICT:-0}"
VERBOSE="${LOCAL_CHECK_VERBOSE:-0}"

if [ "$VERBOSE" = "1" ]; then
  set -x
fi

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_RETRY="${CARGO_NET_RETRY:-5}"
export CARGO_HTTP_TIMEOUT="${CARGO_HTTP_TIMEOUT:-120}"
export RUSTFLAGS=""

TOOLCHAIN_FILE="$ROOT/rust-toolchain.toml"
TOOLCHAIN_CHANNEL=""
if [ -f "$TOOLCHAIN_FILE" ]; then
  TOOLCHAIN_CHANNEL="$(awk -F '"' '/^channel/ {print $2}' "$TOOLCHAIN_FILE" 2>/dev/null || true)"
fi

REQUIRED_COMPONENTS=(rustfmt clippy)
REQUIRED_TARGETS=(wasm32-wasip2 x86_64-unknown-linux-gnu)
SCHEMA_LOCAL_PATH="${SCHEMA_LOCAL_PATH:-static/schemas/provider-descriptor.schema.json}"
SCHEMA_REMOTE_URL="${SCHEMA_REMOTE_URL:-https://raw.githubusercontent.com/greentic/greentic-oauth/main/static/schemas/provider-descriptor.schema.json}"

SKIP_EXIT=99
SKIPPED_STEPS=()

need() {
  command -v "$1" >/dev/null 2>&1 || return 1
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

print_env_overview() {
  echo "LOCAL_CHECK_ONLINE=${ONLINE}"
  echo "LOCAL_CHECK_STRICT=${STRICT}"
  echo "LOCAL_CHECK_VERBOSE=${VERBOSE}"
  echo "CARGO_TERM_COLOR=${CARGO_TERM_COLOR}"
  echo "CARGO_NET_RETRY=${CARGO_NET_RETRY}"
  echo "CARGO_HTTP_TIMEOUT=${CARGO_HTTP_TIMEOUT}"
}

print_tool_version() {
  local tool="$1"
  local desc="$2"
  require_tool "$tool" "$desc" || return $?
  "$tool" --version
}

ensure_toolchain() {
  require_tool "rustup" "rustup toolchain" || return $?
  local active_channel
  active_channel=$(rustup show active-toolchain 2>/dev/null | head -n1 | awk '{print $1}')
  if [ -n "$TOOLCHAIN_CHANNEL" ] && [ -n "$active_channel" ] && [[ "$active_channel" != ${TOOLCHAIN_CHANNEL}-* ]]; then
    echo "[warn] Active toolchain $active_channel does not match $TOOLCHAIN_CHANNEL" >&2
    if [ "$STRICT" = "1" ]; then
      return 1
    fi
  fi
  ensure_rust_components || return $?
  ensure_rust_targets || return $?
}

ensure_rust_components() {
  require_tool "rustup" "rustup components" || return $?
  local missing=()
  local installed
  installed=$(rustup component list 2>/dev/null)
  for component in "${REQUIRED_COMPONENTS[@]}"; do
    if ! grep -q "^${component}[[:alnum:]-]* *(installed)" <<<"$installed"; then
      missing+=("$component")
    fi
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    return 0
  fi
  if [ "$ONLINE" != "1" ]; then
    echo "[info] Missing components: ${missing[*]} (offline mode)" >&2
    if [ "$STRICT" = "1" ]; then
      return 1
    fi
    return "$SKIP_EXIT"
  fi
  rustup component add "${missing[@]}"
}

ensure_rust_targets() {
  require_tool "rustup" "rustup targets" || return $?
  local missing=()
  local installed
  installed=$(rustup target list --installed 2>/dev/null)
  for target in "${REQUIRED_TARGETS[@]}"; do
    if ! grep -q "^${target}$" <<<"$installed"; then
      missing+=("$target")
    fi
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    return 0
  fi
  if [ "$ONLINE" != "1" ]; then
    echo "[info] Missing targets: ${missing[*]} (offline mode)" >&2
    if [ "$STRICT" = "1" ]; then
      return 1
    fi
    return "$SKIP_EXIT"
  fi
  rustup target add "${missing[@]}"
}

run_cargo_fetch() {
  local desc="cargo fetch --locked"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?
  cargo fetch --locked
}

run_cargo_fmt() {
  require_tool "cargo" "cargo fmt" || return $?
  cargo fmt --all -- --check
}

run_cargo_clippy() {
  require_tool "cargo" "cargo clippy" || return $?
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
}

run_cargo_build() {
  require_tool "cargo" "cargo build" || return $?
  cargo build --workspace --all-features --locked
}

run_cargo_test() {
  require_tool "cargo" "cargo test" || return $?
  cargo test --workspace --all-features --locked -- --nocapture
}

run_broker_release_build() {
  require_tool "cargo" "cargo build -p greentic-oauth-broker --release" || return $?
  cargo build -p greentic-oauth-broker --release --locked
}

run_wasm_build() {
  local desc="cargo build (wasm32-wasip2)"
  require_tool "cargo" "$desc" || return $?
  ensure_rust_targets || return $?
  cargo build -p greentic-oauth-sdk --target wasm32-wasip2 --locked
}

run_wit_validation() {
  local desc="wasm-tools component wit validate"
  if [ ! -d "$ROOT" ]; then
    return "$SKIP_EXIT"
  fi
  local wit_files
  mapfile -t wit_files < <(find "$ROOT" -type f -name '*.wit' -print | sort)
  if [ "${#wit_files[@]}" -eq 0 ]; then
    echo "[info] No WIT files detected."
    return "$SKIP_EXIT"
  fi
  require_tool "wasm-tools" "$desc" || return $?
  if ! wasm-tools component wit --help >/dev/null 2>&1; then
    echo "[info] Installed wasm-tools does not expose 'component wit'; please upgrade wasm-tools."
    if [ "$STRICT" = "1" ]; then
      return 1
    fi
    return "$SKIP_EXIT"
  fi
  local rc=0
  for wit in "${wit_files[@]}"; do
    echo "Validating ${wit}"
    wasm-tools component wit validate "$wit" || rc=$?
  done
  if [ "$rc" -ne 0 ]; then
    return "$rc"
  fi
}

run_schema_drift_check() {
  local desc="schema drift check"
  if [ ! -f "$SCHEMA_LOCAL_PATH" ]; then
    echo "[info] No local schema detected at $SCHEMA_LOCAL_PATH"
    return "$SKIP_EXIT"
  fi
  require_tool "curl" "$desc" || return $?
  require_tool "jq" "$desc" || return $?
  require_online "$desc" || return $?

  local tmp_remote tmp_local
  tmp_remote=$(mktemp)
  tmp_local=$(mktemp)
  trap 'rm -f "${tmp_remote:-}" "${tmp_local:-}"; trap - RETURN' RETURN

  jq -S '.' "$SCHEMA_LOCAL_PATH" >"$tmp_local"
  if ! curl -fsSL "$SCHEMA_REMOTE_URL" | jq -S '.' >"$tmp_remote"; then
    echo "[err] Failed to download remote schema from $SCHEMA_REMOTE_URL" >&2
    if [ "$STRICT" = "1" ]; then
      return 1
    fi
    return "$SKIP_EXIT"
  fi

  if ! diff -u "$tmp_remote" "$tmp_local" >/dev/null; then
    echo "[err] Schema drift detected between local and remote reference" >&2
    diff -u "$tmp_remote" "$tmp_local" || true
    return 1
  fi
}

run_publish_dry_run() {
  local desc="cargo publish --dry-run"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?

  local crates=(greentic-oauth-core greentic-oauth-broker greentic-oauth-sdk)
  for crate in "${crates[@]}"; do
    echo "Dry-running publish for ${crate}"
    cargo publish --dry-run --allow-dirty --locked -p "$crate"
  done
}

run_conformance_msgraph() {
  local desc="conformance example (msgraph)"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?
  require_env_vars "$desc" MS_TENANT_ID MS_CLIENT_ID MS_CLIENT_SECRET MS_REFRESH_TOKEN_SEEDED || return $?
  RUST_LOG=info cargo run --locked -p greentic-oauth-broker --example conformance_live -- \
    --provider msgraph \
    --checks discovery,jwks,client_credentials,signed_fetch,refresh,revocation
}

run_conformance_oidc() {
  local desc="conformance example (oidc)"
  require_tool "cargo" "$desc" || return $?
  require_online "$desc" || return $?
  require_env_vars "$desc" OIDC_ISSUER OIDC_CLIENT_ID OIDC_CLIENT_SECRET OIDC_REFRESH_TOKEN_SEEDED OIDC_AUDIENCE || return $?
  RUST_LOG=info cargo run --locked -p greentic-oauth-broker --example conformance_live -- \
    --provider oidc \
    --checks discovery,jwks,client_credentials,signed_fetch,refresh,revocation
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

main() {
  step "Local check configuration"
  print_env_overview

  step "Toolchain sanity"
  run_or_skip "rustup components/targets" ensure_toolchain

  step "Tool versions"
  run_or_skip "rustc --version" print_tool_version rustc "rustc version"
  run_or_skip "cargo --version" print_tool_version cargo "cargo version"
  run_or_skip "wasm-tools --version" print_tool_version wasm-tools "wasm-tools version"

  step "Cargo fetch"
  run_or_skip "cargo fetch --locked" run_cargo_fetch

  step "Formatting"
  run_or_skip "cargo fmt --all -- --check" run_cargo_fmt

  step "Clippy"
  run_or_skip "cargo clippy --workspace --all-targets --all-features --locked" run_cargo_clippy

  step "Workspace build"
  run_or_skip "cargo build --workspace --all-features --locked" run_cargo_build

  step "Workspace tests"
  run_or_skip "cargo test --workspace --all-features --locked" run_cargo_test

  step "Broker release build"
  run_or_skip "cargo build -p greentic-oauth-broker --release --locked" run_broker_release_build

  step "wasm32-wasip2 build"
  run_or_skip "cargo build -p greentic-oauth-sdk --target wasm32-wasip2 --locked" run_wasm_build

  step "WIT validation"
  run_or_skip "wasm-tools wit validate" run_wit_validation

  step "Schema drift"
  run_or_skip "schema drift check" run_schema_drift_check

  step "Publish dry-runs"
  run_or_skip "cargo publish --dry-run" run_publish_dry_run

  step "Conformance example (msgraph)"
  run_or_skip "cargo run conformance msgraph" run_conformance_msgraph

  step "Conformance example (oidc)"
  run_or_skip "cargo run conformance oidc" run_conformance_oidc

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
