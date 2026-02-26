#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_semantic_twin_state_space}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for semantic twin gate commands" >&2
  exit 2
fi

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'falling back to local|fallback to local|local fallback' "$log_path"; then
    echo "rch reported local fallback; refusing local execution" >&2
    return 1
  fi
}

run_step() {
  local command_text="$1"
  local log_path
  shift
  echo "==> $command_text"
  log_path="$(mktemp)"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    rm -f "$log_path"
    return 1
  fi
  if ! reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    return 1
  fi
  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test semantic_twin_state_space" \
        cargo check -p frankenengine-engine --test semantic_twin_state_space
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test semantic_twin_state_space" \
        cargo test -p frankenengine-engine --test semantic_twin_state_space
      run_step "cargo test -p frankenengine-engine semantic_twin" \
        cargo test -p frankenengine-engine semantic_twin
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test semantic_twin_state_space -- -D warnings" \
        cargo clippy -p frankenengine-engine --test semantic_twin_state_space -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test semantic_twin_state_space" \
        cargo check -p frankenengine-engine --test semantic_twin_state_space
      run_step "cargo test -p frankenengine-engine --test semantic_twin_state_space" \
        cargo test -p frankenengine-engine --test semantic_twin_state_space
      run_step "cargo test -p frankenengine-engine semantic_twin" \
        cargo test -p frankenengine-engine semantic_twin
      run_step "cargo clippy -p frankenengine-engine --test semantic_twin_state_space -- -D warnings" \
        cargo clippy -p frankenengine-engine --test semantic_twin_state_space -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

run_mode
