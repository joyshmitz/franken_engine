#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_sqlite_policy_guard}"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

case "$mode" in
  check)
    run_rch cargo check -p frankenengine-engine --test sqlite_policy_guard
    ;;
  test)
    run_rch cargo test -p frankenengine-engine --test sqlite_policy_guard
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --test sqlite_policy_guard
    run_rch cargo test -p frankenengine-engine --test sqlite_policy_guard
    ;;
  *)
    echo "usage: $0 [check|test|ci]" >&2
    exit 2
    ;;
esac
