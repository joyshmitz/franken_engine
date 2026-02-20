#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-test}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_conformance}"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

case "$mode" in
  check)
    run_rch cargo check -p frankenengine-engine --test conformance_assets
    ;;
  test)
    run_rch cargo test -p frankenengine-engine --test conformance_assets
    ;;
  ci)
    run_rch cargo check -p frankenengine-engine --test conformance_assets
    run_rch cargo test -p frankenengine-engine --test conformance_assets
    ;;
  *)
    echo "usage: $0 [check|test|ci]" >&2
    exit 2
    ;;
esac
