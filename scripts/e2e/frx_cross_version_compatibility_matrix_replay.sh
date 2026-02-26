#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-replay}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_frx_cross_version_compatibility_matrix}" \
  "${root_dir}/scripts/run_frx_cross_version_compatibility_matrix_suite.sh" "$mode"
