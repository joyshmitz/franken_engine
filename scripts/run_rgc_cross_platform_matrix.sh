#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

"${root_dir}/scripts/run_rgc_cross_platform_matrix_gate.sh" "$@"
