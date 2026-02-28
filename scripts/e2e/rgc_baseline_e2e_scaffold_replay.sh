#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
"${root_dir}/scripts/run_rgc_baseline_e2e_scaffold_gate.sh" "${mode}"
