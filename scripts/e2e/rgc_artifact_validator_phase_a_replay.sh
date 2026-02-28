#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
"${root_dir}/scripts/run_rgc_artifact_validator_phase_a_gate.sh" "${mode}"
