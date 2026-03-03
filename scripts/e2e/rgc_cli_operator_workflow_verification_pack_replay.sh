#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-ci}"

"${root_dir}/scripts/run_rgc_cli_operator_workflow_verification_pack.sh" "${mode}"
