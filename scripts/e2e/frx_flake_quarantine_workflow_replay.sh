#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-test}"

"${root_dir}/scripts/run_frx_flake_quarantine_workflow_suite.sh" "${mode}"
