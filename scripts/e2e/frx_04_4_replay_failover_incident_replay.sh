#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mode="${1:-ci}"

"${root_dir}/scripts/run_frx_04_4_replay_failover_incident_suite.sh" "$mode"
