#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

echo "[frx-lockstep-oracle] deterministic replay start"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_frx_lockstep_oracle_replay}" \
  ./scripts/run_frx_lockstep_oracle_suite.sh ci

latest_run_dir="$(ls -1dt artifacts/frx_lockstep_oracle/* | head -n 1)"

echo "[frx-lockstep-oracle] latest manifest: ${latest_run_dir}/run_manifest.json"
echo "[frx-lockstep-oracle] latest events: ${latest_run_dir}/events.jsonl"
echo "[frx-lockstep-oracle] latest report: ${latest_run_dir}/oracle_report.json"
