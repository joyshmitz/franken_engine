#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

echo "[parser-differential-nightly-governance] deterministic replay start"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_differential_nightly_governance_replay}" \
  ./scripts/run_parser_differential_nightly_governance.sh ci

latest_run_dir="$(ls -1dt artifacts/parser_differential_nightly_governance/* | head -n 1)"

echo "[parser-differential-nightly-governance] latest manifest: ${latest_run_dir}/run_manifest.json"
cat "${latest_run_dir}/run_manifest.json"
echo "[parser-differential-nightly-governance] latest events: ${latest_run_dir}/events.jsonl"
cat "${latest_run_dir}/events.jsonl"
