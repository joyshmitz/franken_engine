#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_risk_register}"
timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
run_dir="artifacts/risk_register/${timestamp}"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

mkdir -p "${run_dir}"

run_check() {
  run_rch cargo check -p frankenengine-engine --test risk_register
}

run_test() {
  run_rch cargo test -p frankenengine-engine --test risk_register
}

case "$mode" in
  check)
    run_check
    ;;
  test)
    run_test
    ;;
  ci)
    run_check
    run_test
    ;;
  *)
    echo "usage: $0 [check|test|ci]" >&2
    exit 2
    ;;
esac

manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/risk_register_events.jsonl"

cat >"${manifest_path}" <<JSON
{
  "schema_version": "franken-engine.risk-register.run-manifest.v1",
  "bead_id": "bd-21ul",
  "timestamp_utc": "${timestamp}",
  "mode": "${mode}",
  "toolchain": "${toolchain}",
  "commands": [
    "rch exec -- env RUSTUP_TOOLCHAIN=${toolchain} CARGO_TARGET_DIR=${target_dir} cargo check -p frankenengine-engine --test risk_register",
    "rch exec -- env RUSTUP_TOOLCHAIN=${toolchain} CARGO_TARGET_DIR=${target_dir} cargo test -p frankenengine-engine --test risk_register"
  ],
  "artifacts": [
    "docs/RISK_REGISTER.md",
    "crates/franken-engine/tests/risk_register.rs"
  ]
}
JSON

cat >"${events_path}" <<JSONL
{"trace_id":"trace-risk-register-${timestamp}","decision_id":"decision-risk-register-${timestamp}","policy_id":"policy-risk-register-v1","component":"risk_register_guard","event":"ci_run_completed","outcome":"pass","error_code":null}
JSONL

echo "risk register run manifest: ${manifest_path}"
echo "risk register events: ${events_path}"
