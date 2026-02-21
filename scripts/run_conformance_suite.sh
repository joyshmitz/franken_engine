#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_conformance}"
artifact_root="${CONFORMANCE_ARTIFACT_ROOT:-artifacts/conformance_suite}"
timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/conformance_suite_events.jsonl"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

declare -a commands_run=()

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  run_rch "$@"
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test conformance_assets" \
    cargo check -p frankenengine-engine --test conformance_assets
  run_step "cargo check -p frankenengine-engine --test conformance_min_repro" \
    cargo check -p frankenengine-engine --test conformance_min_repro
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test conformance_assets" \
    cargo test -p frankenengine-engine --test conformance_assets
  run_step "cargo test -p frankenengine-engine --test conformance_min_repro" \
    cargo test -p frankenengine-engine --test conformance_min_repro
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

{
  echo "{"
  echo '  "schema_version": "franken-engine.conformance-suite.run-manifest.v1",'
  echo '  "bead_id": "bd-352c",'
  echo "  \"timestamp_utc\": \"${timestamp}\"," 
  echo "  \"mode\": \"${mode}\"," 
  echo "  \"toolchain\": \"${toolchain}\"," 
  echo "  \"cargo_target_dir\": \"${target_dir}\"," 
  echo '  "commands": ['
  for idx in "${!commands_run[@]}"; do
    comma=","
    if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
      comma=""
    fi
    echo "    \"${commands_run[$idx]}\"${comma}"
  done
  echo '  ],'
  echo '  "test_targets": ['
  echo '    "conformance_assets",'
  echo '    "conformance_min_repro"'
  echo '  ],'
  echo '  "evidence_pointers": ['
  echo "    \"${events_path}\"," 
  echo '    "<run_id>/minimized_repros/index.json",'
  echo '    "<run_id>/minimized_repros/events.jsonl"'
  echo '  ],'
  echo '  "replay_pointers": ['
  echo '    "franken-conformance replay minimized_repros/<failure_id>.json",'
  echo '    "franken-conformance replay minimized_repros/<failure_id>.json --verify"'
  echo '  ],'
  echo '  "operator_verification": ['
  echo "    \"cat ${manifest_path}\"," 
  echo "    \"cat ${events_path}\"," 
  echo "    \"$0 ci\""
  echo '  ]'
  echo "}"
} >"${manifest_path}"

cat >"${events_path}" <<JSONL
{"trace_id":"trace-conformance-suite-${timestamp}","decision_id":"decision-conformance-suite-${timestamp}","policy_id":"policy-conformance-v1","component":"conformance_suite_runner","event":"suite_completed","outcome":"pass","error_code":null,"mode":"${mode}","test_targets":["conformance_assets","conformance_min_repro"]}
JSONL

echo "conformance suite run manifest: ${manifest_path}"
echo "conformance suite events: ${events_path}"
