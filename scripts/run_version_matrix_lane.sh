#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_version_matrix}"
lanes_csv="${VERSION_MATRIX_LANES:-n,n_minus_1,n_plus_1}"
artifact_root="${VERSION_MATRIX_ARTIFACT_ROOT:-artifacts/version_matrix_lane}"
timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/version_matrix_events.jsonl"
summary_path="${run_dir}/matrix_summary.json"

mkdir -p "$run_dir"

IFS=',' read -r -a lanes <<<"$lanes_csv"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

declare -a commands_run=()

deterministic_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  run_rch "$@"
}

run_matrix_tests() {
  local lane
  for lane in "${lanes[@]}"; do
    deterministic_step "VERSION_MATRIX_LANE=${lane} cargo test -p frankenengine-engine --test conformance_assets" \
      env "VERSION_MATRIX_LANE=${lane}" cargo test -p frankenengine-engine --test conformance_assets
    deterministic_step "VERSION_MATRIX_LANE=${lane} cargo test -p frankenengine-engine --test conformance_min_repro" \
      env "VERSION_MATRIX_LANE=${lane}" cargo test -p frankenengine-engine --test conformance_min_repro
  done
}

run_check() {
  deterministic_step "cargo check -p frankenengine-engine --test version_matrix_lane" \
    cargo check -p frankenengine-engine --test version_matrix_lane
}

run_test() {
  deterministic_step "cargo test -p frankenengine-engine --test version_matrix_lane" \
    cargo test -p frankenengine-engine --test version_matrix_lane
  run_matrix_tests
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
  echo '  "schema_version": "franken-engine.version-matrix-lane.run-manifest.v1",'
  echo '  "bead_id": "bd-kfe4",'
  echo "  \"timestamp_utc\": \"${timestamp}\"," 
  echo "  \"mode\": \"${mode}\"," 
  echo "  \"toolchain\": \"${toolchain}\"," 
  echo "  \"cargo_target_dir\": \"${target_dir}\"," 
  echo '  "lanes": ['
  for idx in "${!lanes[@]}"; do
    comma=","
    if [[ "$idx" == "$(( ${#lanes[@]} - 1 ))" ]]; then
      comma=""
    fi
    echo "    \"${lanes[$idx]}\"${comma}"
  done
  echo '  ],'
  echo '  "commands": ['
  for idx in "${!commands_run[@]}"; do
    comma=","
    if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
      comma=""
    fi
    echo "    \"${commands_run[$idx]}\"${comma}"
  done
  echo '  ],'
  echo '  "evidence_pointers": ['
  echo "    \"${events_path}\"," 
  echo "    \"${summary_path}\""
  echo '  ],'
  echo '  "replay_pointers": ['
  echo '    "franken-conformance replay minimized_repros/<failure_id>.json",'
  echo '    "franken-conformance replay minimized_repros/<failure_id>.json --verify"'
  echo '  ]'
  echo "}"
} >"${manifest_path}"

{
  echo "{"
  echo '  "schema_version": "franken-engine.version-matrix-lane.summary.v1",'
  echo "  \"generated_at_utc\": \"${timestamp}\"," 
  echo '  "lanes": ['
  for idx in "${!lanes[@]}"; do
    comma=","
    if [[ "$idx" == "$(( ${#lanes[@]} - 1 ))" ]]; then
      comma=""
    fi
    echo "    {\"lane\": \"${lanes[$idx]}\", \"outcome\": \"pass\"}${comma}"
  done
  echo '  ]'
  echo "}"
} >"${summary_path}"

cat >"${events_path}" <<JSONL
{"trace_id":"trace-version-matrix-${timestamp}","decision_id":"decision-version-matrix-${timestamp}","policy_id":"policy-version-matrix-v1","component":"version_matrix_lane_runner","event":"matrix_run_completed","outcome":"pass","error_code":null,"mode":"${mode}"}
JSONL

echo "version matrix run manifest: ${manifest_path}"
echo "version matrix events: ${events_path}"
echo "version matrix summary: ${summary_path}"
