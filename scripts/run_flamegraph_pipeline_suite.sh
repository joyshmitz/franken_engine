#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_flamegraph_pipeline}"
artifact_root="${FLAMEGRAPH_PIPELINE_ARTIFACT_ROOT:-artifacts/flamegraph_pipeline}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/flamegraph_pipeline_events.jsonl"
commands_path="${run_dir}/commands.txt"
logs_dir="${run_dir}/logs"

trace_id="trace-flamegraph-pipeline-suite-${timestamp}"
decision_id="decision-flamegraph-pipeline-suite-${timestamp}"
policy_id="policy-flamegraph-pipeline-suite-v1"
component="flamegraph_pipeline_suite"

mkdir -p "$logs_dir"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

json_escape() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//$'\n'/\\n}"
  printf '%s' "$input"
}

declare -a commands_run=()
declare -a command_logs=()
failed_command=""
failed_log_path=""
final_outcome="pass"

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"
  if "$@" > >(tee "$log_path") 2>&1; then
    return 0
  fi
  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test flamegraph_pipeline" \
    run_rch cargo check -p frankenengine-engine --test flamegraph_pipeline
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test flamegraph_pipeline" \
    run_rch cargo test -p frankenengine-engine --test flamegraph_pipeline
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test flamegraph_pipeline -- -D warnings" \
    run_rch cargo clippy -p frankenengine-engine --test flamegraph_pipeline -- -D warnings
}

run_mode() {
  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    clippy)
      run_clippy
      ;;
    ci)
      run_check
      run_test
      run_clippy
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      return 2
      ;;
  esac
}

write_outputs() {
  local exit_code="${1:-0}"
  local idx comma
  local error_code_json failed_log_json

  if [[ "$exit_code" -eq 0 ]]; then
    final_outcome="pass"
    error_code_json='null'
  else
    final_outcome="fail"
    error_code_json='"FE-FLAME-SUITE-0001"'
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  else
    failed_log_json='null'
  fi

  cat >"$events_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"suite_completed","outcome":"${final_outcome}","error_code":${error_code_json}}
JSONL

  {
    echo "{"
    echo '  "schema_version": "franken-engine.flamegraph-pipeline-suite.run-manifest.v1",'
    echo '  "bead_id": "bd-1nn",'
    echo "  \"timestamp_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"mode\": \"$(json_escape "$mode")\","
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\","
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\","
    echo "  \"trace_id\": \"$(json_escape "$trace_id")\","
    echo "  \"decision_id\": \"$(json_escape "$decision_id")\","
    echo "  \"policy_id\": \"$(json_escape "$policy_id")\","
    echo "  \"component\": \"$(json_escape "$component")\","
    echo "  \"outcome\": \"$(json_escape "$final_outcome")\","
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"failed_log\": ${failed_log_json},"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "command_logs": ['
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${command_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"$(json_escape "$manifest_path")\","
    echo "    \"events\": \"$(json_escape "$events_path")\","
    echo "    \"commands\": \"$(json_escape "$commands_path")\","
    echo '    "module": "crates/franken-engine/src/flamegraph_pipeline.rs",'
    echo '    "tests": "crates/franken-engine/tests/flamegraph_pipeline.rs",'
    echo '    "suite_script": "scripts/run_flamegraph_pipeline_suite.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat $(json_escape "$manifest_path")\","
    echo "    \"cat $(json_escape "$events_path")\","
    echo "    \"cat $(json_escape "$commands_path")\","
    echo "    \"${0} ci\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "flamegraph pipeline run manifest: ${manifest_path}"
  echo "flamegraph pipeline events: ${events_path}"
}

set +e
run_mode
run_exit_code=$?
set -e

write_outputs "$run_exit_code"
exit "$run_exit_code"

