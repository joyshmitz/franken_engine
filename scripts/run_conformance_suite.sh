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
commands_path="${run_dir}/commands.txt"
logs_dir="${run_dir}/logs"

trace_id="trace-conformance-suite-${timestamp}"
decision_id="decision-conformance-suite-${timestamp}"
policy_id="policy-conformance-v1"

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
  run_step "cargo check -p frankenengine-engine --test conformance_assets" \
    run_rch cargo check -p frankenengine-engine --test conformance_assets
  run_step "cargo check -p frankenengine-engine --test conformance_min_repro" \
    run_rch cargo check -p frankenengine-engine --test conformance_min_repro
  run_step "cargo check -p frankenengine-engine --test ifc_conformance_corpus" \
    run_rch cargo check -p frankenengine-engine --test ifc_conformance_corpus
  run_step "cargo check -p frankenengine-engine --bin franken_ifc_conformance_runner" \
    run_rch cargo check -p frankenengine-engine --bin franken_ifc_conformance_runner
  run_step "cargo check -p frankenengine-engine --lib conformance_vector_gen::tests::" \
    run_rch cargo check -p frankenengine-engine --lib
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test conformance_assets" \
    run_rch cargo test -p frankenengine-engine --test conformance_assets
  run_step "cargo test -p frankenengine-engine --test conformance_min_repro" \
    run_rch cargo test -p frankenengine-engine --test conformance_min_repro
  run_step "cargo test -p frankenengine-engine --test ifc_conformance_corpus" \
    run_rch cargo test -p frankenengine-engine --test ifc_conformance_corpus
  run_step "cargo run -p frankenengine-engine --bin franken_ifc_conformance_runner -- --manifest crates/franken-engine/tests/conformance/ifc_corpus/ifc_conformance_assets.json --output-root artifacts/ifc_conformance_suite" \
    run_rch cargo run -p frankenengine-engine --bin franken_ifc_conformance_runner -- --manifest crates/franken-engine/tests/conformance/ifc_corpus/ifc_conformance_assets.json --output-root artifacts/ifc_conformance_suite
  run_step "cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::generate_vectors_produces_all_categories" \
    run_rch cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::generate_vectors_produces_all_categories
  run_step "cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::degraded_vectors_have_scenario" \
    run_rch cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::degraded_vectors_have_scenario
  run_step "cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::fault_vectors_have_scenario" \
    run_rch cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::fault_vectors_have_scenario
  run_step "cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::fault_vectors_expect_failure" \
    run_rch cargo test -p frankenengine-engine --lib conformance_vector_gen::tests::fault_vectors_expect_failure
}

run_mode() {
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
      return 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code idx comma
  local failed_log_json="null"

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code="null"
  else
    outcome="fail"
    error_code='"FE-CONFORMANCE-LAB-0001"'
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  fi

  cat >"$events_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"conformance_suite_runner","event":"suite_completed","outcome":"${outcome}","error_code":${error_code},"mode":"${mode}"}
JSONL

  {
    echo "{"
    echo '  "schema_version": "franken-engine.conformance-suite.run-manifest.v2",'
    echo '  "bead_id": "bd-1999",'
    echo "  \"timestamp_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"mode\": \"$(json_escape "$mode")\","
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\","
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\","
    echo "  \"trace_id\": \"$(json_escape "$trace_id")\","
    echo "  \"decision_id\": \"$(json_escape "$decision_id")\","
    echo "  \"policy_id\": \"$(json_escape "$policy_id")\","
    echo "  \"outcome\": \"$(json_escape "$outcome")\","
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
  echo '  "test_targets": ['
  echo '    "conformance_assets",'
  echo '    "conformance_min_repro",'
  echo '    "ifc_conformance_corpus",'
  echo '    "franken_ifc_conformance_runner",'
  echo '    "conformance_vector_gen::tests::generate_vectors_produces_all_categories",'
    echo '    "conformance_vector_gen::tests::degraded_vectors_have_scenario",'
    echo '    "conformance_vector_gen::tests::fault_vectors_have_scenario",'
    echo '    "conformance_vector_gen::tests::fault_vectors_expect_failure"'
    echo '  ],'
    echo '  "evidence_pointers": ['
    echo "    \"$(json_escape "$events_path")\","
    echo '    "<run_id>/minimized_repros/index.json",'
    echo '    "<run_id>/minimized_repros/events.jsonl"'
    echo '  ],'
    echo '  "replay_pointers": ['
    echo '    "franken-conformance replay minimized_repros/<failure_id>.json",'
    echo '    "franken-conformance replay minimized_repros/<failure_id>.json --verify"'
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat $(json_escape "$manifest_path")\","
    echo "    \"cat $(json_escape "$events_path")\","
    echo "    \"cat $(json_escape "$commands_path")\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"
}

set +e
run_mode
exit_code=$?
set -e

write_manifest "$exit_code"

echo "conformance suite run manifest: ${manifest_path}"
echo "conformance suite events: ${events_path}"

exit "$exit_code"
