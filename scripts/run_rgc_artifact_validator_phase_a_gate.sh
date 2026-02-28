#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_ARTIFACT_VALIDATOR_PHASE_A_ARTIFACT_ROOT:-artifacts/rgc_artifact_validator_phase_a}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_ready_attempts="${RCH_READY_ATTEMPTS:-18}"
rch_ready_sleep_seconds="${RCH_READY_SLEEP_SECONDS:-2}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/data/projects/franken_engine/target_rch_rgc_artifact_validator_phase_a"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
valid_report_path="${run_dir}/validator_report_valid.json"
invalid_report_path="${run_dir}/validator_report_invalid.json"
sample_valid_dir="${run_dir}/sample_valid"
sample_invalid_dir="${run_dir}/sample_invalid"

trace_id="trace-rgc-artifact-validator-phase-a-${timestamp}"
decision_id="decision-rgc-artifact-validator-phase-a-${timestamp}"
policy_id="policy-rgc-artifact-validator-phase-a-v1"
component="rgc_artifact_validator_phase_a_gate"
scenario_id="rgc-062a"
replay_command="./scripts/e2e/rgc_artifact_validator_phase_a_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC artifact validator phase-A heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false

ensure_rch_ready() {
  local attempts="${1:-5}"
  local sleep_seconds="${2:-2}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if rch check >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done
  return 1
}

run_step_expect_exit() {
  local command_text="$1"
  local expected_exit="$2"
  local log_path remote_exit_code
  shift 2

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"
  step_logs+=("$log_path")

  if ! ensure_rch_ready "${rch_ready_attempts}" "${rch_ready_sleep_seconds}"; then
    echo "==> warning: rch check not ready after ${rch_ready_attempts} attempts; attempting remote execution anyway" \
      | tee -a "$log_path"
  fi

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if ! rch_reject_local_fallback "$log_path"; then
      failed_command="${command_text} (rch-local-fallback-detected)"
      return 1
    fi

    if rg -q "Remote command finished: exit=${expected_exit}" "$log_path"; then
      echo "==> recovered: remote execution produced expected exit=${expected_exit}" \
        | tee -a "$log_path"
    elif rg -q 'Remote command finished: exit=0' "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "$remote_exit_code" || "$remote_exit_code" != "$expected_exit" ]]; then
    failed_command="${command_text} (remote-exit=${remote_exit_code:-missing}, expected=${expected_exit})"
    return 1
  fi
}

run_step() {
  local command_text="$1"
  shift
  run_step_expect_exit "$command_text" 0 "$@"
}

prepare_sample_triads() {
  mkdir -p "$sample_valid_dir" "$sample_invalid_dir"

  cat >"${sample_valid_dir}/run_manifest.json" <<'JSON'
{
  "schema_version": "franken-engine.rgc-test-harness.run-manifest.v1",
  "run_id": "run-rgc-062a-valid",
  "scenario_id": "rgc-062a-sample-valid",
  "fixture_id": "fixture-valid",
  "seed": 6201,
  "trace_id": "trace-rgc-062a-valid",
  "decision_id": "decision-rgc-062a-valid",
  "policy_id": "policy-rgc-062a-v1",
  "event_count": 1,
  "command_count": 1,
  "env_fingerprint": "env-rgc-062a-valid",
  "replay_command": "./scripts/e2e/rgc_artifact_validator_phase_a_replay.sh ci"
}
JSON

  cat >"${sample_valid_dir}/events.jsonl" <<'JSON'
{"schema_version":"franken-engine.rgc-test-event.v1","scenario_id":"rgc-062a-sample-valid","fixture_id":"fixture-valid","trace_id":"trace-rgc-062a-valid","decision_id":"decision-rgc-062a-valid","policy_id":"policy-rgc-062a-v1","lane":"e2e","component":"rgc_artifact_validator_phase_a_gate","event":"sample_validated","outcome":"pass","error_code":null,"seed":6201,"sequence":0,"timing_us":10,"timestamp_unix_ms":1700100000000}
JSON

  cat >"${sample_valid_dir}/commands.txt" <<'EOF'
./scripts/run_rgc_artifact_validator_phase_a_gate.sh ci
EOF

  cat >"${sample_invalid_dir}/run_manifest.json" <<'JSON'
{
  "schema_version": "wrong.schema",
  "run_id": "",
  "trace_id": "",
  "decision_id": "",
  "policy_id": "",
  "seed": "not-a-number",
  "event_count": 2,
  "command_count": 1
}
JSON

  cat >"${sample_invalid_dir}/events.jsonl" <<'JSON'
{not-json}
JSON

  # Intentionally empty command transcript to assert fail-closed findings.
  cat >"${sample_invalid_dir}/commands.txt" <<'EOF'

EOF
}

validate_reports_locally() {
  commands_run+=("jq -e '.valid == true and (.findings | length == 0)' ${valid_report_path}")
  jq -e '.valid == true and (.findings | length == 0)' "${valid_report_path}" >/dev/null

  commands_run+=("jq -e '.valid == false and (.findings | length > 0)' ${invalid_report_path}")
  jq -e '.valid == false and (.findings | length > 0)' "${invalid_report_path}" >/dev/null
}

run_mode() {
  local selected_mode="${1:-$mode}"
  case "$selected_mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin rgc_artifact_validator --lib --test rgc_test_harness_integration" \
        cargo check -p frankenengine-engine --bin rgc_artifact_validator --lib --test rgc_test_harness_integration \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_accepts_valid_harness_triad" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_accepts_valid_harness_triad \
        || return $?
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_reports_missing_and_malformed_artifacts" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_reports_missing_and_malformed_artifacts \
        || return $?
      run_step "cargo test -p frankenengine-engine --test rgc_test_harness_integration -- --exact rgc_baseline_registry_selection_and_validator_cover_representative_lanes" \
        cargo test -p frankenengine-engine --test rgc_test_harness_integration -- --exact rgc_baseline_registry_selection_and_validator_cover_representative_lanes \
        || return $?

      prepare_sample_triads

      run_step "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --run-dir ${sample_valid_dir} --out ${valid_report_path} --pretty" \
        cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --run-dir "${sample_valid_dir}" --out "${valid_report_path}" --pretty \
        || return $?

      run_step_expect_exit \
        "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --run-dir ${sample_invalid_dir} --out ${invalid_report_path} --pretty (expect exit 2)" \
        2 \
        cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --run-dir "${sample_invalid_dir}" --out "${invalid_report_path}" --pretty \
        || return $?

      validate_reports_locally || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin rgc_artifact_validator -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin rgc_artifact_validator -- -D warnings \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --test rgc_test_harness_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_test_harness_integration -- -D warnings \
        || return $?
      ;;
    ci)
      run_mode check || return $?
      run_mode test || return $?
      run_mode clippy || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-062A-ARTIFACT-VALIDATOR-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-artifact-validator-phase-a.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo '{'
    echo '  "schema_version": "franken-engine.rgc-artifact-validator-phase-a.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.12.1",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields '    ' 'null'
    echo '  },'
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"valid_report\": \"${valid_report_path}\","
    echo "    \"invalid_report\": \"${invalid_report_path}\","
    echo "    \"rch_logs_dir\": \"${run_dir}\","
    echo '    "gate_script": "scripts/run_rgc_artifact_validator_phase_a_gate.sh",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_artifact_validator_phase_a_replay.sh",'
    echo '    "validator_bin": "crates/franken-engine/src/bin/rgc_artifact_validator.rs",'
    echo '    "validator_module": "crates/franken-engine/src/rgc_test_harness.rs",'
    echo '    "integration_tests": "crates/franken-engine/tests/rgc_test_harness_integration.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${valid_report_path}\","
    echo "    \"cat ${invalid_report_path}\","
    echo "    \"ls -1 ${run_dir}/rch-log.*\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo '  ,'
    echo '  "rch_step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ]'
    echo '}'
  } >"$manifest_path"

  echo "rgc artifact validator phase-a manifest: ${manifest_path}"
  echo "rgc artifact validator phase-a events: ${events_path}"
  echo "rgc artifact validator phase-a commands: ${commands_path}"
  echo "rgc artifact validator phase-a valid report: ${valid_report_path}"
  echo "rgc artifact validator phase-a invalid report: ${invalid_report_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
