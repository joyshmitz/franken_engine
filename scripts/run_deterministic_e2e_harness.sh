#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine}"
artifact_root="${DETERMINISTIC_E2E_HARNESS_ARTIFACT_ROOT:-artifacts/deterministic_e2e_harness}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
scenario_id="${DETERMINISTIC_E2E_HARNESS_SCENARIO_ID:-rgc-053}"
bead_id="${DETERMINISTIC_E2E_HARNESS_BEAD_ID:-bd-1lsy.11.3}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"
trace_id="trace-deterministic-e2e-harness-${timestamp}"
decision_id="decision-deterministic-e2e-harness-${timestamp}"
policy_id="policy-deterministic-e2e-harness-v1"
component="deterministic_e2e_harness_lane"

mkdir -p "${run_dir}" "${step_logs_dir}"

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false
step_log_index=0

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for deterministic e2e harness runs" >&2
    return 127
  fi
  timeout "${rch_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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

rch_recovered_success() {
  local log_path="$1"
  if rg -q 'Remote command finished: exit=0|Finished `dev` profile|Finished `test` profile|test result: ok\.' "$log_path" \
    && ! rg -qi 'error(\[[[:alnum:]]+\])?:' "$log_path"; then
    return 0
  fi
  return 1
}

run_step() {
  local command_text="$1"
  local log_path status remote_exit_code
  shift
  commands_run+=("${command_text}")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  step_logs+=("${log_path}")
  echo "==> ${command_text}"

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    if [[ "${status}" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "${remote_exit_code}" ]]; then
        failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

run_mode() {
  local selected_mode="${1:-${mode}}"
  case "${selected_mode}" in
    check)
      run_step "cargo check -p frankenengine-engine --test e2e_harness --test e2e_harness_integration" \
        cargo check -p frankenengine-engine --test e2e_harness --test e2e_harness_integration
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test e2e_harness -- --exact scenario_matrix_emits_evidence_packs_for_baseline_differential_chaos_and_cross_arch" \
        cargo test -p frankenengine-engine --test e2e_harness -- --exact scenario_matrix_emits_evidence_packs_for_baseline_differential_chaos_and_cross_arch
      run_step "cargo test -p frankenengine-engine --test e2e_harness -- --exact advanced_scenario_matrix_selector_filters_classes_and_faults" \
        cargo test -p frankenengine-engine --test e2e_harness -- --exact advanced_scenario_matrix_selector_filters_classes_and_faults
      run_step "cargo test -p frankenengine-engine --test e2e_harness_integration -- --exact public_advanced_scenario_registry_runs_and_emits_artifact_packs" \
        cargo test -p frankenengine-engine --test e2e_harness_integration -- --exact public_advanced_scenario_registry_runs_and_emits_artifact_packs
      run_step "cargo test -p frankenengine-engine --test e2e_harness_integration -- --exact public_advanced_scenario_selector_can_filter_fault_injection" \
        cargo test -p frankenengine-engine --test e2e_harness_integration -- --exact public_advanced_scenario_selector_can_filter_fault_injection
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test e2e_harness -- -D warnings" \
        cargo clippy -p frankenengine-engine --test e2e_harness -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test e2e_harness_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test e2e_harness_integration -- -D warnings
      ;;
    ci)
      run_mode check
      run_mode test
      run_mode clippy
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      return 2
      ;;
  esac
}

resolve_error_code() {
  case "${mode}" in
    check)
      echo "FE-E2E-HARNESS-CHECK-0001"
      ;;
    test)
      echo "FE-E2E-HARNESS-TEST-0001"
      ;;
    clippy)
      echo "FE-E2E-HARNESS-CLIPPY-0001"
      ;;
    ci)
      echo "FE-E2E-HARNESS-CI-0001"
      ;;
    *)
      echo "FE-E2E-HARNESS-0001"
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json replay_command

  if [[ "${manifest_written}" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json="\"$(resolve_error_code)\""
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  replay_command="DETERMINISTIC_E2E_HARNESS_ARTIFACT_ROOT=${artifact_root} DETERMINISTIC_E2E_HARNESS_SCENARIO_ID=${scenario_id} DETERMINISTIC_E2E_HARNESS_BEAD_ID=${bead_id} ${0} ${mode}"

  {
    echo "{\"schema_version\":\"franken-engine.deterministic-e2e-harness-lane.event.v1\",\"trace_id\":\"$(parser_frontier_json_escape "${trace_id}")\",\"decision_id\":\"$(parser_frontier_json_escape "${decision_id}")\",\"policy_id\":\"$(parser_frontier_json_escape "${policy_id}")\",\"component\":\"$(parser_frontier_json_escape "${component}")\",\"event\":\"lane_completed\",\"scenario_id\":\"$(parser_frontier_json_escape "${scenario_id}")\",\"mode\":\"$(parser_frontier_json_escape "${mode}")\",\"replay_command\":\"$(parser_frontier_json_escape "${replay_command}")\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.deterministic-e2e-harness-lane.run-manifest.v1",'
    echo "  \"bead_id\": \"$(parser_frontier_json_escape "${bead_id}")\","
    echo "  \"scenario_id\": \"$(parser_frontier_json_escape "${scenario_id}")\","
    echo "  \"deterministic_env_schema_version\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_ENV_SCHEMA_VERSION}")\","
    echo "  \"component\": \"$(parser_frontier_json_escape "${component}")\","
    echo "  \"mode\": \"$(parser_frontier_json_escape "${mode}")\","
    echo "  \"toolchain\": \"$(parser_frontier_json_escape "${toolchain}")\","
    echo "  \"cargo_target_dir\": \"$(parser_frontier_json_escape "${target_dir}")\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"$(parser_frontier_json_escape "${trace_id}")\","
    echo "  \"decision_id\": \"$(parser_frontier_json_escape "${decision_id}")\","
    echo "  \"policy_id\": \"$(parser_frontier_json_escape "${policy_id}")\","
    echo "  \"generated_at_utc\": \"$(parser_frontier_json_escape "${timestamp}")\","
    echo "  \"git_commit\": \"$(parser_frontier_json_escape "${git_commit}")\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "${failed_command}" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"$(parser_frontier_json_escape "${manifest_path}")\","
    echo "    \"events\": \"$(parser_frontier_json_escape "${events_path}")\","
    echo "    \"commands\": \"$(parser_frontier_json_escape "${commands_path}")\","
    echo "    \"step_logs_dir\": \"$(parser_frontier_json_escape "${step_logs_dir}")\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat $(parser_frontier_json_escape "${manifest_path}")\","
    echo "    \"cat $(parser_frontier_json_escape "${events_path}")\","
    echo "    \"cat $(parser_frontier_json_escape "${commands_path}")\","
    echo "    \"ls -1 $(parser_frontier_json_escape "${step_logs_dir}")\","
    echo "    \"$(parser_frontier_json_escape "${replay_command}")\""
    echo "  ]"
    echo "}"
  } >"${manifest_path}"

  echo "deterministic e2e harness manifest: ${manifest_path}"
  echo "deterministic e2e harness events: ${events_path}"
  echo "deterministic e2e harness commands: ${commands_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "${main_exit}"
exit "${main_exit}"
