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
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_id="trace-deterministic-e2e-harness-${timestamp}"
decision_id="decision-deterministic-e2e-harness-${timestamp}"
policy_id="policy-deterministic-e2e-harness-v1"
component="deterministic_e2e_harness_lane"

mkdir -p "${run_dir}"

declare -a commands_run=()
failed_command=""
manifest_written=false

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for deterministic e2e harness runs" >&2
    return 127
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

run_step() {
  local command_text="$1"
  shift
  commands_run+=("${command_text}")
  echo "==> ${command_text}"
  if ! run_rch "$@"; then
    failed_command="${command_text}"
    return 1
  fi
}

run_mode() {
  case "${mode}" in
    check)
      run_step "cargo check -p frankenengine-engine --tests" \
        cargo check -p frankenengine-engine --tests
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test e2e_harness" \
        cargo test -p frankenengine-engine --test e2e_harness
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test e2e_harness -- -D warnings" \
        cargo clippy -p frankenengine-engine --test e2e_harness -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --tests" \
        cargo check -p frankenengine-engine --tests
      run_step "cargo test -p frankenengine-engine --test e2e_harness" \
        cargo test -p frankenengine-engine --test e2e_harness
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

  replay_command="DETERMINISTIC_E2E_HARNESS_ARTIFACT_ROOT=${artifact_root} ${0} ${mode}"

  {
    echo "{\"schema_version\":\"franken-engine.deterministic-e2e-harness-lane.event.v1\",\"trace_id\":\"$(parser_frontier_json_escape "${trace_id}")\",\"decision_id\":\"$(parser_frontier_json_escape "${decision_id}")\",\"policy_id\":\"$(parser_frontier_json_escape "${policy_id}")\",\"component\":\"$(parser_frontier_json_escape "${component}")\",\"event\":\"lane_completed\",\"mode\":\"$(parser_frontier_json_escape "${mode}")\",\"replay_command\":\"$(parser_frontier_json_escape "${replay_command}")\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.deterministic-e2e-harness-lane.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.9.3.1",'
    echo "  \"deterministic_env_schema_version\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_ENV_SCHEMA_VERSION}")\","
    echo "  \"component\": \"$(parser_frontier_json_escape "${component}")\","
    echo "  \"mode\": \"$(parser_frontier_json_escape "${mode}")\","
    echo "  \"toolchain\": \"$(parser_frontier_json_escape "${toolchain}")\","
    echo "  \"cargo_target_dir\": \"$(parser_frontier_json_escape "${target_dir}")\","
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
    echo '  "artifacts": {'
    echo "    \"manifest\": \"$(parser_frontier_json_escape "${manifest_path}")\","
    echo "    \"events\": \"$(parser_frontier_json_escape "${events_path}")\","
    echo "    \"commands\": \"$(parser_frontier_json_escape "${commands_path}")\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat $(parser_frontier_json_escape "${manifest_path}")\","
    echo "    \"cat $(parser_frontier_json_escape "${events_path}")\","
    echo "    \"cat $(parser_frontier_json_escape "${commands_path}")\","
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
