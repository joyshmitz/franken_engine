#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
scenario="${PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO:-full}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_error_recovery_adversarial_e2e}"
artifact_root="${PARSER_ERROR_RECOVERY_ADVERSARIAL_ARTIFACT_ROOT:-artifacts/parser_error_recovery_adversarial_e2e}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"

case "${scenario}" in
  adversarial|resync|replay|full)
    ;;
  *)
    echo "unsupported PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO: ${scenario}" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-parser-error-recovery-adversarial-e2e-${scenario}-${timestamp}"
decision_id="decision-parser-error-recovery-adversarial-e2e-${scenario}-${timestamp}"
policy_id="policy-parser-error-recovery-adversarial-e2e-v1"
component="parser_error_recovery_adversarial_e2e_gate"
replay_command="PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO=${scenario} ${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser error recovery adversarial e2e heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'falling back to local|fallback to local|local fallback' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  rm -f "$log_path"
}

run_test_scenario() {
  case "${scenario}" in
    adversarial)
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_e2e_cases_are_deterministic_and_success_rate_bounded" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_e2e_cases_are_deterministic_and_success_rate_bounded
      ;;
    resync)
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_resync_guards_prevent_silent_semantic_corruption" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_resync_guards_prevent_silent_semantic_corruption
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_primitives_respect_resync_edit_bounds" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_primitives_respect_resync_edit_bounds
      ;;
    replay)
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_logs_are_structured_and_replayable" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_logs_are_structured_and_replayable
      ;;
    full)
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_e2e_cases_are_deterministic_and_success_rate_bounded" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_e2e_cases_are_deterministic_and_success_rate_bounded
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_resync_guards_prevent_silent_semantic_corruption" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_resync_guards_prevent_silent_semantic_corruption
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_logs_are_structured_and_replayable" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_logs_are_structured_and_replayable
      run_step \
        "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_primitives_respect_resync_edit_bounds" \
        cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_primitives_respect_resync_edit_bounds
      ;;
  esac

  run_step \
    "cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_e2e_contract_doc_and_fixture_are_well_formed" \
    cargo test -p frankenengine-engine --test parser_error_recovery_integration -- --exact parser_error_recovery_adversarial_e2e_contract_doc_and_fixture_are_well_formed
}

run_mode() {
  case "${mode}" in
    check)
      run_step "cargo check -p frankenengine-engine --test parser_error_recovery_integration" \
        cargo check -p frankenengine-engine --test parser_error_recovery_integration
      ;;
    test)
      run_test_scenario
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_error_recovery_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_error_recovery_integration -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_error_recovery_integration" \
        cargo check -p frankenengine-engine --test parser_error_recovery_integration
      run_test_scenario
      run_step "cargo clippy -p frankenengine-engine --test parser_error_recovery_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_error_recovery_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

resolve_error_code() {
  case "${scenario}" in
    adversarial)
      echo "FE-PARSER-ERROR-RECOVERY-ADVERSARIAL-0001"
      ;;
    resync)
      echo "FE-PARSER-ERROR-RECOVERY-RESYNC-0001"
      ;;
    replay)
      echo "FE-PARSER-ERROR-RECOVERY-REPLAY-0001"
      ;;
    full)
      echo "FE-PARSER-ERROR-RECOVERY-FULL-0001"
      ;;
    *)
      echo "FE-PARSER-ERROR-RECOVERY-0001"
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

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

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-error-recovery-adversarial-e2e.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario\":\"${scenario}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-error-recovery-adversarial-e2e.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.10.2",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"scenario\": \"${scenario}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
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
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo '    "contract_doc": "docs/PARSER_ERROR_RECOVERY_RESYNC_ADVERSARIAL_E2E.md",'
    echo '    "gate_fixture": "crates/franken-engine/tests/fixtures/parser_error_recovery_adversarial_e2e_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/parser_error_recovery_integration.rs",'
    echo '    "replay_wrapper": "scripts/e2e/parser_error_recovery_adversarial_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser error recovery adversarial e2e manifest: ${manifest_path}"
  echo "parser error recovery adversarial e2e events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
