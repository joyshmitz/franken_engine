#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_operator_developer_runbook}"
artifact_root="${PARSER_OPERATOR_DEVELOPER_RUNBOOK_ARTIFACT_ROOT:-artifacts/parser_operator_developer_runbook}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-parser-operator-developer-runbook-${timestamp}"
decision_id="decision-parser-operator-developer-runbook-${timestamp}"
policy_id="policy-parser-operator-developer-runbook-v1"
component="parser_operator_developer_runbook_gate"
replay_command="./scripts/e2e/parser_operator_developer_runbook_replay.sh ${mode}"

drill_replay_a="./scripts/e2e/parser_error_recovery_adversarial_replay.sh"
drill_replay_b="./scripts/e2e/parser_user_impact_regression_alarms_replay.sh"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser operator/developer runbook heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(' "$log_path"; then
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
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
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

run_local_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test parser_operator_developer_runbook" \
        cargo check -p frankenengine-engine --test parser_operator_developer_runbook
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test parser_operator_developer_runbook" \
        cargo test -p frankenengine-engine --test parser_operator_developer_runbook
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_operator_developer_runbook -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_operator_developer_runbook -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_operator_developer_runbook" \
        cargo check -p frankenengine-engine --test parser_operator_developer_runbook
      run_step "cargo test -p frankenengine-engine --test parser_operator_developer_runbook" \
        cargo test -p frankenengine-engine --test parser_operator_developer_runbook
      run_step "cargo clippy -p frankenengine-engine --test parser_operator_developer_runbook -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_operator_developer_runbook -- -D warnings
      ;;
    drill)
      run_step "cargo test -p frankenengine-engine --test parser_operator_developer_runbook -- --exact parser_operator_runbook_replay_drills_cover_required_paths" \
        cargo test -p frankenengine-engine --test parser_operator_developer_runbook -- --exact parser_operator_runbook_replay_drills_cover_required_paths
      run_local_step "${drill_replay_a}" "${root_dir}/${drill_replay_a}"
      run_local_step "${drill_replay_b}" "${root_dir}/${drill_replay_b}"
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci|drill]" >&2
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
    error_code_json='"FE-PARSER-OPERATOR-RUNBOOK-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"runbook_drills_cataloged\",\"outcome\":\"pass\",\"error_code\":null}"
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-operator-developer-runbook.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.10.4",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo "  \"component\": \"${component}\","
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
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "drill_replay_commands": ['
    echo "    \"$(parser_frontier_json_escape "${drill_replay_a}")\","
    echo "    \"$(parser_frontier_json_escape "${drill_replay_b}")\""
    echo "  ],"
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
    echo '    "contract_doc": "docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md",'
    echo '    "fixture": "crates/franken-engine/tests/fixtures/parser_operator_developer_runbook_v1.json",'
    echo '    "tests": "crates/franken-engine/tests/parser_operator_developer_runbook.rs",'
    echo '    "replay_wrapper": "scripts/e2e/parser_operator_developer_runbook_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser operator/developer runbook manifest: ${manifest_path}"
  echo "parser operator/developer runbook events: ${events_path}"
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
