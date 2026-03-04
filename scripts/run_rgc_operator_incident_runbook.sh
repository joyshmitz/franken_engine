#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_OPERATOR_INCIDENT_RUNBOOK_ARTIFACT_ROOT:-artifacts/rgc_operator_incident_runbook}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/tmp/rch_target_franken_engine_rgc_operator_incident_runbook_${timestamp}_$$"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
cargo_home="${CARGO_HOME:-}"

run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
incident_timeline_path="${run_dir}/incident_timeline.json"

trace_id="trace-rgc-operator-incident-runbook-${timestamp}"
decision_id="decision-rgc-operator-incident-runbook-${timestamp}"
policy_id="policy-rgc-operator-incident-runbook-v1"
component="rgc_operator_incident_runbook_gate"
replay_command="./scripts/e2e/rgc_operator_incident_runbook_replay.sh ${mode}"

incident_replay_a="./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh"
incident_replay_b="./scripts/e2e/rgc_performance_regression_verification_pack_replay.sh"
incident_replay_c="./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh"
incident_replay_d="./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh"
incident_replay_e="./scripts/e2e/rgc_execution_waves_coordination_replay.sh"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for rgc operator incident runbook heavy commands" >&2
  exit 2
fi

run_rch() {
  local -a env_args
  env_args=(
    "RUSTUP_TOOLCHAIN=${toolchain}"
    "CARGO_TARGET_DIR=${target_dir}"
  )
  if [[ -n "$cargo_home" ]]; then
    env_args+=("CARGO_HOME=${cargo_home}")
  fi

  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env \
    "${env_args[@]}" \
    "$@"
}

rch_strip_ansi() {
  local input="$1"
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$input"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true)"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
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

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
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
      run_step "cargo check -p frankenengine-engine --test rgc_operator_incident_runbook" \
        cargo check -p frankenengine-engine --test rgc_operator_incident_runbook \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_operator_incident_runbook" \
        cargo test -p frankenengine-engine --test rgc_operator_incident_runbook \
        || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_operator_incident_runbook -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_operator_incident_runbook -- -D warnings \
        || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test rgc_operator_incident_runbook" \
        cargo check -p frankenengine-engine --test rgc_operator_incident_runbook \
        || return $?
      run_step "cargo test -p frankenengine-engine --test rgc_operator_incident_runbook" \
        cargo test -p frankenengine-engine --test rgc_operator_incident_runbook \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --test rgc_operator_incident_runbook -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_operator_incident_runbook -- -D warnings \
        || return $?
      ;;
    drill)
      run_step "cargo test -p frankenengine-engine --test rgc_operator_incident_runbook -- --exact rgc_operator_runbook_replay_drills_cover_required_paths" \
        cargo test -p frankenengine-engine --test rgc_operator_incident_runbook -- --exact rgc_operator_runbook_replay_drills_cover_required_paths \
        || return $?
      run_local_step "test -x ${incident_replay_a}" test -x "${root_dir}/${incident_replay_a}"
      run_local_step "test -x ${incident_replay_b}" test -x "${root_dir}/${incident_replay_b}"
      run_local_step "test -x ${incident_replay_c}" test -x "${root_dir}/${incident_replay_c}"
      run_local_step "test -x ${incident_replay_d}" test -x "${root_dir}/${incident_replay_d}"
      run_local_step "test -x ${incident_replay_e}" test -x "${root_dir}/${incident_replay_e}"
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci|drill]" >&2
      exit 2
      ;;
  esac
}

write_incident_timeline() {
  {
    echo '{'
    echo '  "schema_version": "franken-engine.rgc-operator-incident-runbook.incident-timeline.v1",'
    echo "  \"bead_id\": \"bd-1lsy.10.2\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo '  "incidents": ['
    echo "    {\"scenario_id\":\"semantic_drift\",\"replay_command\":\"${incident_replay_a}\",\"owner\":\"operator-oncall\",\"status\":\"cataloged\"},"
    echo "    {\"scenario_id\":\"performance_regression\",\"replay_command\":\"${incident_replay_b}\",\"owner\":\"performance-oncall\",\"status\":\"cataloged\"},"
    echo "    {\"scenario_id\":\"containment_false_positive\",\"replay_command\":\"${incident_replay_c}\",\"owner\":\"security-oncall\",\"status\":\"cataloged\"},"
    echo "    {\"scenario_id\":\"lockstep_divergence\",\"replay_command\":\"${incident_replay_d}\",\"owner\":\"compatibility-oncall\",\"status\":\"cataloged\"},"
    echo "    {\"scenario_id\":\"replay_mismatch\",\"replay_command\":\"${incident_replay_e}\",\"owner\":\"verification-oncall\",\"status\":\"cataloged\"}"
    echo '  ]'
    echo '}'
  } >"${incident_timeline_path}"
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
    error_code_json='"FE-RGC-902-RUNBOOK-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"incident_matrix_cataloged\",\"outcome\":\"pass\",\"error_code\":null}"
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"rgc-902\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo '{'
    echo '  "schema_version": "franken-engine.rgc-operator-incident-runbook.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.10.2",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    if [[ -n "$cargo_home" ]]; then
      echo "  \"cargo_home\": \"${cargo_home}\","
    else
      echo '  "cargo_home": null,'
    fi
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
    echo '  },'
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo "  \"incident_timeline\": \"${incident_timeline_path}\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"incident_timeline\": \"${incident_timeline_path}\","
    echo '    "contract_doc": "docs/RGC_OPERATOR_INCIDENT_RUNBOOK.md",'
    echo '    "fixture": "crates/franken-engine/tests/fixtures/rgc_operator_incident_runbook_v1.json",'
    echo '    "tests": "crates/franken-engine/tests/rgc_operator_incident_runbook.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_operator_incident_runbook_replay.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${incident_timeline_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo '}'
  } >"$manifest_path"

  echo "rgc operator incident runbook manifest: ${manifest_path}"
  echo "rgc operator incident runbook events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_incident_timeline
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
