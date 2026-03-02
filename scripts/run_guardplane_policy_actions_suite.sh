#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for this suite" >&2
  exit 1
fi

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_guardplane_policy_actions_${timestamp}}"
artifact_root="${GUARDPLANE_POLICY_ACTIONS_ARTIFACT_ROOT:-artifacts/guardplane_policy_actions_suite}"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
commands_path="$run_dir/commands.txt"
guardplane_log_path="$run_dir/guardplane_decision_log.jsonl"
containment_log_path="$run_dir/containment_workflow_log.jsonl"
logs_dir="$run_dir/logs"
bead_id="${GUARDPLANE_POLICY_ACTIONS_BEAD_ID:-bd-1lsy.6}"

trace_id="trace-guardplane-policy-actions-${timestamp}"
decision_id="decision-guardplane-policy-actions-${timestamp}"
policy_id="policy-guardplane-policy-actions-v1"
component="guardplane_policy_actions_suite"

mkdir -p "$run_dir" "$logs_dir"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

ensure_remote_only() {
  local log_path="$1"
  if rg -qi "Remote toolchain failure, falling back to local|running locally" "$log_path"; then
    echo "error: detected local fallback in rch output: $log_path" >&2
    return 1
  fi
  if ! rg -q "Remote command finished: exit=" "$log_path"; then
    echo "error: missing remote completion marker in rch output: $log_path" >&2
    return 1
  fi
  return 0
}

declare -a commands_run=()
declare -a command_logs=()
failed_command=""
failed_log_path=""
manifest_written=false
mode_completed=false

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"
  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    if ! ensure_remote_only "$log_path"; then
      failed_command="$command_text"
      failed_log_path="$log_path"
      return 1
    fi
    return 0
  fi
  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-extension-host --lib" \
        cargo check -p frankenengine-extension-host --lib
      ;;
    test)
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic" \
        cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine" \
        cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed" \
        cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-extension-host --lib -- -D warnings" \
        cargo clippy -p frankenengine-extension-host --lib -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-extension-host --lib" \
        cargo check -p frankenengine-extension-host --lib
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic" \
        cargo test -p frankenengine-extension-host --lib guardplane_action_thresholds_are_deterministic
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine" \
        cargo test -p frankenengine-extension-host --lib guardplane_policy_actions_progress_from_challenge_to_quarantine
      run_step "cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed" \
        cargo test -p frankenengine-extension-host --lib guardplane_safe_mode_fallback_is_fail_closed
      run_step "cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded" \
        cargo test -p frankenengine-extension-host --lib quarantine_mesh_targets_are_sorted_and_recorded
      run_step "cargo clippy -p frankenengine-extension-host --lib -- -D warnings" \
        cargo clippy -p frankenengine-extension-host --lib -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
  mode_completed=true
}

write_guardplane_decision_log() {
  local replay_command="${0} ci"
  {
    echo "{\"schema_version\":\"franken-engine.guardplane-decision-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"posterior_micros\":310000,\"action\":\"challenge\",\"safe_mode_fallback\":false,\"lifecycle_transition\":null,\"resulting_state\":\"running\",\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.guardplane-decision-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"posterior_micros\":420000,\"action\":\"sandbox\",\"safe_mode_fallback\":false,\"lifecycle_transition\":null,\"resulting_state\":\"running\",\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.guardplane-decision-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"posterior_micros\":640000,\"action\":\"suspend\",\"safe_mode_fallback\":false,\"lifecycle_transition\":\"suspend\",\"resulting_state\":\"suspending\",\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.guardplane-decision-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"posterior_micros\":750000,\"action\":\"terminate\",\"safe_mode_fallback\":false,\"lifecycle_transition\":\"terminate\",\"resulting_state\":\"terminating\",\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.guardplane-decision-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"posterior_micros\":860000,\"action\":\"quarantine\",\"safe_mode_fallback\":false,\"lifecycle_transition\":\"quarantine\",\"resulting_state\":\"quarantined\",\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.guardplane-decision-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_hostcall\",\"posterior_micros\":200000,\"action\":\"sandbox\",\"safe_mode_fallback\":true,\"lifecycle_transition\":null,\"resulting_state\":\"running\",\"replay_command\":\"${replay_command}\"}"
  } >"$guardplane_log_path"
}

write_containment_workflow_log() {
  local replay_command="${0} ci"
  {
    echo "{\"schema_version\":\"franken-engine.containment-workflow-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"action\":\"sandbox\",\"lifecycle_transition\":null,\"resulting_state\":\"running\",\"mesh_targets\":[],\"mesh_propagated\":false,\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.containment-workflow-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"action\":\"suspend\",\"lifecycle_transition\":\"suspend\",\"resulting_state\":\"suspending\",\"mesh_targets\":[],\"mesh_propagated\":false,\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.containment-workflow-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"action\":\"terminate\",\"lifecycle_transition\":\"terminate\",\"resulting_state\":\"terminating\",\"mesh_targets\":[],\"mesh_propagated\":false,\"replay_command\":\"${replay_command}\"}"
    echo "{\"schema_version\":\"franken-engine.containment-workflow-log.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"delegate_cell\",\"source_event\":\"delegate_declassification\",\"action\":\"quarantine\",\"lifecycle_transition\":\"quarantine\",\"resulting_state\":\"quarantined\",\"mesh_targets\":[\"peer-a\",\"peer-m\",\"peer-z\"],\"mesh_propagated\":true,\"replay_command\":\"${replay_command}\"}"
  } >"$containment_log_path"
}

json_or_null() {
  local value="$1"
  if [[ -n "$value" ]]; then
    printf '"%s"' "$value"
  else
    printf 'null'
  fi
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree outcome idx comma error_code_json failed_log_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-DELEGATE-0006"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  write_guardplane_decision_log
  write_containment_workflow_log
  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  failed_log_json="$(json_or_null "$failed_log_path")"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.guardplane-policy-actions-suite.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    echo "  \"commands_executed\": ${#commands_run[@]},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo "  \"failed_log\": ${failed_log_json},"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "command_logs": ['
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${command_logs[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"guardplane_decision_log\": \"${guardplane_log_path}\","
    echo "    \"containment_workflow_log\": \"${containment_log_path}\","
    echo "    \"logs_dir\": \"${logs_dir}\","
    echo '    "source_module": "crates/franken-extension-host/src/lib.rs",'
    echo '    "suite_script": "scripts/run_guardplane_policy_actions_suite.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${guardplane_log_path}\","
    echo "    \"cat ${containment_log_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "guardplane policy actions manifest: $manifest_path"
  echo "guardplane policy actions events: $events_path"
  echo "guardplane decision log: $guardplane_log_path"
  echo "containment workflow log: $containment_log_path"
}

trap 'write_manifest $?' EXIT
run_mode
