#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_exception_diagnostics_semantics}"
artifact_root="${RGC_EXCEPTION_DIAGNOSTICS_SEMANTICS_ARTIFACT_ROOT:-artifacts/rgc_exception_diagnostics_semantics}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"
diagnostic_trace_path="${run_dir}/diagnostic_trace.json"
trace_begin_marker="__RGC305_TRACE_BEGIN__"
trace_end_marker="__RGC305_TRACE_END__"

contract_doc="docs/RGC_EXCEPTION_DIAGNOSTICS_SEMANTICS_V1.md"
contract_json="docs/rgc_exception_diagnostics_semantics_v1.json"
vectors_json="docs/rgc_exception_diagnostics_semantics_vectors_v1.json"

trace_id="trace-rgc-exception-diagnostics-semantics-${timestamp}"
decision_id="decision-rgc-exception-diagnostics-semantics-${timestamp}"
policy_id="policy-rgc-exception-diagnostics-semantics-v1"
component="rgc_exception_diagnostics_semantics_gate"
scenario_id="rgc-305"
replay_command="./scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

for required_file in "$contract_doc" "$contract_json" "$vectors_json"; do
  if [[ ! -f "$required_file" ]]; then
    echo "FE-RGC-305-CONTRACT-0001: missing required file (${required_file})" >&2
    exit 1
  fi
done

if ! jq -e '.' "$contract_json" >/dev/null 2>&1; then
  echo "FE-RGC-305-CONTRACT-0002: failed to parse contract JSON (${contract_json})" >&2
  exit 1
fi

if ! jq -e '.' "$vectors_json" >/dev/null 2>&1; then
  echo "FE-RGC-305-VECTORS-0001: failed to parse vectors JSON (${vectors_json})" >&2
  exit 1
fi

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC exception diagnostics semantics heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_recovered_success() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | rg -q 'Remote command finished: exit=0|Finished.*profile|test result: ok\.' \
    && ! rch_strip_ansi "$log_path" | rg -qi 'error(\[[[:alnum:]]+\])?:'; then
    return 0
  fi
  return 1
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false
step_log_index=0

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
  if [[ -z "$remote_exit_code" ]]; then
    failed_command="${command_text} (rch-exit=${status}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ "$remote_exit_code" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${status}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

collect_diagnostic_trace_from_latest_step_log() {
  if [[ -f "$diagnostic_trace_path" ]]; then
    return 0
  fi

  local log_index log_path tmp_path
  log_index="$(( ${#step_logs[@]} - 1 ))"
  if [[ "$log_index" -lt 0 ]]; then
    failed_command="diagnostic trace artifact missing (${diagnostic_trace_path}); no step logs recorded"
    return 1
  fi

  log_path="${step_logs[$log_index]}"
  if [[ ! -f "$log_path" ]]; then
    failed_command="diagnostic trace artifact missing (${diagnostic_trace_path}); missing step log ${log_path}"
    return 1
  fi

  tmp_path="$(mktemp)"
  rch_strip_ansi "$log_path" | awk \
    -v begin_marker="$trace_begin_marker" \
    -v end_marker="$trace_end_marker" \
    '
    $0 == begin_marker {capture = 1; next}
    $0 == end_marker {capture = 0; exit}
    capture {print}
  ' >"$tmp_path"

  if [[ ! -s "$tmp_path" ]]; then
    rm -f "$tmp_path"
    failed_command="diagnostic trace artifact missing (${diagnostic_trace_path}); marker payload not found in ${log_path}"
    return 1
  fi

  if ! jq -e '.' "$tmp_path" >/dev/null 2>&1; then
    rm -f "$tmp_path"
    failed_command="diagnostic trace artifact invalid JSON (${diagnostic_trace_path}); marker payload parse failed"
    return 1
  fi

  mv "$tmp_path" "$diagnostic_trace_path"
}

run_mode() {
  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics" \
      cargo check -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics || return $?
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- --nocapture" \
      env RGC_305_DIAGNOSTIC_TRACE_OUT="${diagnostic_trace_path}" \
      cargo test -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- --nocapture || return $?
    collect_diagnostic_trace_from_latest_step_log || return $?
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- -D warnings" \
      cargo clippy -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- -D warnings || return $?
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics" \
      cargo check -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics || return $?
    run_step "cargo test -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- --nocapture" \
      env RGC_305_DIAGNOSTIC_TRACE_OUT="${diagnostic_trace_path}" \
      cargo test -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- --nocapture || return $?
    collect_diagnostic_trace_from_latest_step_log || return $?
    run_step "cargo clippy -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- -D warnings" \
      cargo clippy -p frankenengine-engine --test eval_pipeline_integration --test rgc_exception_diagnostics_semantics -- -D warnings || return $?
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
    error_code_json='"FE-RGC-305-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-exception-diagnostics-semantics.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"lane\":\"matrix\",\"error_class\":\"mixed\",\"error_code\":${error_code_json},\"outcome\":\"${outcome}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-exception-diagnostics-semantics.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.4.5",'
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
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\"," 
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo "    \"diagnostic_trace\": \"${diagnostic_trace_path}\"," 
    echo "    \"step_logs_dir\": \"${step_logs_dir}\"," 
    echo "    \"contract_doc\": \"${contract_doc}\"," 
    echo "    \"contract_json\": \"${contract_json}\"," 
    echo "    \"vectors_json\": \"${vectors_json}\"," 
    echo '    "gate_tests": "crates/franken-engine/tests/rgc_exception_diagnostics_semantics.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${diagnostic_trace_path}\"," 
    echo "    \"ls -1 ${step_logs_dir}\"," 
    echo "    \"jq empty ${contract_json}\"," 
    echo "    \"jq empty ${vectors_json}\"," 
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc exception-diagnostics manifest: ${manifest_path}"
  echo "rgc exception-diagnostics events: ${events_path}"
}

main_exit=0
set +e
run_mode
main_exit=$?
set -e

if [[ "$main_exit" -eq 0 && ( "$mode" == "test" || "$mode" == "ci" ) ]]; then
  if [[ ! -f "$diagnostic_trace_path" ]]; then
    main_exit=1
    failed_command="diagnostic trace artifact missing (${diagnostic_trace_path})"
  fi
fi

write_manifest "$main_exit"
exit "$main_exit"
