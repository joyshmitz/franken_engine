#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_runtime_diagnostics}"
seed="${RUNTIME_DIAGNOSTICS_SEED:-runtime-diagnostics-seed-v1}"
artifact_root="${RUNTIME_DIAGNOSTICS_ARTIFACT_ROOT:-artifacts/runtime_diagnostics}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}"
rch_artifact_grace_seconds="${RCH_ARTIFACT_GRACE_SECONDS:-120}"
rch_wrapper_timeout_seconds=$((rch_timeout_seconds + rch_artifact_grace_seconds))
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
commands_path="$run_dir/commands.txt"
events_path="$run_dir/events.jsonl"
compat_scenario_fixture="${RUNTIME_DIAGNOSTICS_SCENARIO_FIXTURE:-crates/franken-engine/tests/fixtures/runtime_compatibility_scenario_report_v1.json}"
compat_source_report="${RUNTIME_DIAGNOSTICS_SOURCE_REPORT:-$compat_scenario_fixture}"
compat_advisory_output="${run_dir}/compatibility_advisories.json"

trace_id="trace-runtime-diagnostics-${timestamp}"
decision_id="decision-runtime-diagnostics-${timestamp}"
policy_id="policy-runtime-diagnostics-v1"
component="runtime_diagnostics_suite"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for runtime diagnostics suite commands" >&2
  exit 1
fi

run_rch() {
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    timeout "${rch_wrapper_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

rch_strip_ansi() {
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
    echo "error: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line
  remote_exit_line="$(rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    echo ""
    return
  fi
  echo "${remote_exit_line##*=}"
}

rch_extract_wrapped_timeout_seconds() {
  local log_path="$1"
  local wrapped_timeout
  wrapped_timeout="$(
    rch_strip_ansi "$log_path" \
      | rg -o 'timeout_secs:[[:space:]]*[0-9]+' \
      | tail -n1 \
      | rg -o '[0-9]+$' || true
  )"
  echo "$wrapped_timeout"
}

rch_reject_timeout_policy_drift() {
  local log_path="$1"
  local wrapped_timeout

  wrapped_timeout="$(rch_extract_wrapped_timeout_seconds "$log_path")"
  if [[ -z "$wrapped_timeout" ]]; then
    return 0
  fi

  observed_rch_timeout_seconds="$wrapped_timeout"
  if [[ "$wrapped_timeout" =~ ^[0-9]+$ ]] && [[ "$rch_build_timeout_sec" =~ ^[0-9]+$ ]]; then
    if (( wrapped_timeout < rch_build_timeout_sec )); then
      timeout_policy_drift_detected=true
      echo "error: rch timeout policy drift detected (wrapped ${wrapped_timeout}s < requested ${rch_build_timeout_sec}s)" >&2
      return 1
    fi
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0
compatibility_advisory_generated=false
last_step_log_path=""
observed_rch_timeout_seconds=""
timeout_policy_drift_detected=false

run_step() {
  local command_text="$1"
  local status remote_exit_code
  shift
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  last_step_log_path="$step_log_path"
  commands_run+=("$command_text")
  echo "==> $command_text"
  if run_rch "$@" > >(tee "$step_log_path") 2>&1; then
    status=0
  else
    status=$?
    remote_exit_code="$(rch_last_remote_exit_code "$step_log_path" || true)"
    if [[ "$status" -eq 124 || "$remote_exit_code" == "137" ]]; then
      if ! rch_reject_timeout_policy_drift "$step_log_path"; then
        failed_command="${command_text} (rch-timeout-policy-drift-${observed_rch_timeout_seconds:-unknown}<${rch_build_timeout_sec})"
        return 1
      fi
    fi
    if [[ "$status" -eq 124 ]]; then
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
    elif [[ -n "$remote_exit_code" ]]; then
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    else
      failed_command="${command_text} (rch-exit-${status})"
    fi
    return 1
  fi

  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi

  if ! rch_reject_timeout_policy_drift "$step_log_path"; then
    failed_command="${command_text} (rch-timeout-policy-drift-${observed_rch_timeout_seconds:-unknown}<${rch_build_timeout_sec})"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$step_log_path" || true)"
  if [[ "$remote_exit_code" != "0" ]]; then
    if [[ -z "$remote_exit_code" ]]; then
      failed_command="${command_text} (missing-remote-exit-marker)"
    else
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    fi
    return 1
  fi
}

extract_json_object_from_step_log() {
  local step_log_path="$1"
  local output_path="$2"

  awk '
    BEGIN {
      capture = 0
      depth = 0
    }
    {
      line = $0
      if (!capture && line ~ /^[[:space:]]*\{[[:space:]]*$/) {
        capture = 1
      }
      if (capture) {
        print line
        opens = gsub(/\{/, "{", line)
        closes = gsub(/\}/, "}", line)
        depth += (opens - closes)
        if (depth == 0) {
          exit
        }
      }
    }
  ' "$step_log_path" >"$output_path"
}

run_mode() {
  if [[ "$mode" == "test" || "$mode" == "ci" ]]; then
    if [[ ! -f "$compat_scenario_fixture" ]]; then
      echo "error: compatibility scenario fixture not found: $compat_scenario_fixture" >&2
      return 1
    fi
  fi

  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli" \
        cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli" \
        cargo test -p frankenengine-engine --test runtime_diagnostics_cli
      run_step "cargo test -p frankenengine-engine --bin runtime_diagnostics compatibility -- --nocapture" \
        cargo test -p frankenengine-engine --bin runtime_diagnostics compatibility -- --nocapture
      run_step "cargo run -p frankenengine-engine --bin runtime_diagnostics -- compatibility-advisories --scenario-report ${compat_scenario_fixture} --source-report ${compat_source_report} [rch-json-export]" \
        cargo run -p frankenengine-engine --bin runtime_diagnostics -- compatibility-advisories --scenario-report "${compat_scenario_fixture}" --source-report "${compat_source_report}"
      extract_json_object_from_step_log "$last_step_log_path" "$compat_advisory_output"
      if [[ ! -s "$compat_advisory_output" ]]; then
        failed_command="compatibility-advisories output validation (missing output)"
        return 1
      fi
      if ! jq -e '.advisory_count' "$compat_advisory_output" >/dev/null 2>&1; then
        failed_command="compatibility-advisories output validation (missing advisory_count)"
        return 1
      fi
      compatibility_advisory_generated=true
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli" \
        cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli
      run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli" \
        cargo test -p frankenengine-engine --test runtime_diagnostics_cli
      run_step "cargo test -p frankenengine-engine --bin runtime_diagnostics compatibility -- --nocapture" \
        cargo test -p frankenengine-engine --bin runtime_diagnostics compatibility -- --nocapture
      run_step "cargo run -p frankenengine-engine --bin runtime_diagnostics -- compatibility-advisories --scenario-report ${compat_scenario_fixture} --source-report ${compat_source_report} [rch-json-export]" \
        cargo run -p frankenengine-engine --bin runtime_diagnostics -- compatibility-advisories --scenario-report "${compat_scenario_fixture}" --source-report "${compat_source_report}"
      extract_json_object_from_step_log "$last_step_log_path" "$compat_advisory_output"
      if [[ ! -s "$compat_advisory_output" ]]; then
        failed_command="compatibility-advisories output validation (missing output)"
        return 1
      fi
      if ! jq -e '.advisory_count' "$compat_advisory_output" >/dev/null 2>&1; then
        failed_command="compatibility-advisories output validation (missing advisory_count)"
        return 1
      fi
      compatibility_advisory_generated=true
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    if [[ "$failed_command" == *rch-timeout-policy-drift* ]]; then
      error_code_json='"FE-RUNTIME-DIAGNOSTICS-TIMEOUT-0001"'
    else
      error_code_json='"FE-RUNTIME-DIAGNOSTICS-0001"'
    fi
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}" >"$events_path"
  if [[ "$compatibility_advisory_generated" == true ]]; then
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"compatibility_advisory_generated\",\"outcome\":\"pass\",\"error_code\":null,\"artifact\":\"${compat_advisory_output}\"}" >>"$events_path"
  fi

  {
    echo "{"
    echo '  "schema_version": "franken-engine.runtime-diagnostics.run-manifest.v1",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"seed\": \"${seed}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"rch_build_timeout_sec\": ${rch_build_timeout_sec},"
    if [[ -n "${observed_rch_timeout_seconds}" ]]; then
      echo "  \"rch_observed_timeout_seconds\": ${observed_rch_timeout_seconds},"
    fi
    echo "  \"rch_timeout_policy_drift_detected\": ${timeout_policy_drift_detected},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"outcome\": \"${outcome}\"," 
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\"," 
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${commands_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    if [[ "$compatibility_advisory_generated" == true ]]; then
      echo "    \"compatibility_advisories\": \"${compat_advisory_output}\"," 
    fi
    echo "    \"manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "failure_code_mapping": {'
    echo '    "default": "FE-RUNTIME-DIAGNOSTICS-0001",'
    echo '    "timeout_policy_drift": "FE-RUNTIME-DIAGNOSTICS-TIMEOUT-0001"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    if [[ "$compatibility_advisory_generated" == true ]]; then
      echo "    \"cat ${compat_advisory_output}\"," 
    fi
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "runtime diagnostics manifest: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
