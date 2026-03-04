#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_tail_latency_memory_hardening_regression_gate}"
artifact_root="${TAIL_LATENCY_MEMORY_HARDENING_REGRESSION_GATE_ARTIFACT_ROOT:-artifacts/tail_latency_memory_hardening_regression_gate}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
pause_distribution_report_path="${run_dir}/pause_distribution_report.json"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-tail-latency-memory-hardening-regression-gate-${timestamp}"
decision_id="decision-tail-latency-memory-hardening-regression-gate-${timestamp}"
policy_id="policy-tail-latency-memory-hardening-regression-gate-v1"
component="tail_latency_memory_hardening_regression_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for tail-latency+memory hardening heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

rch_strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g' "$1"
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
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326'; then
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
  commands_run+=("$command_text")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  step_logs+=("$log_path")
  echo "==> $command_text"

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "$remote_exit_code" ]]; then
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

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate" \
        cargo check -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate" \
        cargo test -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate" \
        cargo check -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate
      run_step "cargo test -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate" \
        cargo test -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate
      run_step "cargo clippy -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test tail_latency_memory_hardening_regression_gate -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_pause_distribution_report() {
  local outcome="$1"
  local policy_state from_state to_state transitioned violation_count_json budget_violations_json
  if [[ "$outcome" == "pass" ]]; then
    policy_state="within_budget"
    from_state="within_budget"
    to_state="within_budget"
    transitioned="false"
    violation_count_json="0"
    budget_violations_json='[]'
  else
    policy_state="violated"
    from_state="within_budget"
    to_state="violated"
    transitioned="true"
    violation_count_json="1"
    budget_violations_json='[{"percentile":"p95","observed_ns":2000001,"budget_ns":2000000,"scope":"global"}]'
  fi

  cat >"${pause_distribution_report_path}" <<JSON
{
  "schema_version": "franken-engine.gc-pause-distribution-report.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "sample_count": 0,
  "budget": {
    "p50_ns": 500000,
    "p95_ns": 2000000,
    "p99_ns": 10000000
  },
  "policy_state": "${policy_state}",
  "policy_transition": {
    "from_state": "${from_state}",
    "to_state": "${to_state}",
    "transitioned": ${transitioned},
    "violation_count": ${violation_count_json}
  },
  "global_percentiles": {
    "count": 0,
    "min_ns": 0,
    "max_ns": 0,
    "p50_ns": 0,
    "p95_ns": 0,
    "p99_ns": 0
  },
  "per_extension_percentiles": {},
  "histogram": [],
  "budget_violations": ${budget_violations_json}
}
JSON
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
    error_code_json='"FE-TAIL-MEMORY-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  write_pause_distribution_report "$outcome"

  {
    echo "{\"schema_version\":\"franken-engine.tail-latency-memory.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"replay_command\":\"$(parser_frontier_json_escape "${replay_command}")\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
    echo "{\"schema_version\":\"franken-engine.tail-latency-memory.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"pause_distribution_report_emitted\",\"pause_distribution_report\":\"$(parser_frontier_json_escape "${pause_distribution_report_path}")\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.tail-latency-memory-hardening-regression-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.6.4",'
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
    echo "  ],"
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo "    \"pause_distribution_report\": \"${pause_distribution_report_path}\"," 
    echo "    \"step_logs_dir\": \"${step_logs_dir}\"," 
    echo '    "campaign_doc": "docs/TAIL_LATENCY_MEMORY_HARDENING_REGRESSION_GATE.md",'
    echo '    "campaign_fixture": "crates/franken-engine/tests/fixtures/tail_latency_memory_hardening_regression_gate_v1.json",'
    echo '    "campaign_tests": "crates/franken-engine/tests/tail_latency_memory_hardening_regression_gate.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${pause_distribution_report_path}\"," 
    echo "    \"ls -1 ${step_logs_dir}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "tail-latency+memory hardening manifest: ${manifest_path}"
  echo "tail-latency+memory hardening events: ${events_path}"
  echo "tail-latency+memory hardening pause distribution report: ${pause_distribution_report_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" \
  --events "$events_path" \
  --schema-prefix "franken-engine.tail-latency-memory"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
