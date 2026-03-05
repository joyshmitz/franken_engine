#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_adversarial_gate}"
artifact_root="${ADVERSARIAL_GATE_ARTIFACT_ROOT:-artifacts/adversarial_campaign_gate}"
gate_input_fixture="${ADVERSARIAL_GATE_INPUT_FIXTURE:-crates/franken-engine/tests/fixtures/adversarial_campaign_gate_input_v1.json}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
gate_result_path="$run_dir/gate_result.json"
step_logs_dir="$run_dir/step_logs"

mkdir -p "$run_dir" "$step_logs_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for adversarial campaign gate heavy commands" >&2
  exit 2
fi

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

run_rch() {
  if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
    timeout "${rch_timeout_seconds}" \
      rch exec -- env CARGO_TARGET_DIR="$target_dir" CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS" "$@"
  else
    timeout "${rch_timeout_seconds}" \
      rch exec -- env CARGO_TARGET_DIR="$target_dir" "$@"
  fi
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
  local log_path rch_exit_code remote_exit_code
  shift

  commands_run+=("$command_text")
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))
  step_logs+=("$log_path")
  echo "==> $command_text"

  set +e
  run_rch "$@" > >(tee "$log_path") 2>&1
  rch_exit_code=$?
  set -e

  if [[ "${rch_exit_code}" -ne 0 ]]; then
    if [[ "${rch_exit_code}" -eq 124 ]]; then
      echo "==> failure: rch command timed out after ${rch_timeout_seconds}s" | tee -a "$log_path"
      failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      return 1
    fi

    if rch_recovered_success "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
      if [[ -n "${remote_exit_code}" ]]; then
        failed_command="${command_text} (rch-exit=${rch_exit_code}; remote-exit=${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit=${rch_exit_code}; missing-remote-exit-marker)"
      fi
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -z "${remote_exit_code}" ]]; then
    failed_command="${command_text} (rch-exit=${rch_exit_code}; missing-remote-exit-marker)"
    return 1
  fi
  if [[ "${remote_exit_code}" != "0" ]]; then
    failed_command="${command_text} (rch-exit=${rch_exit_code}; remote-exit=${remote_exit_code})"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate" \
        cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate
      run_step "cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator" \
        cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_" \
        cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli" \
        cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields" \
        cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields
      run_step "cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- --input ${gate_input_fixture} --out ${gate_result_path}" \
        cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- \
          --input "$gate_input_fixture" \
          --out "$gate_result_path"
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings" \
        cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate" \
        cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate
      run_step "cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator" \
        cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator
      run_step "cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_" \
        cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli" \
        cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields" \
        cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields
      run_step "cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- --input ${gate_input_fixture} --out ${gate_result_path}" \
        cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- \
          --input "$gate_input_fixture" \
          --out "$gate_result_path"
      run_step "cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings" \
        cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$run_dir/commands.txt"

  {
    echo "{"
    echo '  "component": "adversarial_campaign_suppression_gate",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"gate_input_fixture\": \"${gate_input_fixture}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(json_escape "${failed_command}")\","
    fi
    echo '  "thresholds": {'
    echo '    "minimum_baseline_runtimes": 2,'
    echo '    "max_p_value_millionths": 50000,'
    echo '    "require_continuous_run": true,'
    echo '    "minimum_trend_points": 2,'
    echo '    "max_escalation_latency_seconds": 3600'
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${run_dir}/commands.txt\","
    echo "    \"gate_result\": \"${gate_result_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\","
    echo "    \"manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"cat ${gate_result_path}\","
    echo "    \"ls -1 ${step_logs_dir}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "Manifest written to: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
