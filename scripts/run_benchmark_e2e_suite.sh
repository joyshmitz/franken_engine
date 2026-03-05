#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_benchmark_e2e_suite}"
artifact_root="${BENCHMARK_E2E_ARTIFACT_ROOT:-artifacts/benchmark_e2e_suite}"
component="${BENCHMARK_E2E_COMPONENT:-benchmark_e2e_suite}"
bead_id="${BENCHMARK_E2E_BEAD_ID:-bd-1lsy.8.1}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
benchmark_manifest_path="${run_dir}/run_manifest.json"
benchmark_events_path="${run_dir}/events.jsonl"
benchmark_commands_path="${run_dir}/commands.txt"
benchmark_env_manifest_path="${run_dir}/benchmark_env_manifest.json"
raw_results_archive_path="${run_dir}/raw_results_archive.json"

suite_manifest_path="${run_dir}/suite_run_manifest.json"
suite_events_path="${run_dir}/suite_events.jsonl"
suite_commands_path="${run_dir}/suite_commands.txt"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for benchmark e2e suite commands" >&2
  exit 1
fi

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

benchmark_artifacts_complete() {
  local required
  for required in \
    "$benchmark_manifest_path" \
    "$benchmark_events_path" \
    "$benchmark_commands_path" \
    "$benchmark_env_manifest_path" \
    "$raw_results_archive_path"; do
    if [[ ! -f "$required" ]]; then
      return 1
    fi
  done
  return 0
}

pull_remote_file_if_missing() {
  local path="$1"
  local tmp_path

  if [[ -f "$path" ]]; then
    return 0
  fi

  if ! RCH_LOG_LEVEL=error run_rch test -f "$path" >/dev/null 2>&1; then
    return 1
  fi

  mkdir -p "$(dirname "$path")"
  tmp_path="${path}.remote.$$"
  if ! RCH_LOG_LEVEL=error run_rch cat "$path" >"$tmp_path"; then
    rm -f "$tmp_path"
    return 1
  fi

  mv "$tmp_path" "$path"
}

sync_benchmark_artifacts_from_remote() {
  local required
  local missing_any=false
  for required in \
    "$benchmark_manifest_path" \
    "$benchmark_events_path" \
    "$benchmark_commands_path" \
    "$benchmark_env_manifest_path" \
    "$raw_results_archive_path"; do
    if [[ -f "$required" ]]; then
      continue
    fi
    if ! pull_remote_file_if_missing "$required"; then
      missing_any=true
    fi
  done

  [[ "$missing_any" == false ]]
}

ensure_benchmark_artifacts_complete() {
  if benchmark_artifacts_complete; then
    return 0
  fi

  sync_benchmark_artifacts_from_remote || true
  benchmark_artifacts_complete
}

reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|running locally|Failed to query daemon:.*running locally|RCH-E326' "$log_path"; then
    echo "error: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

require_remote_success_marker() {
  local log_path="$1"
  if ! grep -Eq 'Remote command finished: exit=0' "$log_path"; then
    echo "error: missing successful remote completion marker in ${log_path}" >&2
    return 1
  fi
}

json_path_or_null() {
  local path="$1"
  if [[ -f "$path" ]]; then
    printf '"%s"' "$path"
  else
    printf 'null'
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  shift
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  commands_run+=("$command_text")
  echo "==> $command_text"
  set +e
  run_rch "$@" > >(tee "$step_log_path") 2>&1
  local rc=$?
  set -e
  if ! reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi
  if ! require_remote_success_marker "$step_log_path"; then
    failed_command="${command_text} (rch-success-marker-missing)"
    return 87
  fi
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration" \
    cargo check -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration
}

run_test() {
  run_step "FRANKEN_BENCH_E2E_OUTPUT_DIR=${run_dir} cargo test -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration" \
    env FRANKEN_BENCH_E2E_OUTPUT_DIR="${run_dir}" \
    cargo test -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration
  if ! ensure_benchmark_artifacts_complete; then
    echo "error: benchmark artifact contract missing after test mode" >&2
    failed_command="test_artifact_validation"
    return 1
  fi
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration -- -D warnings" \
    cargo clippy -p frankenengine-engine --test benchmark_e2e --test benchmark_e2e_integration -- -D warnings
}

run_report() {
  run_step "FRANKEN_BENCH_E2E_OUTPUT_DIR=${run_dir} cargo test -p frankenengine-engine --test benchmark_e2e_integration benchmark_e2e_script_emits_artifacts_to_env_dir -- --exact --nocapture" \
    env FRANKEN_BENCH_E2E_OUTPUT_DIR="${run_dir}" \
    cargo test -p frankenengine-engine --test benchmark_e2e_integration \
    benchmark_e2e_script_emits_artifacts_to_env_dir -- --exact --nocapture

  if ! ensure_benchmark_artifacts_complete; then
    echo "error: benchmark artifact contract missing after report mode" >&2
    failed_command="report_artifact_validation"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    clippy)
      run_clippy
      ;;
    report)
      run_report
      ;;
    ci)
      run_check
      run_test
      run_clippy
      run_report
      ;;
    *)
      echo "usage: $0 [check|test|clippy|report|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma
  local benchmark_artifacts_available op_idx
  local -a operator_verification_commands=()

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-BENCH-E2E-SUITE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  benchmark_artifacts_available=false
  if benchmark_artifacts_complete; then
    benchmark_artifacts_available=true
  fi

  operator_verification_commands+=("cat ${suite_manifest_path}")
  operator_verification_commands+=("cat ${suite_events_path}")
  operator_verification_commands+=("cat ${suite_commands_path}")
  if [[ "$benchmark_artifacts_available" == true ]]; then
    operator_verification_commands+=("cat ${benchmark_manifest_path}")
    operator_verification_commands+=("cat ${benchmark_events_path}")
    operator_verification_commands+=("cat ${benchmark_commands_path}")
    operator_verification_commands+=("cat ${benchmark_env_manifest_path}")
    operator_verification_commands+=("cat ${raw_results_archive_path}")
  fi
  operator_verification_commands+=("${0} ci")

  printf '%s\n' "${commands_run[@]}" >"$suite_commands_path"
  {
    echo "{\"trace_id\":\"trace-benchmark-e2e-suite-${timestamp}\",\"decision_id\":\"decision-benchmark-e2e-suite-${timestamp}\",\"policy_id\":\"policy-benchmark-e2e-suite-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$suite_events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.benchmark-e2e-suite.run-manifest.v1",'
    echo "  \"bead_id\": \"${bead_id}\"," 
    echo "  \"component\": \"${component}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"benchmark_artifacts_available\": ${benchmark_artifacts_available},"
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
    echo "    \"suite_manifest\": \"${suite_manifest_path}\"," 
    echo "    \"suite_events\": \"${suite_events_path}\"," 
    echo "    \"suite_commands\": \"${suite_commands_path}\"," 
    echo "    \"benchmark_manifest\": $(json_path_or_null "$benchmark_manifest_path")," 
    echo "    \"benchmark_events\": $(json_path_or_null "$benchmark_events_path")," 
    echo "    \"benchmark_commands\": $(json_path_or_null "$benchmark_commands_path")," 
    echo "    \"benchmark_env_manifest\": $(json_path_or_null "$benchmark_env_manifest_path")," 
    echo "    \"raw_results_archive\": $(json_path_or_null "$raw_results_archive_path")" 
    echo '  },'
    echo '  "operator_verification": ['
    for op_idx in "${!operator_verification_commands[@]}"; do
      comma=","
      if [[ "$op_idx" == "$(( ${#operator_verification_commands[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${operator_verification_commands[$op_idx]}\"${comma}"
    done
    echo '  ]'
    echo "}"
  } >"$suite_manifest_path"

  echo "benchmark e2e suite manifest: ${suite_manifest_path}"
  echo "benchmark artifacts: ${benchmark_manifest_path}" 
}

trap 'write_manifest $?' EXIT
run_mode
