#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_frx_cross_version_compatibility_matrix}"
artifact_root="${FRX_CROSS_VERSION_COMPAT_ARTIFACT_ROOT:-artifacts/frx_cross_version_compatibility_matrix}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-frx-cross-version-compatibility-matrix-${timestamp}"
decision_id="decision-frx-cross-version-compatibility-matrix-${timestamp}"
policy_id="policy-frx-cross-version-compat-v1"
component="frx_cross_version_compatibility_matrix_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for FRX cross-version compatibility matrix heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

kill_target_dir_processes() {
  pkill -TERM -f "${target_dir}" >/dev/null 2>&1 || true
  sleep 1
  pkill -KILL -f "${target_dir}" >/dev/null 2>&1 || true
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|\[RCH\] local \(|falling back to local|fallback to local|local fallback' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path run_pid status
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  run_rch "$@" >"$log_path" 2>&1 &
  run_pid=$!

  while kill -0 "$run_pid" >/dev/null 2>&1; do
    if rch_reject_local_fallback "$log_path"; then
      :
    else
      kill -TERM "$run_pid" >/dev/null 2>&1 || true
      sleep 1
      kill -KILL "$run_pid" >/dev/null 2>&1 || true
      wait "$run_pid" >/dev/null 2>&1 || true
      kill_target_dir_processes
      cat "$log_path"
      rm -f "$log_path"
      failed_command="${command_text} (rch-local-fallback-detected)"
      return 1
    fi
    sleep 1
  done

  wait "$run_pid"
  status=$?
  cat "$log_path"

  if [[ "$status" -ne 0 ]]; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi
  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test frx_cross_version_compatibility_matrix" \
        cargo check -p frankenengine-engine --test frx_cross_version_compatibility_matrix || return 1
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test frx_cross_version_compatibility_matrix" \
        cargo test -p frankenengine-engine --test frx_cross_version_compatibility_matrix || return 1
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test frx_cross_version_compatibility_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test frx_cross_version_compatibility_matrix -- -D warnings || return 1
      ;;
    replay)
      run_step "cargo test -p frankenengine-engine --test frx_cross_version_compatibility_matrix -- --nocapture" \
        cargo test -p frankenengine-engine --test frx_cross_version_compatibility_matrix -- --nocapture || return 1
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test frx_cross_version_compatibility_matrix" \
        cargo check -p frankenengine-engine --test frx_cross_version_compatibility_matrix || return 1
      run_step "cargo test -p frankenengine-engine --test frx_cross_version_compatibility_matrix" \
        cargo test -p frankenengine-engine --test frx_cross_version_compatibility_matrix || return 1
      run_step "cargo clippy -p frankenengine-engine --test frx_cross_version_compatibility_matrix -- -D warnings" \
        cargo clippy -p frankenengine-engine --test frx_cross_version_compatibility_matrix -- -D warnings || return 1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|replay|ci]" >&2
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
    error_code_json='"FE-CROSS-VERSION-MATRIX-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.cross-version-compatibility-matrix.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.2.4",'
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
    echo '    "contract_doc": "docs/FRX_CROSS_VERSION_COMPATIBILITY_MATRIX_V1.md",'
    echo '    "matrix_json": "docs/frx_cross_version_compatibility_matrix_v1.json",'
    echo '    "integration_tests": "crates/franken-engine/tests/frx_cross_version_compatibility_matrix.rs",'
    echo '    "replay_wrapper": "scripts/e2e/frx_cross_version_compatibility_matrix_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "frx cross-version matrix manifest: ${manifest_path}"
  echo "frx cross-version matrix events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  write_manifest 1
  exit 1
fi

echo "parser log schema validation passed: ${events_path}"
exit "$main_exit"
