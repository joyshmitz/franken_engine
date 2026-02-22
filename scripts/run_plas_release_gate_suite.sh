#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_plas_release_gate_${timestamp}}"
artifact_root="${PLAS_RELEASE_GATE_ARTIFACT_ROOT:-artifacts/plas_release_gate}"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/plas_release_gate_events.jsonl"
logs_dir="$run_dir/logs"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
bead_id="${PLAS_RELEASE_GATE_BEAD_ID:-bd-2n3}"

mkdir -p "$run_dir" "$logs_dir"

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
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
    return 0
  fi

  if rg -q "Remote command finished: exit=0" "$log_path"; then
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out or stalled" \
      | tee -a "$log_path"
    return 0
  fi

  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

json_or_null() {
  local value="$1"
  if [[ -n "$value" ]]; then
    printf '"%s"' "$value"
  else
    printf 'null'
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test plas_release_gate_integration" \
        cargo check -p frankenengine-engine --test plas_release_gate_integration
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test plas_release_gate_integration" \
        cargo test -p frankenengine-engine --test plas_release_gate_integration
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test plas_release_gate_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test plas_release_gate_integration -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test plas_release_gate_integration" \
        cargo check -p frankenengine-engine --test plas_release_gate_integration
      run_step "cargo test -p frankenengine-engine --test plas_release_gate_integration" \
        cargo test -p frankenengine-engine --test plas_release_gate_integration
      run_step "cargo clippy -p frankenengine-engine --test plas_release_gate_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test plas_release_gate_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
  mode_completed=true
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
    error_code_json='"FE-PLAS-RELEASE-GATE-0010"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$run_dir/commands.txt"
  failed_log_json="$(json_or_null "$failed_log_path")"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.plas-release-gate-suite.run-manifest.v1",'
    echo '  "component": "plas_release_gate_suite",'
    echo "  \"bead_id\": \"${bead_id}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
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
    echo "    \"command_log\": \"${run_dir}/commands.txt\"," 
    echo "    \"logs_dir\": \"${logs_dir}\"," 
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo '    "source_module": "crates/franken-engine/src/plas_release_gate.rs",'
    echo '    "integration_test": "crates/franken-engine/tests/plas_release_gate_integration.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${run_dir}/commands.txt\"," 
    echo "    \"find ${logs_dir} -maxdepth 1 -type f | sort\"," 
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"trace-plas-release-${timestamp}\",\"decision_id\":\"decision-plas-release-${timestamp}\",\"policy_id\":\"policy-plas-release-v1\",\"component\":\"plas_release_gate_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "PLAS release gate run manifest: $manifest_path"
  echo "PLAS release gate events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
