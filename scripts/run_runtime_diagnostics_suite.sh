#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_runtime_diagnostics}"
seed="${RUNTIME_DIAGNOSTICS_SEED:-runtime-diagnostics-seed-v1}"
artifact_root="${RUNTIME_DIAGNOSTICS_ARTIFACT_ROOT:-artifacts/runtime_diagnostics}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
commands_path="$run_dir/commands.txt"
events_path="$run_dir/events.jsonl"

trace_id="trace-runtime-diagnostics-${timestamp}"
decision_id="decision-runtime-diagnostics-${timestamp}"
policy_id="policy-runtime-diagnostics-v1"
component="runtime_diagnostics_suite"

mkdir -p "$run_dir"

run_rch() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
  else
    echo "warning: rch not found; running locally for this environment" >&2
    env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! run_rch "$@"; then
    failed_command="$command_text"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli" \
        cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli" \
        cargo test -p frankenengine-engine --test runtime_diagnostics_cli
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
    error_code_json='"FE-RUNTIME-DIAGNOSTICS-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}" >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.runtime-diagnostics.run-manifest.v1",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"seed\": \"${seed}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
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
    echo "    \"manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "runtime diagnostics manifest: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
