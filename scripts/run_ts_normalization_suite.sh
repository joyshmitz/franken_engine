#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_ts_normalization}"
artifact_root="${TS_NORMALIZATION_ARTIFACT_ROOT:-artifacts/ts_normalization}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
trace_id="trace-ts-normalization-$timestamp"
decision_id="decision-ts-normalization-$timestamp"
policy_id="policy-ts-normalization-v1"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
manifest_written=false

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for TS normalization suite runs" >&2
    return 127
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

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
      run_step "cargo check -p frankenengine-engine --test ts_normalization" \
        cargo check -p frankenengine-engine --test ts_normalization
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test ts_normalization" \
        cargo test -p frankenengine-engine --test ts_normalization
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test ts_normalization" \
        cargo check -p frankenengine-engine --test ts_normalization
      run_step "cargo test -p frankenengine-engine --test ts_normalization" \
        cargo test -p frankenengine-engine --test ts_normalization
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-TSNORM-0004"'
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
    echo '  "component": "ts_normalization_suite",'
    echo '  "bead_id": "bd-309",'
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
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
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"command_log\": \"${run_dir}/commands.txt\""
    echo '  }'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"ts_normalization_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "ts-normalization manifest: $manifest_path"
  echo "ts-normalization events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
