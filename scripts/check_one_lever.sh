#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
seed="${ONE_LEVER_POLICY_SEED:-one-lever-policy-seed-v1}"
artifact_root="${ONE_LEVER_POLICY_ARTIFACT_ROOT:-artifacts/one_lever_policy}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_one_lever_${timestamp}}"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
logs_dir="$run_dir/logs"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"

mkdir -p "$run_dir" "$logs_dir"

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

json_escape() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//$'\n'/\\n}"
  printf '%s' "$input"
}

declare -a commands_run=()
declare -a command_logs=()
failed_command=""
failed_log_path=""
manifest_written=false

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
    echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
      | tee -a "$log_path"
    return 0
  fi

  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test one_lever_policy" \
        cargo check -p frankenengine-engine --test one_lever_policy
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib one_lever_policy" \
        cargo test -p frankenengine-engine --lib one_lever_policy
      run_step "cargo test -p frankenengine-engine --test one_lever_policy" \
        cargo test -p frankenengine-engine --test one_lever_policy
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test one_lever_policy -- -D warnings" \
        cargo clippy -p frankenengine-engine --test one_lever_policy -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test one_lever_policy" \
        cargo check -p frankenengine-engine --test one_lever_policy
      run_step "cargo test -p frankenengine-engine --lib one_lever_policy" \
        cargo test -p frankenengine-engine --lib one_lever_policy
      run_step "cargo test -p frankenengine-engine --test one_lever_policy" \
        cargo test -p frankenengine-engine --test one_lever_policy
      run_step "cargo clippy -p frankenengine-engine --test one_lever_policy -- -D warnings" \
        cargo clippy -p frankenengine-engine --test one_lever_policy -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome failed_log_json

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

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  else
    failed_log_json="null"
  fi

  {
    echo "{"
    echo '  "schema_version": "franken-engine.one-lever-policy.run-manifest.v1",'
    echo '  "component": "one_lever_policy",'
    echo "  \"mode\": \"$(json_escape "$mode")\","
    echo "  \"seed\": \"$(json_escape "$seed")\","
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\","
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\","
    echo "  \"git_commit\": \"$(json_escape "$git_commit")\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"outcome\": \"$(json_escape "$outcome")\","
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"failed_log\": ${failed_log_json},"
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "command_logs": ['
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${command_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"commands\": \"$(json_escape "$run_dir/commands.txt")\","
    echo "    \"logs_dir\": \"$(json_escape "$logs_dir")\","
    echo "    \"manifest\": \"$(json_escape "$manifest_path")\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat $(json_escape "$manifest_path")\","
    echo "    \"cat $(json_escape "$run_dir/commands.txt")\","
    echo "    \"find $(json_escape "$logs_dir") -maxdepth 1 -type f | sort\","
    echo "    \"$(json_escape "$0") ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "Manifest written to: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
