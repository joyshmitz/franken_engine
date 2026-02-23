#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_opportunity_matrix_${timestamp}}"
artifact_root="${OPPORTUNITY_MATRIX_ARTIFACT_ROOT:-artifacts/opportunity_matrix}"
run_dir="${artifact_root}/${timestamp}"
logs_dir="${run_dir}/logs"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-600}"
bead_id="${OPPORTUNITY_MATRIX_BEAD_ID:-bd-js4}"
component="opportunity_matrix"

mkdir -p "$logs_dir"

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"
  if "$@" > >(tee "$log_path") 2>&1; then
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
      run_step "cargo check -p frankenengine-engine --test opportunity_matrix" \
        run_rch cargo check -p frankenengine-engine --test opportunity_matrix
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib opportunity_matrix" \
        run_rch cargo test -p frankenengine-engine --lib opportunity_matrix
      run_step "cargo test -p frankenengine-engine --test opportunity_matrix" \
        run_rch cargo test -p frankenengine-engine --test opportunity_matrix
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test opportunity_matrix -- -D warnings" \
        run_rch cargo clippy -p frankenengine-engine --test opportunity_matrix -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test opportunity_matrix" \
        run_rch cargo check -p frankenengine-engine --test opportunity_matrix
      run_step "cargo test -p frankenengine-engine --lib opportunity_matrix" \
        run_rch cargo test -p frankenengine-engine --lib opportunity_matrix
      run_step "cargo test -p frankenengine-engine --test opportunity_matrix" \
        run_rch cargo test -p frankenengine-engine --test opportunity_matrix
      run_step "cargo clippy -p frankenengine-engine --test opportunity_matrix -- -D warnings" \
        run_rch cargo clippy -p frankenengine-engine --test opportunity_matrix -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      return 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome failed_log_json idx comma

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  else
    failed_log_json="null"
  fi

  {
    echo "{"
    echo "  \"schema_version\": \"franken-engine.${component}.suite-manifest.v1\","
    echo "  \"bead_id\": \"$(json_escape "$bead_id")\","
    echo "  \"component\": \"$(json_escape "$component")\","
    echo "  \"timestamp_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"mode\": \"$(json_escape "$mode")\","
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\","
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"outcome\": \"$(json_escape "$outcome")\","
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"failed_log\": ${failed_log_json},"
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
    echo "    \"manifest\": \"$(json_escape "$manifest_path")\","
    echo "    \"commands\": \"$(json_escape "$commands_path")\","
    echo "    \"logs_dir\": \"$(json_escape "$logs_dir")\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat $(json_escape "$manifest_path")\","
    echo "    \"cat $(json_escape "$commands_path")\","
    echo "    \"find $(json_escape "$logs_dir") -maxdepth 1 -type f | sort\","
    echo "    \"$(json_escape "$0") ci\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "Manifest written to: $manifest_path"
}

set +e
run_mode
exit_code=$?
set -e

write_manifest "$exit_code"
exit "$exit_code"
