#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-default}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_constrained_ambient_lane}"
component="constrained_ambient_benchmark_lane"
bead_id="bd-3qv"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/constrained_ambient_benchmark_lane/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/constrained_ambient_benchmark_lane_events.jsonl"
commands_path="${run_dir}/commands.txt"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
}

declare -a commands_run=()
failed_command=""
manifest_written=false
expected_steps=0

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

run_check() {
  run_step "cargo check -p frankenengine-engine --test constrained_ambient_benchmark_lane" \
    cargo check -p frankenengine-engine --test constrained_ambient_benchmark_lane
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test constrained_ambient_benchmark_lane" \
    cargo test -p frankenengine-engine --test constrained_ambient_benchmark_lane
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test constrained_ambient_benchmark_lane -- -D warnings" \
    cargo clippy -p frankenengine-engine --test constrained_ambient_benchmark_lane -- -D warnings
}

run_mode() {
  expected_steps=0
  case "$mode" in
    check)
      expected_steps=1
      run_check
      ;;
    test)
      expected_steps=1
      run_test
      ;;
    clippy)
      expected_steps=1
      run_clippy
      ;;
    ci)
      expected_steps=3
      run_check
      run_test
      run_clippy
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
  local suite_incomplete=false

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "${#commands_run[@]}" -lt "$expected_steps" ]]; then
    suite_incomplete=true
  fi

  if [[ "$exit_code" -eq 0 && "$suite_incomplete" == false ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  if [[ "$suite_incomplete" == true && -z "$failed_command" ]]; then
    failed_command="incomplete_suite:executed_${#commands_run[@]}_of_${expected_steps}"
  fi

  if [[ -n "$failed_command" || "$suite_incomplete" == true ]]; then
    error_code_json='"FE-CABL-1005"'
  else
    error_code_json='null'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.constrained-ambient-lane.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
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
    echo "    \"command_log\": \"${commands_path}\","
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo '    "module": "crates/franken-engine/src/constrained_ambient_benchmark_lane.rs",'
    echo '    "tests": "crates/franken-engine/tests/constrained_ambient_benchmark_lane.rs",'
    echo '    "suite_script": "scripts/run_constrained_ambient_benchmark_lane_suite.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    echo "{\"trace_id\":\"trace-constrained-ambient-lane-${timestamp}\",\"decision_id\":\"decision-constrained-ambient-lane-${timestamp}\",\"policy_id\":\"policy-constrained-ambient-lane-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  echo "constrained ambient lane run manifest: ${manifest_path}"
  echo "constrained ambient lane events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
