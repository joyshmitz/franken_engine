#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-default}"
component="benchmark_denominator"
bead_id="bd-2n9"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/benchmark_denominator/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/benchmark_denominator_events.jsonl"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- "$@"
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

run_check() {
  run_step "cargo check -p frankenengine-engine --test benchmark_denominator" \
    cargo check -p frankenengine-engine --test benchmark_denominator
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test benchmark_denominator" \
    cargo test -p frankenengine-engine --test benchmark_denominator
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test benchmark_denominator -- -D warnings" \
    cargo clippy -p frankenengine-engine --test benchmark_denominator -- -D warnings
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
    ci)
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

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi
  if [[ -n "$failed_command" ]]; then
    error_code_json='"FE-BENCH-1007"'
  else
    error_code_json='null'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${run_dir}/commands.txt"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.benchmark-denominator.run-manifest.v1",'
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
    echo "    \"command_log\": \"${run_dir}/commands.txt\"," 
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo '    "module": "crates/franken-engine/src/benchmark_denominator.rs",'
    echo '    "tests": "crates/franken-engine/tests/benchmark_denominator.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${run_dir}/commands.txt\"," 
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    echo "{\"trace_id\":\"trace-benchmark-denominator-${timestamp}\",\"decision_id\":\"decision-benchmark-denominator-${timestamp}\",\"policy_id\":\"policy-benchmark-denominator-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  echo "benchmark denominator run manifest: ${manifest_path}"
  echo "benchmark denominator events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
