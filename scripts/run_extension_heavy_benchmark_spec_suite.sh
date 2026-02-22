#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-default}"
component="${BENCH_COMPONENT:-extension_heavy_benchmark_suite_contract}"
bead_id="${BEAD_ID:-bd-2ql}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/extension_heavy_benchmark_spec/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/extension_heavy_benchmark_spec_events.jsonl"

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
  run_step "cargo check -p frankenengine-engine --test extension_heavy_benchmark_spec --test extension_heavy_benchmark_matrix" \
    cargo check -p frankenengine-engine --test extension_heavy_benchmark_spec --test extension_heavy_benchmark_matrix
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test extension_heavy_benchmark_spec --test extension_heavy_benchmark_matrix" \
    cargo test -p frankenengine-engine --test extension_heavy_benchmark_spec --test extension_heavy_benchmark_matrix
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test extension_heavy_benchmark_spec --test extension_heavy_benchmark_matrix -- -D warnings" \
    cargo clippy -p frankenengine-engine --test extension_heavy_benchmark_spec --test extension_heavy_benchmark_matrix -- -D warnings
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
    error_code_json='"FE-BENCH-0006"'
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
    echo '  "schema_version": "franken-engine.extension-heavy-benchmark-spec.run-manifest.v1",'
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
    echo '    "spec": "docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md",'
    echo '    "workload_matrix": "docs/extension_heavy_workload_matrix_v1.json",'
    echo '    "golden_outputs": "docs/extension_heavy_golden_outputs_v1.json",'
    echo '    "tests": [' 
    echo '      "crates/franken-engine/tests/extension_heavy_benchmark_spec.rs",'
    echo '      "crates/franken-engine/tests/extension_heavy_benchmark_matrix.rs"'
    echo '    ]'
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
    echo "{\"trace_id\":\"trace-ext-heavy-benchmark-suite-${timestamp}\",\"decision_id\":\"decision-ext-heavy-benchmark-suite-${timestamp}\",\"policy_id\":\"policy-ext-heavy-benchmark-suite-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  echo "extension-heavy benchmark spec run manifest: ${manifest_path}"
  echo "extension-heavy benchmark spec events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
