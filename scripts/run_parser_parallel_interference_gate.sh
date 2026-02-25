#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_parser_parallel_interference}"
artifact_root="${PARSER_PARALLEL_INTERFERENCE_ARTIFACT_ROOT:-artifacts/parser_parallel_interference}"
scenario_id="${PARSER_PARALLEL_INTERFERENCE_SCENARIO:-psrp-05-4-2}"
arch_profile="${PARSER_PARALLEL_INTERFERENCE_ARCH_PROFILE:-${PARSER_FRONTIER_RUST_HOST}}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-parser-parallel-interference-${timestamp}"
decision_id="decision-parser-parallel-interference-${timestamp}"
policy_id="policy-parser-parallel-interference-v1"
component="parser_parallel_interference_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for parser parallel interference gate runs" >&2
  exit 2
fi

run_rch() {
  RCH_QUIET=1 rch -q exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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

run_test_lane() {
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_correct_run_count" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_correct_run_count
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_many_worker_variations" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_many_worker_variations
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_deterministic_repeated" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_deterministic_repeated
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_operators_and_strings" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact evaluate_gate_operators_and_strings
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact compare_witnesses_all_fields_differ" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact compare_witnesses_all_fields_differ
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact build_replay_bundle_deduplicates_seeds_and_workers" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact build_replay_bundle_deduplicates_seeds_and_workers
  run_step \
    "cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact operator_summary_multiple_classes_sorted_by_count" \
    cargo test -p frankenengine-engine --test parallel_interference_gate_integration -- --exact operator_summary_multiple_classes_sorted_by_count
  run_step \
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact parse_parallel_merge_witness_present" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact parse_parallel_merge_witness_present
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration" \
        cargo check -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration
      ;;
    test)
      run_test_lane
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration" \
        cargo check -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration
      run_test_lane
      run_step \
        "cargo clippy -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test parallel_interference_gate_integration --test parallel_parser_integration -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
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
    error_code_json='"FE-PARSER-PARALLEL-INTERFERENCE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-parallel-interference.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-parallel-interference.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.5.4.2",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\"," 
    echo "  \"component\": \"${component}\"," 
    echo "  \"scenario_id\": \"${scenario_id}\"," 
    echo "  \"arch_profile\": \"$(parser_frontier_json_escape "${arch_profile}")\"," 
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
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\"," 
    fi
    echo '  "matrix_profile": {'
    echo '    "worker_counts": [2, 4, 8],'
    echo '    "seed_count": 3,'
    echo '    "repeats_per_seed": 2,'
    echo '    "adversarial_profiles": ["operators-and-strings", "witness-diff-synthetic"]'
    echo '  },'
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
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
    echo '    "contract_doc": "docs/PARSER_PARALLEL_INTERFERENCE_GATE.md",'
    echo '    "integration_tests": "crates/franken-engine/tests/parallel_interference_gate_integration.rs",'
    echo '    "parallel_parser_tests": "crates/franken-engine/tests/parallel_parser_integration.rs",'
    echo '    "source_modules": ["crates/franken-engine/src/parallel_interference_gate.rs", "crates/franken-engine/src/parallel_parser.rs"]'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser parallel interference manifest: ${manifest_path}"
  echo "parser parallel interference events: ${events_path}"
}

main_exit=0
set +e
run_mode
main_exit=$?
set -e
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
