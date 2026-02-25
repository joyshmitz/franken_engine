#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_failover_controls}"
artifact_root="${PARSER_FAILOVER_CONTROLS_ARTIFACT_ROOT:-artifacts/parser_failover_controls}"
scenario_id="${PARSER_FAILOVER_CONTROLS_SCENARIO:-psrp-05-4-1}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-parser-failover-controls-${timestamp}"
decision_id="decision-parser-failover-controls-${timestamp}"
policy_id="policy-parser-failover-controls-v1"
component="parser_failover_controls_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for parser failover controls gate runs" >&2
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
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact parse_merge_buffer_exceeded_falls_back_serial" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact parse_merge_buffer_exceeded_falls_back_serial
  run_step \
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact log_entries_failover_include_trigger_transition_and_replay" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact log_entries_failover_include_trigger_transition_and_replay
  run_step \
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact replay_envelope_includes_failover_decision" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact replay_envelope_includes_failover_decision
  run_step \
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact failover_trigger_class_display" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact failover_trigger_class_display
  run_step \
    "cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact failover_decision_serde_roundtrip" \
    cargo test -p frankenengine-engine --test parallel_parser_integration -- --exact failover_decision_serde_roundtrip
}

run_mode() {
  case "$mode" in
    check)
      run_step \
        "cargo check -p frankenengine-engine --lib --test parallel_parser_integration" \
        cargo check -p frankenengine-engine --lib --test parallel_parser_integration
      ;;
    test)
      run_test_lane
      ;;
    clippy)
      run_step \
        "cargo clippy -p frankenengine-engine --lib --test parallel_parser_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test parallel_parser_integration -- -D warnings
      ;;
    ci)
      run_step \
        "cargo check -p frankenengine-engine --lib --test parallel_parser_integration" \
        cargo check -p frankenengine-engine --lib --test parallel_parser_integration
      run_test_lane
      run_step \
        "cargo clippy -p frankenengine-engine --lib --test parallel_parser_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test parallel_parser_integration -- -D warnings
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
    error_code_json='"FE-PARSER-FAILOVER-CONTROLS-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-failover-controls.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-failover-controls.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.5.4.1",'
    echo "  \"deterministic_env_schema_version\": \"${PARSER_FRONTIER_ENV_SCHEMA_VERSION}\","
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
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
    echo '    "contract_doc": "docs/PARSER_FALLBACK_FAILOVER_CONTROLS.md",'
    echo '    "integration_tests": "crates/franken-engine/tests/parallel_parser_integration.rs",'
    echo '    "source_module": "crates/franken-engine/src/parallel_parser.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser failover controls manifest: ${manifest_path}"
  echo "parser failover controls events: ${events_path}"
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
