#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_supremacy_criteria}"
artifact_root="${PARSER_SUPREMACY_CRITERIA_ARTIFACT_ROOT:-artifacts/parser_supremacy_criteria}"
criteria_version="0.1.0"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

run_id="parser-supremacy-criteria-${timestamp}"
trace_id="trace-parser-supremacy-criteria-${timestamp}"
decision_id="decision-parser-supremacy-criteria-${timestamp}"
policy_id="policy-parser-supremacy-criteria-v1"
component="parser_supremacy_criteria_gate"
artifact_bundle_id="parser_supremacy_criteria_contract_v1"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser supremacy criteria heavy commands" >&2
  exit 2
fi

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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
      run_step "cargo check -p frankenengine-engine --test parser_supremacy_criteria_contract" \
        cargo check -p frankenengine-engine --test parser_supremacy_criteria_contract
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test parser_supremacy_criteria_contract" \
        cargo test -p frankenengine-engine --test parser_supremacy_criteria_contract
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_supremacy_criteria_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_supremacy_criteria_contract -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_supremacy_criteria_contract" \
        cargo check -p frankenengine-engine --test parser_supremacy_criteria_contract
      run_step "cargo test -p frankenengine-engine --test parser_supremacy_criteria_contract" \
        cargo test -p frankenengine-engine --test parser_supremacy_criteria_contract
      run_step "cargo clippy -p frankenengine-engine --test parser_supremacy_criteria_contract -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_supremacy_criteria_contract -- -D warnings
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
    error_code_json='"FE-PARSER-SUPREMACY-CRITERIA-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"run_id\":\"${run_id}\",\"criteria_version\":\"${criteria_version}\",\"git_sha\":\"${git_commit}\",\"artifact_bundle_id\":\"${artifact_bundle_id}\",\"verdict\":\"${outcome}\",\"replay_command\":\"${replay_command}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-supremacy-criteria.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.8.1",'
    echo "  \"criteria_version\": \"${criteria_version}\"," 
    echo "  \"component\": \"${component}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"run_id\": \"${run_id}\"," 
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
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo '    "criteria_doc": "docs/PARSER_SUPREMACY_CRITERIA_CONTRACT.md",'
    echo '    "criteria_fixture": "crates/franken-engine/tests/fixtures/parser_supremacy_criteria_contract_v1.json",'
    echo '    "criteria_tests": "crates/franken-engine/tests/parser_supremacy_criteria_contract.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser supremacy criteria manifest: ${manifest_path}"
  echo "parser supremacy criteria events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
