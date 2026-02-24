#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_phase1_arena}"
artifact_root="${PARSER_PHASE1_ARENA_ARTIFACT_ROOT:-artifacts/parser_phase1_arena}"
scenario="${PARSER_PHASE1_ARENA_SCENARIO:-full}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_id="trace-parser-phase1-arena-${scenario}-${timestamp}"
decision_id="decision-parser-phase1-arena-${scenario}-${timestamp}"
policy_id="policy-parser-phase1-arena-v1"
component="parser_phase1_arena_suite"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
manifest_written=false

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for parser phase1 arena suite runs" >&2
    return 127
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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

run_test_scenario() {
  case "$scenario" in
    full)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1" \
        cargo test -p frankenengine-engine --test parser_arena_phase1
      ;;
    smoke)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact arena_alloc_order_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact arena_alloc_order_is_deterministic
      ;;
    parity)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact semantic_roundtrip_preserves_hash" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact semantic_roundtrip_preserves_hash
      ;;
    budget_failures)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact budget_enforcement_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact budget_enforcement_is_deterministic
      ;;
    replay)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact arena_alloc_order_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact arena_alloc_order_is_deterministic
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact semantic_roundtrip_preserves_hash" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact semantic_roundtrip_preserves_hash
      ;;
    *)
      echo "unsupported PARSER_PHASE1_ARENA_SCENARIO: ${scenario}" >&2
      return 2
      ;;
  esac
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test parser_arena_phase1" \
        cargo check -p frankenengine-engine --test parser_arena_phase1
      ;;
    test)
      run_test_scenario
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_arena_phase1 -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_arena_phase1 -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_arena_phase1" \
        cargo check -p frankenengine-engine --test parser_arena_phase1
      run_test_scenario
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
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
    error_code_json='"FE-PARSER-PHASE1-ARENA-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-phase1-arena-suite.run-manifest.v1",'
    echo '  "bead_id": "bd-drjd",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"scenario\": \"${scenario}\","
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
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"PARSER_PHASE1_ARENA_SCENARIO=${scenario} ${0} ${mode}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser phase1 arena manifest: $manifest_path"
  echo "parser phase1 arena events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
