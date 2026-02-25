#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

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
allocator_epoch="${PARSER_PHASE1_ARENA_ALLOCATOR_EPOCH:-phase1-v1}"
arena_fragmentation_ratio="${PARSER_PHASE1_ARENA_FRAGMENTATION_RATIO:-0.0}"
arena_fragmentation_threshold="${PARSER_PHASE1_ARENA_FRAGMENTATION_THRESHOLD:-0.15}"
rollback_token="${PARSER_PHASE1_ARENA_ROLLBACK_TOKEN:-parser-phase1-arena-rollback-disabled}"

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

fragmentation_ratio_exceeds_threshold() {
  awk -v ratio="${arena_fragmentation_ratio}" -v threshold="${arena_fragmentation_threshold}" 'BEGIN { exit !(ratio > threshold) }'
}

resolve_failure_code() {
  if [[ "${failed_command}" == fragmentation_threshold_check* ]]; then
    echo "FE-PARSER-PHASE1-ARENA-FRAG-0001"
    return
  fi

  case "$scenario" in
    budget_failures)
      echo "FE-PARSER-PHASE1-ARENA-BUDGET-0001"
      ;;
    handle_audit | corruption_injection)
      echo "FE-PARSER-PHASE1-ARENA-HANDLE-0001"
      ;;
    parity | replay)
      echo "FE-PARSER-PHASE1-ARENA-PARITY-0001"
      ;;
    *)
      echo "FE-PARSER-PHASE1-ARENA-0001"
      ;;
  esac
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
    handle_audit)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact handle_audit_entries_are_deterministic" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact handle_audit_entries_are_deterministic
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact handle_audit_jsonl_is_parseable_and_stable" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact handle_audit_jsonl_is_parseable_and_stable
      ;;
    corruption_injection)
      run_step "cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact corruption_injection_guards_fail_closed_deterministically" \
        cargo test -p frankenengine-engine --test parser_arena_phase1 -- --exact corruption_injection_guards_fail_closed_deterministically
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
  local git_commit dirty_worktree idx comma outcome error_code_json error_code

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code="$(resolve_failure_code)"
    error_code_json="\"${error_code}\""
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  local replay_command
  replay_command="PARSER_PHASE1_ARENA_SCENARIO=${scenario} ${0} ${mode}"

  {
    echo "{\"schema_version\":\"franken-engine.parser-phase1-arena-suite.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"allocator_epoch\":\"${allocator_epoch}\",\"handle_kind\":\"mixed\",\"arena_fragmentation_ratio\":${arena_fragmentation_ratio},\"arena_fragmentation_threshold\":${arena_fragmentation_threshold},\"rollback_token\":\"${rollback_token}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-phase1-arena-suite.run-manifest.v1",'
    echo '  "bead_id": "bd-drjd",'
    echo '  "deterministic_env_schema_version": "franken-engine.parser-frontier.env-contract.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"scenario\": \"${scenario}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"allocator_epoch\": \"${allocator_epoch}\","
    echo "  \"arena_fragmentation_ratio\": ${arena_fragmentation_ratio},"
    echo "  \"arena_fragmentation_threshold\": ${arena_fragmentation_threshold},"
    echo "  \"rollback_token\": \"${rollback_token}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "deterministic_environment": {'
    echo "    \"timezone\": \"${TZ}\","
    echo "    \"lang\": \"${LANG}\","
    echo "    \"lc_all\": \"${LC_ALL}\","
    echo "    \"source_date_epoch\": \"${SOURCE_DATE_EPOCH}\","
    echo "    \"rustc_version\": \"${PARSER_FRONTIER_RUSTC_VERSION}\","
    echo "    \"cargo_version\": \"${PARSER_FRONTIER_CARGO_VERSION}\","
    echo "    \"rust_host\": \"${PARSER_FRONTIER_RUST_HOST}\","
    echo "    \"cpu_fingerprint\": \"${PARSER_FRONTIER_CPU_FINGERPRINT}\","
    echo "    \"rustc_verbose_hash\": \"${PARSER_FRONTIER_RUSTC_VERBOSE_HASH}\","
    echo "    \"toolchain_fingerprint\": \"${PARSER_FRONTIER_TOOLCHAIN_FINGERPRINT}\","
    echo '    "seed_transcript_checksum": null'
    echo "  },"
    echo "  \"replay_command\": \"${replay_command}\","
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
    echo '  "failure_code_mapping": {'
    echo '    "generic": "FE-PARSER-PHASE1-ARENA-0001",'
    echo '    "budget_failure": "FE-PARSER-PHASE1-ARENA-BUDGET-0001",'
    echo '    "handle_integrity": "FE-PARSER-PHASE1-ARENA-HANDLE-0001",'
    echo '    "parity_or_replay": "FE-PARSER-PHASE1-ARENA-PARITY-0001",'
    echo '    "fragmentation_threshold": "FE-PARSER-PHASE1-ARENA-FRAG-0001"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser phase1 arena manifest: $manifest_path"
  echo "parser phase1 arena events: $events_path"
}

main_exit=0
run_mode || main_exit=$?

if [[ "$main_exit" -eq 0 ]] && fragmentation_ratio_exceeds_threshold; then
  failed_command="fragmentation_threshold_check(${arena_fragmentation_ratio}>${arena_fragmentation_threshold})"
  echo "fragmentation threshold violated: ratio=${arena_fragmentation_ratio} threshold=${arena_fragmentation_threshold}" >&2
  main_exit=3
fi

write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
