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
step_logs_dir="${run_dir}/step_logs"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
rch_build_timeout_sec="${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-2}"
trace_id="trace-parser-phase1-arena-${scenario}-${timestamp}"
decision_id="decision-parser-phase1-arena-${scenario}-${timestamp}"
policy_id="policy-parser-phase1-arena-v1"
component="parser_phase1_arena_suite"
allocator_epoch="${PARSER_PHASE1_ARENA_ALLOCATOR_EPOCH:-phase1-v1}"
arena_fragmentation_ratio="${PARSER_PHASE1_ARENA_FRAGMENTATION_RATIO:-0.0}"
arena_fragmentation_threshold="${PARSER_PHASE1_ARENA_FRAGMENTATION_THRESHOLD:-0.15}"
rollback_token="${PARSER_PHASE1_ARENA_ROLLBACK_TOKEN:-parser-phase1-arena-rollback-disabled}"

mkdir -p "$run_dir" "$step_logs_dir"

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
failed_step_log_path=""
step_counter=0
manifest_written=false

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for parser phase1 arena suite runs" >&2
    return 127
  fi
  RCH_BUILD_TIMEOUT_SEC="${rch_build_timeout_sec}" \
    timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(grep -Eo 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts' "$log_path"
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23' "$log_path"; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

run_step() {
  local command_text="$1"
  local log_path run_rc remote_exit_code
  shift

  step_counter=$((step_counter + 1))
  log_path="${step_logs_dir}/step_${step_counter}.log"
  commands_run+=("$command_text")
  step_logs+=("$log_path")
  echo "==> $command_text"

  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    run_rc=0
  else
    run_rc=$?
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      if [[ "$run_rc" -eq 124 ]]; then
        failed_command="${command_text} (timeout-${rch_timeout_seconds}s)"
      elif [[ -n "$remote_exit_code" ]]; then
        failed_command="${command_text} (remote-exit-${remote_exit_code})"
      else
        failed_command="${command_text} (rch-exit-${run_rc})"
      fi
      failed_step_log_path="$log_path"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    failed_step_log_path="$log_path"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    failed_step_log_path="$log_path"
    return 1
  fi

  remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
  if [[ "$remote_exit_code" != "0" ]]; then
    if [[ -z "$remote_exit_code" ]]; then
      echo "rch output missing remote exit marker; failing closed" | tee -a "$log_path"
      failed_command="${command_text} (missing-remote-exit-marker)"
    else
      failed_command="${command_text} (remote-exit-${remote_exit_code})"
    fi
    failed_step_log_path="$log_path"
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
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"rch_build_timeout_seconds\": ${rch_build_timeout_sec},"
    echo "  \"cargo_build_jobs\": ${cargo_build_jobs},"
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
    if [[ -n "$failed_step_log_path" ]]; then
      echo "  \"failed_step_log\": \"${failed_step_log_path}\","
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
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"step_logs_dir\": \"${step_logs_dir}\""
    echo "  },"
    echo '  "step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${step_logs[$idx]}\"${comma}"
    done
    echo "  ],"
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
    echo "    \"ls -1 ${step_logs_dir}\","
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
