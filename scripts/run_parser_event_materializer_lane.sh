#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_event_materializer}"
artifact_root="${PARSER_EVENT_MATERIALIZER_ARTIFACT_ROOT:-artifacts/parser_event_materializer}"
scenario="${PARSER_EVENT_MATERIALIZER_SCENARIO:-parity}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_id="trace-parser-event-materializer-${scenario}-${timestamp}"
decision_id="decision-parser-event-materializer-${scenario}-${timestamp}"
policy_id="policy-parser-event-materializer-v1"
component="parser_event_materializer_lane"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
manifest_written=false

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for parser event materializer lane runs" >&2
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
    parity)
      run_step "cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_event_to_ast_hash_parity_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_event_to_ast_hash_parity_is_deterministic
      run_step "cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_event_to_ast_node_id_witnesses_are_stable" \
        cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_event_to_ast_node_id_witnesses_are_stable
      ;;
    tamper)
      run_step "cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_event_to_ast_tamper_detection_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_event_to_ast_tamper_detection_is_deterministic
      ;;
    replay)
      run_step "cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_with_materialized_ast_replay_contract_is_deterministic" \
        cargo test -p frankenengine-engine --test parser_trait_ast -- --exact canonical_parse_with_materialized_ast_replay_contract_is_deterministic
      ;;
    full)
      run_step "cargo test -p frankenengine-engine --test parser_trait_ast" \
        cargo test -p frankenengine-engine --test parser_trait_ast
      ;;
    *)
      echo "unsupported PARSER_EVENT_MATERIALIZER_SCENARIO: ${scenario}" >&2
      return 2
      ;;
  esac
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test parser_trait_ast" \
        cargo check -p frankenengine-engine --test parser_trait_ast
      ;;
    test)
      run_test_scenario
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_trait_ast -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_trait_ast -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_trait_ast" \
        cargo check -p frankenengine-engine --test parser_trait_ast
      run_test_scenario
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

resolve_error_code() {
  case "$scenario" in
    parity)
      echo "FE-PARSER-EVENT-MATERIALIZER-PARITY-0001"
      ;;
    tamper)
      echo "FE-PARSER-EVENT-MATERIALIZER-TAMPER-0001"
      ;;
    replay)
      echo "FE-PARSER-EVENT-MATERIALIZER-REPLAY-0001"
      ;;
    full)
      echo "FE-PARSER-EVENT-MATERIALIZER-FULL-0001"
      ;;
    *)
      echo "FE-PARSER-EVENT-MATERIALIZER-0001"
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json replay_command

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json="\"$(resolve_error_code)\""
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  replay_command="PARSER_EVENT_MATERIALIZER_SCENARIO=${scenario} ${0} ${mode}"

  {
    echo "{\"schema_version\":\"franken-engine.parser-event-materializer-lane.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"lane_completed\",\"scenario\":\"${scenario}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-event-materializer-lane.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.4.3",'
    echo '  "deterministic_env_schema_version": "franken-engine.parser-frontier.env-contract.v1",'
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
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser event materializer lane manifest: $manifest_path"
  echo "parser event materializer lane events: $events_path"
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
