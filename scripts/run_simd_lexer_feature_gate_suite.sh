#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
scenario="${SIMD_LEXER_FEATURE_GATE_SCENARIO:-full}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_simd_lexer_feature_gate}"
artifact_root="${SIMD_LEXER_FEATURE_GATE_ARTIFACT_ROOT:-artifacts/simd_lexer_feature_gate}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_id="trace-simd-lexer-feature-gate-${scenario}-${timestamp}"
decision_id="decision-simd-lexer-feature-gate-${scenario}-${timestamp}"
policy_id="policy-simd-lexer-feature-gate-v1"
component="simd_lexer_feature_gate_suite"
bead_id="bd-2mds.1.3.4"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
manifest_written=false

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for SIMD lexer feature-gate runs" >&2
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

resolve_failure_code() {
  case "$scenario" in
    fallback_matrix)
      echo "FE-SIMD-LEXER-FEATURE-GATE-0002"
      ;;
    witness)
      echo "FE-SIMD-LEXER-FEATURE-GATE-0003"
      ;;
    smoke)
      echo "FE-SIMD-LEXER-FEATURE-GATE-0004"
      ;;
    *)
      echo "FE-SIMD-LEXER-FEATURE-GATE-0001"
      ;;
  esac
}

run_test_scenario() {
  case "$scenario" in
    full)
      run_step "cargo test -p frankenengine-engine simd_lexer" \
        cargo test -p frankenengine-engine simd_lexer
      ;;
    smoke)
      run_step "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact scalar_swar_parity_simple" \
        cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact scalar_swar_parity_simple
      ;;
    fallback_matrix)
      run_step "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact fallback_matrix_rejects_missing_avx2_gate" \
        cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact fallback_matrix_rejects_missing_avx2_gate
      run_step "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact fallback_matrix_rejects_big_endian_profile" \
        cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact fallback_matrix_rejects_big_endian_profile
      ;;
    witness)
      run_step "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_contains_replay_command" \
        cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_contains_replay_command
      run_step "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_serde_roundtrip" \
        cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_serde_roundtrip
      ;;
    *)
      echo "unsupported SIMD_LEXER_FEATURE_GATE_SCENARIO: ${scenario}" >&2
      return 2
      ;;
  esac
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test simd_lexer_integration" \
        cargo check -p frankenengine-engine --test simd_lexer_integration
      ;;
    test)
      run_test_scenario
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test simd_lexer_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test simd_lexer_integration -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test simd_lexer_integration" \
        cargo check -p frankenengine-engine --test simd_lexer_integration
      run_test_scenario
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      return 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree outcome error_code error_code_json idx comma replay_command

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

  replay_command="SIMD_LEXER_FEATURE_GATE_SCENARIO=${scenario} ${0} ${mode}"

  {
    echo "{\"schema_version\":\"franken-engine.simd-lexer-feature-gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"scenario\":\"${scenario}\",\"mode\":\"${mode}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.simd-lexer-feature-gate.run-manifest.v1",'
    echo "  \"bead_id\": \"${bead_id}\"," 
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
    echo '  },'
    echo "  \"replay_command\": \"${replay_command}\"," 
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" -eq $((${#commands_run[@]} - 1)) ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "simd lexer feature-gate run manifest: ${manifest_path}"
  echo "simd lexer feature-gate events: ${events_path}"
}

cleanup() {
  local exit_code=$?
  write_manifest "$exit_code"
  exit "$exit_code"
}
trap cleanup EXIT

run_mode
