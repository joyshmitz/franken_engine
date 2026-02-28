#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_BASELINE_E2E_SCAFFOLD_ARTIFACT_ROOT:-artifacts/rgc_baseline_e2e_scaffold}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/data/projects/franken_engine/target_rch_rgc_baseline_e2e"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-rgc-baseline-e2e-${timestamp}"
decision_id="decision-rgc-baseline-e2e-${timestamp}"
policy_id="policy-rgc-baseline-e2e-v1"
component="rgc_baseline_e2e_scaffold_gate"
scenario_id="rgc-053a"
replay_command="./scripts/e2e/rgc_baseline_e2e_scaffold_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC baseline e2e scaffold heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q 'Remote command finished: exit=0' "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi

  rm -f "$log_path"
}

run_mode() {
  local selected_mode="${1:-$mode}"
  case "$selected_mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib --test rgc_test_harness_integration" \
        cargo check -p frankenengine-engine --lib --test rgc_test_harness_integration
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test rgc_test_harness_integration -- --exact rgc_baseline_registry_selection_and_validator_cover_representative_lanes" \
        cargo test -p frankenengine-engine --test rgc_test_harness_integration -- --exact rgc_baseline_registry_selection_and_validator_cover_representative_lanes
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::baseline_registry_covers_runtime_module_security_happy_and_failure" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::baseline_registry_covers_runtime_module_security_happy_and_failure
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::baseline_selection_is_deterministic_and_filterable" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::baseline_selection_is_deterministic_and_filterable
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_accepts_valid_harness_triad" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_accepts_valid_harness_triad
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_reports_missing_and_malformed_artifacts" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_validator_reports_missing_and_malformed_artifacts
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test rgc_test_harness_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_test_harness_integration -- -D warnings
      ;;
    ci)
      run_mode check
      run_mode test
      run_mode clippy
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
    error_code_json='"FE-RGC-053A-E2E-SCAFFOLD-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-baseline-e2e-scaffold.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo '{'
    echo '  "schema_version": "franken-engine.rgc-baseline-e2e-scaffold.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.15",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields '    ' 'null'
    echo '  },'
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo '    "module": "crates/franken-engine/src/rgc_test_harness.rs",'
    echo '    "integration_tests": "crates/franken-engine/tests/rgc_test_harness_integration.rs",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_baseline_e2e_scaffold_replay.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo '}'
  } >"$manifest_path"

  echo "rgc baseline e2e scaffold manifest: ${manifest_path}"
  echo "rgc baseline e2e scaffold events: ${events_path}"
  echo "rgc baseline e2e scaffold commands: ${commands_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
