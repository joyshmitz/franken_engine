#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/data/projects/franken_engine/target_rch_rgc_cli_operator_workflow_verification_pack}"
artifact_root="${RGC_CLI_OPERATOR_WORKFLOW_ARTIFACT_ROOT:-artifacts/rgc_cli_operator_workflow_verification_pack}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-rgc-cli-operator-workflow-verification-pack-${timestamp}"
decision_id="decision-rgc-cli-operator-workflow-verification-pack-${timestamp}"
policy_id="policy-rgc-cli-operator-workflow-verification-pack-v1"
component="rgc_cli_operator_workflow_verification_pack_gate"
scenario_id="rgc-061"
replay_command="./scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC CLI/operator workflow verification pack heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  step_log_index=$((step_log_index + 1))
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  if ! run_rch "$@" > >(tee "$step_log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$step_log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$step_log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
  check)
    run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    ;;
  test)
    run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    ;;
  clippy)
    run_step "cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings
    ;;
  ci)
    run_step "cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo check -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    run_step "cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack" \
      cargo test -p frankenengine-engine --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack
    run_step "cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings" \
      cargo clippy -p frankenengine-engine --bin runtime_diagnostics --test runtime_diagnostics_cli --test rgc_cli_operator_workflow_verification_pack -- -D warnings
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
    error_code_json='"FE-RGC-061-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-cli-operator-workflow-verification-pack.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"path_type\":\"golden\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.rgc-cli-operator-workflow-verification-pack.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.11",'
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
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\"," 
    fi
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\"," 
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo '    "contract_doc": "docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md",'
    echo '    "contract_json": "docs/rgc_cli_operator_workflow_verification_pack_v1.json",'
    echo '    "gate_tests": "crates/franken-engine/tests/rgc_cli_operator_workflow_verification_pack.rs",'
    echo '    "runtime_cli_tests": "crates/franken-engine/tests/runtime_diagnostics_cli.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo '    "jq empty docs/rgc_cli_operator_workflow_verification_pack_v1.json",'
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "rgc cli/operator workflow verification pack manifest: ${manifest_path}"
  echo "rgc cli/operator workflow verification pack events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
