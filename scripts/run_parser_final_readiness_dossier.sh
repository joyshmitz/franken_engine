#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${PARSER_FINAL_READINESS_DOSSIER_ARTIFACT_ROOT:-artifacts/parser_final_readiness_dossier}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_final_readiness_dossier_${timestamp}}"
fixture_path="crates/franken-engine/tests/fixtures/parser_final_readiness_dossier_v1.json"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-parser-final-readiness-dossier-${timestamp}"
decision_id="decision-parser-final-readiness-dossier-${timestamp}"
policy_id="policy-parser-final-readiness-dossier-v1"
component="parser_final_readiness_dossier_gate"
replay_command="./scripts/e2e/parser_final_readiness_dossier_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser final readiness dossier heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to emit parser final readiness structured inventories" >&2
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

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
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
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code run_rc
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="$(mktemp)"

  run_rc=0
  if run_rch "$@" > >(tee "$log_path") 2>&1; then
    run_rc=0
  else
    run_rc=$?
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if [[ "$run_rc" -ne 0 ]]; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return "$run_rc"
    fi
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
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test parser_final_readiness_dossier" \
        cargo check -p frankenengine-engine --test parser_final_readiness_dossier
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test parser_final_readiness_dossier" \
        cargo test -p frankenengine-engine --test parser_final_readiness_dossier
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test parser_final_readiness_dossier -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_final_readiness_dossier -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test parser_final_readiness_dossier" \
        cargo check -p frankenengine-engine --test parser_final_readiness_dossier
      run_step "cargo test -p frankenengine-engine --test parser_final_readiness_dossier" \
        cargo test -p frankenengine-engine --test parser_final_readiness_dossier
      run_step "cargo clippy -p frankenengine-engine --test parser_final_readiness_dossier -- -D warnings" \
        cargo clippy -p frankenengine-engine --test parser_final_readiness_dossier -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

json_array_or_empty() {
  local jq_expr="$1"
  if [[ -f "$fixture_path" ]]; then
    jq -c "$jq_expr" "$fixture_path"
  else
    echo "[]"
  fi
}

json_string_or_default() {
  local jq_expr="$1"
  local default_value="$2"
  if [[ -f "$fixture_path" ]]; then
    jq -r "$jq_expr // \"${default_value}\"" "$fixture_path"
  else
    echo "$default_value"
  fi
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma
  local blocked_dependencies risk_ids hold_reasons expected_outcome dossier_version dossier_id bead_id

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PARSER-FINAL-DOSSIER-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  blocked_dependencies="$(json_array_or_empty '.blocked_dependency_ids')"
  risk_ids="$(json_array_or_empty '[.residual_risks[].risk_id]')"
  hold_reasons="$(json_array_or_empty '.expected_gate.expected_hold_reasons')"
  expected_outcome="$(json_string_or_default '.expected_gate.expected_outcome' 'unknown')"
  dossier_version="$(json_string_or_default '.dossier_version' 'unknown')"
  dossier_id="$(json_string_or_default '.dossier_id' 'unknown')"
  bead_id="$(json_string_or_default '.bead_id' 'bd-2mds.1.8.4')"

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"final_readiness_dossier_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"dossier_id\":\"${dossier_id}\",\"risk_register_hash\":\"fixture-hash-pending-eval\",\"replay_command\":\"${replay_command}\",\"blocked_dependency_ids\":${blocked_dependencies},\"expected_hold_reasons\":${hold_reasons}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-final-readiness-dossier.run-manifest.v1",'
    echo "  \"bead_id\": \"$(parser_frontier_json_escape "${bead_id}")\","
    echo "  \"dossier_version\": \"$(parser_frontier_json_escape "${dossier_version}")\","
    echo "  \"component\": \"${component}\","
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
    echo "  \"expected_gate_outcome\": \"$(parser_frontier_json_escape "${expected_outcome}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"blocked_dependency_ids\": ${blocked_dependencies},"
    echo "  \"risk_ids\": ${risk_ids},"
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
    echo '    "contract_doc": "docs/PARSER_FINAL_READINESS_DOSSIER.md",'
    echo '    "fixture": "crates/franken-engine/tests/fixtures/parser_final_readiness_dossier_v1.json",'
    echo '    "tests": "crates/franken-engine/tests/parser_final_readiness_dossier.rs",'
    echo '    "replay_wrapper": "scripts/e2e/parser_final_readiness_dossier_replay.sh"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "parser final readiness dossier manifest: ${manifest_path}"
  echo "parser final readiness dossier events: ${events_path}"
}

main_exit=0
if run_mode; then
  main_exit=0
else
  main_exit=$?
fi
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
