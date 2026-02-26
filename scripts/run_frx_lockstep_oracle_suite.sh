#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target/rch/frx_lockstep_oracle_suite}"
artifact_root="${FRX_LOCKSTEP_ORACLE_ARTIFACT_ROOT:-artifacts/frx_lockstep_oracle}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/oracle_report.json"

trace_id="trace-frx-lockstep-oracle-${timestamp}"
decision_id="decision-frx-lockstep-oracle-${timestamp}"
policy_id="policy-frx-lockstep-oracle-v1"
component="frx_lockstep_oracle_suite"
scenario_id="frx-05.1"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for FRX lockstep oracle suite" >&2
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
    if [[ -z "$failed_command" ]]; then
      failed_command="$command_text"
    fi
    return 1
  fi
}

run_mode() {
  local mode_exit=0
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle" \
        cargo check -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle || mode_exit=1
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test frx_lockstep_oracle" \
        cargo test -p frankenengine-engine --test frx_lockstep_oracle || mode_exit=1
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle -- -D warnings || mode_exit=1
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle" \
        cargo check -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle || mode_exit=1
      run_step "cargo test -p frankenengine-engine --test frx_lockstep_oracle" \
        cargo test -p frankenengine-engine --test frx_lockstep_oracle || mode_exit=1
      run_step "cargo clippy -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin frx_lockstep_oracle --test frx_lockstep_oracle -- -D warnings || mode_exit=1
      run_step "cargo run -p frankenengine-engine --bin frx_lockstep_oracle -- --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --react-traces-dir crates/franken-engine/tests/conformance/frx_react_corpus/traces --franken-traces-dir crates/franken-engine/tests/conformance/frx_react_corpus/traces --out ${report_path} --fail-on-divergence" \
        cargo run -p frankenengine-engine --bin frx_lockstep_oracle -- \
          --trace-id "${trace_id}" \
          --decision-id "${decision_id}" \
          --policy-id "${policy_id}" \
          --react-traces-dir crates/franken-engine/tests/conformance/frx_react_corpus/traces \
          --franken-traces-dir crates/franken-engine/tests/conformance/frx_react_corpus/traces \
          --out "${report_path}" \
          --fail-on-divergence || mode_exit=1
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  return "$mode_exit"
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
    error_code_json='"FE-FRX-05-1-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"frx.05.1.lockstep-oracle-gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "frx.05.1.lockstep-oracle-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.5.1",'
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
      echo "  \"failed_command\": \"${failed_command}\"," 
    fi
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
    echo "    \"oracle_report\": \"${report_path}\"," 
    echo '    "source_module": "crates/franken-engine/src/frx_lockstep_oracle.rs",'
    echo '    "cli": "crates/franken-engine/src/bin/frx_lockstep_oracle.rs",'
    echo '    "integration_test": "crates/franken-engine/tests/frx_lockstep_oracle.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${report_path}\"," 
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "frx lockstep oracle manifest: ${manifest_path}"
  echo "frx lockstep oracle events: ${events_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
