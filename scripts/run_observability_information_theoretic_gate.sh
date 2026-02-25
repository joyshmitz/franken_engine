#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/var/tmp/rch_target_franken_engine_observability_information_theoretic}"
artifact_root="${OBSERVABILITY_INFORMATION_THEORETIC_ARTIFACT_ROOT:-artifacts/observability_information_theoretic}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-observability-information-theoretic-${timestamp}"
decision_id="decision-observability-information-theoretic-${timestamp}"
policy_id="policy-observability-information-theoretic-v1"
component="observability_information_theoretic_gate"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for observability information-theoretic heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for event JSON validation" >&2
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
      run_step "cargo check -p frankenengine-engine --test observability_channel_model" \
        cargo check -p frankenengine-engine --test observability_channel_model
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test observability_channel_model" \
        cargo test -p frankenengine-engine --test observability_channel_model
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test observability_channel_model -- -D warnings" \
        cargo clippy -p frankenengine-engine --test observability_channel_model -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test observability_channel_model" \
        cargo check -p frankenengine-engine --test observability_channel_model
      run_step "cargo test -p frankenengine-engine --test observability_channel_model" \
        cargo test -p frankenengine-engine --test observability_channel_model
      run_step "cargo clippy -p frankenengine-engine --test observability_channel_model -- -D warnings" \
        cargo clippy -p frankenengine-engine --test observability_channel_model -- -D warnings
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
    error_code_json='"FE-OBSERVABILITY-CHANNEL-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.observability-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.observability-information-theoretic.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.17",'
    echo '  "feature_contract_version": "frx-17.information-theoretic-observability.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
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
    echo '    "contract_doc": "docs/OBSERVABILITY_INFORMATION_THEORETIC_CHANNEL.md",'
    echo '    "integration_tests": "crates/franken-engine/tests/observability_channel_model.rs"'
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "observability information-theoretic manifest: ${manifest_path}"
  echo "observability information-theoretic events: ${events_path}"
}

validate_events() {
  jq -e -c . "$events_path" >/dev/null
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! validate_events; then
  failed_command="${failed_command:-validate_events_jsonl}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
