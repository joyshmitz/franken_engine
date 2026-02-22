#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required for this suite" >&2
  exit 1
fi

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_runtime_decision_scoring}"
seed="${RUNTIME_DECISION_SCORING_SEED:-runtime-decision-scoring-seed-v1}"
artifact_root="${RUNTIME_DECISION_SCORING_ARTIFACT_ROOT:-artifacts/runtime_decision_scoring}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
commands_path="$run_dir/commands.txt"

trace_id="trace-runtime-decision-scoring-${timestamp}"
decision_id="decision-runtime-decision-scoring-${timestamp}"
policy_id="policy-runtime-decision-scoring-v1"
component="runtime_decision_scoring_suite"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
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
      run_step "cargo check -p frankenengine-engine --test runtime_decision_scoring" \
        cargo check -p frankenengine-engine --test runtime_decision_scoring
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test runtime_decision_scoring" \
        cargo test -p frankenengine-engine --test runtime_decision_scoring
      run_step "cargo test -p frankenengine-engine --lib expected_loss_selector::tests::runtime_scoring_" \
        cargo test -p frankenengine-engine --lib expected_loss_selector::tests::runtime_scoring_
      run_step "cargo test -p frankenengine-engine --lib trust_economics::tests::roi_" \
        cargo test -p frankenengine-engine --lib trust_economics::tests::roi_
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test runtime_decision_scoring" \
        cargo check -p frankenengine-engine --test runtime_decision_scoring
      run_step "cargo test -p frankenengine-engine --test runtime_decision_scoring" \
        cargo test -p frankenengine-engine --test runtime_decision_scoring
      run_step "cargo test -p frankenengine-engine --lib expected_loss_selector::tests::runtime_scoring_" \
        cargo test -p frankenengine-engine --lib expected_loss_selector::tests::runtime_scoring_
      run_step "cargo test -p frankenengine-engine --lib trust_economics::tests::roi_" \
        cargo test -p frankenengine-engine --lib trust_economics::tests::roi_
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-RUNTIME-DECISION-SCORING-SUITE-0001"'
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
    echo '  "schema_version": "franken-engine.runtime-decision-scoring.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"seed\": \"${seed}\","
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
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"command_log\": \"${commands_path}\","
    echo '    "integration_test": "crates/franken-engine/tests/runtime_decision_scoring.rs",'
    echo '    "module_expected_loss_selector": "crates/franken-engine/src/expected_loss_selector.rs",'
    echo '    "module_trust_economics": "crates/franken-engine/src/trust_economics.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "runtime decision scoring suite manifest: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
