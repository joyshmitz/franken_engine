#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_self_replacement_progress}"
artifact_root="${SELF_REPLACEMENT_PROGRESS_ARTIFACT_ROOT:-artifacts/self_replacement_progress}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/self_replacement_progress_events.jsonl"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

declare -a commands_run=()
failed_command=""
manifest_written=false
mode_completed=false

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
      run_step "cargo check -p frankenengine-engine --lib" \
        cargo check -p frankenengine-engine --lib
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib replacement_progress_snapshot_" \
        cargo test -p frankenengine-engine --lib replacement_progress_snapshot_
      run_step "cargo test -p frankenengine-engine --lib slot_registry::tests::replacement_progress_snapshot_reports_weighted_metrics_and_ev_order -- --exact" \
        cargo test -p frankenengine-engine --lib slot_registry::tests::replacement_progress_snapshot_reports_weighted_metrics_and_ev_order -- --exact
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib" \
        cargo check -p frankenengine-engine --lib
      run_step "cargo test -p frankenengine-engine --lib replacement_progress_snapshot_" \
        cargo test -p frankenengine-engine --lib replacement_progress_snapshot_
      run_step "cargo test -p frankenengine-engine --lib slot_registry::tests::replacement_progress_snapshot_reports_weighted_metrics_and_ev_order -- --exact" \
        cargo test -p frankenengine-engine --lib slot_registry::tests::replacement_progress_snapshot_reports_weighted_metrics_and_ev_order -- --exact
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
  mode_completed=true
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree outcome idx comma error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-SLOT-REPLACEMENT-PROGRESS-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$run_dir/commands.txt"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.self-replacement-progress.run-manifest.v1",'
    echo '  "component": "self_replacement_progress",'
    echo '  "bead_id": "bd-1a5z",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"mode_completed\": ${mode_completed},"
    echo "  \"commands_executed\": ${#commands_run[@]},"
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
    echo "    \"command_log\": \"${run_dir}/commands.txt\","
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo '    "source_module": "crates/franken-engine/src/slot_registry.rs",'
    echo '    "suite_entrypoint": "scripts/run_self_replacement_progress_suite.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"trace-self-replacement-progress-${timestamp}\",\"decision_id\":\"decision-self-replacement-progress-${timestamp}\",\"policy_id\":\"policy-self-replacement-progress-v1\",\"component\":\"self_replacement_progress_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "self-replacement progress run manifest: $manifest_path"
  echo "self-replacement progress events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
