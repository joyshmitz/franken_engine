#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_control_plane_invariants_dashboard}"
artifact_root="${CONTROL_PLANE_INVARIANTS_DASHBOARD_ARTIFACT_ROOT:-artifacts/control_plane_invariants_dashboard}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

trace_id="trace-control-plane-invariants-dashboard-${timestamp}"
decision_id="decision-control-plane-invariants-dashboard-${timestamp}"
policy_id="policy-control-plane-invariants-dashboard-v1"
component="control_plane_invariants_dashboard_suite"

mkdir -p "$run_dir"

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    echo "error: rch is required for this suite" >&2
    exit 3
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
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

run_optional_lib_variant_test() {
  if [[ "${CONTROL_PLANE_INVARIANTS_DASHBOARD_RUN_LIB_VARIANT_TEST:-0}" == "1" ]]; then
    run_step "cargo test -p frankenengine-engine --lib frankentui_all_payload_variants_serialize -- --exact" \
      cargo test -p frankenengine-engine --lib frankentui_all_payload_variants_serialize -- --exact
  else
    commands_run+=(
      "SKIPPED optional: cargo test -p frankenengine-engine --lib frankentui_all_payload_variants_serialize -- --exact"
    )
    echo "==> skipped optional lib-wide payload-variant test (set CONTROL_PLANE_INVARIANTS_DASHBOARD_RUN_LIB_VARIANT_TEST=1 to enable)"
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib" \
        cargo check -p frankenengine-engine --lib
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib control_plane_invariants_dashboard_" \
        cargo test -p frankenengine-engine --lib control_plane_invariants_dashboard_
      run_step "cargo test -p frankenengine-engine --test frankentui_adapter control_plane_invariants_dashboard_round_trips_with_alerts -- --exact" \
        cargo test -p frankenengine-engine --test frankentui_adapter control_plane_invariants_dashboard_round_trips_with_alerts -- --exact
      run_optional_lib_variant_test
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --lib --test frankentui_adapter -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test frankentui_adapter -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib" \
        cargo check -p frankenengine-engine --lib
      run_step "cargo test -p frankenengine-engine --lib control_plane_invariants_dashboard_" \
        cargo test -p frankenengine-engine --lib control_plane_invariants_dashboard_
      run_step "cargo test -p frankenengine-engine --test frankentui_adapter control_plane_invariants_dashboard_round_trips_with_alerts -- --exact" \
        cargo test -p frankenengine-engine --test frankentui_adapter control_plane_invariants_dashboard_round_trips_with_alerts -- --exact
      run_optional_lib_variant_test
      run_step "cargo clippy -p frankenengine-engine --lib --test frankentui_adapter -- -D warnings" \
        cargo clippy -p frankenengine-engine --lib --test frankentui_adapter -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac

  mode_completed=true
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "$mode_completed" == true ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-CP-INV-DASH-0001"'
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
    echo '  "schema_version": "franken-engine.control-plane-invariants-dashboard.run-manifest.v1",'
    echo "  \"component\": \"${component}\"," 
    echo '  "bead_id": "bd-36of",'
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
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
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "control-plane invariants dashboard manifest: $manifest_path"
  echo "control-plane invariants dashboard events: $events_path"
}

trap 'write_manifest $?' EXIT
run_mode
