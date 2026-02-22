#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_shadow_ablation_engine}"
component="shadow_ablation_engine"
bead_id="bd-1kdc"
seed="${SHADOW_ABLATION_SEED:-shadow-ablation-seed-v1}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/shadow_ablation_engine/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/shadow_ablation_engine_events.jsonl"

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

run_check() {
  run_step "cargo check -p frankenengine-engine --test shadow_ablation_engine" \
    cargo check -p frankenengine-engine --test shadow_ablation_engine
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test shadow_ablation_engine" \
    cargo test -p frankenengine-engine --test shadow_ablation_engine
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test shadow_ablation_engine -- -D warnings" \
    cargo clippy -p frankenengine-engine --test shadow_ablation_engine -- -D warnings
}

run_mode() {
  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    clippy)
      run_clippy
      ;;
    ci)
      run_check
      run_test
      run_clippy
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
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
    error_code_json='"FE-ABLATION-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${run_dir}/commands.txt"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.shadow-ablation-suite.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"seed\": \"${seed}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
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
    echo "    \"command_log\": \"${run_dir}/commands.txt\","
    echo '    "tests": "crates/franken-engine/tests/shadow_ablation_engine.rs",'
    echo '    "module": "crates/franken-engine/src/shadow_ablation_engine.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    echo "{\"trace_id\":\"trace-shadow-ablation-suite-${timestamp}\",\"decision_id\":\"decision-shadow-ablation-suite-${timestamp}\",\"policy_id\":\"policy-shadow-ablation-suite-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  echo "shadow ablation suite manifest: ${manifest_path}"
  echo "shadow ablation suite events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
