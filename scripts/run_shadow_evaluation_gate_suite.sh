#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_shadow_evaluation_gate}"
seed="${SHADOW_EVAL_GATE_SEED:-shadow-evaluation-gate-seed-v1}"
artifact_root="${SHADOW_EVAL_GATE_ARTIFACT_ROOT:-artifacts/shadow_evaluation_gate}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"

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
      run_step "cargo check -p frankenengine-engine" \
        cargo check -p frankenengine-engine
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test shadow_evaluation_gate" \
        cargo test -p frankenengine-engine --test shadow_evaluation_gate
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test shadow_evaluation_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test shadow_evaluation_gate -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine" \
        cargo check -p frankenengine-engine
      run_step "cargo test -p frankenengine-engine --test shadow_evaluation_gate" \
        cargo test -p frankenengine-engine --test shadow_evaluation_gate
      run_step "cargo clippy -p frankenengine-engine --test shadow_evaluation_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --test shadow_evaluation_gate -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome
  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
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
    echo '  "component": "shadow_evaluation_gate",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"seed\": \"${seed}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
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
      if [[ "$idx" == "$((${#commands_run[@]} - 1))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${run_dir}/commands.txt\","
    echo "    \"manifest\": \"${manifest_path}\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"${0} ci\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "Manifest written to: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
