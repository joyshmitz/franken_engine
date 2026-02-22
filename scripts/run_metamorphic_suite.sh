#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_metamorphic}"
pairs="${METAMORPHIC_PAIRS:-1000}"
seed="${METAMORPHIC_SEED:-1}"
artifact_root="${METAMORPHIC_ARTIFACT_ROOT:-artifacts/metamorphic}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
relation_events_path="$run_dir/relation_events.jsonl"
evidence_path="$run_dir/metamorphic_evidence.jsonl"
failures_dir="$run_dir/failures"
trace_id="trace-metamorphic-$timestamp"
decision_id="decision-metamorphic-$timestamp"
policy_id="policy-metamorphic-v1"

mkdir -p "$run_dir" "$failures_dir"

run_rch() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
  else
    echo "warning: rch not found; running locally" >&2
    env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
  fi
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
      run_step "cargo check -p frankenengine-metamorphic --all-targets" \
        cargo check -p frankenengine-metamorphic --all-targets
      ;;
    test)
      run_step "cargo test -p frankenengine-metamorphic" \
        cargo test -p frankenengine-metamorphic
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$evidence_path --events=$relation_events_path --failures-dir=$failures_dir" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
        --pairs "$pairs" --seed "$seed" --trace-id "$trace_id" --decision-id "$decision_id" \
        --policy-id "$policy_id" --evidence "$evidence_path" --events "$relation_events_path" \
        --failures-dir "$failures_dir"
      ;;
    ci)
      run_step "cargo check -p frankenengine-metamorphic --all-targets" \
        cargo check -p frankenengine-metamorphic --all-targets
      run_step "cargo test -p frankenengine-metamorphic" \
        cargo test -p frankenengine-metamorphic
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$evidence_path --events=$relation_events_path --failures-dir=$failures_dir" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
        --pairs "$pairs" --seed "$seed" --trace-id "$trace_id" --decision-id "$decision_id" \
        --policy-id "$policy_id" --evidence "$evidence_path" --events "$relation_events_path" \
        --failures-dir "$failures_dir"
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
  else
    outcome="fail"
    error_code_json='"FE-META-0001"'
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
    echo '  "component": "metamorphic_suite",'
    echo '  "bead_id": "bd-2eu",'
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"pairs\": ${pairs},"
    echo "  \"seed\": ${seed},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
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
    echo "    \"relation_events\": \"${relation_events_path}\"," 
    echo "    \"evidence\": \"${evidence_path}\"," 
    echo "    \"failures_dir\": \"${failures_dir}\"," 
    echo "    \"command_log\": \"${run_dir}/commands.txt\""
    echo '  }'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"metamorphic_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "metamorphic manifest: $manifest_path"
  echo "metamorphic events: $events_path"
  echo "metamorphic evidence: $evidence_path"
}

trap 'write_manifest $?' EXIT
run_mode
