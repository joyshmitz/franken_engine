#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_metamorphic_uid$(id -u)}"
pairs="${METAMORPHIC_PAIRS:-1000}"
seed="${METAMORPHIC_SEED:-1}"
relation_filter_csv="${METAMORPHIC_RELATIONS:-}"
artifact_root="${METAMORPHIC_ARTIFACT_ROOT:-artifacts/metamorphic}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
relation_events_path="$run_dir/relation_events.jsonl"
evidence_path="$run_dir/metamorphic_evidence.jsonl"
seed_transcript_path="$run_dir/seed_transcript.jsonl"
failures_dir="$run_dir/failures"
trace_id="trace-metamorphic-$timestamp"
decision_id="decision-metamorphic-$timestamp"
policy_id="policy-metamorphic-v1"
rch_required=true
rch_present=true
rch_missing=false
rch_missing_error_code="FE-META-RCH-0002"
declare -a relation_filters=()
declare -a relation_args=()
relation_command_suffix=""
relation_filters_manifest_json="[]"
replay_command="./scripts/e2e/metamorphic_suite_replay.sh ${mode}"

mkdir -p "$run_dir" "$failures_dir"

run_rch() {
  if ! command -v rch >/dev/null 2>&1; then
    rch_present=false
    rch_missing=true
    echo "error: rch is required for metamorphic suite heavy cargo execution (${rch_missing_error_code})" >&2
    return 127
  fi
  rch exec -- env "RUSTUP_TOOLCHAIN=$toolchain" "CARGO_TARGET_DIR=$target_dir" "$@"
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

trim_ascii_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

configure_relation_filters() {
  local raw_filter trimmed idx comma
  local raw_filters=()

  if [[ -z "$relation_filter_csv" ]]; then
    return
  fi

  IFS=',' read -r -a raw_filters <<< "$relation_filter_csv"
  for raw_filter in "${raw_filters[@]}"; do
    trimmed="$(trim_ascii_whitespace "$raw_filter")"
    if [[ -z "$trimmed" ]]; then
      continue
    fi
    relation_filters+=("$trimmed")
    relation_args+=(--relation "$trimmed")
  done

  if [[ "${#relation_filters[@]}" -eq 0 ]]; then
    return
  fi

  relation_filters_manifest_json="["
  for idx in "${!relation_filters[@]}"; do
    relation_command_suffix+=" --relation=${relation_filters[$idx]}"
    comma=","
    if [[ "$idx" == "$(( ${#relation_filters[@]} - 1 ))" ]]; then
      comma=""
    fi
    relation_filters_manifest_json+="\"$(json_escape "${relation_filters[$idx]}")\"${comma}"
  done
  relation_filters_manifest_json+="]"
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

ensure_rch() {
  if command -v rch >/dev/null 2>&1; then
    return 0
  fi
  rch_present=false
  rch_missing=true
  failed_command="rch exec (required preflight)"
  echo "error: rch is required for ${0##*/} and local fallback is disabled (${rch_missing_error_code})" >&2
  return 127
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
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$evidence_path --events=$relation_events_path --seed-transcript=$seed_transcript_path --failures-dir=$failures_dir${relation_command_suffix}" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
        --pairs "$pairs" --seed "$seed" --trace-id "$trace_id" --decision-id "$decision_id" \
        --policy-id "$policy_id" --evidence "$evidence_path" --events "$relation_events_path" \
        --seed-transcript "$seed_transcript_path" \
        --failures-dir "$failures_dir" "${relation_args[@]}"
      ;;
    ci)
      run_step "cargo check -p frankenengine-metamorphic --all-targets" \
        cargo check -p frankenengine-metamorphic --all-targets
      run_step "cargo test -p frankenengine-metamorphic" \
        cargo test -p frankenengine-metamorphic
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$evidence_path --events=$relation_events_path --seed-transcript=$seed_transcript_path --failures-dir=$failures_dir${relation_command_suffix}" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
        --pairs "$pairs" --seed "$seed" --trace-id "$trace_id" --decision-id "$decision_id" \
        --policy-id "$policy_id" --evidence "$evidence_path" --events "$relation_events_path" \
        --seed-transcript "$seed_transcript_path" \
        --failures-dir "$failures_dir" "${relation_args[@]}"
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome error_code_json failure_reason_json

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json='null'
    failure_reason_json='null'
  else
    outcome="fail"
    if [[ "$rch_missing" == true ]]; then
      error_code_json="\"${rch_missing_error_code}\""
      failure_reason_json='"rch_unavailable"'
    else
      error_code_json='"FE-META-0001"'
      failure_reason_json='null'
    fi
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
    echo '  "bead_id": "bd-mjh3.5.2",'
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"rch_required\": ${rch_required},"
    echo "  \"rch_present\": ${rch_present},"
    echo "  \"error_code\": ${error_code_json},"
    echo "  \"failure_reason\": ${failure_reason_json},"
    echo "  \"pairs\": ${pairs},"
    echo "  \"seed\": ${seed},"
    echo "  \"relation_filter_count\": ${#relation_filters[@]},"
    echo "  \"relation_filters\": ${relation_filters_manifest_json},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"replay_command\": \"$(json_escape "${replay_command}")\"," 
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\"," 
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(json_escape "${failed_command}")\"," 
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"relation_events\": \"${relation_events_path}\"," 
    echo "    \"evidence\": \"${evidence_path}\"," 
    echo "    \"seed_transcript\": \"${seed_transcript_path}\"," 
    echo "    \"failures_dir\": \"${failures_dir}\"," 
    echo "    \"command_log\": \"${run_dir}/commands.txt\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${relation_events_path}\"," 
    echo "    \"cat ${evidence_path}\"," 
    echo "    \"cat ${seed_transcript_path}\"," 
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  {
    echo "{\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"metamorphic_suite\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  echo "metamorphic manifest: $manifest_path"
  echo "metamorphic events: $events_path"
  echo "metamorphic evidence: $evidence_path"
}

configure_relation_filters
trap 'write_manifest $?' EXIT
ensure_rch
run_mode
