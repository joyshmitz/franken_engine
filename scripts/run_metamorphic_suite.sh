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
runner_run_dir="$target_dir/debug/metamorphic_artifacts/$timestamp"
manifest_path="$run_dir/run_manifest.json"
events_path="$run_dir/events.jsonl"
relation_events_path="$run_dir/relation_events.jsonl"
evidence_path="$run_dir/metamorphic_evidence.jsonl"
seed_transcript_path="$run_dir/seed_transcript.jsonl"
seed_manifest_path="$run_dir/seed_manifest.json"
triage_report_path="$run_dir/triage_report.json"
governance_actions_path="$run_dir/repro_governance_actions.json"
failures_dir="$run_dir/failures"
runner_relation_events_path="$runner_run_dir/relation_events.jsonl"
runner_evidence_path="$runner_run_dir/metamorphic_evidence.jsonl"
runner_seed_transcript_path="$runner_run_dir/seed_transcript.jsonl"
runner_seed_manifest_path="$runner_run_dir/seed_manifest.json"
runner_triage_report_path="$runner_run_dir/triage_report.json"
runner_governance_actions_path="$runner_run_dir/repro_governance_actions.json"
runner_failures_dir="$runner_run_dir/failures"
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
step_log_index=0

run_step() {
  local command_text="$1"
  shift
  local step_log_path="${run_dir}/step_$(printf '%03d' "$step_log_index").log"
  local rc
  step_log_index=$((step_log_index + 1))
  commands_run+=("$command_text")
  echo "==> $command_text"
  set +e
  run_rch "$@" > >(tee "$step_log_path") 2>&1
  rc=$?
  set -e
  if ! reject_local_fallback "$step_log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 86
  fi
  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi
  if ! require_remote_success_marker "$step_log_path"; then
    failed_command="${command_text} (rch-success-marker-missing)"
    return 87
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
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$runner_evidence_path --events=$runner_relation_events_path --seed-transcript=$runner_seed_transcript_path --seed-manifest=$runner_seed_manifest_path --triage-report=$runner_triage_report_path --governance-actions=$runner_governance_actions_path --failures-dir=$runner_failures_dir${relation_command_suffix}" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
        --pairs "$pairs" --seed "$seed" --trace-id "$trace_id" --decision-id "$decision_id" \
        --policy-id "$policy_id" --evidence "$runner_evidence_path" --events "$runner_relation_events_path" \
        --seed-transcript "$runner_seed_transcript_path" --seed-manifest "$runner_seed_manifest_path" \
        --triage-report "$runner_triage_report_path" --governance-actions "$runner_governance_actions_path" \
        --failures-dir "$runner_failures_dir" "${relation_args[@]}"
      hydrate_local_metamorphic_artifacts
      if ! ensure_metamorphic_artifacts_complete; then
        echo "error: metamorphic artifact contract missing after test mode" >&2
        failed_command="test_artifact_validation"
        return 1
      fi
      ;;
    ci)
      run_step "cargo check -p frankenengine-metamorphic --all-targets" \
        cargo check -p frankenengine-metamorphic --all-targets
      run_step "cargo test -p frankenengine-metamorphic" \
        cargo test -p frankenengine-metamorphic
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs=$pairs --seed=$seed --trace-id=$trace_id --decision-id=$decision_id --policy-id=$policy_id --evidence=$runner_evidence_path --events=$runner_relation_events_path --seed-transcript=$runner_seed_transcript_path --seed-manifest=$runner_seed_manifest_path --triage-report=$runner_triage_report_path --governance-actions=$runner_governance_actions_path --failures-dir=$runner_failures_dir${relation_command_suffix}" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
        --pairs "$pairs" --seed "$seed" --trace-id "$trace_id" --decision-id "$decision_id" \
        --policy-id "$policy_id" --evidence "$runner_evidence_path" --events "$runner_relation_events_path" \
        --seed-transcript "$runner_seed_transcript_path" --seed-manifest "$runner_seed_manifest_path" \
        --triage-report "$runner_triage_report_path" --governance-actions "$runner_governance_actions_path" \
        --failures-dir "$runner_failures_dir" "${relation_args[@]}"
      hydrate_local_metamorphic_artifacts
      if ! ensure_metamorphic_artifacts_complete; then
        echo "error: metamorphic artifact contract missing after ci mode" >&2
        failed_command="ci_artifact_validation"
        return 1
      fi
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
    echo '  "bead_id": "bd-1lsy.9.3",'
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
    echo "    \"seed_manifest\": \"${seed_manifest_path}\"," 
    echo "    \"triage_report\": \"${triage_report_path}\"," 
    echo "    \"governance_actions\": \"${governance_actions_path}\"," 
    echo "    \"failures_dir\": \"${failures_dir}\"," 
    echo "    \"command_log\": \"${run_dir}/commands.txt\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${relation_events_path}\"," 
    echo "    \"cat ${evidence_path}\"," 
    echo "    \"cat ${seed_transcript_path}\"," 
    echo "    \"cat ${seed_manifest_path}\"," 
    echo "    \"cat ${triage_report_path}\"," 
    echo "    \"cat ${governance_actions_path}\"," 
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

hydrate_local_metamorphic_artifacts() {
  local runner_file local_file

  mkdir -p "$run_dir" "$failures_dir"

  local runner_files=(
    "$runner_relation_events_path"
    "$runner_evidence_path"
    "$runner_seed_transcript_path"
    "$runner_seed_manifest_path"
    "$runner_triage_report_path"
    "$runner_governance_actions_path"
  )
  local local_files=(
    "$relation_events_path"
    "$evidence_path"
    "$seed_transcript_path"
    "$seed_manifest_path"
    "$triage_report_path"
    "$governance_actions_path"
  )

  local idx
  for idx in "${!runner_files[@]}"; do
    runner_file="${runner_files[$idx]}"
    local_file="${local_files[$idx]}"
    if [[ -f "$runner_file" ]]; then
      mkdir -p "$(dirname "$local_file")"
      cp "$runner_file" "$local_file"
    fi
  done

  if [[ -d "$runner_failures_dir" ]]; then
    mkdir -p "$failures_dir"
    while IFS= read -r -d '' runner_file; do
      cp "$runner_file" "$failures_dir/"
    done < <(find "$runner_failures_dir" -maxdepth 1 -mindepth 1 -type f -print0)
  fi
}

metamorphic_artifacts_complete() {
  local required
  for required in \
    "$relation_events_path" \
    "$evidence_path" \
    "$seed_transcript_path" \
    "$seed_manifest_path" \
    "$triage_report_path" \
    "$governance_actions_path"; do
    if [[ ! -f "$required" ]]; then
      return 1
    fi
  done
  return 0
}

pull_remote_file_if_missing() {
  local path="$1"
  local remote_path
  local tmp_path

  if [[ -f "$path" ]]; then
    return 0
  fi

  if [[ "$path" = /* ]]; then
    remote_path="$path"
  else
    remote_path="$root_dir/$path"
  fi

  if ! RCH_LOG_LEVEL=error run_rch test -f "$remote_path" >/dev/null 2>&1; then
    return 1
  fi

  mkdir -p "$(dirname "$path")"
  tmp_path="${path}.remote.$$"
  if ! RCH_LOG_LEVEL=error run_rch cat "$remote_path" >"$tmp_path"; then
    rm -f "$tmp_path"
    return 1
  fi

  mv "$tmp_path" "$path"
}

sync_metamorphic_artifacts_from_remote() {
  local required
  local missing_any=false

  for required in \
    "$relation_events_path" \
    "$evidence_path" \
    "$seed_transcript_path" \
    "$seed_manifest_path" \
    "$triage_report_path" \
    "$governance_actions_path"; do
    if [[ -f "$required" ]]; then
      continue
    fi
    if ! pull_remote_file_if_missing "$required"; then
      missing_any=true
    fi
  done

  [[ "$missing_any" == false ]]
}

ensure_metamorphic_artifacts_complete() {
  hydrate_local_metamorphic_artifacts
  if metamorphic_artifacts_complete; then
    return 0
  fi

  sync_metamorphic_artifacts_from_remote || true
  metamorphic_artifacts_complete
}

reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|running locally|Failed to query daemon:.*running locally|RCH-E326' "$log_path"; then
    echo "error: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

require_remote_success_marker() {
  local log_path="$1"
  if ! grep -Eq 'Remote command finished: exit=0' "$log_path"; then
    echo "error: missing successful remote completion marker in ${log_path}" >&2
    return 1
  fi
}

trap 'write_manifest $?' EXIT
ensure_rch
run_mode
