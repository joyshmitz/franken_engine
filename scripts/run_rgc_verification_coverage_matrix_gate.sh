#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-check}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${RGC_VERIFICATION_COVERAGE_MATRIX_ARTIFACT_ROOT:-artifacts/rgc_verification_coverage_matrix}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/coverage_report.json"

matrix_json="docs/rgc_verification_coverage_matrix_v1.json"
matrix_doc="docs/RGC_VERIFICATION_COVERAGE_MATRIX_V1.md"

trace_id="trace-rgc-verification-coverage-matrix-${timestamp}"
decision_id="decision-rgc-verification-coverage-matrix-${timestamp}"
policy_id="policy-rgc-verification-coverage-matrix-v1"
component="rgc_verification_coverage_matrix_gate"
scenario_id="rgc-051"
replay_command="./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ${mode}"

mkdir -p "$run_dir"

declare -a commands_run=()
declare -a validation_errors=()
declare -a uncovered_beads=()
declare -a critical_gaps=()
declare -a active_beads=()
declare -a critical_beads=()
declare -a required_log_fields=()
declare -a required_artifact_triad=()
declare -a required_critical_kinds=("unit" "integration" "e2e")
declare -a coverage_rows=()

total_active_beads=0
covered_beads=0
coverage_ratio="0.000"
failed_command=""
manifest_written=false

array_to_json() {
  local -n ref="$1"
  if (( ${#ref[@]} == 0 )); then
    printf '[]'
  else
    printf '%s\n' "${ref[@]}" | jq -R . | jq -s .
  fi
}

record_error() {
  validation_errors+=("$1")
}

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    return 1
  fi
}

selector_matches_bead() {
  local selector="$1"
  local bead="$2"

  # Support wildcard selectors from the matrix (e.g. bd-1lsy.*).
  if [[ "$selector" == *"*"* ]]; then
    [[ "$bead" == $selector ]]
  else
    [[ "$bead" == "$selector" ]]
  fi
}

row_matches_bead() {
  local row_json="$1"
  local bead="$2"
  local selector

  while IFS= read -r selector; do
    if selector_matches_bead "$selector" "$bead"; then
      return 0
    fi
  done < <(jq -r '.bead_selectors[]? // empty' <<<"$row_json")

  return 1
}

validate_harness_entrypoint() {
  local row_id="$1"
  local harness_entrypoint="$2"
  local first_token

  if [[ -z "$harness_entrypoint" ]]; then
    record_error "${row_id}: missing harness_entrypoint"
    return
  fi

  first_token="$(awk '{print $1}' <<<"$harness_entrypoint")"
  if [[ -z "$first_token" ]]; then
    record_error "${row_id}: invalid harness_entrypoint '${harness_entrypoint}'"
    return
  fi

  if [[ "$first_token" == ./* ]]; then
    if [[ ! -e "${root_dir}/${first_token#./}" ]]; then
      record_error "${row_id}: harness path not found (${first_token})"
    fi
    return
  fi

  if [[ "$first_token" == scripts/* ]]; then
    if [[ ! -e "${root_dir}/${first_token}" ]]; then
      record_error "${row_id}: harness path not found (${first_token})"
    fi
    return
  fi

  if ! command -v "$first_token" >/dev/null 2>&1; then
    record_error "${row_id}: harness executable not available (${first_token})"
  fi
}

load_matrix_contract() {
  local schema_ok

  if [[ ! -f "$matrix_json" ]]; then
    record_error "missing matrix JSON: ${matrix_json}"
    return 1
  fi
  if [[ ! -f "$matrix_doc" ]]; then
    record_error "missing matrix document: ${matrix_doc}"
    return 1
  fi

  schema_ok="$(jq -r '.schema_version == "rgc.verification-coverage-matrix.v1"' "$matrix_json")"
  if [[ "$schema_ok" != "true" ]]; then
    record_error "unexpected schema_version in ${matrix_json}"
  fi

  mapfile -t coverage_rows < <(jq -c '(.rows // .coverage_rows // [])[]' "$matrix_json")
  if (( ${#coverage_rows[@]} == 0 )); then
    record_error "matrix has no coverage rows"
  fi

  mapfile -t required_log_fields < <(jq -r '(.required_log_fields // .required_structured_log_fields // [])[]' "$matrix_json")
  if (( ${#required_log_fields[@]} == 0 )); then
    record_error "matrix missing required_log_fields/required_structured_log_fields"
  fi

  mapfile -t required_artifact_triad < <(jq -r '(.required_artifact_triad // [])[]' "$matrix_json")
  if (( ${#required_artifact_triad[@]} == 0 )); then
    record_error "matrix missing required_artifact_triad"
  fi

  mapfile -t critical_beads < <(jq -r '(.critical_behavior_bead_ids // [])[]' "$matrix_json")

  return 0
}

validate_rows() {
  local duplicate_rows row row_id selectors_len artifacts_len required_len harness req triad

  duplicate_rows="$(jq -r '(.rows // .coverage_rows // [])[].row_id' "$matrix_json" | sort | uniq -d || true)"
  if [[ -n "$duplicate_rows" ]]; then
    record_error "duplicate row_id entries: ${duplicate_rows//$'\n'/, }"
  fi

  for row in "${coverage_rows[@]}"; do
    row_id="$(jq -r '.row_id // empty' <<<"$row")"
    if [[ -z "$row_id" ]]; then
      record_error "row missing row_id"
      continue
    fi

    selectors_len="$(jq -r '.bead_selectors | length' <<<"$row")"
    if [[ "$selectors_len" == "0" ]]; then
      record_error "${row_id}: bead_selectors cannot be empty"
    fi

    harness="$(jq -r '.harness_entrypoint // empty' <<<"$row")"
    validate_harness_entrypoint "$row_id" "$harness"

    artifacts_len="$(jq -r '.artifact_paths | length' <<<"$row")"
    if [[ "$artifacts_len" == "0" ]]; then
      record_error "${row_id}: artifact_paths cannot be empty"
    fi

    required_len="$(jq -r '.required_log_fields | length' <<<"$row")"
    if [[ "$required_len" == "0" ]]; then
      record_error "${row_id}: required_log_fields cannot be empty"
    fi

    for req in "${required_log_fields[@]}"; do
      if ! jq -e --arg req "$req" '.required_log_fields | index($req) != null' <<<"$row" >/dev/null; then
        record_error "${row_id}: required_log_fields missing '${req}'"
      fi
    done

    for triad in "${required_artifact_triad[@]}"; do
      if ! jq -e --arg triad "$triad" '.artifact_paths | map(contains($triad)) | any' <<<"$row" >/dev/null; then
        record_error "${row_id}: artifact_paths missing '${triad}'"
      fi
    done
  done
}

compute_coverage() {
  local bead row kind bead_kinds kind_found

  mapfile -t active_beads < <(
    br list --json | jq -r '
      .[]
      | select((.id | startswith("bd-1lsy")) and (.status == "open" or .status == "in_progress"))
      | .id
    ' | sort -u
  )

  total_active_beads=${#active_beads[@]}
  if (( total_active_beads == 0 )); then
    record_error "no active RGC beads found in status scope"
    return
  fi

  for bead in "${active_beads[@]}"; do
    kind_found=false
    for row in "${coverage_rows[@]}"; do
      if row_matches_bead "$row" "$bead"; then
        kind_found=true
        break
      fi
    done

    if [[ "$kind_found" == false ]]; then
      uncovered_beads+=("$bead")
    fi
  done

  covered_beads=$(( total_active_beads - ${#uncovered_beads[@]} ))
  coverage_ratio="$(awk -v c="$covered_beads" -v t="$total_active_beads" 'BEGIN { printf "%.3f", c / t }')"

  if (( ${#critical_beads[@]} > 0 )); then
    for bead in "${critical_beads[@]}"; do
      if ! printf '%s\n' "${active_beads[@]}" | rg -q "^${bead}$"; then
        continue
      fi

      bead_kinds=""
      for row in "${coverage_rows[@]}"; do
        if row_matches_bead "$row" "$bead"; then
          kind="$(jq -r '.test_kind' <<<"$row")"
          bead_kinds+="${kind}"$'\n'
        fi
      done
      bead_kinds="$(printf '%s' "$bead_kinds" | sort -u)"

      for kind in "${required_critical_kinds[@]}"; do
        if ! grep -qx "$kind" <<<"$bead_kinds"; then
          critical_gaps+=("${bead}:missing_${kind}")
        fi
      done
    done
  fi

  if (( ${#uncovered_beads[@]} > 0 )); then
    record_error "uncovered beads: ${uncovered_beads[*]}"
  fi

  if (( ${#critical_gaps[@]} > 0 )); then
    record_error "critical coverage gaps: ${critical_gaps[*]}"
  fi
}

write_report() {
  local active_json uncovered_json errors_json critical_json

  active_json="$(array_to_json active_beads)"
  uncovered_json="$(array_to_json uncovered_beads)"
  errors_json="$(array_to_json validation_errors)"
  critical_json="$(array_to_json critical_gaps)"

  jq -n \
    --arg schema_version "rgc.verification-coverage-matrix.report.v1" \
    --arg generated_at_utc "$timestamp" \
    --arg matrix_path "$matrix_json" \
    --arg matrix_doc "$matrix_doc" \
    --arg scenario_id "$scenario_id" \
    --argjson active_beads "$active_json" \
    --argjson uncovered_beads "$uncovered_json" \
    --argjson validation_errors "$errors_json" \
    --argjson critical_gaps "$critical_json" \
    --argjson total_active_beads "$total_active_beads" \
    --argjson covered_beads "$covered_beads" \
    --arg coverage_ratio "$coverage_ratio" \
    '{
      schema_version: $schema_version,
      generated_at_utc: $generated_at_utc,
      scenario_id: $scenario_id,
      matrix_json: $matrix_path,
      matrix_doc: $matrix_doc,
      total_active_beads: $total_active_beads,
      covered_beads: $covered_beads,
      coverage_ratio: ($coverage_ratio | tonumber),
      uncovered_beads: $uncovered_beads,
      critical_gaps: $critical_gaps,
      validation_errors: $validation_errors,
      active_beads: $active_beads
    }' >"$report_path"
}

run_mode() {
  case "$mode" in
    check|ci|report)
      run_step "jq empty ${matrix_json}" jq empty "$matrix_json"
      run_step "load matrix contract" load_matrix_contract
      run_step "validate coverage rows" validate_rows
      run_step "compute bead coverage" compute_coverage
      ;;
    *)
      echo "usage: $0 [check|ci|report]" >&2
      exit 2
      ;;
  esac

  if (( ${#validation_errors[@]} > 0 )); then
    return 1
  fi

  return 0
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
    error_code_json='"FE-RGC-051-COVERAGE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"rgc.verification-coverage-matrix.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"coverage_validation_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"runtime_lane\":\"verification\",\"seed\":\"matrix-v1\",\"result\":\"${outcome}\"}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "rgc.verification-coverage-matrix.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.1",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    echo "  \"total_active_beads\": ${total_active_beads},"
    echo "  \"covered_beads\": ${covered_beads},"
    echo "  \"coverage_ratio\": ${coverage_ratio},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    " "null"
    echo "  },"
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"coverage_report\": \"${report_path}\","
    echo "    \"matrix_json\": \"${matrix_json}\","
    echo "    \"matrix_doc\": \"${matrix_doc}\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"jq empty ${matrix_json}\","
    echo "    \"cat ${report_path}\","
    echo "    \"./scripts/run_rgc_verification_coverage_matrix.sh check\","
    echo "    \"${replay_command}\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "rgc verification coverage matrix manifest: ${manifest_path}"
  echo "rgc verification coverage matrix events: ${events_path}"
  echo "rgc verification coverage matrix report: ${report_path}"
}

main_exit=0
run_mode || main_exit=$?
write_report
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path" --schema-prefix "rgc.verification-coverage-matrix"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

if [[ "$mode" == "report" ]]; then
  exit 0
fi

exit "$main_exit"
