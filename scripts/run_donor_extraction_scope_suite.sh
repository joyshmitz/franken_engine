#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
component="donor_extraction_scope"
bead_id="bd-10a"
doc_path="docs/DONOR_EXTRACTION_SCOPE.md"
plan_path="PLAN_TO_CREATE_FRANKEN_ENGINE.md"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/donor_extraction_scope/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/donor_extraction_scope_events.jsonl"

mkdir -p "$run_dir"

declare -a commands_run=()
failed_command=""
failed_error_code=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! "$@"; then
    failed_command="$command_text"
    if [[ -z "$failed_error_code" ]]; then
      failed_error_code="FE-DONOR-SCOPE-0006"
    fi
    return 1
  fi
}

require_literal() {
  local literal="$1"
  local file="$2"
  local code="$3"
  if ! rg -nFi -- "$literal" "$file" >/dev/null; then
    echo "missing required literal in ${file}: ${literal}" >&2
    failed_error_code="$code"
    return 1
  fi
}

validate_change_record_fixture() {
  local file="$1"
  local required_fields=(
    "source_corpus_ref:"
    "extracted_behavior:"
    "native_mapping:"
    "equivalence_artifact_ref:"
    "trace_id:"
    "decision_id:"
    "policy_id:"
    "component:"
    "event:"
    "outcome:"
    "error_code:"
  )

  local forbidden_phrases=(
    "hidden class layout"
    "inline cache architecture"
    "turbofan"
    "ignition"
    "quickjs bytecode"
    "copy donor code"
    "rusty_v8"
    "rquickjs"
    "silent fallback-to-delegate"
  )

  local field
  for field in "${required_fields[@]}"; do
    if ! rg -nF "$field" "$file" >/dev/null; then
      echo "fixture ${file} missing required field ${field}" >&2
      return 1
    fi
  done

  local phrase
  for phrase in "${forbidden_phrases[@]}"; do
    if rg -nFi "$phrase" "$file" >/dev/null; then
      echo "fixture ${file} contains forbidden donor phrase: ${phrase}" >&2
      return 1
    fi
  done
}

check_scope_document_structure() {
  require_literal "## 1. Policy Objective" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 2. Allowlist: Permitted Donor Outputs" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 3. Denylist: Prohibited Donor Imports" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 5. Workflow Stages (Collect -> Normalize -> Approve -> Integrate)" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 6. PR/Review Gate Checklist (Blocking)" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 7. CI Guardrails And Audit Logging" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 8. Exception Policy (Strict, Time-Bounded)" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1
  require_literal "## 9. Anti-Drift Policy" "$doc_path" "FE-DONOR-SCOPE-0001" || return 1

  require_literal "observable semantics" "$doc_path" "FE-DONOR-SCOPE-0002" || return 1
  require_literal "compatibility-critical edge cases" "$doc_path" "FE-DONOR-SCOPE-0002" || return 1
  require_literal "conformance vectors and fixtures" "$doc_path" "FE-DONOR-SCOPE-0002" || return 1
  require_literal "hidden classes/shapes" "$doc_path" "FE-DONOR-SCOPE-0002" || return 1
  require_literal "inline-cache architecture" "$doc_path" "FE-DONOR-SCOPE-0002" || return 1
  require_literal "hidden fallback-to-delegate behavior" "$doc_path" "FE-DONOR-SCOPE-0002" || return 1

  require_literal '- [x] Add donor-extraction scope document with explicit exclusions for V8/QuickJS semantic harvesting (`docs/DONOR_EXTRACTION_SCOPE.md`).' "$plan_path" "FE-DONOR-SCOPE-0003" || return 1

  require_literal '`trace_id`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
  require_literal '`decision_id`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
  require_literal '`policy_id`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
  require_literal '`component`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
  require_literal '`event`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
  require_literal '`outcome`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
  require_literal '`error_code`' "$doc_path" "FE-DONOR-SCOPE-0005" || return 1
}

run_policy_fixtures() {
  local pass_fixture="${run_dir}/fixture_pass.md"
  local fail_missing_fixture="${run_dir}/fixture_fail_missing_field.md"
  local fail_forbidden_fixture="${run_dir}/fixture_fail_forbidden_phrase.md"

  cat >"$pass_fixture" <<'EOF'
source_corpus_ref: legacy_v8/test262/promises.json#v1
extracted_behavior: Promise job ordering for chained then/catch handlers.
native_mapping: crates/franken-engine/src/scheduler_lane.rs
equivalence_artifact_ref: artifacts/lockstep/promise_jobs_20260222.json
trace_id: trace-donor-0001
decision_id: decision-donor-0001
policy_id: donor-scope-v1
component: donor_extraction_scope
event: integrate
outcome: approved
error_code:
EOF

  cat >"$fail_missing_fixture" <<'EOF'
source_corpus_ref: legacy_quickjs/tests/iterators.json#v1
extracted_behavior: Iterator closing semantics on abrupt completion.
equivalence_artifact_ref: artifacts/lockstep/iterator_close_20260222.json
trace_id: trace-donor-0002
decision_id: decision-donor-0002
policy_id: donor-scope-v1
component: donor_extraction_scope
event: integrate
outcome: approved
error_code:
EOF

  cat >"$fail_forbidden_fixture" <<'EOF'
source_corpus_ref: legacy_v8/v8/src/objects#shape
extracted_behavior: Object property reads.
native_mapping: crates/franken-engine/src/runtime_observability.rs
equivalence_artifact_ref: artifacts/lockstep/object_read_20260222.json
trace_id: trace-donor-0003
decision_id: decision-donor-0003
policy_id: donor-scope-v1
component: donor_extraction_scope
event: integrate
outcome: approved
error_code:
notes: mirror hidden class layout for speed.
EOF

  if ! validate_change_record_fixture "$pass_fixture"; then
    failed_error_code="FE-DONOR-SCOPE-0004"
    return 1
  fi

  if ( validate_change_record_fixture "$fail_missing_fixture" >/dev/null 2>&1 ); then
    echo "expected missing-field fixture to fail validation" >&2
    failed_error_code="FE-DONOR-SCOPE-0004"
    return 1
  fi

  if ( validate_change_record_fixture "$fail_forbidden_fixture" >/dev/null 2>&1 ); then
    echo "expected forbidden-phrase fixture to fail validation" >&2
    failed_error_code="FE-DONOR-SCOPE-0004"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "donor scope document structure checks" check_scope_document_structure
      ;;
    test)
      run_step "donor scope policy fixtures" run_policy_fixtures
      ;;
    ci)
      run_step "donor scope document structure checks" check_scope_document_structure
      run_step "donor scope policy fixtures" run_policy_fixtures
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma

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

  printf '%s\n' "${commands_run[@]}" >"${run_dir}/commands.txt"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.donor-extraction-scope.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    if [[ -n "$failed_error_code" ]]; then
      echo "  \"error_code\": \"${failed_error_code}\","
    else
      echo '  "error_code": null,'
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
    echo "    \"scope_doc\": \"${doc_path}\","
    echo "    \"plan_doc\": \"${plan_path}\""
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
    if [[ -n "$failed_error_code" ]]; then
      echo "{\"trace_id\":\"trace-donor-scope-${timestamp}\",\"decision_id\":\"decision-donor-scope-${timestamp}\",\"policy_id\":\"policy-donor-scope-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":\"${failed_error_code}\"}"
    else
      echo "{\"trace_id\":\"trace-donor-scope-${timestamp}\",\"decision_id\":\"decision-donor-scope-${timestamp}\",\"policy_id\":\"policy-donor-scope-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":null}"
    fi
  } >"${events_path}"

  echo "donor extraction scope run manifest: ${manifest_path}"
  echo "donor extraction scope events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
