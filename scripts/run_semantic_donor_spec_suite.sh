#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
component="semantic_donor_spec"
bead_id="bd-3u5"
doc_path="docs/SEMANTIC_DONOR_SPEC.md"
plan_path="PLAN_TO_CREATE_FRANKEN_ENGINE.md"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/semantic_donor_spec/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/semantic_donor_spec_events.jsonl"

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
      failed_error_code="FE-SEM-DONOR-0006"
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

count_semantic_entries() {
  rg -n -- "SEM-[A-Z]{3}-[0-9]{3}" "$doc_path" | wc -l | tr -d ' '
}

validate_machine_readable_fixture() {
  local file="$1"
  local required_fields=(
    "semantic_id:"
    "category:"
    "observable_contract:"
    "edge_cases:"
    "compatibility_impact:"
    "test262_refs:"
    "lockstep_fixture_refs:"
    "waiver_policy:"
    "status:"
  )
  local field
  for field in "${required_fields[@]}"; do
    if ! rg -nF -- "$field" "$file" >/dev/null; then
      echo "fixture ${file} missing required field ${field}" >&2
      return 1
    fi
  done
}

check_document_structure() {
  require_literal "## 1. Purpose And Scope" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 2. Semantic Entry Schema (Machine-Readable Contract)" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 3. Semantic Domain Catalog" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 4. Compatibility-Critical Semantic Entries" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 5. Edge-Case Coverage Requirements" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 6. test262 And Lockstep Mapping Rules" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 7. Non-Goals (Explicitly Excluded)" "$doc_path" "FE-SEM-DONOR-0001" || return 1
  require_literal "## 8. Structured Audit Requirements" "$doc_path" "FE-SEM-DONOR-0001" || return 1

  require_literal "test262_refs" "$doc_path" "FE-SEM-DONOR-0002" || return 1
  require_literal "lockstep_fixture_refs" "$doc_path" "FE-SEM-DONOR-0002" || return 1
  require_literal "observable semantics" "$doc_path" "FE-SEM-DONOR-0002" || return 1
  require_literal "not HOW donor engines implement it" "$doc_path" "FE-SEM-DONOR-0002" || return 1

  require_literal '- [x] Add semantic donor spec document (observable behavior, edge cases, compatibility-critical semantics) as implementation source of truth (`docs/SEMANTIC_DONOR_SPEC.md`).' "$plan_path" "FE-SEM-DONOR-0003" || return 1

  require_literal '`trace_id`' "$doc_path" "FE-SEM-DONOR-0005" || return 1
  require_literal '`decision_id`' "$doc_path" "FE-SEM-DONOR-0005" || return 1
  require_literal '`policy_id`' "$doc_path" "FE-SEM-DONOR-0005" || return 1
  require_literal '`component`' "$doc_path" "FE-SEM-DONOR-0005" || return 1
  require_literal '`event`' "$doc_path" "FE-SEM-DONOR-0005" || return 1
  require_literal '`outcome`' "$doc_path" "FE-SEM-DONOR-0005" || return 1
  require_literal '`error_code`' "$doc_path" "FE-SEM-DONOR-0005" || return 1

  local entry_count
  entry_count="$(count_semantic_entries)"
  if [[ "$entry_count" -lt 20 ]]; then
    echo "semantic entry count too low: ${entry_count} (expected >= 20)" >&2
    failed_error_code="FE-SEM-DONOR-0002"
    return 1
  fi
}

run_schema_fixtures() {
  local pass_fixture="${run_dir}/semantic_fixture_pass.yml"
  local fail_fixture="${run_dir}/semantic_fixture_fail_missing_field.yml"

  cat >"$pass_fixture" <<'EOF'
semantic_id: SEM-PRM-001
category: promise-microtasks
observable_contract: FIFO microtask ordering for promise jobs.
edge_cases:
  - nested queueMicrotask in then
compatibility_impact: high
test262_refs:
  - test/built-ins/Promise/prototype/then/S25.4.5.3_A5.1_T1.js
lockstep_fixture_refs:
  - artifacts/lockstep/promise_fifo_jobs_seed_v1.json
waiver_policy: explicit-waiver-required
status: required
EOF

  cat >"$fail_fixture" <<'EOF'
semantic_id: SEM-PRM-002
category: promise-microtasks
observable_contract: rejection propagation ordering
edge_cases:
  - then throws synchronously
compatibility_impact: high
test262_refs:
  - test/built-ins/Promise/prototype/catch/name.js
waiver_policy: explicit-waiver-required
status: required
EOF

  if ! validate_machine_readable_fixture "$pass_fixture"; then
    failed_error_code="FE-SEM-DONOR-0004"
    return 1
  fi

  if ( validate_machine_readable_fixture "$fail_fixture" >/dev/null 2>&1 ); then
    echo "expected fail fixture to be rejected by schema validator" >&2
    failed_error_code="FE-SEM-DONOR-0004"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "semantic donor spec structure checks" check_document_structure
      ;;
    test)
      run_step "semantic donor schema fixtures" run_schema_fixtures
      ;;
    ci)
      run_step "semantic donor spec structure checks" check_document_structure
      run_step "semantic donor schema fixtures" run_schema_fixtures
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
    echo '  "schema_version": "franken-engine.semantic-donor-spec.run-manifest.v1",'
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
    echo "    \"semantic_doc\": \"${doc_path}\","
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
      echo "{\"trace_id\":\"trace-sem-donor-${timestamp}\",\"decision_id\":\"decision-sem-donor-${timestamp}\",\"policy_id\":\"policy-sem-donor-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":\"${failed_error_code}\"}"
    else
      echo "{\"trace_id\":\"trace-sem-donor-${timestamp}\",\"decision_id\":\"decision-sem-donor-${timestamp}\",\"policy_id\":\"policy-sem-donor-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":null}"
    fi
  } >"${events_path}"

  echo "semantic donor spec run manifest: ${manifest_path}"
  echo "semantic donor spec events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
