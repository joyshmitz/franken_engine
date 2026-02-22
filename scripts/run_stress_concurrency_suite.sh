#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-worker-default}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_stress_concurrency}"
component="stress_concurrency_suite"
bead_id="bd-3c1"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/stress_concurrency/${timestamp}"
manifest_path="${run_dir}/suite_run_manifest.json"
suite_events_path="${run_dir}/suite_events.jsonl"
commands_path="${run_dir}/commands.txt"
stress_manifest_path="${run_dir}/run_manifest.json"
stress_evidence_path="${run_dir}/stress_evidence.jsonl"
stress_structured_events_path="${run_dir}/stress_structured_events.jsonl"
test_output_path="${run_dir}/test_output.log"
raw_stress_evidence_path="${run_dir}/stress_evidence_raw.jsonl"

mkdir -p "$run_dir"

run_rch() {
  if [[ "${toolchain}" == "worker-default" ]]; then
    rch exec -- env CARGO_TARGET_DIR="${target_dir}" "$@"
  else
    rch exec -- env CARGO_TARGET_DIR="${target_dir}" RUSTUP_TOOLCHAIN="${toolchain}" "$@"
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

run_check() {
  run_step "cargo check -p frankenengine-engine --test stress_concurrency" \
    cargo check -p frankenengine-engine --test stress_concurrency
}

build_stress_artifacts_from_output() {
  local scenario_count aggregate_invariant_violations os arch rust_toolchain rustflags
  local tsan_enabled asan_enabled sanitizer_profile

  grep -E '^\[stress\] \{.*\}$' "${test_output_path}" | sed 's/^\[stress\] //' >"${raw_stress_evidence_path}" || true

  if [[ ! -s "${raw_stress_evidence_path}" ]]; then
    scenario_count=0
    aggregate_invariant_violations=0
  else
    scenario_count="$(jq -s 'length' "${raw_stress_evidence_path}")"
    aggregate_invariant_violations="$(jq -s 'map(.invariant_violations // 0) | add' "${raw_stress_evidence_path}")"
  fi

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  rust_toolchain="${toolchain}"
  rustflags="${RUSTFLAGS:-}"
  tsan_enabled=false
  asan_enabled=false
  if [[ "${rustflags}" == *"sanitize=thread"* ]]; then
    tsan_enabled=true
  fi
  if [[ "${rustflags}" == *"sanitize=address"* ]]; then
    asan_enabled=true
  fi
  if [[ "${tsan_enabled}" == true ]]; then
    sanitizer_profile="stress-tsan"
  elif [[ "${asan_enabled}" == true ]]; then
    sanitizer_profile="stress-asan"
  else
    sanitizer_profile="stress-default"
  fi

  if [[ -s "${raw_stress_evidence_path}" ]]; then
    cat "${raw_stress_evidence_path}" >"${stress_evidence_path}"
  else
    : >"${stress_evidence_path}"
  fi

  jq -n \
    --arg os "${os}" \
    --arg arch "${arch}" \
    --arg rust_toolchain "${rust_toolchain}" \
    --arg sanitizer_profile "${sanitizer_profile}" \
    --argjson tsan_enabled "${tsan_enabled}" \
    --argjson asan_enabled "${asan_enabled}" \
    --argjson scenario_count "${scenario_count}" \
    --argjson aggregate_invariant_violations "${aggregate_invariant_violations}" \
    '{
      record_type: "aggregate",
      aggregate_invariant_violations: $aggregate_invariant_violations,
      scenario_count: $scenario_count,
      environment_fingerprint: {
        os: $os,
        arch: $arch,
        rust_toolchain: $rust_toolchain
      },
      sanitizer_configuration: {
        profile: $sanitizer_profile,
        tsan_enabled: $tsan_enabled,
        asan_enabled: $asan_enabled
      }
    }' >>"${stress_evidence_path}"

  if [[ -s "${raw_stress_evidence_path}" ]]; then
    jq -c \
      --arg policy_id "policy-stress-concurrency-v1" \
      --arg component "${component}" \
      '
      {
        trace_id: ("trace-" + .scenario_id),
        decision_id: ("decision-" + .scenario_id),
        policy_id: $policy_id,
        component: $component,
        event: "scenario_evidence",
        outcome: (if (.invariant_violations // 0) == 0 then "ok" else "error" end),
        error_code: (if (.invariant_violations // 0) == 0 then null else "STRESS_INVARIANT_VIOLATION" end),
        scenario_id: .scenario_id,
        workload_family: .workload_family,
        concurrency_level: .concurrency_level,
        duration_s: .duration_s,
        total_hostcalls: .total_hostcalls,
        total_lifecycle_events: .total_lifecycle_events,
        invariant_violations: .invariant_violations,
        budget_exhaustion_events: .budget_exhaustion_events,
        quarantine_events: .quarantine_events
      }' "${raw_stress_evidence_path}" >"${stress_structured_events_path}"
  else
    : >"${stress_structured_events_path}"
  fi

  jq -n \
    --arg component "${component}" \
    --arg bead_id "${bead_id}" \
    --arg generated_at_utc "${timestamp}" \
    --argjson default_duration_s 60 \
    --argjson scenario_count "${scenario_count}" \
    --argjson aggregate_invariant_violations "${aggregate_invariant_violations}" \
    --arg os "${os}" \
    --arg arch "${arch}" \
    --arg rust_toolchain "${rust_toolchain}" \
    --arg sanitizer_profile "${sanitizer_profile}" \
    --argjson tsan_enabled "${tsan_enabled}" \
    --argjson asan_enabled "${asan_enabled}" \
    --arg stress_evidence_path "${stress_evidence_path}" \
    --arg stress_structured_events_path "${stress_structured_events_path}" \
    --arg test_module "crates/franken-engine/tests/stress_concurrency.rs" \
    --arg suite_script "scripts/run_stress_concurrency_suite.sh" \
    '{
      schema_version: "franken-engine.stress-concurrency.run-manifest.v1",
      component: $component,
      bead_id: $bead_id,
      generated_at_utc: $generated_at_utc,
      default_duration_s: $default_duration_s,
      scenario_count: $scenario_count,
      aggregate_invariant_violations: $aggregate_invariant_violations,
      environment_fingerprint: {
        os: $os,
        arch: $arch,
        rust_toolchain: $rust_toolchain
      },
      sanitizer_configuration: {
        profile: $sanitizer_profile,
        tsan_enabled: $tsan_enabled,
        asan_enabled: $asan_enabled
      },
      artifacts: {
        stress_evidence_jsonl: $stress_evidence_path,
        stress_structured_events_jsonl: $stress_structured_events_path,
        test_module: $test_module,
        suite_script: $suite_script
      }
    }' >"${stress_manifest_path}"
}

run_test() {
  local command_text="cargo test -p frankenengine-engine --test stress_concurrency -- --nocapture"
  commands_run+=("$command_text")
  echo "==> $command_text"
  set +e
  run_rch cargo test -p frankenengine-engine --test stress_concurrency -- --nocapture 2>&1 | tee "${test_output_path}"
  local status=${PIPESTATUS[0]}
  set -e
  if [[ "${status}" -ne 0 ]]; then
    failed_command="$command_text"
    return "${status}"
  fi
  build_stress_artifacts_from_output
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test stress_concurrency -- -D warnings" \
    cargo clippy -p frankenengine-engine --test stress_concurrency -- -D warnings
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
  else
    outcome="fail"
  fi

  if [[ -n "$failed_command" ]]; then
    error_code_json='"FE-STRESS-1001"'
  else
    error_code_json='null'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.stress-concurrency.suite-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
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
    echo "    \"suite_manifest\": \"${manifest_path}\","
    echo "    \"suite_events\": \"${suite_events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"stress_manifest\": \"${stress_manifest_path}\","
    echo "    \"stress_evidence\": \"${stress_evidence_path}\","
    echo "    \"stress_structured_events\": \"${stress_structured_events_path}\","
    echo '    "test_module": "crates/franken-engine/tests/stress_concurrency.rs",'
    echo '    "suite_script": "scripts/run_stress_concurrency_suite.sh"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${suite_events_path}\","
    echo "    \"cat ${stress_manifest_path}\","
    echo "    \"cat ${stress_evidence_path}\","
    echo "    \"cat ${stress_structured_events_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    echo "{\"trace_id\":\"trace-stress-suite-${timestamp}\",\"decision_id\":\"decision-stress-suite-${timestamp}\",\"policy_id\":\"policy-stress-concurrency-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${suite_events_path}"

  echo "stress suite run manifest: ${manifest_path}"
  echo "stress suite events: ${suite_events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
