#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${RGC_ARTIFACT_VALIDATOR_PHASE_B_ARTIFACT_ROOT:-artifacts/rgc_artifact_validator_phase_b}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-2400}"
rch_ready_attempts="${RCH_READY_ATTEMPTS:-18}"
rch_ready_sleep_seconds="${RCH_READY_SLEEP_SECONDS:-2}"
rch_step_retry_attempts="${RCH_STEP_RETRY_ATTEMPTS:-3}"
rch_step_retry_sleep_seconds="${RCH_STEP_RETRY_SLEEP_SECONDS:-2}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="/data/projects/franken_engine/target_rch_rgc_artifact_validator_phase_b"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
valid_report_path="${run_dir}/validator_bundle_report_valid.json"
invalid_report_path="${run_dir}/validator_bundle_report_invalid.json"
valid_bundle_dir="${run_dir}/bundle_valid"
invalid_bundle_dir="${run_dir}/bundle_invalid"

trace_id="trace-rgc-artifact-validator-phase-b-${timestamp}"
decision_id="decision-rgc-artifact-validator-phase-b-${timestamp}"
policy_id="policy-rgc-artifact-validator-phase-b-v1"
component="rgc_artifact_validator_phase_b_gate"
scenario_id="rgc-062b"
replay_command="./scripts/e2e/rgc_artifact_validator_phase_b_replay.sh ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for RGC artifact validator phase-B heavy commands" >&2
  exit 2
fi

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

run_rch_strict_logged() {
  local log_path="$1"
  shift

  local rch_status=0
  local -a rch_cmd

  rch_cmd=(
    timeout "${rch_timeout_seconds}"
    rch exec -- env
    "RUSTUP_TOOLCHAIN=${toolchain}"
    "CARGO_TARGET_DIR=${target_dir}"
    "$@"
  )

  : >"$log_path"
  "${rch_cmd[@]}" 2>&1 | tee -a "$log_path"
  rch_status=${PIPESTATUS[0]}

  if ! rch_reject_local_fallback "$log_path"; then
    return 125
  fi

  return "$rch_status"
}

declare -a commands_run=()
declare -a step_logs=()
failed_command=""
manifest_written=false

ensure_rch_ready() {
  local attempts="${1:-5}"
  local sleep_seconds="${2:-2}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if rch check >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done
  return 1
}

run_step_expect_exit() {
  local command_text="$1"
  local expected_exit="$2"
  local log_path remote_exit_code run_status attempt
  local fallback_detected
  shift 2

  commands_run+=("$command_text")
  echo "==> $command_text"
  for ((attempt = 1; attempt <= rch_step_retry_attempts; attempt++)); do
    log_path="$(mktemp "${run_dir}/rch-log.XXXXXX")"
    step_logs+=("$log_path")

    if ! ensure_rch_ready "${rch_ready_attempts}" "${rch_ready_sleep_seconds}"; then
      echo "==> warning: rch check not ready after ${rch_ready_attempts} attempts; attempting remote execution anyway" \
        | tee -a "$log_path"
    fi

    run_rch_strict_logged "$log_path" "$@"
    run_status=$?
    fallback_detected=false
    if [[ "$run_status" -eq 125 ]]; then
      fallback_detected=true
    fi

    if ! rch_reject_local_fallback "$log_path"; then
      fallback_detected=true
    fi

    if [[ "$fallback_detected" == true ]]; then
      if [[ "$attempt" -lt "$rch_step_retry_attempts" ]]; then
        echo "==> warning: detected rch local fallback signature (attempt ${attempt}/${rch_step_retry_attempts}); retrying" \
          | tee -a "$log_path"
        rch daemon start >/dev/null 2>&1 || true
        sleep "${rch_step_retry_sleep_seconds}"
        continue
      fi
      failed_command="${command_text} (rch-local-fallback-detected)"
      return 1
    fi

    if [[ "$run_status" -ne 0 ]]; then
      if rg -q "Remote command finished: exit=${expected_exit}" "$log_path"; then
        echo "==> recovered: remote execution produced expected exit=${expected_exit}" | tee -a "$log_path"
      elif rg -q 'Remote command finished: exit=0' "$log_path"; then
        echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
      elif [[ "$run_status" -eq "$expected_exit" ]]; then
        echo "==> info: accepted rch process exit=${run_status} without explicit remote marker" | tee -a "$log_path"
      else
        failed_command="$command_text"
        return 1
      fi
    fi

    remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
    if [[ -z "$remote_exit_code" ]]; then
      if [[ "$run_status" -eq "$expected_exit" ]]; then
        echo "==> info: remote exit marker missing; accepted rch process exit=${run_status}" | tee -a "$log_path"
        return 0
      fi
      failed_command="${command_text} (remote-exit=missing, expected=${expected_exit})"
      return 1
    fi

    if [[ "$remote_exit_code" != "$expected_exit" ]]; then
      failed_command="${command_text} (remote-exit=${remote_exit_code:-missing}, expected=${expected_exit})"
      return 1
    fi

    return 0
  done
}

run_step() {
  local command_text="$1"
  shift
  run_step_expect_exit "$command_text" 0 "$@"
}

compute_ids() {
  local scenario="$1"
  local fixture="$2"
  local lane="$3"
  local seed="$4"
  local seed_material digest short

  seed_material="${scenario}|${fixture}|${lane}|${seed}"
  digest="$(printf '%s' "$seed_material" | sha256sum | awk '{print $1}')"
  short="${digest:0:16}"

  echo "trace-rgc-${short}" "decision-rgc-${short}" "policy-rgc-${lane}-v1" "run-${scenario}-${short}"
}

emit_sample_triad() {
  local base_dir="$1"
  local scenario="$2"
  local fixture="$3"
  local lane="$4"
  local seed="$5"
  local component="$6"
  local event_name="$7"
  local ids trace decision policy run_id run_subdir

  ids="$(compute_ids "$scenario" "$fixture" "$lane" "$seed")"
  read -r trace decision policy run_id <<<"$ids"

  run_subdir="${base_dir}/${run_id}"
  mkdir -p "$run_subdir"

  cat >"${run_subdir}/run_manifest.json" <<JSON
{
  "schema_version": "franken-engine.rgc-test-harness.run-manifest.v1",
  "harness_schema_version": "franken-engine.rgc-test-harness.v1",
  "run_id": "${run_id}",
  "scenario_id": "${scenario}",
  "fixture_id": "${fixture}",
  "lane": "${lane}",
  "seed": ${seed},
  "trace_id": "${trace}",
  "decision_id": "${decision}",
  "policy_id": "${policy}",
  "event_count": 1,
  "command_count": 1,
  "env_fingerprint": "env-${scenario}-${lane}",
  "replay_command": "./scripts/e2e/rgc_artifact_validator_phase_b_replay.sh ci",
  "generated_at_unix_ms": 1700400000100
}
JSON

  cat >"${run_subdir}/events.jsonl" <<JSON
{"schema_version":"franken-engine.rgc-test-event.v1","scenario_id":"${scenario}","fixture_id":"${fixture}","trace_id":"${trace}","decision_id":"${decision}","policy_id":"${policy}","lane":"${lane}","component":"${component}","event":"${event_name}","outcome":"pass","error_code":null,"seed":${seed},"sequence":0,"timing_us":10,"timestamp_unix_ms":1700400000000}
JSON

  cat >"${run_subdir}/commands.txt" <<'TXT'
cargo test -p frankenengine-engine --test rgc_test_harness_integration
TXT
}

prepare_sample_bundles() {
  local scenario="rgc-062b-sample"
  local fixture="fixture-shared"
  local seed="6208"

  mkdir -p "$valid_bundle_dir" "$invalid_bundle_dir"

  emit_sample_triad "$valid_bundle_dir" "$scenario" "$fixture" "runtime" "$seed" "runtime_lane" "lane_complete"
  emit_sample_triad "$valid_bundle_dir" "$scenario" "$fixture" "security" "$seed" "security_lane" "lane_complete"
  emit_sample_triad "$valid_bundle_dir" "$scenario" "$fixture" "e2e" "$seed" "e2e_lane" "lane_complete"

  emit_sample_triad "$invalid_bundle_dir" "$scenario" "$fixture" "runtime" "$seed" "runtime_lane" "lane_complete"
  emit_sample_triad "$invalid_bundle_dir" "$scenario" "$fixture" "security" "$seed" "security_lane" "lane_complete"

  local security_run_dir
  security_run_dir="$(find "$invalid_bundle_dir" -maxdepth 1 -mindepth 1 -type d -name 'run-*' | rg 'security|runtime' | sort | tail -n1)"
  if [[ -z "$security_run_dir" ]]; then
    security_run_dir="$(find "$invalid_bundle_dir" -maxdepth 1 -mindepth 1 -type d | sort | tail -n1)"
  fi

  jq '.trace_id = "trace-rgc-corrupted-bundle"' "${security_run_dir}/run_manifest.json" >"${security_run_dir}/run_manifest.tmp"
  mv "${security_run_dir}/run_manifest.tmp" "${security_run_dir}/run_manifest.json"

  jq '.trace_id = "trace-rgc-corrupted-bundle"' "${security_run_dir}/events.jsonl" >"${security_run_dir}/events.tmp"
  mv "${security_run_dir}/events.tmp" "${security_run_dir}/events.jsonl"
}

validate_reports_locally() {
  commands_run+=("jq -e '.report_kind == \"bundle\" and .report.valid == true and (.report.findings | length == 0)' ${valid_report_path}")
  jq -e '.report_kind == "bundle" and .report.valid == true and (.report.findings | length == 0)' "${valid_report_path}" >/dev/null

  commands_run+=("jq -e '.report_kind == \"bundle\" and .report.valid == false and (.report.findings | map(select(.error_code == \"correlation_mismatch\")) | length >= 1)' ${invalid_report_path}")
  jq -e '.report_kind == "bundle" and .report.valid == false and (.report.findings | map(select(.error_code == "correlation_mismatch")) | length >= 1)' "${invalid_report_path}" >/dev/null
}

run_mode() {
  local selected_mode="${1:-$mode}"
  case "$selected_mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin rgc_artifact_validator --lib --test rgc_test_harness_integration" \
        cargo check -p frankenengine-engine --bin rgc_artifact_validator --lib --test rgc_test_harness_integration \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_bundle_validator_accepts_valid_multi_lane_bundle" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_bundle_validator_accepts_valid_multi_lane_bundle \
        || return $?
      run_step "cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_bundle_validator_detects_cross_lane_drift_even_when_triads_self_consistent" \
        cargo test -p frankenengine-engine --lib rgc_test_harness::tests::artifact_bundle_validator_detects_cross_lane_drift_even_when_triads_self_consistent \
        || return $?
      run_step "cargo test -p frankenengine-engine --test rgc_test_harness_integration -- --exact rgc_bundle_validator_detects_cross_lane_drift_even_when_lane_triads_pass" \
        cargo test -p frankenengine-engine --test rgc_test_harness_integration -- --exact rgc_bundle_validator_detects_cross_lane_drift_even_when_lane_triads_pass \
        || return $?

      prepare_sample_bundles

      run_step "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --bundle-dir ${valid_bundle_dir} --required-lanes runtime,security,e2e --out ${valid_report_path} --pretty" \
        cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --bundle-dir "${valid_bundle_dir}" --required-lanes runtime,security,e2e --out "${valid_report_path}" --pretty \
        || return $?

      run_step_expect_exit \
        "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --bundle-dir ${invalid_bundle_dir} --required-lanes runtime,security --out ${invalid_report_path} --pretty (expect exit 2)" \
        2 \
        cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --bundle-dir "${invalid_bundle_dir}" --required-lanes runtime,security --out "${invalid_report_path}" --pretty \
        || return $?

      validate_reports_locally || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin rgc_artifact_validator -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin rgc_artifact_validator -- -D warnings \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --test rgc_test_harness_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test rgc_test_harness_integration -- -D warnings \
        || return $?
      ;;
    ci)
      run_mode check || return $?
      run_mode test || return $?
      run_mode clippy || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
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
    error_code_json='"FE-RGC-062B-ARTIFACT-BUNDLE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"franken-engine.rgc-artifact-validator-phase-b.gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo '{'
    echo '  "schema_version": "franken-engine.rgc-artifact-validator-phase-b.gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.11.12.2",'
    echo "  \"component\": \"${component}\"," 
    echo "  \"scenario_id\": \"${scenario_id}\"," 
    echo "  \"mode\": \"${mode}\"," 
    echo "  \"toolchain\": \"${toolchain}\"," 
    echo "  \"cargo_target_dir\": \"${target_dir}\"," 
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\"," 
    echo "  \"decision_id\": \"${decision_id}\"," 
    echo "  \"policy_id\": \"${policy_id}\"," 
    echo "  \"git_commit\": \"${git_commit}\"," 
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\"," 
    echo "  \"outcome\": \"${outcome}\"," 
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\"," 
    fi
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields '    ' 'null'
    echo '  },'
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\"," 
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\"," 
    echo "    \"events\": \"${events_path}\"," 
    echo "    \"commands\": \"${commands_path}\"," 
    echo "    \"valid_report\": \"${valid_report_path}\"," 
    echo "    \"invalid_report\": \"${invalid_report_path}\"," 
    echo "    \"valid_bundle_dir\": \"${valid_bundle_dir}\"," 
    echo "    \"invalid_bundle_dir\": \"${invalid_bundle_dir}\"," 
    echo '    "gate_script": "scripts/run_rgc_artifact_validator_phase_b_gate.sh",'
    echo '    "replay_wrapper": "scripts/e2e/rgc_artifact_validator_phase_b_replay.sh",'
    echo '    "validator_bin": "crates/franken-engine/src/bin/rgc_artifact_validator.rs",'
    echo '    "validator_module": "crates/franken-engine/src/rgc_test_harness.rs",'
    echo '    "integration_tests": "crates/franken-engine/tests/rgc_test_harness_integration.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\"," 
    echo "    \"cat ${events_path}\"," 
    echo "    \"cat ${commands_path}\"," 
    echo "    \"cat ${valid_report_path}\"," 
    echo "    \"cat ${invalid_report_path}\"," 
    echo "    \"ls -1 ${run_dir}/rch-log.*\"," 
    echo "    \"${replay_command}\""
    echo '  ],'
    echo '  "rch_step_logs": ['
    for idx in "${!step_logs[@]}"; do
      comma=,
      if [[ "$idx" == "$(( ${#step_logs[@]} - 1 ))" ]]; then
        comma=''
      fi
      echo "    \"$(parser_frontier_json_escape "${step_logs[$idx]}")\"${comma}"
    done
    echo '  ]'
    echo '}'
  } >"$manifest_path"

  echo "rgc artifact validator phase-b manifest: ${manifest_path}"
  echo "rgc artifact validator phase-b events: ${events_path}"
  echo "rgc artifact validator phase-b commands: ${commands_path}"
  echo "rgc artifact validator phase-b valid report: ${valid_report_path}"
  echo "rgc artifact validator phase-b invalid report: ${invalid_report_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
