#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_frx_pilot_rollout_harness}"
artifact_root="${FRX_PILOT_ROLLOUT_HARNESS_ARTIFACT_ROOT:-artifacts/frx_pilot_rollout_harness}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
phase_scorecards_path="${run_dir}/phase_exit_scorecards.json"
readiness_inputs_path="${run_dir}/migration_readiness_inputs.json"
remediation_queue_path="${run_dir}/blocked_workload_remediation_queue.json"
rollback_drill_path="${run_dir}/forced_regression_rollback_drill.json"
cohort_manifest_path="${run_dir}/pilot_cohort_manifest.json"

trace_id="trace-frx-pilot-rollout-harness-${timestamp}"
decision_id="decision-frx-pilot-rollout-harness-${timestamp}"
policy_id="policy-frx-pilot-rollout-harness-v1"
component="frx_pilot_rollout_harness_gate"
scenario_id="frx-09.1"
replay_command="${0} ${mode}"

mkdir -p "$run_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for FRX pilot rollout harness heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" rch exec -q -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'falling back to local|fallback to local|local fallback' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"

  log_path="$(mktemp)"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rg -q "Remote command finished: exit=0" "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  rm -f "$log_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test frx_pilot_rollout_harness" \
        cargo check -p frankenengine-engine --test frx_pilot_rollout_harness
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test frx_pilot_rollout_harness" \
        cargo test -p frankenengine-engine --test frx_pilot_rollout_harness
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test frx_pilot_rollout_harness -- -D warnings" \
        cargo clippy -p frankenengine-engine --test frx_pilot_rollout_harness -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test frx_pilot_rollout_harness" \
        cargo check -p frankenengine-engine --test frx_pilot_rollout_harness
      run_step "cargo test -p frankenengine-engine --test frx_pilot_rollout_harness" \
        cargo test -p frankenengine-engine --test frx_pilot_rollout_harness
      run_step "cargo clippy -p frankenengine-engine --test frx_pilot_rollout_harness -- -D warnings" \
        cargo clippy -p frankenengine-engine --test frx_pilot_rollout_harness -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_contract_artifacts() {
  local outcome="$1"

  cat >"$phase_scorecards_path" <<EOF
{
  "schema_version": "frx.pilot-rollout-harness.phase-exit-scorecards.v1",
  "scenario_id": "${scenario_id}",
  "generated_at_utc": "${timestamp}",
  "outcome": "${outcome}",
  "phases": [
    {
      "phase_id": "shadow",
      "user_traffic_bps": 0,
      "phase_exit_scorecard_id": "scorecard.shadow.v1",
      "required_readiness_inputs": [
        "preflight_verdict",
        "compatibility_advisories",
        "onboarding_scorecard",
        "support_bundle_ref"
      ],
      "promotion_requirements": [
        "divergence_budget_within_threshold",
        "tail_latency_regression_within_threshold",
        "security_incident_delta_within_threshold",
        "evidence_bundle_complete"
      ],
      "rollback_trigger_ids": [
        "shadow_divergence_budget_exceeded",
        "shadow_security_incident_delta_exceeded"
      ],
      "automatic_rollback_required": true
    },
    {
      "phase_id": "canary",
      "user_traffic_bps": 500,
      "phase_exit_scorecard_id": "scorecard.canary.v1",
      "required_readiness_inputs": [
        "preflight_verdict",
        "compatibility_advisories",
        "onboarding_scorecard",
        "support_bundle_ref"
      ],
      "promotion_requirements": [
        "error_budget_burn_within_threshold",
        "p95_latency_regression_within_threshold",
        "security_incident_delta_within_threshold",
        "correlated_readiness_artifacts_complete"
      ],
      "rollback_trigger_ids": [
        "canary_error_budget_burn_exceeded",
        "canary_security_incident_delta_exceeded"
      ],
      "automatic_rollback_required": true
    },
    {
      "phase_id": "active",
      "user_traffic_bps": 10000,
      "phase_exit_scorecard_id": "scorecard.active.v1",
      "required_readiness_inputs": [
        "preflight_verdict",
        "compatibility_advisories",
        "onboarding_scorecard",
        "support_bundle_ref"
      ],
      "promotion_requirements": [
        "active_cohort_error_budget_within_threshold",
        "tail_latency_regression_within_threshold",
        "containment_incident_delta_within_threshold",
        "remediation_queue_drained_or_accepted"
      ],
      "rollback_trigger_ids": [
        "active_error_budget_burn_exceeded",
        "active_containment_incident_delta_exceeded"
      ],
      "automatic_rollback_required": true
    }
  ]
}
EOF

  cat >"$readiness_inputs_path" <<EOF
{
  "schema_version": "frx.pilot-rollout-harness.migration-readiness.v1",
  "scenario_id": "${scenario_id}",
  "generated_at_utc": "${timestamp}",
  "required_inputs": [
    "preflight_verdict",
    "compatibility_advisories",
    "onboarding_scorecard",
    "support_bundle_ref"
  ],
  "fail_closed_on_missing_inputs": true,
  "require_remediation_queue_for_blocked_workloads": true,
  "require_support_bundle_linkage": true
}
EOF

  cat >"$remediation_queue_path" <<EOF
{
  "schema_version": "frx.pilot-rollout-harness.remediation-queue.v1",
  "scenario_id": "${scenario_id}",
  "generated_at_utc": "${timestamp}",
  "fail_closed_on_missing_inputs": true,
  "required_fields": [
    "workload_id",
    "phase_id",
    "blocking_signal",
    "remediation_owner",
    "recommended_action",
    "evidence_ref",
    "replay_command"
  ],
  "entries": []
}
EOF

  cat >"$rollback_drill_path" <<EOF
{
  "schema_version": "frx.pilot-rollout-harness.rollback-drill.v1",
  "scenario_id": "${scenario_id}",
  "generated_at_utc": "${timestamp}",
  "forced_regression_drill_required": true,
  "automatic_rollback_expected": true,
  "required_artifacts": [
    "run_manifest.json",
    "events.jsonl",
    "phase_exit_scorecards.json",
    "blocked_workload_remediation_queue.json"
  ],
  "success_criteria": [
    "rollback_decision_emitted",
    "incident_capture_recorded",
    "replay_bundle_linked",
    "support_bundle_linked"
  ]
}
EOF

  cat >"$cohort_manifest_path" <<EOF
{
  "schema_version": "frx.pilot-rollout-harness.cohort-manifest.v1",
  "scenario_id": "${scenario_id}",
  "generated_at_utc": "${timestamp}",
  "strata": [
    {
      "stratum_id": "low_risk_transactional_dashboard",
      "risk_tier": "low",
      "target_share_bps": 3000
    },
    {
      "stratum_id": "medium_risk_data_sync_optimistic_ui",
      "risk_tier": "medium",
      "target_share_bps": 3000
    },
    {
      "stratum_id": "high_risk_collaboration_concurrency",
      "risk_tier": "high",
      "target_share_bps": 2000
    },
    {
      "stratum_id": "security_sensitive_admin_policy_control",
      "risk_tier": "critical",
      "target_share_bps": 2000
    }
  ],
  "phase_order": [
    "shadow",
    "canary",
    "active"
  ]
}
EOF
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
    error_code_json='"FE-FRX-09-1-GATE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  write_contract_artifacts "$outcome"
  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  {
    echo "{\"schema_version\":\"frx.pilot-rollout-harness-gate.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "frx.pilot-rollout-harness-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-mjh3.9.1",'
    echo "  \"component\": \"${component}\","
    echo "  \"scenario_id\": \"${scenario_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"rch_exec_timeout_seconds\": ${rch_timeout_seconds},"
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"error_code\": ${error_code_json},"
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(parser_frontier_json_escape "${failed_command}")\","
    fi
    echo "  \"replay_command\": \"$(parser_frontier_json_escape "${replay_command}")\","
    echo '  "deterministic_environment": {'
    parser_frontier_emit_manifest_environment_fields "    "
    echo '  },'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(parser_frontier_json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"phase_exit_scorecards\": \"${phase_scorecards_path}\","
    echo "    \"migration_readiness_inputs\": \"${readiness_inputs_path}\","
    echo "    \"blocked_workload_remediation_queue\": \"${remediation_queue_path}\","
    echo "    \"forced_regression_rollback_drill\": \"${rollback_drill_path}\","
    echo "    \"pilot_cohort_manifest\": \"${cohort_manifest_path}\","
    echo '    "contract_doc": "docs/FRX_PILOT_ROLLOUT_HARNESS_V1.md",'
    echo '    "contract_json": "docs/frx_pilot_rollout_harness_v1.json",'
    echo '    "integration_test": "crates/franken-engine/tests/frx_pilot_rollout_harness.rs"'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${commands_path}\","
    echo "    \"cat ${phase_scorecards_path}\","
    echo "    \"cat ${readiness_inputs_path}\","
    echo "    \"cat ${remediation_queue_path}\","
    echo "    \"cat ${rollback_drill_path}\","
    echo "    \"cat ${cohort_manifest_path}\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "frx pilot rollout harness manifest: ${manifest_path}"
  echo "frx pilot rollout harness events: ${events_path}"
  echo "frx pilot rollout harness scorecards: ${phase_scorecards_path}"
  echo "frx pilot rollout harness readiness: ${readiness_inputs_path}"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"
exit "$main_exit"
