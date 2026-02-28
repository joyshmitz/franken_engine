use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[path = "../src/test_flake_quarantine_workflow.rs"]
mod test_flake_quarantine_workflow;

use test_flake_quarantine_workflow::{
    FLAKE_WORKFLOW_COMPONENT, FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION,
    FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION, FLAKE_WORKFLOW_FAILURE_CODE, FlakePolicy, FlakeRunRecord,
    build_quarantine_records, classify_flakes, emit_structured_events, evaluate_gate_confidence,
    validate_quarantine_records,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = read_to_string(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct FlakeWorkflowContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    flake_detection: FlakeDetectionContract,
    reproducer_contract: ReproducerContract,
    quarantine_policy: QuarantinePolicyContract,
    gate_confidence: GateConfidenceContract,
    linkage_contract: LinkageContract,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FlakeDetectionContract {
    warning_flake_threshold_millionths: u32,
    high_flake_threshold_millionths: u32,
    required_run_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReproducerContract {
    require_ci_and_local_replay_commands: bool,
    required_bundle_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QuarantinePolicyContract {
    ttl_epochs: u32,
    require_owner_binding: bool,
    require_expiry: bool,
}

#[derive(Debug, Deserialize)]
struct GateConfidenceContract {
    require_flake_burden_metrics: bool,
    require_trendlines: bool,
    max_flake_burden_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct LinkageContract {
    require_impacted_unit_suite_links: bool,
    require_root_cause_hypothesis_artifacts: bool,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_missing_owner: bool,
    block_on_non_expiring_quarantine: bool,
}

fn sample_runs() -> Vec<FlakeRunRecord> {
    vec![
        FlakeRunRecord {
            run_id: "run-001".to_string(),
            epoch: 11,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "pass".to_string(),
            error_signature: None,
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-a".to_string(),
            related_unit_suites: vec!["unit_router_fallback".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-router-a".to_string()],
            seed: 9001,
        },
        FlakeRunRecord {
            run_id: "run-002".to_string(),
            epoch: 11,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "fail".to_string(),
            error_signature: Some("panic:router-fallback-timeout".to_string()),
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-b".to_string(),
            related_unit_suites: vec![
                "unit_router_fallback".to_string(),
                "unit_scheduler_budget".to_string(),
            ],
            root_cause_hypothesis_artifacts: vec![
                "hypothesis-router-a".to_string(),
                "hypothesis-scheduler-b".to_string(),
            ],
            seed: 9001,
        },
        FlakeRunRecord {
            run_id: "run-101".to_string(),
            epoch: 12,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "fail".to_string(),
            error_signature: Some("panic:router-fallback-timeout".to_string()),
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-c".to_string(),
            related_unit_suites: vec!["unit_router_fallback".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-router-a".to_string()],
            seed: 9001,
        },
        FlakeRunRecord {
            run_id: "run-102".to_string(),
            epoch: 12,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "pass".to_string(),
            error_signature: None,
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-d".to_string(),
            related_unit_suites: vec!["unit_router_fallback".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-router-a".to_string()],
            seed: 9001,
        },
    ]
}

#[test]
fn frx_20_5_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_FLAKE_QUARANTINE_WORKFLOW_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# FRX Flake Detection, Reproducer, and Quarantine Workflow v1",
        "## Scope",
        "## Deterministic Flake Classification Contract",
        "## Deterministic Reproducer Bundle Contract",
        "## Quarantine Workflow Contract",
        "## Gate Confidence and Trendline Contract",
        "## Scenario-to-Unit and Root-Cause Linkage Contract",
        "## Structured Event Contract",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn frx_20_5_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&path);

    assert_eq!(
        contract.schema_version,
        FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.bead_id, "bd-mjh3.20.5");
    assert_eq!(contract.generated_by, "bd-mjh3.20.5");
    assert!(
        contract.flake_detection.warning_flake_threshold_millionths
            <= contract.flake_detection.high_flake_threshold_millionths
    );
    assert!(
        contract
            .reproducer_contract
            .require_ci_and_local_replay_commands
    );
    assert!(contract.quarantine_policy.require_owner_binding);
    assert!(contract.quarantine_policy.require_expiry);
    assert!(contract.gate_confidence.require_flake_burden_metrics);
    assert!(contract.gate_confidence.require_trendlines);
    assert!(contract.linkage_contract.require_impacted_unit_suite_links);
    assert!(
        contract
            .linkage_contract
            .require_root_cause_hypothesis_artifacts
    );
    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        FLAKE_WORKFLOW_FAILURE_CODE
    );
    assert!(contract.failure_policy.block_on_missing_owner);
    assert!(contract.failure_policy.block_on_non_expiring_quarantine);

    let required_fields: BTreeSet<_> = contract
        .flake_detection
        .required_run_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "run_id",
        "epoch",
        "suite_kind",
        "scenario_id",
        "outcome",
        "replay_command_ci",
        "replay_command_local",
        "artifact_bundle_id",
    ] {
        assert!(
            required_fields.contains(field),
            "missing run field: {field}"
        );
    }

    let bundle_fields: BTreeSet<_> = contract
        .reproducer_contract
        .required_bundle_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "bundle_id",
        "replay_command_ci",
        "replay_command_local",
        "artifact_bundle_ids",
        "run_ids",
    ] {
        assert!(
            bundle_fields.contains(field),
            "missing bundle field: {field}"
        );
    }

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_flake_quarantine_workflow_suite.sh ci")),
        "operator verification must include suite command"
    );
}

#[test]
fn frx_20_5_flake_classification_is_deterministic_and_linked() {
    let contract_path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&contract_path);
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: contract
            .flake_detection
            .warning_flake_threshold_millionths,
        high_flake_threshold_millionths: contract.flake_detection.high_flake_threshold_millionths,
        quarantine_ttl_epochs: contract.quarantine_policy.ttl_epochs,
        max_flake_burden_millionths: contract.gate_confidence.max_flake_burden_millionths,
        trend_stability_epsilon_millionths: 10_000,
    };

    let runs = sample_runs();
    let first = classify_flakes(&runs, &policy);
    let second = classify_flakes(&runs, &policy);
    assert_eq!(first, second, "classification must be deterministic");
    assert_eq!(first.len(), 1);

    let flake = &first[0];
    assert!(!flake.reproducer_bundle.bundle_id.is_empty());
    assert!(!flake.reproducer_bundle.replay_command_ci.is_empty());
    assert!(!flake.reproducer_bundle.replay_command_local.is_empty());
    assert!(
        !flake.impacted_unit_suites.is_empty(),
        "flake must link to impacted unit suites"
    );
    assert!(
        !flake.root_cause_hypothesis_artifacts.is_empty(),
        "flake must link to root-cause artifacts"
    );
}

#[test]
fn frx_20_5_quarantine_gate_confidence_and_events_are_complete() {
    let contract_path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&contract_path);
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: contract
            .flake_detection
            .warning_flake_threshold_millionths,
        high_flake_threshold_millionths: contract.flake_detection.high_flake_threshold_millionths,
        quarantine_ttl_epochs: contract.quarantine_policy.ttl_epochs,
        max_flake_burden_millionths: contract.gate_confidence.max_flake_burden_millionths,
        trend_stability_epsilon_millionths: 10_000,
    };

    let runs = sample_runs();
    let flakes = classify_flakes(&runs, &policy);

    let mut owners = BTreeMap::new();
    owners.insert(
        "e2e::scenario-router-fallback".to_string(),
        "router-oncall".to_string(),
    );
    let quarantines = build_quarantine_records(&flakes, &owners, 12, &policy);
    let quarantine_violations = validate_quarantine_records(&quarantines, 12);
    assert!(
        quarantine_violations.is_empty(),
        "quarantine workflow must be owner-bound and time-bounded: {quarantine_violations:?}"
    );

    let report = evaluate_gate_confidence(&runs, &flakes, &policy);
    assert!(
        report.per_epoch_burden.len() >= 2,
        "gate confidence must contain trendline points"
    );
    assert!(report.flake_burden_millionths > 0);
    assert_eq!(report.promotion_outcome, "hold");
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("high_flake_rate")),
        "high flake classes must become gate blockers"
    );

    let events = emit_structured_events(
        "trace-frx-20-5",
        "decision-frx-20-5",
        "policy-frx-20-5-v1",
        &flakes,
        &quarantines,
        &report,
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event == "flake_classified")
            .count(),
        flakes.len()
    );
    assert!(
        events
            .iter()
            .all(|event| event.schema_version == FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION),
        "every event must use stable schema version"
    );

    let flake_event = events
        .iter()
        .find(|event| event.event == "flake_classified")
        .expect("flake event");
    assert_eq!(flake_event.component, FLAKE_WORKFLOW_COMPONENT);
    assert!(!flake_event.replay_command_ci.is_empty());
    assert!(!flake_event.replay_command_local.is_empty());
    assert!(
        !flake_event.impacted_unit_suites.is_empty(),
        "flake event should carry impacted unit suite links"
    );
    assert!(
        !flake_event.root_cause_hypothesis_artifacts.is_empty(),
        "flake event should carry root-cause artifacts"
    );
}
