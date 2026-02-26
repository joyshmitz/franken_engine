#![forbid(unsafe_code)]

use std::{
    collections::{BTreeSet, HashSet},
    fs,
    path::PathBuf,
};

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "frx.pilot-rollout-harness.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/frx_pilot_rollout_harness_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PilotRolloutHarnessContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    pilot_portfolio: PilotPortfolio,
    experiment_harness: ExperimentHarness,
    off_policy_evaluation: OffPolicyEvaluation,
    sequential_monitoring: SequentialMonitoring,
    incident_linkage: IncidentLinkage,
    required_structured_log_fields: Vec<String>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PilotPortfolio {
    strata: Vec<PilotStratum>,
    stratification_required: bool,
    fail_closed_on_unclassified_workload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PilotStratum {
    stratum_id: String,
    workload_archetype: String,
    risk_tier: String,
    target_share_bps: u32,
    inclusion_criteria: Vec<String>,
    exclusion_criteria: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExperimentHarness {
    modes: Vec<String>,
    deterministic_assignment_required: bool,
    required_assignment_fields: Vec<String>,
    required_observation_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OffPolicyEvaluation {
    estimators: Vec<String>,
    propensity_clip_min_millionths: u64,
    minimum_effective_sample_size: u64,
    require_baseline_predictions_for_dr: bool,
    fail_closed_on_missing_propensity: bool,
    fail_closed_on_weight_explosion: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SequentialMonitoring {
    evidence_mode: String,
    decision_actions: Vec<String>,
    thresholds_millionths: Thresholds,
    require_loss_aware_decision_path: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Thresholds {
    promote_min_confidence: u64,
    stop_max_regret: u64,
    rollback_incident_delta: u64,
    rollback_tail_latency_delta: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentLinkage {
    required_fields: Vec<String>,
    require_replay_bundle: bool,
    require_evidence_bundle: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> PilotRolloutHarnessContract {
    serde_json::from_str(CONTRACT_JSON).expect("pilot rollout harness json must parse")
}

#[test]
fn frx_09_1_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_PILOT_ROLLOUT_HARNESS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Pilot App Program and A/B Rollout Harness v1",
        "## Scope",
        "## Pilot Portfolio Stratification",
        "## A/B and Shadow-Run Harness Contract",
        "## Telemetry Contract for Causal and Off-Policy Safety Analysis",
        "## Off-Policy Evaluator Contract (IPS + Doubly Robust)",
        "## Sequential-Valid Monitoring and Decision Policies",
        "## Incident Linkage and Replay/Evidence Artifacts",
        "## Deterministic Logging and Artifact Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn frx_09_1_contract_is_versioned_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.9.1");
    assert_eq!(contract.generated_by, "bd-mjh3.9.1");
    assert_eq!(contract.track.id, "FRX-09.1");
    assert!(contract.track.name.contains("Pilot App Program"));
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_09_1_pilot_portfolio_is_stratified_and_actionable() {
    let contract = parse_contract();
    let portfolio = contract.pilot_portfolio;

    assert!(portfolio.stratification_required);
    assert!(portfolio.fail_closed_on_unclassified_workload);
    assert!(
        portfolio.strata.len() >= 4,
        "expected at least four pilot strata"
    );

    let mut stratum_ids = HashSet::new();
    let mut risk_tiers = HashSet::new();
    let total_share_bps: u32 = portfolio.strata.iter().map(|s| s.target_share_bps).sum();
    assert_eq!(total_share_bps, 10_000, "pilot shares must sum to 100%");

    for stratum in portfolio.strata {
        assert!(stratum_ids.insert(stratum.stratum_id.clone()));
        assert!(!stratum.workload_archetype.trim().is_empty());
        assert!(!stratum.risk_tier.trim().is_empty());
        assert!(risk_tiers.insert(stratum.risk_tier));
        assert!(
            !stratum.inclusion_criteria.is_empty(),
            "stratum must define inclusion criteria"
        );
        assert!(
            !stratum.exclusion_criteria.is_empty(),
            "stratum must define exclusion criteria"
        );
    }

    assert!(
        risk_tiers.contains("low")
            && risk_tiers.contains("medium")
            && risk_tiers.contains("high")
            && risk_tiers.contains("critical"),
        "risk tiers must cover low/medium/high/critical"
    );
}

#[test]
fn frx_09_1_harness_and_off_policy_requirements_are_complete() {
    let contract = parse_contract();

    let modes: BTreeSet<&str> = contract
        .experiment_harness
        .modes
        .iter()
        .map(String::as_str)
        .collect();
    let expected_modes: BTreeSet<&str> = ["ab_online", "shadow_run"].into_iter().collect();
    assert_eq!(modes, expected_modes);
    assert!(
        contract
            .experiment_harness
            .deterministic_assignment_required
    );

    for field in [
        "assignment_id",
        "cohort_id",
        "variant",
        "propensity_millionths",
        "policy_snapshot_id",
        "seed",
    ] {
        assert!(
            contract
                .experiment_harness
                .required_assignment_fields
                .iter()
                .any(|candidate| candidate == field),
            "missing assignment field: {field}"
        );
    }

    for field in [
        "scenario_id",
        "trace_id",
        "latency_us",
        "reward_millionths",
        "loss_millionths",
        "safety_outcome",
    ] {
        assert!(
            contract
                .experiment_harness
                .required_observation_fields
                .iter()
                .any(|candidate| candidate == field),
            "missing observation field: {field}"
        );
    }

    let estimators: BTreeSet<&str> = contract
        .off_policy_evaluation
        .estimators
        .iter()
        .map(String::as_str)
        .collect();
    let expected_estimators: BTreeSet<&str> = ["ips", "doubly_robust"].into_iter().collect();
    assert_eq!(estimators, expected_estimators);
    assert!(
        contract
            .off_policy_evaluation
            .propensity_clip_min_millionths
            > 0
            && contract
                .off_policy_evaluation
                .propensity_clip_min_millionths
                < 1_000_000
    );
    assert!(contract.off_policy_evaluation.minimum_effective_sample_size >= 100);
    assert!(
        contract
            .off_policy_evaluation
            .require_baseline_predictions_for_dr
    );
    assert!(
        contract
            .off_policy_evaluation
            .fail_closed_on_missing_propensity
    );
    assert!(
        contract
            .off_policy_evaluation
            .fail_closed_on_weight_explosion
    );
}

#[test]
fn frx_09_1_sequential_decisioning_and_incident_linkage_are_fail_closed() {
    let contract = parse_contract();

    assert_eq!(
        contract.sequential_monitoring.evidence_mode,
        "anytime_valid_e_process"
    );
    let actions: BTreeSet<&str> = contract
        .sequential_monitoring
        .decision_actions
        .iter()
        .map(String::as_str)
        .collect();
    let expected_actions: BTreeSet<&str> = ["stop", "promote", "rollback"].into_iter().collect();
    assert_eq!(actions, expected_actions);
    assert!(
        contract
            .sequential_monitoring
            .require_loss_aware_decision_path
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .promote_min_confidence
            > 900_000
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .stop_max_regret
            > 0
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .rollback_incident_delta
            > 0
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .rollback_tail_latency_delta
            > 0
    );

    let incident_fields: BTreeSet<&str> = contract
        .incident_linkage
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    let expected_incident_fields: BTreeSet<&str> = [
        "trace_id",
        "incident_id",
        "decision_id",
        "replay_bundle_id",
        "evidence_bundle_id",
        "run_manifest_id",
    ]
    .into_iter()
    .collect();
    assert_eq!(incident_fields, expected_incident_fields);
    assert!(contract.incident_linkage.require_replay_bundle);
    assert!(contract.incident_linkage.require_evidence_bundle);
}

#[test]
fn frx_09_1_contract_matches_logging_and_runtime_surfaces() {
    let contract = parse_contract();

    let required_fields: BTreeSet<&str> = [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let actual_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| { line.contains("run_frx_pilot_rollout_harness_suite.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| { line.contains("frx_pilot_rollout_harness_replay.sh") })
    );

    let activation =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/activation_lifecycle.rs"))
            .expect("activation_lifecycle source must exist");
    for snippet in ["RolloutPhase", "advance_rollout", "pub fn rollback"] {
        assert!(
            activation.contains(snippet),
            "activation_lifecycle missing: {snippet}"
        );
    }

    let decision_core =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/runtime_decision_core.rs"))
            .expect("runtime_decision_core source must exist");
    for snippet in [
        "Conformal calibration layer",
        "RoutingAction",
        "fallback:safe_mode",
    ] {
        assert!(
            decision_core.contains(snippet),
            "runtime_decision_core missing: {snippet}"
        );
    }

    let router =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/regret_bounded_router.rs"))
            .expect("regret_bounded_router source must exist");
    for snippet in [
        "counterfactual_rewards_millionths",
        "regret_within_bound",
        "exact_regret_available",
    ] {
        assert!(
            router.contains(snippet),
            "regret_bounded_router missing: {snippet}"
        );
    }

    let replayer =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/forensic_replayer.rs"))
            .expect("forensic_replayer source must exist");
    for snippet in [
        "CounterfactualSpec",
        "pub fn counterfactual",
        "ReplayResult",
    ] {
        assert!(
            replayer.contains(snippet),
            "forensic_replayer missing: {snippet}"
        );
    }
}
