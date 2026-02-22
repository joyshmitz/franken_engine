use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::bayesian_posterior::{BayesianPosteriorUpdater, Evidence, Posterior};
use frankenengine_engine::expected_loss_selector::{
    ContainmentAction, ExpectedLossSelector, RuntimeDecisionScoringError,
    RuntimeDecisionScoringInput,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trust_economics::{AttackerCostModel, StrategyCostAdjustment};

fn sample_attacker_cost_model() -> AttackerCostModel {
    let mut strategy_adjustments = BTreeMap::new();
    strategy_adjustments.insert(
        "supply_chain".to_string(),
        StrategyCostAdjustment {
            strategy_name: "supply_chain".to_string(),
            discovery_delta: 100_000,
            development_delta: 200_000,
            evasion_delta: 50_000,
            justification: "integration-test".to_string(),
        },
    );
    AttackerCostModel {
        discovery_cost: 1_000_000,
        development_cost: 2_000_000,
        deployment_cost: 1_000_000,
        persistence_cost: 500_000,
        evasion_cost: 1_000_000,
        expected_gain: 20_000_000,
        strategy_adjustments,
        version: 1,
        calibration_source: "integration-test".to_string(),
    }
}

fn malicious_evidence(extension_id: &str) -> Evidence {
    Evidence {
        extension_id: extension_id.to_string(),
        hostcall_rate_millionths: 900_000_000,
        distinct_capabilities: 14,
        resource_score_millionths: 950_000,
        timing_anomaly_millionths: 900_000,
        denial_rate_millionths: 500_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn benign_evidence(extension_id: &str) -> Evidence {
    Evidence {
        extension_id: extension_id.to_string(),
        hostcall_rate_millionths: 10_000_000,
        distinct_capabilities: 2,
        resource_score_millionths: 100_000,
        timing_anomaly_millionths: 10_000,
        denial_rate_millionths: 0,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn scoring_input(
    extension_id: &str,
    decision_id: &str,
    posterior: Posterior,
) -> RuntimeDecisionScoringInput {
    RuntimeDecisionScoringInput {
        trace_id: format!("trace-{decision_id}"),
        decision_id: decision_id.to_string(),
        policy_id: "policy-runtime-score-v1".to_string(),
        extension_id: extension_id.to_string(),
        policy_version: "policy-v1.0.0".to_string(),
        timestamp_ns: 1_700_000_000_000_000_123,
        posterior,
        attacker_cost_model: sample_attacker_cost_model(),
        extension_roi_history_millionths: vec![1_100_000, 1_500_000, 2_200_000],
        fleet_roi_baseline_millionths: BTreeMap::from([
            ("ext-other-a".to_string(), 400_000),
            ("ext-other-b".to_string(), 1_300_000),
        ]),
        blocked_actions: BTreeSet::new(),
    }
}

#[test]
fn evidence_to_scoring_flow_emits_structured_artifact() {
    let extension_id = "ext-runtime-flow";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..10 {
        updater.update(&malicious_evidence(extension_id));
    }

    let mut selector = ExpectedLossSelector::balanced();
    selector.set_epoch(SecurityEpoch::from_raw(42));
    let artifact = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-runtime-flow",
            updater.posterior().clone(),
        ))
        .expect("runtime decision scoring");

    assert!(
        artifact.selected_action.severity() >= ContainmentAction::Sandbox.severity(),
        "malicious posterior should avoid permissive actions, got {}",
        artifact.selected_action
    );
    assert_eq!(artifact.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(
        artifact.candidate_actions.len(),
        ContainmentAction::ALL.len()
    );
    assert!(artifact.events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && event.component == "runtime_decision_scoring"
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
}

#[test]
fn guardrail_veto_path_changes_selected_action() {
    let extension_id = "ext-runtime-guardrail";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..3 {
        updater.update(&benign_evidence(extension_id));
    }

    let mut selector = ExpectedLossSelector::balanced();
    let baseline = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-runtime-guardrail-baseline",
            updater.posterior().clone(),
        ))
        .expect("baseline scoring");
    assert_eq!(baseline.selected_action, ContainmentAction::Allow);

    let mut blocked_input = scoring_input(
        extension_id,
        "decision-runtime-guardrail-veto",
        updater.posterior().clone(),
    );
    blocked_input
        .blocked_actions
        .insert(ContainmentAction::Allow);
    let blocked = selector
        .score_runtime_decision(&blocked_input)
        .expect("guardrail scoring");

    assert_ne!(blocked.selected_action, ContainmentAction::Allow);
    assert!(blocked.events.iter().any(|event| {
        event.event == "guardrail_veto_applied"
            && event.error_code.as_deref() == Some("FE-RUNTIME-SCORING-GUARDRAIL-VETO")
    }));
}

#[test]
fn scoring_output_is_replay_deterministic() {
    let extension_id = "ext-runtime-replay";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..5 {
        updater.update(&malicious_evidence(extension_id));
    }

    let input = scoring_input(
        extension_id,
        "decision-runtime-replay",
        updater.posterior().clone(),
    );
    let mut selector_a = ExpectedLossSelector::balanced();
    let mut selector_b = ExpectedLossSelector::balanced();
    let artifact_a = selector_a
        .score_runtime_decision(&input)
        .expect("artifact a");
    let artifact_b = selector_b
        .score_runtime_decision(&input)
        .expect("artifact b");

    assert_eq!(artifact_a, artifact_b);
}

#[test]
fn zero_attacker_cost_is_fail_closed() {
    let extension_id = "ext-runtime-zero-cost";
    let mut input = scoring_input(
        extension_id,
        "decision-runtime-zero-cost",
        Posterior::default_prior(),
    );
    input.attacker_cost_model.discovery_cost = 0;
    input.attacker_cost_model.development_cost = 0;
    input.attacker_cost_model.deployment_cost = 0;
    input.attacker_cost_model.persistence_cost = 0;
    input.attacker_cost_model.evasion_cost = 0;

    let mut selector = ExpectedLossSelector::balanced();
    let err = selector
        .score_runtime_decision(&input)
        .expect_err("zero attacker cost should fail");
    assert_eq!(err, RuntimeDecisionScoringError::ZeroAttackerCost);
}

#[test]
fn borderline_detection_emits_event_when_applicable() {
    // Near-uniform posterior: actions should be close in EL.
    let extension_id = "ext-runtime-borderline";
    let posterior = Posterior::uniform();
    let mut selector = ExpectedLossSelector::balanced();
    let artifact = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-borderline",
            posterior,
        ))
        .expect("scoring should succeed");

    // Verify new fields are present and well-formed.
    if artifact.borderline_decision {
        assert!(
            !artifact.sensitivity_deltas.is_empty(),
            "borderline decisions must have sensitivity deltas"
        );
        assert!(
            artifact
                .events
                .iter()
                .any(|e| e.event == "borderline_decision"
                    && e.error_code.as_deref() == Some("FE-RUNTIME-SCORING-BORDERLINE")),
            "borderline event must have correct error code"
        );
    }
}

#[test]
fn scoring_artifact_contains_all_posterior_probabilities_in_rationale() {
    let extension_id = "ext-runtime-rationale";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..3 {
        updater.update(&malicious_evidence(extension_id));
    }

    let mut selector = ExpectedLossSelector::balanced();
    let artifact = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-rationale",
            updater.posterior().clone(),
        ))
        .expect("scoring should succeed");

    assert!(
        artifact.selection_rationale.contains("p_benign="),
        "rationale must show p_benign"
    );
    assert!(
        artifact.selection_rationale.contains("p_malicious="),
        "rationale must show p_malicious"
    );
    assert!(
        artifact.selection_rationale.contains("margin="),
        "rationale must show decision margin"
    );
}

#[test]
fn monotonicity_across_malicious_gradient() {
    let extension_id = "ext-runtime-monotonicity";
    let steps = 10;
    let million: i64 = 1_000_000;
    let mut prev_severity = 0u32;

    for i in 0..=steps {
        let p_malicious = million * i / steps;
        let p_benign = million - p_malicious;
        let posterior = Posterior::from_millionths(p_benign, 0, p_malicious, 0);
        let mut selector = ExpectedLossSelector::balanced();
        let artifact = selector
            .score_runtime_decision(&scoring_input(
                extension_id,
                &format!("decision-mono-{i}"),
                posterior,
            ))
            .expect("scoring should succeed");
        let severity = artifact.selected_action.severity();
        assert!(
            severity >= prev_severity,
            "monotonicity: step {i} severity {} < previous {prev_severity}",
            severity
        );
        prev_severity = severity;
    }
}
