use frankenengine_engine::semantic_twin_state_space::{
    SEMANTIC_TWIN_COMPONENT, SemanticTwinSpecification, TwinSpecError, TwinStateSnapshot,
};

#[test]
fn lane_decision_default_exposes_expected_contracts() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert_eq!(spec.component, SEMANTIC_TWIN_COMPONENT);
    assert_eq!(spec.treatment_variable, "lane_choice");
    assert_eq!(spec.outcome_variable, "latency_outcome");
    assert!(
        spec.assumptions
            .iter()
            .any(|assumption| assumption.id == "assumption_nondeterminism_log_complete")
    );
    assert!(
        spec.transitions
            .iter()
            .any(|transition| transition.id == "transition_fallback_to_safe_mode")
    );
}

#[test]
fn causal_model_backdoor_recommendation_is_consistent() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let backdoor = spec
        .causal_model
        .backdoor_criterion(&spec.treatment_variable, &spec.outcome_variable)
        .expect("backdoor criterion");
    assert!(backdoor.identified);
    assert_eq!(backdoor.adjustment_set, spec.recommended_adjustment_set);
}

#[test]
fn assumption_ledger_from_spec_is_deterministic_and_actionable() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut first = spec
        .to_assumption_ledger("decision-semantic-ledger", 11)
        .expect("first ledger");
    let second = spec
        .to_assumption_ledger("decision-semantic-ledger", 11)
        .expect("second ledger");

    assert_eq!(first.assumption_count(), second.assumption_count());
    assert_eq!(first.monitors().len(), second.monitors().len());
    assert_eq!(first.chain_hash(), second.chain_hash());

    // Violate monitor_replay_completeness (requires >= 1_000_000).
    let before = first.chain_hash().to_string();
    let actions = first.observe("nondeterminism_log_completeness", 800_000, 11, 3);
    let after = first.chain_hash().to_string();
    assert_eq!(actions.len(), 1);
    assert_eq!(first.violated_count(), 1);
    assert_ne!(before, after);
}

#[test]
fn snapshot_validation_requires_mandatory_fields() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let mut snapshot = TwinStateSnapshot::new("trace-1", "decision-1", "policy-1", 1, 1);
    snapshot.upsert_value("workload_complexity", 500_000);

    let err = spec
        .validate_snapshot(&snapshot)
        .expect_err("missing required contracts should fail");
    assert!(matches!(err, TwinSpecError::MissingSnapshotValue { .. }));
}
