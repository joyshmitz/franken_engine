use frankenengine_engine::semantic_twin_state_space::{
    SEMANTIC_TWIN_COMPONENT, SemanticTwinSpecification, TwinSpecError, TwinStateSnapshot,
    TwinStateDomain,
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

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, validation, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn twin_spec_error_display_is_non_empty_for_key_variants() {
    let errors: Vec<TwinSpecError> = vec![
        TwinSpecError::Scm("test scm error".to_string()),
        TwinSpecError::InvalidSchemaVersion("bad-version".to_string()),
        TwinSpecError::DuplicateVariable("var-x".to_string()),
        TwinSpecError::UnknownVariable("var-y".to_string()),
        TwinSpecError::DuplicateTransition("trans-z".to_string()),
        TwinSpecError::UnknownAssumption("assumption-q".to_string()),
        TwinSpecError::DuplicateAssumption("assumption-r".to_string()),
        TwinSpecError::DuplicateMonitor("monitor-s".to_string()),
        TwinSpecError::InvalidMonitorTriggerCount {
            monitor_id: "monitor-t".to_string(),
        },
        TwinSpecError::InvalidMeasurementRange {
            variable_id: "var-u".to_string(),
        },
        TwinSpecError::MissingTreatmentVariable("treatment".to_string()),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "error display must not be empty: {err:?}");
    }
}

#[test]
fn twin_state_snapshot_serde_round_trip() {
    let mut snapshot = TwinStateSnapshot::new("trace-rt", "decision-rt", "policy-rt", 1, 10);
    snapshot.upsert_value("workload_complexity", 500_000);
    snapshot.upsert_value("control_intensity", 800_000);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: TwinStateSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn semantic_twin_specification_serde_round_trip() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: SemanticTwinSpecification =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn twin_spec_error_serde_round_trip() {
    let err = TwinSpecError::DuplicateVariable("var-dup".to_string());
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: TwinSpecError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn semantic_twin_component_constant_is_non_empty() {
    assert!(!SEMANTIC_TWIN_COMPONENT.is_empty());
}

#[test]
fn twin_state_domain_serde_round_trip() {
    for domain in [
        TwinStateDomain::Workload,
        TwinStateDomain::Risk,
        TwinStateDomain::Policy,
        TwinStateDomain::Lane,
        TwinStateDomain::Outcome,
        TwinStateDomain::Regime,
        TwinStateDomain::Resource,
        TwinStateDomain::Replay,
        TwinStateDomain::Calibration,
    ] {
        let json = serde_json::to_string(&domain).expect("serialize");
        let recovered: TwinStateDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(domain, recovered);
    }
}

#[test]
fn default_spec_produces_non_empty_adjustment_set() {
    let spec = SemanticTwinSpecification::lane_decision_default().expect("default spec");
    assert!(!spec.recommended_adjustment_set.is_empty());
    assert!(!spec.variables.is_empty());
    assert!(!spec.transitions.is_empty());
    assert!(!spec.measurement_contracts.is_empty());
    assert!(!spec.assumptions.is_empty());
}
