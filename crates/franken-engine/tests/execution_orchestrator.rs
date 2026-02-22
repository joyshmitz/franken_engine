//! Integration tests for `ExecutionOrchestrator`.

use std::collections::BTreeMap;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
    OrchestratorError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn simple_package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn high_capability_package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "high-cap-ext".to_string(),
        source: "42".to_string(),
        capabilities: (0..16).map(|i| format!("cap_{i}")).collect(),
        version: "2.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

// -----------------------------------------------------------------------
// 1. End-to-end simple source
// -----------------------------------------------------------------------

#[test]
fn end_to_end_simple_source() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-42", "42");
    let result = orch.execute(&pkg).expect("execute should succeed");

    assert_eq!(result.extension_id, "ext-42");
    assert!(!result.trace_id.is_empty());
    assert!(!result.decision_id.is_empty());
    assert!(!result.source_label.is_empty());
    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
    assert_eq!(result.epoch, SecurityEpoch::from_raw(1));
    assert!(result.instructions_executed > 0);
}

// -----------------------------------------------------------------------
// 2. High capability extension
// -----------------------------------------------------------------------

#[test]
fn high_capability_extension_produces_valid_decision() {
    let config = OrchestratorConfig {
        loss_matrix_preset: LossMatrixPreset::Conservative,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = high_capability_package();
    let result = orch.execute(&pkg).expect("execute should succeed");

    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
    assert_eq!(result.extension_id, "high-cap-ext");
}

// -----------------------------------------------------------------------
// 3. Evidence entries contain required fields
// -----------------------------------------------------------------------

#[test]
fn evidence_entries_contain_required_fields() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-evidence", "42");
    let result = orch.execute(&pkg).expect("execute");

    let entry = &result.evidence_entries[0];
    assert!(!entry.entry_id.is_empty());
    assert!(!entry.trace_id.is_empty());
    assert!(!entry.decision_id.is_empty());
    assert!(!entry.evidence_hash.is_empty());
    assert!(!entry.candidates.is_empty());
    assert!(!entry.chosen_action.action_name.is_empty());
    assert!(!entry.witnesses.is_empty());
    assert!(!entry.metadata.is_empty());
}

// -----------------------------------------------------------------------
// 4. Empty source returns error
// -----------------------------------------------------------------------

#[test]
fn empty_source_returns_error() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "ext-empty".to_string(),
        source: "".to_string(),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("empty source should fail");
    assert!(matches!(err, OrchestratorError::EmptySource));
}

// -----------------------------------------------------------------------
// 5. Empty extension ID returns error
// -----------------------------------------------------------------------

#[test]
fn empty_extension_id_returns_error() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "".to_string(),
        source: "42".to_string(),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("empty id should fail");
    assert!(matches!(err, OrchestratorError::EmptyExtensionId));
}

// -----------------------------------------------------------------------
// 6. Multiple executions accumulate evidence
// -----------------------------------------------------------------------

#[test]
fn multiple_executions_accumulate_evidence() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    for i in 0..3 {
        let pkg = simple_package(&format!("ext-{i}"), "42");
        orch.execute(&pkg).expect("execute");
    }
    assert_eq!(orch.execution_count(), 3);
    assert!(orch.ledger().len() >= 3);
}
