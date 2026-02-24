//! Integration tests for specialization_conformance module.
//!
//! Validates end-to-end conformance workflows: inventory registration,
//! corpus management, differential execution, epoch transitions, receipt
//! validation, evidence artifact production, and CI gate logic.
//!
//! bd-2pv: Section 10.7 item 9.

use frankenengine_engine::engine_object_id::{self, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_specialization_receipt::{
    OptimizationClass, ProofInput, ProofType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_conformance::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn schema_id() -> SchemaId {
    SchemaId::from_definition(b"SpecConformanceIntegration.v1")
}

fn test_id(tag: &str) -> frankenengine_engine::engine_object_id::EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "integration",
        &schema_id(),
        tag.as_bytes(),
    )
    .unwrap()
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn proof_input(tag: &str, ep: SecurityEpoch) -> ProofInput {
    ProofInput {
        proof_type: ProofType::CapabilityWitness,
        proof_id: test_id(&format!("proof-{tag}")),
        proof_epoch: ep,
        validity_window_ticks: 10_000,
    }
}

fn inventory_entry(
    tag: &str,
    ep: SecurityEpoch,
    tt: TransformationType,
) -> SpecializationInventoryEntry {
    SpecializationInventoryEntry {
        specialization_id: test_id(&format!("spec-{tag}")),
        slot_id: format!("slot-{tag}"),
        proof_inputs: vec![proof_input(tag, ep)],
        transformation_type: tt,
        optimization_receipt_hash: ContentHash::compute(format!("receipt-{tag}").as_bytes()),
        rollback_token_hash: ContentHash::compute(format!("rollback-{tag}").as_bytes()),
        validity_epoch: ep,
        fallback_path: format!("fallback-{tag}"),
    }
}

fn workload(id: &str, cat: CorpusCategory) -> SpecializationWorkload {
    SpecializationWorkload {
        workload_id: id.to_string(),
        category: cat,
        input: format!("input-{id}"),
        expected_output: format!("output-{id}"),
        expected_side_effects: vec![SideEffect {
            effect_type: "hostcall".to_string(),
            description: format!("effect-{id}"),
            sequence: 0,
        }],
    }
}

fn full_corpus(prefix: &str) -> Vec<SpecializationWorkload> {
    let mut wl = Vec::new();
    for i in 0..30 {
        wl.push(workload(
            &format!("{prefix}-p{i}"),
            CorpusCategory::SemanticParity,
        ));
    }
    for i in 0..10 {
        wl.push(workload(
            &format!("{prefix}-e{i}"),
            CorpusCategory::EdgeCase,
        ));
    }
    for i in 0..5 {
        wl.push(workload(
            &format!("{prefix}-t{i}"),
            CorpusCategory::EpochTransition,
        ));
    }
    wl
}

fn ok_outcome(val: &str) -> WorkloadOutcome {
    WorkloadOutcome {
        return_value: val.to_string(),
        side_effect_trace: vec![SideEffect {
            effect_type: "hostcall".to_string(),
            description: "call-1".to_string(),
            sequence: 0,
        }],
        exceptions: vec![],
        evidence_entries: vec!["ev-1".to_string()],
    }
}

// ---------------------------------------------------------------------------
// E2E: full lifecycle with matching specializations passes gate
// ---------------------------------------------------------------------------

#[test]
fn e2e_full_lifecycle_matching_passes_gate() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-e2e", ep);

    // Register 3 specializations covering all transformation types
    for (tag, tt) in [
        ("hostcall", TransformationType::HostcallDispatchElision),
        ("ifc", TransformationType::LabelCheckElision),
        ("path", TransformationType::PathRemoval),
    ] {
        let entry = inventory_entry(tag, ep, tt);
        let key = format!("{}", entry.specialization_id);
        engine.register_specialization(entry);
        engine.register_corpus(&key, full_corpus(tag));
    }

    // Verify corpus
    for key in engine.inventory().keys() {
        let errors = engine.validate_corpus(key);
        assert!(errors.is_empty(), "corpus validation failed for {key}");
    }

    // Registry sync
    assert!(engine.check_registry_sync().is_empty());

    // Run differential for each specialization
    let spec_ids: Vec<_> = engine
        .inventory()
        .values()
        .map(|e| e.specialization_id.clone())
        .collect();

    for spec_id in &spec_ids {
        let outcome = ok_outcome("42");
        // Run multiple workloads per specialization
        for i in 0..5 {
            engine.compare_outcomes(&CompareOutcomesInput {
                specialization_id: spec_id,
                workload_id: &format!("w{i}"),
                category: CorpusCategory::SemanticParity,
                specialized: &outcome,
                unspecialized: &outcome,
                specialized_duration_us: 80,
                unspecialized_duration_us: 100,
                epoch_transition_tested: false,
                fallback_outcome: None,
                receipt_valid: true,
            });
        }
    }

    assert_eq!(engine.total_workloads_run(), 15);
    assert_eq!(engine.total_matches(), 15);
    assert_eq!(engine.total_divergences(), 0);

    // Produce evidence artifact
    let artifact = engine.produce_evidence(
        "e2e-run-1",
        ContentHash::compute(b"registry-hash"),
        "integration-test-env",
        1_000_000,
    );

    assert!(artifact.ci_gate_passed);
    assert_eq!(artifact.total_specializations, 3);
    assert_eq!(artifact.total_workloads, 15);
    assert_eq!(artifact.total_divergences, 0);
    assert_eq!(artifact.total_fallback_failures, 0);
    assert_eq!(artifact.total_receipt_failures, 0);
    assert_eq!(artifact.failed_specialization_count(), 0);

    // JSONL serialization
    let jsonl = artifact.to_jsonl();
    assert!(!jsonl.is_empty());
    let back: ConformanceEvidenceArtifact = serde_json::from_str(&jsonl).unwrap();
    assert_eq!(back.run_id, "e2e-run-1");
    assert!(back.ci_gate_passed);
}

// ---------------------------------------------------------------------------
// E2E: divergence in one specialization fails the whole gate
// ---------------------------------------------------------------------------

#[test]
fn e2e_single_divergence_fails_gate() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-div", ep);

    let entry_ok = inventory_entry("ok", ep, TransformationType::HostcallDispatchElision);
    let spec_ok = entry_ok.specialization_id.clone();
    engine.register_specialization(entry_ok);

    let entry_bad = inventory_entry("bad", ep, TransformationType::LabelCheckElision);
    let spec_bad = entry_bad.specialization_id.clone();
    engine.register_specialization(entry_bad);

    let outcome = ok_outcome("42");
    let diverged = ok_outcome("99");

    // OK specialization
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_ok,
        workload_id: "w1",
        category: CorpusCategory::SemanticParity,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });

    // BAD specialization (divergence)
    let result = engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_bad,
        workload_id: "w2",
        category: CorpusCategory::SemanticParity,
        specialized: &outcome,
        unspecialized: &diverged,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });

    assert!(result.outcome.is_diverge());
    assert_eq!(
        result.divergence_detail.as_ref().unwrap().divergence_kind,
        DivergenceKind::ReturnValue
    );

    let artifact =
        engine.produce_evidence("div-run", ContentHash::compute(b"reg"), "test", 2_000_000);
    assert!(!artifact.ci_gate_passed);
    assert_eq!(artifact.failed_specialization_count(), 1);
}

// ---------------------------------------------------------------------------
// E2E: epoch transition with successful fallback
// ---------------------------------------------------------------------------

#[test]
fn e2e_epoch_transition_successful_fallback() {
    let old_ep = epoch(5);
    let new_ep = epoch(6);
    let mut engine = SpecializationConformanceEngine::new("policy-epoch", old_ep);

    let entry = inventory_entry("ep-test", old_ep, TransformationType::PathRemoval);
    let spec_id = entry.specialization_id.clone();
    let key = format!("{}", spec_id);
    engine.register_specialization(entry);
    engine.register_corpus(&key, full_corpus("ep"));

    // Pre-transition: run normal workloads
    let outcome = ok_outcome("42");
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "pre-epoch",
        category: CorpusCategory::SemanticParity,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });

    // Simulate epoch transition
    let simulation = EpochTransitionSimulation {
        old_epoch: old_ep,
        new_epoch: new_ep,
        invalidated_specialization_ids: vec![spec_id.clone()],
        proof_revoked: false,
        transition_timestamp_ns: 1_000_000,
    };
    let evidence = engine.simulate_epoch_transition(&simulation);

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].fallback_outcome.is_success());
    assert_eq!(evidence[0].epoch_old, old_ep);
    assert_eq!(evidence[0].epoch_new, new_ep);
    assert_eq!(engine.current_epoch(), new_ep);

    // Post-transition: run workloads with fallback
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "post-epoch",
        category: CorpusCategory::EpochTransition,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Success {
            invalidation_evidence_id: "inv-1".to_string(),
        }),
        receipt_valid: true,
    });

    let artifact =
        engine.produce_evidence("epoch-run", ContentHash::compute(b"reg"), "test", 3_000_000);
    assert!(artifact.ci_gate_passed);
}

// ---------------------------------------------------------------------------
// E2E: epoch transition with failed fallback blocks gate
// ---------------------------------------------------------------------------

#[test]
fn e2e_epoch_transition_failed_fallback_blocks_gate() {
    let old_ep = epoch(5);
    let _new_ep = epoch(6);
    let mut engine = SpecializationConformanceEngine::new("policy-fb-fail", old_ep);

    let entry = inventory_entry(
        "fb-fail",
        old_ep,
        TransformationType::SuperinstructionFusion,
    );
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    let outcome = ok_outcome("42");
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "w1",
        category: CorpusCategory::EpochTransition,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Failure {
            reason: "crash during rollback".to_string(),
        }),
        receipt_valid: true,
    });

    let artifact = engine.produce_evidence(
        "fb-fail-run",
        ContentHash::compute(b"reg"),
        "test",
        4_000_000,
    );
    assert!(!artifact.ci_gate_passed);
    assert_eq!(artifact.total_fallback_failures, 1);
}

// ---------------------------------------------------------------------------
// Corpus coverage validation: minimum workload counts
// ---------------------------------------------------------------------------

#[test]
fn corpus_validation_enforces_minimums() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-corpus", ep);

    // Too few parity workloads
    let sparse_corpus: Vec<_> = (0..5)
        .map(|i| workload(&format!("w{i}"), CorpusCategory::SemanticParity))
        .collect();
    engine.register_corpus("sparse", sparse_corpus);

    let errors = engine.validate_corpus("sparse");
    assert!(errors.len() >= 2); // Missing edge + epoch too

    let found_parity_error = errors.iter().any(|e| {
        matches!(
            e,
            ConformanceError::InsufficientCorpus {
                category: CorpusCategory::SemanticParity,
                ..
            }
        )
    });
    assert!(found_parity_error);
}

// ---------------------------------------------------------------------------
// Registry sync: new specialization without corpus detected
// ---------------------------------------------------------------------------

#[test]
fn registry_sync_detects_missing_corpus() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-sync", ep);

    let entry_a = inventory_entry("a", ep, TransformationType::HostcallDispatchElision);
    let key_a = format!("{}", entry_a.specialization_id);
    engine.register_specialization(entry_a);
    engine.register_corpus(&key_a, full_corpus("a"));

    // Register b without corpus
    engine.register_specialization(inventory_entry(
        "b",
        ep,
        TransformationType::LabelCheckElision,
    ));

    let errors = engine.check_registry_sync();
    assert_eq!(errors.len(), 1);
    assert!(matches!(&errors[0], ConformanceError::MissingCorpus { .. }));
}

// ---------------------------------------------------------------------------
// Performance delta tracking
// ---------------------------------------------------------------------------

#[test]
fn performance_delta_tracks_speedup_and_slowdown() {
    // 20% speedup
    let delta = SpecializationConformanceEngine::compute_performance_delta(80, 100);
    assert!(delta.speedup_millionths > 0);
    assert_eq!(delta.speedup_millionths, 200_000);

    // 50% slowdown
    let delta = SpecializationConformanceEngine::compute_performance_delta(150, 100);
    assert!(delta.speedup_millionths < 0);
    assert_eq!(delta.speedup_millionths, -500_000);

    // No change
    let delta = SpecializationConformanceEngine::compute_performance_delta(100, 100);
    assert_eq!(delta.speedup_millionths, 0);
}

// ---------------------------------------------------------------------------
// Determinism validation: repeated runs produce identical hashes
// ---------------------------------------------------------------------------

#[test]
fn determinism_validation_identical_runs() {
    let outcome = ok_outcome("42");
    let outcomes: Vec<_> = (0..5).map(|_| outcome.clone()).collect();
    assert!(SpecializationConformanceEngine::check_determinism(
        &outcomes
    ));
}

#[test]
fn determinism_validation_detects_drift() {
    let mut outcomes: Vec<_> = (0..4).map(|_| ok_outcome("42")).collect();
    outcomes.push(ok_outcome("43")); // Different value
    assert!(!SpecializationConformanceEngine::check_determinism(
        &outcomes
    ));
}

// ---------------------------------------------------------------------------
// All transformation types round-trip through from_optimization_class
// ---------------------------------------------------------------------------

#[test]
fn transformation_types_map_all_optimization_classes() {
    let mappings = [
        (
            OptimizationClass::HostcallDispatchSpecialization,
            TransformationType::HostcallDispatchElision,
        ),
        (
            OptimizationClass::IfcCheckElision,
            TransformationType::LabelCheckElision,
        ),
        (
            OptimizationClass::PathElimination,
            TransformationType::PathRemoval,
        ),
        (
            OptimizationClass::SuperinstructionFusion,
            TransformationType::SuperinstructionFusion,
        ),
    ];

    for (class, expected_tt) in &mappings {
        let tt = TransformationType::from_optimization_class(*class);
        assert_eq!(tt, *expected_tt);
    }
}

// ---------------------------------------------------------------------------
// Multi-epoch lifecycle: register, run, transition, re-run
// ---------------------------------------------------------------------------

#[test]
fn multi_epoch_lifecycle() {
    let ep1 = epoch(1);
    let ep2 = epoch(2);
    let ep3 = epoch(3);
    let mut engine = SpecializationConformanceEngine::new("policy-multi", ep1);

    let entry = inventory_entry("multi", ep1, TransformationType::LabelCheckElision);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    let outcome = ok_outcome("42");

    // Epoch 1: run workloads
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "ep1-w1",
        category: CorpusCategory::SemanticParity,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });

    // Transition to epoch 2
    engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: ep1,
        new_epoch: ep2,
        invalidated_specialization_ids: vec![spec_id.clone()],
        proof_revoked: false,
        transition_timestamp_ns: 100_000,
    });
    assert_eq!(engine.current_epoch(), ep2);

    // Epoch 2: run fallback workloads
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "ep2-w1",
        category: CorpusCategory::EpochTransition,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Success {
            invalidation_evidence_id: "inv-ep2".to_string(),
        }),
        receipt_valid: true,
    });

    // Transition to epoch 3
    engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: ep2,
        new_epoch: ep3,
        invalidated_specialization_ids: vec![],
        proof_revoked: false,
        transition_timestamp_ns: 200_000,
    });
    assert_eq!(engine.current_epoch(), ep3);

    // Final artifact
    let artifact = engine.produce_evidence(
        "multi-epoch-run",
        ContentHash::compute(b"reg"),
        "test",
        300_000,
    );
    assert!(artifact.ci_gate_passed);
    assert_eq!(artifact.total_workloads, 2);
}

// ---------------------------------------------------------------------------
// All 4 divergence kinds are correctly classified
// ---------------------------------------------------------------------------

#[test]
fn all_divergence_kinds_classified() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-div-kinds", ep);
    let spec_id = test_id("spec-div");

    // Return value divergence
    let r = engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "return",
        category: CorpusCategory::SemanticParity,
        specialized: &ok_outcome("a"),
        unspecialized: &ok_outcome("b"),
        specialized_duration_us: 50,
        unspecialized_duration_us: 50,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });
    assert_eq!(
        r.divergence_detail.unwrap().divergence_kind,
        DivergenceKind::ReturnValue
    );

    // Side-effect divergence
    let mut se_out = ok_outcome("same");
    se_out.side_effect_trace.push(SideEffect {
        effect_type: "extra".to_string(),
        description: "extra".to_string(),
        sequence: 1,
    });
    let r = engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "side-effect",
        category: CorpusCategory::SemanticParity,
        specialized: &ok_outcome("same"),
        unspecialized: &se_out,
        specialized_duration_us: 50,
        unspecialized_duration_us: 50,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });
    assert_eq!(
        r.divergence_detail.unwrap().divergence_kind,
        DivergenceKind::SideEffectTrace
    );

    // Exception divergence
    let mut ex_out = ok_outcome("same");
    ex_out.exceptions.push("TypeError".to_string());
    let base = ok_outcome("same");
    let r = engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "exception",
        category: CorpusCategory::SemanticParity,
        specialized: &base,
        unspecialized: &ex_out,
        specialized_duration_us: 50,
        unspecialized_duration_us: 50,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });
    assert_eq!(
        r.divergence_detail.unwrap().divergence_kind,
        DivergenceKind::ExceptionSequence
    );

    // Evidence emission divergence
    let mut ev_out = ok_outcome("same");
    ev_out.evidence_entries.push("extra-ev".to_string());
    let r = engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "evidence",
        category: CorpusCategory::SemanticParity,
        specialized: &base,
        unspecialized: &ev_out,
        specialized_duration_us: 50,
        unspecialized_duration_us: 50,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });
    assert_eq!(
        r.divergence_detail.unwrap().divergence_kind,
        DivergenceKind::EvidenceEmission
    );

    assert_eq!(engine.total_divergences(), 4);
}

// ---------------------------------------------------------------------------
// Structured logging: all fields populated
// ---------------------------------------------------------------------------

#[test]
fn structured_logs_populated() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-log", ep);
    let spec_id = test_id("spec-log");
    let outcome = ok_outcome("42");

    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "w-log",
        category: CorpusCategory::SemanticParity,
        specialized: &outcome,
        unspecialized: &outcome,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    });

    let logs = engine.logs();
    assert_eq!(logs.len(), 1);
    let log = &logs[0];
    assert!(log.trace_id.starts_with("conformance-"));
    assert!(!log.specialization_id.is_empty());
    assert_eq!(log.workload_id, "w-log");
    assert_eq!(log.corpus_category, CorpusCategory::SemanticParity);
    assert!(log.outcome.is_match());
    assert_eq!(log.specialized_duration_us, 80);
    assert_eq!(log.unspecialized_duration_us, 100);
    assert!(!log.epoch_transition_tested);
    assert!(log.receipt_valid);
}

// ---------------------------------------------------------------------------
// Evidence artifact round-trip serialization
// ---------------------------------------------------------------------------

#[test]
fn evidence_artifact_deterministic_serialization() {
    let ep = epoch(5);
    let engine = SpecializationConformanceEngine::new("policy-ser", ep);
    let artifact = engine.produce_evidence(
        "ser-run",
        ContentHash::compute(b"reg"),
        "test-env",
        1_000_000,
    );

    let json1 = serde_json::to_string(&artifact).unwrap();
    let json2 = serde_json::to_string(&artifact).unwrap();
    assert_eq!(json1, json2, "serialization must be deterministic");

    let back: ConformanceEvidenceArtifact = serde_json::from_str(&json1).unwrap();
    assert_eq!(back.run_id, artifact.run_id);
    assert_eq!(back.ci_gate_passed, artifact.ci_gate_passed);
}
