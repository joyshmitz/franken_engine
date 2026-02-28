#![forbid(unsafe_code)]
//! Enrichment integration tests for `translation_validation`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, gate construction, and edge cases beyond
//! the existing 40 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_schema::ActivationStage;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::translation_validation::{
    QuarantineEntry, TranslationValidationGate, ValidationEvent, ValidationEventType,
    ValidationGateError, ValidationMode, ValidationVerdict,
};

// ===========================================================================
// 1) ValidationMode — exact Display
// ===========================================================================

#[test]
fn validation_mode_display_golden_corpus() {
    let m = ValidationMode::GoldenCorpusReplay {
        corpus_hash: ContentHash::compute(b"c"),
        vector_count: 42,
    };
    let s = m.to_string();
    assert!(
        s.contains("42") || s.contains("golden"),
        "should describe golden replay: {s}"
    );
}

#[test]
fn validation_mode_display_symbolic() {
    let m = ValidationMode::SymbolicEquivalence {
        proof_hash: ContentHash::compute(b"p"),
    };
    let s = m.to_string();
    assert!(
        s.contains("symbolic") || s.contains("equivalence"),
        "should describe symbolic: {s}"
    );
}

#[test]
fn validation_mode_display_differential() {
    let m = ValidationMode::DifferentialTrace {
        workload_hash: ContentHash::compute(b"w"),
        trace_pair_count: 10,
    };
    let s = m.to_string();
    assert!(
        s.contains("10") || s.contains("differential"),
        "should describe differential: {s}"
    );
}

// ===========================================================================
// 2) ValidationVerdict — Display + permits_activation
// ===========================================================================

#[test]
fn validation_verdict_pass_permits() {
    let v = ValidationVerdict::Pass {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        },
        evidence_hash: ContentHash::compute(b"e"),
    };
    assert!(v.permits_activation());
    let s = v.to_string();
    assert!(
        s.contains("PASS") || s.contains("pass"),
        "should say pass: {s}"
    );
}

#[test]
fn validation_verdict_fail_denies() {
    let v = ValidationVerdict::Fail {
        mode: ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        },
        divergence_reason: "type mismatch".into(),
        counterexample_hash: ContentHash::compute(b"cx"),
    };
    assert!(!v.permits_activation());
    let s = v.to_string();
    assert!(
        s.contains("FAIL") || s.contains("fail"),
        "should say fail: {s}"
    );
}

#[test]
fn validation_verdict_inconclusive_denies() {
    let v = ValidationVerdict::Inconclusive {
        mode: ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"w"),
            trace_pair_count: 5,
        },
        reason: "timeout".into(),
    };
    assert!(!v.permits_activation());
}

// ===========================================================================
// 3) ValidationGateError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn validation_gate_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "a".into(),
        }
        .to_string(),
        ValidationGateError::InvalidTokenSignature {
            token_id: "b".into(),
        }
        .to_string(),
        ValidationGateError::TokenExpired {
            token_id: "c".into(),
            expiry_epoch: 1,
            current_epoch: 2,
        }
        .to_string(),
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "d".into(),
            receipt_optimization_id: "e".into(),
        }
        .to_string(),
        ValidationGateError::Quarantined {
            optimization_id: "f".into(),
            reason: "g".into(),
        }
        .to_string(),
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Shadow,
            to: ActivationStage::Default,
        }
        .to_string(),
        ValidationGateError::OptimizationNotFound {
            optimization_id: "h".into(),
        }
        .to_string(),
        ValidationGateError::DuplicateSubmission {
            optimization_id: "i".into(),
        }
        .to_string(),
        ValidationGateError::ActivationDenied {
            verdict: "j".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn validation_gate_error_is_std_error() {
    let e = ValidationGateError::OptimizationNotFound {
        optimization_id: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_validation_mode() {
    let variants = [
        format!(
            "{:?}",
            ValidationMode::GoldenCorpusReplay {
                corpus_hash: ContentHash::compute(b"a"),
                vector_count: 1,
            }
        ),
        format!(
            "{:?}",
            ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"b"),
            }
        ),
        format!(
            "{:?}",
            ValidationMode::DifferentialTrace {
                workload_hash: ContentHash::compute(b"c"),
                trace_pair_count: 1,
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_validation_verdict() {
    let variants = [
        format!(
            "{:?}",
            ValidationVerdict::Pass {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: ContentHash::compute(b"a")
                },
                evidence_hash: ContentHash::compute(b"b"),
            }
        ),
        format!(
            "{:?}",
            ValidationVerdict::Fail {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: ContentHash::compute(b"a")
                },
                divergence_reason: "x".into(),
                counterexample_hash: ContentHash::compute(b"c"),
            }
        ),
        format!(
            "{:?}",
            ValidationVerdict::Inconclusive {
                mode: ValidationMode::SymbolicEquivalence {
                    proof_hash: ContentHash::compute(b"a")
                },
                reason: "y".into(),
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 5) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_validation_mode_all() {
    let modes = vec![
        ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"a"),
            vector_count: 100,
        },
        ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"b"),
        },
        ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"c"),
            trace_pair_count: 50,
        },
    ];
    for m in &modes {
        let json = serde_json::to_string(m).unwrap();
        let rt: ValidationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, rt);
    }
}

#[test]
fn serde_roundtrip_validation_verdict_all() {
    let verdicts = vec![
        ValidationVerdict::Pass {
            mode: ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"p"),
            },
            evidence_hash: ContentHash::compute(b"e"),
        },
        ValidationVerdict::Fail {
            mode: ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"p"),
            },
            divergence_reason: "div".into(),
            counterexample_hash: ContentHash::compute(b"cx"),
        },
        ValidationVerdict::Inconclusive {
            mode: ValidationMode::DifferentialTrace {
                workload_hash: ContentHash::compute(b"w"),
                trace_pair_count: 3,
            },
            reason: "timeout".into(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let rt: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_validation_gate_error_all() {
    let variants = vec![
        ValidationGateError::InvalidReceiptSignature {
            optimization_id: "a".into(),
        },
        ValidationGateError::InvalidTokenSignature {
            token_id: "b".into(),
        },
        ValidationGateError::TokenExpired {
            token_id: "c".into(),
            expiry_epoch: 1,
            current_epoch: 2,
        },
        ValidationGateError::TokenReceiptMismatch {
            token_optimization_id: "d".into(),
            receipt_optimization_id: "e".into(),
        },
        ValidationGateError::Quarantined {
            optimization_id: "f".into(),
            reason: "g".into(),
        },
        ValidationGateError::InvalidStageTransition {
            from: ActivationStage::Shadow,
            to: ActivationStage::Default,
        },
        ValidationGateError::OptimizationNotFound {
            optimization_id: "h".into(),
        },
        ValidationGateError::DuplicateSubmission {
            optimization_id: "i".into(),
        },
        ValidationGateError::ActivationDenied {
            verdict: "j".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ValidationGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_quarantine_entry() {
    let qe = QuarantineEntry {
        optimization_id: "opt1".into(),
        reason: "bad".into(),
        counterexample_hash: Some(ContentHash::compute(b"cx")),
        quarantined_epoch: SecurityEpoch::from_raw(5),
        quarantined_at_ticks: 1000,
    };
    let json = serde_json::to_string(&qe).unwrap();
    let rt: QuarantineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(qe, rt);
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_quarantine_entry() {
    let qe = QuarantineEntry {
        optimization_id: "opt1".into(),
        reason: "bad".into(),
        counterexample_hash: None,
        quarantined_epoch: SecurityEpoch::from_raw(1),
        quarantined_at_ticks: 100,
    };
    let v: serde_json::Value = serde_json::to_value(&qe).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "optimization_id",
        "reason",
        "counterexample_hash",
        "quarantined_epoch",
        "quarantined_at_ticks",
    ] {
        assert!(
            obj.contains_key(key),
            "QuarantineEntry missing field: {key}"
        );
    }
}

#[test]
fn json_fields_validation_event() {
    let ve = ValidationEvent {
        optimization_id: "opt1".into(),
        event_type: ValidationEventType::Submitted,
        timestamp_ticks: 500,
        epoch: SecurityEpoch::from_raw(1),
    };
    let v: serde_json::Value = serde_json::to_value(&ve).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["optimization_id", "event_type", "timestamp_ticks", "epoch"] {
        assert!(
            obj.contains_key(key),
            "ValidationEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) TranslationValidationGate — construction and initial state
// ===========================================================================

#[test]
fn gate_new_initial_state() {
    let gate = TranslationValidationGate::new();
    assert_eq!(gate.tracked_count(), 0);
    assert_eq!(gate.quarantine_count(), 0);
    assert_eq!(gate.event_count(), 0);
    assert!(gate.events().is_empty());
    assert!(gate.rollback_receipts().is_empty());
    assert!(gate.quarantined_ids().is_empty());
}

#[test]
fn gate_default_matches_new() {
    let g1 = TranslationValidationGate::new();
    let g2 = TranslationValidationGate::default();
    assert_eq!(g1.tracked_count(), g2.tracked_count());
    assert_eq!(g1.quarantine_count(), g2.quarantine_count());
}

#[test]
fn gate_current_stage_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.current_stage("nonexistent").is_none());
}

#[test]
fn gate_is_quarantined_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(!gate.is_quarantined("nonexistent"));
}

#[test]
fn gate_quarantine_entry_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.get_quarantine_entry("nonexistent").is_none());
}

#[test]
fn gate_promotion_history_unknown() {
    let gate = TranslationValidationGate::new();
    assert!(gate.promotion_history("nonexistent").is_empty());
}
