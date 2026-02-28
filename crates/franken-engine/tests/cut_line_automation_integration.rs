//! Integration tests for the `cut_line_automation` module.
//!
//! Exercises the public API from outside the crate boundary:
//! CutLine, InputValidity, GateCategory, GateRequirement, CutLineSpec,
//! GateInput, GateEvaluationInput, GateEvaluation, PromotionRecord,
//! CutLineEvaluator, PromotionSummary, GateHistory.

use std::collections::BTreeMap;

use frankenengine_engine::cut_line_automation::{
    CutLine, CutLineEvaluator, CutLineSpec, GateCategory, GateEvaluation, GateEvaluationInput,
    GateHistory, GateInput, GateRequirement, InputValidity, PromotionRecord, PromotionSummary,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{GateVerdict, RiskLevel};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn now_ns() -> u64 {
    1_000_000_000 // 1 second
}

fn make_passing_input(category: GateCategory, ts: u64) -> GateInput {
    GateInput {
        category,
        score_millionths: Some(1_000_000),
        passed: true,
        evidence_hash: ContentHash::compute(category.as_str().as_bytes()),
        evidence_refs: vec![format!("{}_evidence", category)],
        collected_at_ns: ts,
        schema_major: 1,
        metadata: BTreeMap::new(),
    }
}

fn make_failing_input(category: GateCategory, ts: u64) -> GateInput {
    GateInput {
        category,
        score_millionths: Some(500_000),
        passed: false,
        evidence_hash: ContentHash::compute(b"fail"),
        evidence_refs: vec![format!("{}_fail", category)],
        collected_at_ns: ts,
        schema_major: 1,
        metadata: BTreeMap::new(),
    }
}

fn make_c0_inputs(ts: u64) -> Vec<GateInput> {
    vec![
        make_passing_input(GateCategory::SemanticContract, ts),
        make_passing_input(GateCategory::GovernanceCompliance, ts),
    ]
}

fn make_c1_inputs(ts: u64) -> Vec<GateInput> {
    vec![
        make_passing_input(GateCategory::CompilerCorrectness, ts),
        make_passing_input(GateCategory::RuntimeParity, ts),
        make_passing_input(GateCategory::FlakeBurden, ts),
    ]
}

// =========================================================================
// CutLine enum
// =========================================================================

#[test]
fn cut_line_as_str_all() {
    assert_eq!(CutLine::C0.as_str(), "C0");
    assert_eq!(CutLine::C1.as_str(), "C1");
    assert_eq!(CutLine::C2.as_str(), "C2");
    assert_eq!(CutLine::C3.as_str(), "C3");
    assert_eq!(CutLine::C4.as_str(), "C4");
    assert_eq!(CutLine::C5.as_str(), "C5");
}

#[test]
fn cut_line_display_matches_as_str() {
    for cl in CutLine::all() {
        assert_eq!(cl.to_string(), cl.as_str());
    }
}

#[test]
fn cut_line_all_returns_six() {
    assert_eq!(CutLine::all().len(), 6);
}

#[test]
fn cut_line_predecessor_chain() {
    assert_eq!(CutLine::C0.predecessor(), None);
    assert_eq!(CutLine::C1.predecessor(), Some(CutLine::C0));
    assert_eq!(CutLine::C2.predecessor(), Some(CutLine::C1));
    assert_eq!(CutLine::C3.predecessor(), Some(CutLine::C2));
    assert_eq!(CutLine::C4.predecessor(), Some(CutLine::C3));
    assert_eq!(CutLine::C5.predecessor(), Some(CutLine::C4));
}

#[test]
fn cut_line_ordering() {
    assert!(CutLine::C0 < CutLine::C1);
    assert!(CutLine::C1 < CutLine::C2);
    assert!(CutLine::C4 < CutLine::C5);
}

#[test]
fn cut_line_serde_roundtrip() {
    for cl in CutLine::all() {
        let json = serde_json::to_string(cl).unwrap();
        let restored: CutLine = serde_json::from_str(&json).unwrap();
        assert_eq!(*cl, restored);
    }
}

// =========================================================================
// InputValidity
// =========================================================================

#[test]
fn input_validity_valid() {
    let v = InputValidity::Valid;
    assert!(v.is_valid());
    assert_eq!(v.to_string(), "valid");
}

#[test]
fn input_validity_stale() {
    let v = InputValidity::Stale {
        age_ns: 100,
        max_age_ns: 50,
    };
    assert!(!v.is_valid());
    assert!(v.to_string().contains("stale"));
    assert!(v.to_string().contains("100"));
}

#[test]
fn input_validity_missing() {
    let v = InputValidity::Missing {
        field: "test_field".into(),
    };
    assert!(!v.is_valid());
    assert!(v.to_string().contains("test_field"));
}

#[test]
fn input_validity_incompatible() {
    let v = InputValidity::Incompatible {
        reason: "bad schema".into(),
    };
    assert!(!v.is_valid());
    assert!(v.to_string().contains("bad schema"));
}

#[test]
fn input_validity_serde_roundtrip() {
    let variants = vec![
        InputValidity::Valid,
        InputValidity::Stale {
            age_ns: 10,
            max_age_ns: 5,
        },
        InputValidity::Missing { field: "x".into() },
        InputValidity::Incompatible { reason: "y".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: InputValidity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// =========================================================================
// GateCategory
// =========================================================================

#[test]
fn gate_category_as_str() {
    assert_eq!(GateCategory::SemanticContract.as_str(), "semantic_contract");
    assert_eq!(
        GateCategory::CompilerCorrectness.as_str(),
        "compiler_correctness"
    );
    assert_eq!(GateCategory::HandoffReadiness.as_str(), "handoff_readiness");
}

#[test]
fn gate_category_display_matches_as_str() {
    let cats = [
        GateCategory::SemanticContract,
        GateCategory::CompilerCorrectness,
        GateCategory::RuntimeParity,
        GateCategory::PerformanceBenchmark,
        GateCategory::SecuritySurvival,
        GateCategory::DeterministicReplay,
        GateCategory::ObservabilityIntegrity,
        GateCategory::FlakeBurden,
        GateCategory::GovernanceCompliance,
        GateCategory::HandoffReadiness,
    ];
    for c in &cats {
        assert_eq!(c.to_string(), c.as_str());
    }
}

#[test]
fn gate_category_serde_roundtrip() {
    let cat = GateCategory::SecuritySurvival;
    let json = serde_json::to_string(&cat).unwrap();
    let restored: GateCategory = serde_json::from_str(&json).unwrap();
    assert_eq!(cat, restored);
}

// =========================================================================
// GateRequirement
// =========================================================================

#[test]
fn gate_requirement_serde_roundtrip() {
    let req = GateRequirement {
        category: GateCategory::PerformanceBenchmark,
        mandatory: true,
        description: "P99 latency below 10ms".into(),
        min_score_millionths: Some(900_000),
    };
    let json = serde_json::to_string(&req).unwrap();
    let restored: GateRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(req, restored);
}

// =========================================================================
// CutLineSpec
// =========================================================================

#[test]
fn default_c0_spec_properties() {
    let spec = CutLineSpec::default_c0();
    assert_eq!(spec.cut_line, CutLine::C0);
    assert!(!spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 2);
    assert_eq!(spec.mandatory_count(), 2);
    assert_eq!(spec.min_schema_major, 1);
}

#[test]
fn default_c1_spec_properties() {
    let spec = CutLineSpec::default_c1();
    assert_eq!(spec.cut_line, CutLine::C1);
    assert!(spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 3);
    assert_eq!(spec.mandatory_count(), 3);
}

#[test]
fn cut_line_spec_serde_roundtrip() {
    let spec = CutLineSpec::default_c0();
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CutLineSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}

// =========================================================================
// GateInput
// =========================================================================

#[test]
fn gate_input_serde_roundtrip() {
    let input = make_passing_input(GateCategory::SemanticContract, now_ns());
    let json = serde_json::to_string(&input).unwrap();
    let restored: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

// =========================================================================
// GateEvaluationInput
// =========================================================================

#[test]
fn gate_evaluation_input_serde_roundtrip() {
    let gei = GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "test-zone".into(),
    };
    let json = serde_json::to_string(&gei).unwrap();
    let restored: GateEvaluationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(gei, restored);
}

// =========================================================================
// GateEvaluation
// =========================================================================

#[test]
fn gate_evaluation_to_gate_result() {
    let eval = GateEvaluation {
        category: GateCategory::SemanticContract,
        mandatory: true,
        passed: true,
        score_millionths: Some(1_000_000),
        evidence_refs: vec!["ref-1".into()],
        summary: "passed".into(),
        input_validity: InputValidity::Valid,
    };
    let result = eval.to_gate_result();
    assert!(result.passed);
    assert_eq!(result.gate_name, "semantic_contract");
    assert_eq!(result.evidence_refs, vec!["ref-1".to_string()]);
}

#[test]
fn gate_evaluation_serde_roundtrip() {
    let eval = GateEvaluation {
        category: GateCategory::FlakeBurden,
        mandatory: false,
        passed: false,
        score_millionths: Some(500_000),
        evidence_refs: vec!["flake-evidence".into()],
        summary: "flake rate too high".into(),
        input_validity: InputValidity::Valid,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let restored: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, restored);
}

// =========================================================================
// CutLineEvaluator — basic construction
// =========================================================================

#[test]
fn evaluator_new_empty() {
    let eval = CutLineEvaluator::new(vec![]);
    assert!(!eval.is_promoted(CutLine::C0));
    assert_eq!(eval.history_len(), 0);
}

#[test]
fn evaluator_with_defaults() {
    let eval = CutLineEvaluator::with_defaults();
    assert!(!eval.is_promoted(CutLine::C0));
    assert!(!eval.is_promoted(CutLine::C1));
    assert_eq!(eval.history_len(), 0);
}

#[test]
fn evaluator_register_spec() {
    let mut eval = CutLineEvaluator::new(vec![]);
    eval.register_spec(CutLineSpec::default_c0());
    // Verify by evaluating C0
    let result = eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "z".into(),
    });
    assert!(result.is_some());
}

// =========================================================================
// CutLineEvaluator — evaluate C0
// =========================================================================

#[test]
fn evaluate_c0_all_pass() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.cut_line, CutLine::C0);
    assert_eq!(record.verdict, GateVerdict::Approved);
    assert_eq!(record.risk_level, RiskLevel::Low);
    assert!(eval.is_promoted(CutLine::C0));
    assert!(eval.promotion_hash(CutLine::C0).is_some());
    assert_eq!(eval.history_len(), 1);
}

#[test]
fn evaluate_c0_missing_evidence_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // Submit only SemanticContract, missing GovernanceCompliance
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![make_passing_input(GateCategory::SemanticContract, now_ns())],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert!(!eval.is_promoted(CutLine::C0));
}

#[test]
fn evaluate_c0_failing_evidence_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![
                make_failing_input(GateCategory::SemanticContract, now_ns()),
                make_passing_input(GateCategory::GovernanceCompliance, now_ns()),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert!(!eval.is_promoted(CutLine::C0));
}

#[test]
fn evaluate_c0_stale_input_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // C0 max staleness is 86_400_000_000_000 (24h).
    // Set collected_at_ns to 0, now_ns to 100_000_000_000_000 (way past 24h).
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: 100_000_000_000_000,
            epoch: epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, 0),
                make_passing_input(GateCategory::GovernanceCompliance, 0),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    // Evaluation should have Stale input_validity
    let stale_eval = record
        .evaluations
        .iter()
        .find(|e| matches!(e.input_validity, InputValidity::Stale { .. }));
    assert!(stale_eval.is_some());
}

#[test]
fn evaluate_c0_schema_incompatible_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let mut input = make_passing_input(GateCategory::SemanticContract, now_ns());
    input.schema_major = 0; // Below min_schema_major (1)
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![
                input,
                make_passing_input(GateCategory::GovernanceCompliance, now_ns()),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let incompat = record
        .evaluations
        .iter()
        .find(|e| matches!(e.input_validity, InputValidity::Incompatible { .. }));
    assert!(incompat.is_some());
}

#[test]
fn evaluate_unregistered_cut_line_returns_none() {
    let mut eval = CutLineEvaluator::new(vec![CutLineSpec::default_c0()]);
    let result = eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C3,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: vec![],
        predecessor_promoted: false,
        zone: "z".into(),
    });
    assert!(result.is_none());
}

// =========================================================================
// CutLineEvaluator — evaluate C1 (requires predecessor)
// =========================================================================

#[test]
fn evaluate_c1_without_predecessor_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // C0 not promoted, try C1
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert_eq!(record.risk_level, RiskLevel::Critical);
    assert!(!eval.is_promoted(CutLine::C1));
}

#[test]
fn evaluate_c1_with_predecessor_flag_passes() {
    let mut eval = CutLineEvaluator::with_defaults();
    // Even without promoting C0 internally, the predecessor_promoted flag
    // in the input overrides.
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: true,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C1));
}

#[test]
fn evaluate_c1_after_c0_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    // First promote C0
    let c0_record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();
    assert_eq!(c0_record.verdict, GateVerdict::Approved);

    // Now C1 should pass (predecessor promoted internally)
    let c1_record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();
    assert_eq!(c1_record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C1));
    // C1 record should link to C0 predecessor hash
    assert!(c1_record.predecessor_hash.is_some());
}

#[test]
fn evaluate_c1_score_below_threshold_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // Promote C0 first
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    // C1 CompilerCorrectness requires 1_000_000, give 999_999
    let mut cc_input = make_passing_input(GateCategory::CompilerCorrectness, now_ns());
    cc_input.score_millionths = Some(999_999);

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![
                cc_input,
                make_passing_input(GateCategory::RuntimeParity, now_ns()),
                make_passing_input(GateCategory::FlakeBurden, now_ns()),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
}

// =========================================================================
// PromotionRecord
// =========================================================================

#[test]
fn promotion_record_hash_deterministic() {
    let mut eval1 = CutLineEvaluator::with_defaults();
    let mut eval2 = CutLineEvaluator::with_defaults();

    let input = GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    };

    let r1 = eval1.evaluate(input.clone()).unwrap();
    let r2 = eval2.evaluate(input).unwrap();
    assert_eq!(r1.record_hash, r2.record_hash);
}

#[test]
fn promotion_record_serde_roundtrip() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    let json = serde_json::to_string(&record).unwrap();
    let restored: PromotionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// =========================================================================
// PromotionSummary
// =========================================================================

#[test]
fn promotion_summary_initial() {
    let eval = CutLineEvaluator::with_defaults();
    let summary = eval.promotion_summary();
    assert!(summary.promoted_lines.is_empty());
    assert_eq!(summary.next_line, Some(CutLine::C0));
    assert_eq!(summary.total_evaluations, 0);
    assert_eq!(summary.approved_count, 0);
    assert_eq!(summary.denied_count, 0);
    assert!(!summary.all_promoted());
    assert_eq!(summary.progress_millionths(), 0);
}

#[test]
fn promotion_summary_after_c0_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let summary = eval.promotion_summary();
    assert_eq!(summary.promoted_lines, vec![CutLine::C0]);
    assert_eq!(summary.next_line, Some(CutLine::C1));
    assert_eq!(summary.total_evaluations, 1);
    assert_eq!(summary.approved_count, 1);
    assert_eq!(summary.denied_count, 0);
    // 1 of 6 promoted = 166_666 millionths
    assert_eq!(summary.progress_millionths(), 166_666);
}

#[test]
fn promotion_summary_serde_roundtrip() {
    let summary = PromotionSummary {
        promoted_lines: vec![CutLine::C0, CutLine::C1],
        next_line: Some(CutLine::C2),
        total_evaluations: 5,
        approved_count: 2,
        denied_count: 3,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: PromotionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// CutLineEvaluator — revoke promotion
// =========================================================================

#[test]
fn revoke_promotion() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    assert!(eval.is_promoted(CutLine::C0));
    assert!(eval.revoke_promotion(CutLine::C0));
    assert!(!eval.is_promoted(CutLine::C0));
    // Revoking again returns false
    assert!(!eval.revoke_promotion(CutLine::C0));
}

// =========================================================================
// GateHistory
// =========================================================================

#[test]
fn gate_history_empty() {
    let eval = CutLineEvaluator::with_defaults();
    let history = GateHistory::from_evaluator(&eval);
    assert!(history.records.is_empty());
    assert!(history.verify());
}

#[test]
fn gate_history_with_records() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let history = GateHistory::from_evaluator(&eval);
    assert_eq!(history.records.len(), 1);
    assert!(history.verify());
}

#[test]
fn gate_history_tampered_fails_verify() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut history = GateHistory::from_evaluator(&eval);
    // Tamper with the hash
    history.history_hash = ContentHash::compute(b"tampered");
    assert!(!history.verify());
}

#[test]
fn gate_history_serde_roundtrip() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let history = GateHistory::from_evaluator(&eval);
    let json = serde_json::to_string(&history).unwrap();
    let restored: GateHistory = serde_json::from_str(&json).unwrap();
    assert_eq!(history, restored);
    assert!(restored.verify());
}

// =========================================================================
// CutLineEvaluator — serde roundtrip
// =========================================================================

#[test]
fn evaluator_serde_roundtrip() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let json = serde_json::to_string(&eval).unwrap();
    let restored: CutLineEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, restored);
    assert!(restored.is_promoted(CutLine::C0));
}

// =========================================================================
// Full lifecycle: C0 → C1 → denied C1 with advisory failure
// =========================================================================

#[test]
fn full_lifecycle_c0_then_c1() {
    let mut eval = CutLineEvaluator::with_defaults();

    // Promote C0
    let c0 = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "staging".into(),
        })
        .unwrap();
    assert_eq!(c0.verdict, GateVerdict::Approved);
    assert_eq!(c0.zone, "staging");

    // Promote C1
    let c1 = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "staging".into(),
        })
        .unwrap();
    assert_eq!(c1.verdict, GateVerdict::Approved);

    // Summary
    let summary = eval.promotion_summary();
    assert_eq!(summary.promoted_lines.len(), 2);
    assert_eq!(summary.next_line, Some(CutLine::C2));
    assert_eq!(summary.approved_count, 2);
    assert_eq!(eval.history_len(), 2);

    // History integrity
    let history = GateHistory::from_evaluator(&eval);
    assert!(history.verify());
}

#[test]
fn risk_level_varies_with_failures() {
    let mut eval = CutLineEvaluator::with_defaults();

    // All pass → Low risk
    let r = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "z".into(),
        })
        .unwrap();
    assert_eq!(r.risk_level, RiskLevel::Low);
}

// =========================================================================
// Multiple evaluations accumulate history
// =========================================================================

#[test]
fn multiple_evaluations_accumulate() {
    let mut eval = CutLineEvaluator::with_defaults();

    // Attempt 1: denied (missing evidence)
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: vec![],
        predecessor_promoted: false,
        zone: "z".into(),
    });

    // Attempt 2: approved
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "z".into(),
    });

    assert_eq!(eval.history_len(), 2);
    let summary = eval.promotion_summary();
    assert_eq!(summary.total_evaluations, 2);
    assert_eq!(summary.approved_count, 1);
    assert_eq!(summary.denied_count, 1);
}
