//! Benchmark denominator calculator and publication gate for Section 10.6 (`bd-2n9`).
//!
//! This module provides deterministic weighted-geometric-mean scoring for
//! FrankenEngine-vs-baseline comparisons and an explicit publication gate for
//! the normative `>= 3x` claim contract against both Node and Bun.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BENCHMARK_PUBLICATION_COMPONENT: &str = "benchmark_denominator";
pub const SCORE_THRESHOLD: f64 = 3.0;
const ROUND_SCALE: f64 = 1_000_000_000_000.0;
const WEIGHT_SUM_EPSILON: f64 = 1e-9;

const ERROR_INVALID_CASE_SET: &str = "FE-BENCH-1001";
const ERROR_INVALID_WEIGHT: &str = "FE-BENCH-1002";
const ERROR_INVALID_THROUGHPUT: &str = "FE-BENCH-1003";
const ERROR_WEIGHT_SUM: &str = "FE-BENCH-1004";
const ERROR_MISSING_COVERAGE: &str = "FE-BENCH-1005";
const ERROR_MISSING_LINEAGE: &str = "FE-BENCH-1006";
const ERROR_PUBLICATION_GATE_DENY: &str = "FE-BENCH-1007";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineEngine {
    Node,
    Bun,
}

impl BaselineEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub workload_id: String,
    pub throughput_franken_tps: f64,
    pub throughput_baseline_tps: f64,
    pub weight: Option<f64>,
    #[serde(default = "default_true")]
    pub behavior_equivalent: bool,
    #[serde(default = "default_true")]
    pub latency_envelope_ok: bool,
    #[serde(default = "default_true")]
    pub error_envelope_ok: bool,
}

impl BenchmarkCase {
    pub fn speedup(&self) -> f64 {
        self.throughput_franken_tps / self.throughput_baseline_tps
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl PublicationContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCoveragePoint {
    pub recorded_at_utc: String,
    pub native_slots: u64,
    pub total_slots: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationGateInput {
    pub node_cases: Vec<BenchmarkCase>,
    pub bun_cases: Vec<BenchmarkCase>,
    pub native_coverage_progression: Vec<NativeCoveragePoint>,
    pub replacement_lineage_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkPublicationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationGateDecision {
    pub score_vs_node: f64,
    pub score_vs_bun: f64,
    pub publish_allowed: bool,
    pub blockers: Vec<String>,
    pub native_coverage_progression: Vec<NativeCoveragePoint>,
    pub replacement_lineage_ids: Vec<String>,
    pub events: Vec<BenchmarkPublicationEvent>,
}

impl PublicationGateDecision {
    pub fn to_json_pretty(&self) -> Result<String, BenchmarkDenominatorError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| BenchmarkDenominatorError::SerializationFailure(error.to_string()))
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum BenchmarkDenominatorError {
    #[error("{baseline} case set is empty")]
    EmptyCaseSet { baseline: String },
    #[error("empty workload id in {baseline} case set")]
    EmptyWorkloadId { baseline: String },
    #[error("duplicate workload id `{workload_id}` in {baseline} case set")]
    DuplicateWorkloadId {
        baseline: String,
        workload_id: String,
    },
    #[error("invalid weight for workload `{workload_id}`: {reason}")]
    InvalidWeight { workload_id: String, reason: String },
    #[error("invalid throughput for workload `{workload_id}` field `{field}`")]
    InvalidThroughput { workload_id: String, field: String },
    #[error("weights for {baseline} case set do not sum to 1 (sum={sum})")]
    InvalidWeightSum { baseline: String, sum: f64 },
    #[error("native coverage progression is required for publication")]
    MissingCoverageProgression,
    #[error("replacement lineage ids are required for publication")]
    MissingReplacementLineage,
    #[error("serialization failure: {0}")]
    SerializationFailure(String),
}

impl BenchmarkDenominatorError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::EmptyCaseSet { .. }
            | Self::EmptyWorkloadId { .. }
            | Self::DuplicateWorkloadId { .. } => ERROR_INVALID_CASE_SET,
            Self::InvalidWeight { .. } => ERROR_INVALID_WEIGHT,
            Self::InvalidThroughput { .. } => ERROR_INVALID_THROUGHPUT,
            Self::InvalidWeightSum { .. } => ERROR_WEIGHT_SUM,
            Self::MissingCoverageProgression => ERROR_MISSING_COVERAGE,
            Self::MissingReplacementLineage => ERROR_MISSING_LINEAGE,
            Self::SerializationFailure(_) => ERROR_PUBLICATION_GATE_DENY,
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedCase {
    workload_id: String,
    speedup: f64,
    weight: f64,
}

/// Computes deterministic weighted geometric mean speedup for one baseline.
///
/// If all case weights are omitted (`None`), equal weighting is applied.
pub fn weighted_geometric_mean(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
) -> Result<f64, BenchmarkDenominatorError> {
    let prepared = prepare_cases(cases, baseline)?;

    let mut log_sum = 0.0_f64;
    for case in prepared {
        log_sum += case.weight * case.speedup.ln();
    }

    Ok(deterministic_round(log_sum.exp()))
}

/// Evaluates publication-gate rules for the normative `>= 3x` claim.
///
/// Publication requires:
/// - valid score computation inputs
/// - `score_vs_node >= 3.0`
/// - `score_vs_bun >= 3.0`
/// - all case behavior-equivalence + latency/error envelopes passing
/// - non-empty native-coverage progression and replacement lineage IDs
pub fn evaluate_publication_gate(
    input: &PublicationGateInput,
    ctx: &PublicationContext,
) -> Result<PublicationGateDecision, BenchmarkDenominatorError> {
    if input.native_coverage_progression.is_empty() {
        return Err(BenchmarkDenominatorError::MissingCoverageProgression);
    }

    let mut lineage_ids: Vec<String> = input
        .replacement_lineage_ids
        .iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();
    lineage_ids.sort();
    lineage_ids.dedup();
    if lineage_ids.is_empty() {
        return Err(BenchmarkDenominatorError::MissingReplacementLineage);
    }

    let score_vs_node = weighted_geometric_mean(&input.node_cases, BaselineEngine::Node)?;
    let score_vs_bun = weighted_geometric_mean(&input.bun_cases, BaselineEngine::Bun)?;

    let mut blockers = Vec::new();

    append_case_quality_blockers(&input.node_cases, BaselineEngine::Node, &mut blockers);
    append_case_quality_blockers(&input.bun_cases, BaselineEngine::Bun, &mut blockers);

    if score_vs_node < SCORE_THRESHOLD {
        blockers.push(format!(
            "score_vs_node below threshold: {score_vs_node:.12} < {SCORE_THRESHOLD:.1}"
        ));
    }
    if score_vs_bun < SCORE_THRESHOLD {
        blockers.push(format!(
            "score_vs_bun below threshold: {score_vs_bun:.12} < {SCORE_THRESHOLD:.1}"
        ));
    }

    let publish_allowed = blockers.is_empty();

    let baseline_events = [
        (BaselineEngine::Node, score_vs_node),
        (BaselineEngine::Bun, score_vs_bun),
    ]
    .into_iter()
    .map(|(baseline, score)| BenchmarkPublicationEvent {
        trace_id: ctx.trace_id.clone(),
        decision_id: ctx.decision_id.clone(),
        policy_id: ctx.policy_id.clone(),
        component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
        event: format!("{}_score_evaluated", baseline.as_str()),
        outcome: if score >= SCORE_THRESHOLD {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if score >= SCORE_THRESHOLD {
            None
        } else {
            Some(ERROR_PUBLICATION_GATE_DENY.to_string())
        },
    });

    let final_event = BenchmarkPublicationEvent {
        trace_id: ctx.trace_id.clone(),
        decision_id: ctx.decision_id.clone(),
        policy_id: ctx.policy_id.clone(),
        component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
        event: "publication_gate_decision".to_string(),
        outcome: if publish_allowed {
            "allow".to_string()
        } else {
            "deny".to_string()
        },
        error_code: if publish_allowed {
            None
        } else {
            Some(ERROR_PUBLICATION_GATE_DENY.to_string())
        },
    };

    let mut events: Vec<BenchmarkPublicationEvent> = baseline_events.collect();
    events.push(final_event);

    Ok(PublicationGateDecision {
        score_vs_node,
        score_vs_bun,
        publish_allowed,
        blockers,
        native_coverage_progression: input.native_coverage_progression.clone(),
        replacement_lineage_ids: lineage_ids,
        events,
    })
}

fn append_case_quality_blockers(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
    blockers: &mut Vec<String>,
) {
    for case in cases {
        if !case.behavior_equivalent {
            blockers.push(format!(
                "{} case `{}` failed behavior-equivalence",
                baseline.as_str(),
                case.workload_id
            ));
        }
        if !case.latency_envelope_ok {
            blockers.push(format!(
                "{} case `{}` failed latency envelope",
                baseline.as_str(),
                case.workload_id
            ));
        }
        if !case.error_envelope_ok {
            blockers.push(format!(
                "{} case `{}` failed error envelope",
                baseline.as_str(),
                case.workload_id
            ));
        }
    }
}

fn prepare_cases(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
) -> Result<Vec<PreparedCase>, BenchmarkDenominatorError> {
    if cases.is_empty() {
        return Err(BenchmarkDenominatorError::EmptyCaseSet {
            baseline: baseline.as_str().to_string(),
        });
    }

    let mut seen_ids = BTreeSet::new();
    for case in cases {
        let workload_id = case.workload_id.trim();
        if workload_id.is_empty() {
            return Err(BenchmarkDenominatorError::EmptyWorkloadId {
                baseline: baseline.as_str().to_string(),
            });
        }
        if !seen_ids.insert(workload_id.to_string()) {
            return Err(BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: baseline.as_str().to_string(),
                workload_id: workload_id.to_string(),
            });
        }
    }

    let weights_provided = cases.iter().filter(|case| case.weight.is_some()).count();
    if weights_provided != 0 && weights_provided != cases.len() {
        return Err(BenchmarkDenominatorError::InvalidWeight {
            workload_id: "<mixed>".to_string(),
            reason: "weights must be provided for all cases or none".to_string(),
        });
    }

    let default_weight = 1.0_f64 / cases.len() as f64;
    let mut prepared = Vec::with_capacity(cases.len());

    for case in cases {
        if !case.throughput_franken_tps.is_finite() || case.throughput_franken_tps <= 0.0 {
            return Err(BenchmarkDenominatorError::InvalidThroughput {
                workload_id: case.workload_id.clone(),
                field: "throughput_franken_tps".to_string(),
            });
        }
        if !case.throughput_baseline_tps.is_finite() || case.throughput_baseline_tps <= 0.0 {
            return Err(BenchmarkDenominatorError::InvalidThroughput {
                workload_id: case.workload_id.clone(),
                field: "throughput_baseline_tps".to_string(),
            });
        }

        let speedup = case.speedup();
        if !speedup.is_finite() || speedup <= 0.0 {
            return Err(BenchmarkDenominatorError::InvalidThroughput {
                workload_id: case.workload_id.clone(),
                field: "speedup".to_string(),
            });
        }

        let weight = match case.weight {
            Some(weight) => {
                if !weight.is_finite() || weight <= 0.0 {
                    return Err(BenchmarkDenominatorError::InvalidWeight {
                        workload_id: case.workload_id.clone(),
                        reason: "weight must be finite and > 0".to_string(),
                    });
                }
                weight
            }
            None => default_weight,
        };

        prepared.push(PreparedCase {
            workload_id: case.workload_id.clone(),
            speedup,
            weight,
        });
    }

    let weight_sum: f64 = prepared.iter().map(|case| case.weight).sum();
    if (weight_sum - 1.0).abs() > WEIGHT_SUM_EPSILON {
        return Err(BenchmarkDenominatorError::InvalidWeightSum {
            baseline: baseline.as_str().to_string(),
            sum: deterministic_round(weight_sum),
        });
    }

    prepared.sort_by(|lhs, rhs| lhs.workload_id.cmp(&rhs.workload_id));
    Ok(prepared)
}

fn deterministic_round(value: f64) -> f64 {
    (value * ROUND_SCALE).round() / ROUND_SCALE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_case(id: &str, franken: f64, baseline: f64) -> BenchmarkCase {
        BenchmarkCase {
            workload_id: id.into(),
            throughput_franken_tps: franken,
            throughput_baseline_tps: baseline,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        }
    }

    fn test_case_weighted(id: &str, franken: f64, baseline: f64, weight: f64) -> BenchmarkCase {
        BenchmarkCase {
            workload_id: id.into(),
            throughput_franken_tps: franken,
            throughput_baseline_tps: baseline,
            weight: Some(weight),
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        }
    }

    fn test_context() -> PublicationContext {
        PublicationContext::new("trace-1", "dec-1", "pol-1")
    }

    fn test_gate_input() -> PublicationGateInput {
        PublicationGateInput {
            node_cases: vec![test_case("w1", 3000.0, 1000.0)],
            bun_cases: vec![test_case("w1", 4000.0, 1000.0)],
            native_coverage_progression: vec![NativeCoveragePoint {
                recorded_at_utc: "2026-01-01T00:00:00Z".into(),
                native_slots: 10,
                total_slots: 20,
            }],
            replacement_lineage_ids: vec!["lineage-1".into()],
        }
    }

    // ── BaselineEngine ────────────────────────────────────────────

    #[test]
    fn baseline_engine_as_str() {
        assert_eq!(BaselineEngine::Node.as_str(), "node");
        assert_eq!(BaselineEngine::Bun.as_str(), "bun");
    }

    #[test]
    fn baseline_engine_serde_round_trip() {
        for e in [BaselineEngine::Node, BaselineEngine::Bun] {
            let json = serde_json::to_string(&e).unwrap();
            let back: BaselineEngine = serde_json::from_str(&json).unwrap();
            assert_eq!(e, back);
        }
    }

    // ── BenchmarkCase::speedup ────────────────────────────────────

    #[test]
    fn speedup_basic() {
        let c = test_case("w1", 3000.0, 1000.0);
        assert!((c.speedup() - 3.0).abs() < 1e-10);
    }

    #[test]
    fn speedup_fractional() {
        let c = test_case("w1", 500.0, 1000.0);
        assert!((c.speedup() - 0.5).abs() < 1e-10);
    }

    // ── BenchmarkDenominatorError ─────────────────────────────────

    #[test]
    fn error_stable_codes() {
        assert_eq!(
            BenchmarkDenominatorError::EmptyCaseSet {
                baseline: "node".into()
            }
            .stable_code(),
            "FE-BENCH-1001"
        );
        assert_eq!(
            BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: "node".into(),
                workload_id: "w1".into()
            }
            .stable_code(),
            "FE-BENCH-1001"
        );
        assert_eq!(
            BenchmarkDenominatorError::InvalidWeight {
                workload_id: "w1".into(),
                reason: "bad".into()
            }
            .stable_code(),
            "FE-BENCH-1002"
        );
        assert_eq!(
            BenchmarkDenominatorError::InvalidThroughput {
                workload_id: "w1".into(),
                field: "f".into()
            }
            .stable_code(),
            "FE-BENCH-1003"
        );
        assert_eq!(
            BenchmarkDenominatorError::InvalidWeightSum {
                baseline: "node".into(),
                sum: 0.5
            }
            .stable_code(),
            "FE-BENCH-1004"
        );
        assert_eq!(
            BenchmarkDenominatorError::MissingCoverageProgression.stable_code(),
            "FE-BENCH-1005"
        );
        assert_eq!(
            BenchmarkDenominatorError::MissingReplacementLineage.stable_code(),
            "FE-BENCH-1006"
        );
        assert_eq!(
            BenchmarkDenominatorError::SerializationFailure("x".into()).stable_code(),
            "FE-BENCH-1007"
        );
    }

    #[test]
    fn error_display() {
        let e = BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".into(),
        };
        assert!(e.to_string().contains("node"));
        assert!(e.to_string().contains("empty"));
    }

    // ── deterministic_round ───────────────────────────────────────

    #[test]
    fn deterministic_round_identity_for_integer() {
        assert!((deterministic_round(3.0) - 3.0).abs() < 1e-15);
    }

    #[test]
    fn deterministic_round_truncates_noise() {
        let a = deterministic_round(3.000_000_000_001);
        let b = deterministic_round(3.000_000_000_001);
        assert_eq!(a, b);
    }

    // ── weighted_geometric_mean ───────────────────────────────────

    #[test]
    fn geometric_mean_uniform_weights() {
        let cases = vec![test_case("w1", 3000.0, 1000.0)];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
        assert!((score - 3.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_multiple_equal_speedups() {
        let cases = vec![
            test_case("w1", 4000.0, 1000.0),
            test_case("w2", 4000.0, 1000.0),
        ];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
        assert!((score - 4.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_with_explicit_weights() {
        let cases = vec![
            test_case_weighted("w1", 9000.0, 1000.0, 0.5),
            test_case_weighted("w2", 1000.0, 1000.0, 0.5),
        ];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
        // geometric mean of 9x and 1x with equal weights = sqrt(9*1) = 3
        assert!((score - 3.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_empty_cases_errors() {
        let err = weighted_geometric_mean(&[], BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::EmptyCaseSet { .. }
        ));
    }

    #[test]
    fn geometric_mean_empty_workload_id_errors() {
        let cases = vec![test_case("", 3000.0, 1000.0)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::EmptyWorkloadId { .. }
        ));
    }

    #[test]
    fn geometric_mean_duplicate_workload_errors() {
        let cases = vec![
            test_case("w1", 3000.0, 1000.0),
            test_case("w1", 4000.0, 1000.0),
        ];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::DuplicateWorkloadId { .. }
        ));
    }

    #[test]
    fn geometric_mean_invalid_throughput_zero() {
        let cases = vec![test_case("w1", 0.0, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_throughput_negative() {
        let cases = vec![test_case("w1", -1.0, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_baseline_zero() {
        let cases = vec![test_case("w1", 3000.0, 0.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_throughput_nan() {
        let cases = vec![test_case("w1", f64::NAN, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_weight_negative() {
        let cases = vec![test_case_weighted("w1", 3000.0, 1000.0, -0.5)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_mixed_weights_errors() {
        let cases = vec![
            test_case("w1", 3000.0, 1000.0),               // None weight
            test_case_weighted("w2", 4000.0, 1000.0, 1.0), // Some weight
        ];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeight { .. }
        ));
    }

    #[test]
    fn geometric_mean_weights_not_summing_to_one() {
        let cases = vec![
            test_case_weighted("w1", 3000.0, 1000.0, 0.3),
            test_case_weighted("w2", 4000.0, 1000.0, 0.3),
        ];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeightSum { .. }
        ));
    }

    // ── PublicationContext ─────────────────────────────────────────

    #[test]
    fn publication_context_new() {
        let ctx = PublicationContext::new("t", "d", "p");
        assert_eq!(ctx.trace_id, "t");
        assert_eq!(ctx.decision_id, "d");
        assert_eq!(ctx.policy_id, "p");
    }

    // ── evaluate_publication_gate ──────────────────────────────────

    #[test]
    fn gate_passing() {
        let input = test_gate_input();
        let ctx = test_context();
        let decision = evaluate_publication_gate(&input, &ctx).unwrap();
        assert!(decision.publish_allowed);
        assert!(decision.score_vs_node >= SCORE_THRESHOLD);
        assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
        assert!(decision.blockers.is_empty());
        assert!(!decision.events.is_empty());
    }

    #[test]
    fn gate_below_threshold_node() {
        let mut input = test_gate_input();
        input.node_cases = vec![test_case("w1", 2000.0, 1000.0)]; // 2x < 3x
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("score_vs_node"))
        );
    }

    #[test]
    fn gate_below_threshold_bun() {
        let mut input = test_gate_input();
        input.bun_cases = vec![test_case("w1", 1000.0, 1000.0)]; // 1x < 3x
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert!(!decision.publish_allowed);
        assert!(decision.blockers.iter().any(|b| b.contains("score_vs_bun")));
    }

    #[test]
    fn gate_behavior_equivalent_false_blocks() {
        let mut input = test_gate_input();
        input.node_cases[0].behavior_equivalent = false;
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("behavior-equivalence"))
        );
    }

    #[test]
    fn gate_latency_envelope_false_blocks() {
        let mut input = test_gate_input();
        input.bun_cases[0].latency_envelope_ok = false;
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("latency envelope"))
        );
    }

    #[test]
    fn gate_error_envelope_false_blocks() {
        let mut input = test_gate_input();
        input.node_cases[0].error_envelope_ok = false;
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert!(!decision.publish_allowed);
    }

    #[test]
    fn gate_missing_coverage_progression() {
        let mut input = test_gate_input();
        input.native_coverage_progression.clear();
        let err = evaluate_publication_gate(&input, &test_context()).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::MissingCoverageProgression
        ));
    }

    #[test]
    fn gate_missing_lineage() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids.clear();
        let err = evaluate_publication_gate(&input, &test_context()).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::MissingReplacementLineage
        ));
    }

    #[test]
    fn gate_lineage_dedup_and_trim() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids = vec![
            "  lineage-1 ".into(),
            "lineage-1".into(),
            "lineage-2".into(),
        ];
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert_eq!(decision.replacement_lineage_ids.len(), 2);
    }

    #[test]
    fn gate_empty_lineage_strings_filtered() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids = vec!["  ".into(), "".into()];
        let err = evaluate_publication_gate(&input, &test_context()).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::MissingReplacementLineage
        ));
    }

    #[test]
    fn gate_events_contain_baselines() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "node_score_evaluated")
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "bun_score_evaluated")
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "publication_gate_decision")
        );
    }

    // ── PublicationGateDecision::to_json_pretty ───────────────────

    #[test]
    fn decision_to_json_pretty() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        let json = decision.to_json_pretty().unwrap();
        assert!(json.contains("publish_allowed"));
    }

    // ── serde round-trips ─────────────────────────────────────────

    #[test]
    fn benchmark_case_serde_round_trip() {
        let c = test_case("w1", 3000.0, 1000.0);
        let json = serde_json::to_string(&c).unwrap();
        let back: BenchmarkCase = serde_json::from_str(&json).unwrap();
        assert_eq!(c.workload_id, back.workload_id);
        assert!((c.throughput_franken_tps - back.throughput_franken_tps).abs() < 1e-10);
    }

    #[test]
    fn publication_context_serde_round_trip() {
        let ctx = test_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let back: PublicationContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }

    #[test]
    fn native_coverage_point_serde_round_trip() {
        let p = NativeCoveragePoint {
            recorded_at_utc: "2026-01-01T00:00:00Z".into(),
            native_slots: 10,
            total_slots: 20,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: NativeCoveragePoint = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn benchmark_publication_event_serde_round_trip() {
        let e = BenchmarkPublicationEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "o".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: BenchmarkPublicationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn gate_decision_serde_round_trip() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context()).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        let back: PublicationGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision.publish_allowed, back.publish_allowed);
        assert!((decision.score_vs_node - back.score_vs_node).abs() < 1e-10);
    }

    // ── BenchmarkCase defaults ────────────────────────────────────

    #[test]
    fn case_defaults_from_json() {
        let json =
            r#"{"workload_id":"w","throughput_franken_tps":100.0,"throughput_baseline_tps":50.0}"#;
        let c: BenchmarkCase = serde_json::from_str(json).unwrap();
        assert!(c.behavior_equivalent);
        assert!(c.latency_envelope_ok);
        assert!(c.error_envelope_ok);
        assert!(c.weight.is_none());
    }
}
