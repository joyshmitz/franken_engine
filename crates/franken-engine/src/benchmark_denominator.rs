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
            Self::EmptyCaseSet { .. } | Self::DuplicateWorkloadId { .. } => ERROR_INVALID_CASE_SET,
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
            return Err(BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: baseline.as_str().to_string(),
                workload_id: "<empty>".to_string(),
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
