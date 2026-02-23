//! Deterministic benchmark split gate for Section 10.13 item 17 (`bd-1rdj`).
//!
//! This module isolates control-plane integration overhead from VM hot-loop
//! behavior and enforces bounded regressions for:
//! - Cx threading
//! - decision contracts
//! - evidence emission
//! - full integration

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const CONTROL_PLANE_BENCHMARK_SPLIT_DOMAIN: &[u8] =
    b"FrankenEngine.ControlPlaneBenchmarkSplitGate.v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Benchmark split phases for control-plane integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkSplit {
    Baseline,
    CxThreading,
    DecisionContracts,
    EvidenceEmission,
    FullIntegration,
}

impl BenchmarkSplit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::CxThreading => "cx_threading",
            Self::DecisionContracts => "decision_contracts",
            Self::EvidenceEmission => "evidence_emission",
            Self::FullIntegration => "full_integration",
        }
    }

    fn all_required() -> BTreeSet<Self> {
        BTreeSet::from([
            Self::Baseline,
            Self::CxThreading,
            Self::DecisionContracts,
            Self::EvidenceEmission,
            Self::FullIntegration,
        ])
    }
}

impl fmt::Display for BenchmarkSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deterministic latency summary in nanoseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyStatsNs {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

impl LatencyStatsNs {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("p50_ns".to_string(), CanonicalValue::U64(self.p50_ns));
        map.insert("p95_ns".to_string(), CanonicalValue::U64(self.p95_ns));
        map.insert("p99_ns".to_string(), CanonicalValue::U64(self.p99_ns));
        CanonicalValue::Map(map)
    }
}

/// Benchmark metrics per split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitBenchmarkMetrics {
    pub throughput_ops_per_sec: u64,
    pub latency_ns: LatencyStatsNs,
    /// Delta from baseline peak RSS in bytes.
    pub peak_rss_delta_bytes: u64,
}

impl SplitBenchmarkMetrics {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "throughput_ops_per_sec".to_string(),
            CanonicalValue::U64(self.throughput_ops_per_sec),
        );
        map.insert("latency_ns".to_string(), self.latency_ns.canonical_value());
        map.insert(
            "peak_rss_delta_bytes".to_string(),
            CanonicalValue::U64(self.peak_rss_delta_bytes),
        );
        CanonicalValue::Map(map)
    }
}

/// Deterministic snapshot for one benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitSnapshot {
    pub snapshot_id: String,
    pub benchmark_run_id: String,
    pub split_metrics: BTreeMap<BenchmarkSplit, SplitBenchmarkMetrics>,
    /// Baseline throughput samples used for CV stability checks.
    pub baseline_throughput_runs_ops_per_sec: Vec<u64>,
}

impl BenchmarkSplitSnapshot {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "snapshot_id".to_string(),
            CanonicalValue::String(self.snapshot_id.clone()),
        );
        map.insert(
            "benchmark_run_id".to_string(),
            CanonicalValue::String(self.benchmark_run_id.clone()),
        );

        let mut split_map = BTreeMap::new();
        for (split, metrics) in &self.split_metrics {
            split_map.insert(split.as_str().to_string(), metrics.canonical_value());
        }
        map.insert("split_metrics".to_string(), CanonicalValue::Map(split_map));

        let mut baseline_runs = self.baseline_throughput_runs_ops_per_sec.clone();
        baseline_runs.sort_unstable();
        map.insert(
            "baseline_throughput_runs_ops_per_sec".to_string(),
            CanonicalValue::Array(baseline_runs.into_iter().map(CanonicalValue::U64).collect()),
        );

        CanonicalValue::Map(map)
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        hash_bytes(&deterministic_serde::encode_value(&self.canonical_value()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitGateInput {
    pub trace_id: String,
    pub policy_id: String,
    pub previous_snapshot: BenchmarkSplitSnapshot,
    pub candidate_snapshot: BenchmarkSplitSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitThresholds {
    pub min_baseline_runs: usize,
    pub max_baseline_cv_millionths: u64,
    pub max_cx_throughput_regression_millionths: u64,
    pub max_decision_latency_regression_millionths: u64,
    pub max_evidence_throughput_regression_millionths: u64,
    pub max_full_integration_throughput_regression_millionths: u64,
    pub max_peak_rss_delta_bytes: BTreeMap<BenchmarkSplit, u64>,
    pub max_previous_run_throughput_regression_millionths: BTreeMap<BenchmarkSplit, u64>,
    pub max_previous_run_latency_regression_millionths: u64,
}

impl Default for BenchmarkSplitThresholds {
    fn default() -> Self {
        let mut max_peak_rss_delta_bytes = BTreeMap::new();
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::Baseline, 0);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::CxThreading, 16 * 1024 * 1024);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::DecisionContracts, 32 * 1024 * 1024);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::EvidenceEmission, 48 * 1024 * 1024);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::FullIntegration, 64 * 1024 * 1024);

        let mut max_previous_run_throughput_regression_millionths = BTreeMap::new();
        max_previous_run_throughput_regression_millionths.insert(BenchmarkSplit::Baseline, 50_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::CxThreading, 10_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::DecisionContracts, 20_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::EvidenceEmission, 20_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::FullIntegration, 50_000);

        Self {
            min_baseline_runs: 10,
            max_baseline_cv_millionths: 50_000,
            max_cx_throughput_regression_millionths: 10_000,
            max_decision_latency_regression_millionths: 50_000,
            max_evidence_throughput_regression_millionths: 20_000,
            max_full_integration_throughput_regression_millionths: 50_000,
            max_peak_rss_delta_bytes,
            max_previous_run_throughput_regression_millionths,
            max_previous_run_latency_regression_millionths: 50_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkSplitFailureCode {
    MissingSplitMetrics,
    InsufficientBaselineRuns,
    BaselineVarianceExceeded,
    InvalidMetric,
    ThroughputRegressionExceeded,
    LatencyRegressionExceeded,
    MemoryOverheadExceeded,
    PreviousRunRegressionExceeded,
}

impl fmt::Display for BenchmarkSplitFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSplitMetrics => f.write_str("missing_split_metrics"),
            Self::InsufficientBaselineRuns => f.write_str("insufficient_baseline_runs"),
            Self::BaselineVarianceExceeded => f.write_str("baseline_variance_exceeded"),
            Self::InvalidMetric => f.write_str("invalid_metric"),
            Self::ThroughputRegressionExceeded => f.write_str("throughput_regression_exceeded"),
            Self::LatencyRegressionExceeded => f.write_str("latency_regression_exceeded"),
            Self::MemoryOverheadExceeded => f.write_str("memory_overhead_exceeded"),
            Self::PreviousRunRegressionExceeded => f.write_str("previous_run_regression_exceeded"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitFinding {
    pub code: BenchmarkSplitFailureCode,
    pub split: Option<BenchmarkSplit>,
    pub metric: Option<String>,
    pub detail: String,
    pub observed_millionths: Option<u64>,
    pub threshold_millionths: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitBenchmarkEvaluation {
    pub split: BenchmarkSplit,
    pub previous_metrics: SplitBenchmarkMetrics,
    pub candidate_metrics: SplitBenchmarkMetrics,
    pub throughput_regression_vs_previous_millionths: u64,
    pub latency_p95_regression_vs_previous_millionths: u64,
    pub latency_p99_regression_vs_previous_millionths: u64,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub split: Option<String>,
    pub metric: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitGateDecision {
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
    pub previous_snapshot_hash: [u8; 32],
    pub candidate_snapshot_hash: [u8; 32],
    pub baseline_cv_millionths: Option<u64>,
    pub evaluations: Vec<SplitBenchmarkEvaluation>,
    pub findings: Vec<BenchmarkSplitFinding>,
    pub logs: Vec<BenchmarkSplitLogEvent>,
}

fn throughput_regression_millionths(reference: u64, candidate: u64) -> u64 {
    if reference == 0 {
        return u64::MAX;
    }
    if candidate >= reference {
        return 0;
    }
    let delta = reference.saturating_sub(candidate);
    ((delta as u128 * 1_000_000) / reference as u128) as u64
}

fn latency_regression_millionths(reference: u64, candidate: u64) -> u64 {
    if reference == 0 {
        return u64::MAX;
    }
    if candidate <= reference {
        return 0;
    }
    let delta = candidate.saturating_sub(reference);
    ((delta as u128 * 1_000_000) / reference as u128) as u64
}

fn coefficient_of_variation_millionths(samples: &[u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }

    let len = samples.len() as f64;
    let mean = samples.iter().map(|value| *value as f64).sum::<f64>() / len;
    if mean == 0.0 {
        return None;
    }

    let variance = samples
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / len;
    let stddev = variance.sqrt();
    Some(((stddev / mean) * 1_000_000.0).round() as u64)
}

fn decision_canonical_value(
    input: &BenchmarkSplitGateInput,
    previous_hash: [u8; 32],
    candidate_hash: [u8; 32],
    pass: bool,
    baseline_cv_millionths: Option<u64>,
    evaluations: &[SplitBenchmarkEvaluation],
    findings: &[BenchmarkSplitFinding],
) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert("pass".to_string(), CanonicalValue::Bool(pass));
    map.insert(
        "previous_snapshot_hash".to_string(),
        CanonicalValue::Bytes(previous_hash.to_vec()),
    );
    map.insert(
        "candidate_snapshot_hash".to_string(),
        CanonicalValue::Bytes(candidate_hash.to_vec()),
    );
    map.insert(
        "baseline_cv_millionths".to_string(),
        match baseline_cv_millionths {
            Some(value) => CanonicalValue::U64(value),
            None => CanonicalValue::Null,
        },
    );

    map.insert(
        "evaluations".to_string(),
        CanonicalValue::Array(
            evaluations
                .iter()
                .map(|evaluation| {
                    let mut eval_map = BTreeMap::new();
                    eval_map.insert(
                        "split".to_string(),
                        CanonicalValue::String(evaluation.split.as_str().to_string()),
                    );
                    eval_map.insert("pass".to_string(), CanonicalValue::Bool(evaluation.pass));
                    eval_map.insert(
                        "throughput_regression_vs_previous_millionths".to_string(),
                        CanonicalValue::U64(
                            evaluation.throughput_regression_vs_previous_millionths,
                        ),
                    );
                    eval_map.insert(
                        "latency_p95_regression_vs_previous_millionths".to_string(),
                        CanonicalValue::U64(
                            evaluation.latency_p95_regression_vs_previous_millionths,
                        ),
                    );
                    eval_map.insert(
                        "latency_p99_regression_vs_previous_millionths".to_string(),
                        CanonicalValue::U64(
                            evaluation.latency_p99_regression_vs_previous_millionths,
                        ),
                    );
                    eval_map.insert(
                        "candidate_metrics".to_string(),
                        evaluation.candidate_metrics.canonical_value(),
                    );
                    eval_map.insert(
                        "previous_metrics".to_string(),
                        evaluation.previous_metrics.canonical_value(),
                    );
                    CanonicalValue::Map(eval_map)
                })
                .collect(),
        ),
    );

    map.insert(
        "findings".to_string(),
        CanonicalValue::Array(
            findings
                .iter()
                .map(|finding| {
                    let mut finding_map = BTreeMap::new();
                    finding_map.insert(
                        "code".to_string(),
                        CanonicalValue::String(finding.code.to_string()),
                    );
                    finding_map.insert(
                        "detail".to_string(),
                        CanonicalValue::String(finding.detail.clone()),
                    );
                    finding_map.insert(
                        "metric".to_string(),
                        match &finding.metric {
                            Some(metric) => CanonicalValue::String(metric.clone()),
                            None => CanonicalValue::Null,
                        },
                    );
                    finding_map.insert(
                        "split".to_string(),
                        match finding.split {
                            Some(split) => CanonicalValue::String(split.as_str().to_string()),
                            None => CanonicalValue::Null,
                        },
                    );
                    finding_map.insert(
                        "observed_millionths".to_string(),
                        match finding.observed_millionths {
                            Some(value) => CanonicalValue::U64(value),
                            None => CanonicalValue::Null,
                        },
                    );
                    finding_map.insert(
                        "threshold_millionths".to_string(),
                        match finding.threshold_millionths {
                            Some(value) => CanonicalValue::U64(value),
                            None => CanonicalValue::Null,
                        },
                    );
                    CanonicalValue::Map(finding_map)
                })
                .collect(),
        ),
    );

    CanonicalValue::Map(map)
}

/// Evaluate control-plane benchmark split inputs and produce deterministic gate output.
pub fn evaluate_control_plane_benchmark_split(
    input: &BenchmarkSplitGateInput,
    thresholds: &BenchmarkSplitThresholds,
) -> BenchmarkSplitGateDecision {
    let previous_hash = input.previous_snapshot.snapshot_hash();
    let candidate_hash = input.candidate_snapshot.snapshot_hash();

    let mut findings = Vec::new();
    let required_splits = BenchmarkSplit::all_required();

    for split in &required_splits {
        if !input.previous_snapshot.split_metrics.contains_key(split) {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::MissingSplitMetrics,
                split: Some(*split),
                metric: None,
                detail: format!("previous snapshot missing split `{split}`"),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }
        if !input.candidate_snapshot.split_metrics.contains_key(split) {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::MissingSplitMetrics,
                split: Some(*split),
                metric: None,
                detail: format!("candidate snapshot missing split `{split}`"),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }
    }

    let baseline_cv_millionths = if input
        .candidate_snapshot
        .baseline_throughput_runs_ops_per_sec
        .len()
        < thresholds.min_baseline_runs
    {
        findings.push(BenchmarkSplitFinding {
            code: BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            split: Some(BenchmarkSplit::Baseline),
            metric: Some("baseline_cv".to_string()),
            detail: format!(
                "candidate baseline stability requires at least {} runs",
                thresholds.min_baseline_runs
            ),
            observed_millionths: Some(
                input
                    .candidate_snapshot
                    .baseline_throughput_runs_ops_per_sec
                    .len() as u64,
            ),
            threshold_millionths: Some(thresholds.min_baseline_runs as u64),
        });
        None
    } else {
        match coefficient_of_variation_millionths(
            &input
                .candidate_snapshot
                .baseline_throughput_runs_ops_per_sec,
        ) {
            Some(cv) => {
                if cv > thresholds.max_baseline_cv_millionths {
                    findings.push(BenchmarkSplitFinding {
                        code: BenchmarkSplitFailureCode::BaselineVarianceExceeded,
                        split: Some(BenchmarkSplit::Baseline),
                        metric: Some("baseline_cv".to_string()),
                        detail: format!(
                            "baseline coefficient of variation exceeded threshold (observed {} ppm, max {} ppm)",
                            cv, thresholds.max_baseline_cv_millionths
                        ),
                        observed_millionths: Some(cv),
                        threshold_millionths: Some(thresholds.max_baseline_cv_millionths),
                    });
                }
                Some(cv)
            }
            None => {
                findings.push(BenchmarkSplitFinding {
                    code: BenchmarkSplitFailureCode::InvalidMetric,
                    split: Some(BenchmarkSplit::Baseline),
                    metric: Some("baseline_cv".to_string()),
                    detail: "baseline coefficient of variation could not be computed".to_string(),
                    observed_millionths: None,
                    threshold_millionths: None,
                });
                None
            }
        }
    };

    let mut evaluations = Vec::new();
    for split in &required_splits {
        let previous_metrics = input.previous_snapshot.split_metrics.get(split);
        let candidate_metrics = input.candidate_snapshot.split_metrics.get(split);

        let (Some(previous_metrics), Some(candidate_metrics)) =
            (previous_metrics, candidate_metrics)
        else {
            continue;
        };

        if previous_metrics.throughput_ops_per_sec == 0
            || candidate_metrics.throughput_ops_per_sec == 0
        {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::InvalidMetric,
                split: Some(*split),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: "throughput must be non-zero for regression checks".to_string(),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }

        let throughput_regression = throughput_regression_millionths(
            previous_metrics.throughput_ops_per_sec,
            candidate_metrics.throughput_ops_per_sec,
        );
        let latency_p95_regression = latency_regression_millionths(
            previous_metrics.latency_ns.p95_ns,
            candidate_metrics.latency_ns.p95_ns,
        );
        let latency_p99_regression = latency_regression_millionths(
            previous_metrics.latency_ns.p99_ns,
            candidate_metrics.latency_ns.p99_ns,
        );

        evaluations.push(SplitBenchmarkEvaluation {
            split: *split,
            previous_metrics: previous_metrics.clone(),
            candidate_metrics: candidate_metrics.clone(),
            throughput_regression_vs_previous_millionths: throughput_regression,
            latency_p95_regression_vs_previous_millionths: latency_p95_regression,
            latency_p99_regression_vs_previous_millionths: latency_p99_regression,
            pass: true,
        });
    }

    let candidate_baseline = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::Baseline);
    let candidate_cx = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::CxThreading);
    let candidate_decision = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::DecisionContracts);
    let candidate_evidence = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::EvidenceEmission);
    let candidate_full = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::FullIntegration);

    if let (Some(baseline), Some(cx)) = (candidate_baseline, candidate_cx) {
        let regression = throughput_regression_millionths(
            baseline.throughput_ops_per_sec,
            cx.throughput_ops_per_sec,
        );
        if regression > thresholds.max_cx_throughput_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
                split: Some(BenchmarkSplit::CxThreading),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "Cx threading throughput regression exceeded threshold (observed {} ppm, max {} ppm)",
                    regression, thresholds.max_cx_throughput_regression_millionths
                ),
                observed_millionths: Some(regression),
                threshold_millionths: Some(thresholds.max_cx_throughput_regression_millionths),
            });
        }
    }

    if let (Some(cx), Some(decision)) = (candidate_cx, candidate_decision) {
        let p95_regression =
            latency_regression_millionths(cx.latency_ns.p95_ns, decision.latency_ns.p95_ns);
        let p99_regression =
            latency_regression_millionths(cx.latency_ns.p99_ns, decision.latency_ns.p99_ns);
        let max_observed = p95_regression.max(p99_regression);
        if max_observed > thresholds.max_decision_latency_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::LatencyRegressionExceeded,
                split: Some(BenchmarkSplit::DecisionContracts),
                metric: Some("latency_ns.p95_p99".to_string()),
                detail: format!(
                    "decision contract latency regression exceeded threshold (p95 {} ppm, p99 {} ppm, max {} ppm)",
                    p95_regression, p99_regression, thresholds.max_decision_latency_regression_millionths
                ),
                observed_millionths: Some(max_observed),
                threshold_millionths: Some(thresholds.max_decision_latency_regression_millionths),
            });
        }
    }

    if let (Some(decision), Some(evidence)) = (candidate_decision, candidate_evidence) {
        let regression = throughput_regression_millionths(
            decision.throughput_ops_per_sec,
            evidence.throughput_ops_per_sec,
        );
        if regression > thresholds.max_evidence_throughput_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
                split: Some(BenchmarkSplit::EvidenceEmission),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "evidence emission throughput regression exceeded threshold (observed {} ppm, max {} ppm)",
                    regression, thresholds.max_evidence_throughput_regression_millionths
                ),
                observed_millionths: Some(regression),
                threshold_millionths: Some(thresholds.max_evidence_throughput_regression_millionths),
            });
        }
    }

    if let (Some(baseline), Some(full)) = (candidate_baseline, candidate_full) {
        let regression = throughput_regression_millionths(
            baseline.throughput_ops_per_sec,
            full.throughput_ops_per_sec,
        );
        if regression > thresholds.max_full_integration_throughput_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
                split: Some(BenchmarkSplit::FullIntegration),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "full integration throughput regression exceeded threshold (observed {} ppm, max {} ppm)",
                    regression, thresholds.max_full_integration_throughput_regression_millionths
                ),
                observed_millionths: Some(regression),
                threshold_millionths: Some(
                    thresholds.max_full_integration_throughput_regression_millionths,
                ),
            });
        }
    }

    for (split, metrics) in &input.candidate_snapshot.split_metrics {
        if let Some(limit) = thresholds.max_peak_rss_delta_bytes.get(split)
            && metrics.peak_rss_delta_bytes > *limit
        {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::MemoryOverheadExceeded,
                split: Some(*split),
                metric: Some("peak_rss_delta_bytes".to_string()),
                detail: format!(
                    "peak RSS delta exceeded threshold (observed {} bytes, max {} bytes)",
                    metrics.peak_rss_delta_bytes, limit
                ),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }
    }

    for evaluation in &evaluations {
        if let Some(limit) = thresholds
            .max_previous_run_throughput_regression_millionths
            .get(&evaluation.split)
            && evaluation.throughput_regression_vs_previous_millionths > *limit
        {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
                split: Some(evaluation.split),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "throughput regressed vs previous run (observed {} ppm, max {} ppm)",
                    evaluation.throughput_regression_vs_previous_millionths, limit
                ),
                observed_millionths: Some(evaluation.throughput_regression_vs_previous_millionths),
                threshold_millionths: Some(*limit),
            });
        }

        let max_latency_regression = evaluation
            .latency_p95_regression_vs_previous_millionths
            .max(evaluation.latency_p99_regression_vs_previous_millionths);
        if max_latency_regression > thresholds.max_previous_run_latency_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
                split: Some(evaluation.split),
                metric: Some("latency_ns.p95_p99".to_string()),
                detail: format!(
                    "latency regressed vs previous run (p95 {} ppm, p99 {} ppm, max {} ppm)",
                    evaluation.latency_p95_regression_vs_previous_millionths,
                    evaluation.latency_p99_regression_vs_previous_millionths,
                    thresholds.max_previous_run_latency_regression_millionths
                ),
                observed_millionths: Some(max_latency_regression),
                threshold_millionths: Some(
                    thresholds.max_previous_run_latency_regression_millionths,
                ),
            });
        }
    }

    for evaluation in &mut evaluations {
        evaluation.pass = !findings
            .iter()
            .any(|finding| finding.split == Some(evaluation.split));
    }

    let pass = findings.is_empty() && evaluations.iter().all(|evaluation| evaluation.pass);

    let decision_hash = hash_bytes(&deterministic_serde::encode_value(&CanonicalValue::Array(
        vec![
            CanonicalValue::Bytes(CONTROL_PLANE_BENCHMARK_SPLIT_DOMAIN.to_vec()),
            decision_canonical_value(
                input,
                previous_hash,
                candidate_hash,
                pass,
                baseline_cv_millionths,
                &evaluations,
                &findings,
            ),
        ],
    )));
    let decision_id = format!("cp-bench-split-{}", to_hex(&decision_hash[..16]));

    let mut logs = Vec::new();
    let stability_failure = findings.iter().find(|finding| {
        finding.split == Some(BenchmarkSplit::Baseline)
            && finding.metric.as_deref() == Some("baseline_cv")
    });
    logs.push(BenchmarkSplitLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "control_plane_benchmark_split_gate".to_string(),
        event: "baseline_stability_check".to_string(),
        outcome: if stability_failure.is_none() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: stability_failure.map(|finding| finding.code.to_string()),
        split: Some(BenchmarkSplit::Baseline.as_str().to_string()),
        metric: Some("baseline_cv".to_string()),
    });

    for evaluation in &evaluations {
        let failure = findings
            .iter()
            .find(|finding| finding.split == Some(evaluation.split));
        logs.push(BenchmarkSplitLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "control_plane_benchmark_split_gate".to_string(),
            event: "split_evaluation".to_string(),
            outcome: if evaluation.pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_code: failure.map(|finding| finding.code.to_string()),
            split: Some(evaluation.split.as_str().to_string()),
            metric: failure.and_then(|finding| finding.metric.clone()),
        });
    }

    logs.push(BenchmarkSplitLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "control_plane_benchmark_split_gate".to_string(),
        event: "benchmark_split_decision".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if pass {
            None
        } else {
            Some("control_plane_benchmark_split_failed".to_string())
        },
        split: None,
        metric: None,
    });

    BenchmarkSplitGateDecision {
        decision_id,
        pass,
        rollback_required: !pass,
        previous_snapshot_hash: previous_hash,
        candidate_snapshot_hash: candidate_hash,
        baseline_cv_millionths,
        evaluations,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(
        throughput_ops_per_sec: u64,
        p50_ns: u64,
        p95_ns: u64,
        p99_ns: u64,
        peak_rss_delta_bytes: u64,
    ) -> SplitBenchmarkMetrics {
        SplitBenchmarkMetrics {
            throughput_ops_per_sec,
            latency_ns: LatencyStatsNs {
                p50_ns,
                p95_ns,
                p99_ns,
            },
            peak_rss_delta_bytes,
        }
    }

    fn previous_snapshot() -> BenchmarkSplitSnapshot {
        let split_metrics = BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                metrics(1_002_000, 950_000, 1_000_000, 1_050_000, 0),
            ),
            (
                BenchmarkSplit::CxThreading,
                metrics(997_000, 960_000, 1_008_000, 1_060_000, 8 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::DecisionContracts,
                metrics(994_000, 970_000, 1_052_000, 1_098_000, 16 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                metrics(976_000, 980_000, 1_068_000, 1_116_000, 24 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::FullIntegration,
                metrics(958_000, 990_000, 1_080_000, 1_130_000, 30 * 1024 * 1024),
            ),
        ]);

        BenchmarkSplitSnapshot {
            snapshot_id: "previous-snapshot".to_string(),
            benchmark_run_id: "previous-run".to_string(),
            split_metrics,
            baseline_throughput_runs_ops_per_sec: vec![
                1_000_100, 1_000_300, 999_900, 1_000_200, 1_000_000, 1_000_250, 1_000_150,
                1_000_350, 999_950, 1_000_050,
            ],
        }
    }

    fn candidate_snapshot() -> BenchmarkSplitSnapshot {
        let split_metrics = BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                metrics(1_000_000, 950_000, 1_000_000, 1_050_000, 0),
            ),
            (
                BenchmarkSplit::CxThreading,
                metrics(995_000, 962_000, 1_008_000, 1_060_000, 8 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::DecisionContracts,
                metrics(993_500, 972_000, 1_055_000, 1_100_000, 16 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                metrics(975_000, 980_000, 1_068_000, 1_115_000, 24 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::FullIntegration,
                metrics(955_000, 990_000, 1_080_000, 1_130_000, 30 * 1024 * 1024),
            ),
        ]);

        BenchmarkSplitSnapshot {
            snapshot_id: "candidate-snapshot".to_string(),
            benchmark_run_id: "candidate-run".to_string(),
            split_metrics,
            baseline_throughput_runs_ops_per_sec: vec![
                1_000_100, 1_000_250, 999_950, 1_000_000, 1_000_150, 1_000_300, 999_975, 1_000_050,
                1_000_125, 1_000_225,
            ],
        }
    }

    fn input(
        previous: BenchmarkSplitSnapshot,
        candidate: BenchmarkSplitSnapshot,
    ) -> BenchmarkSplitGateInput {
        BenchmarkSplitGateInput {
            trace_id: "trace-cp-bench".to_string(),
            policy_id: "policy-cp-bench".to_string(),
            previous_snapshot: previous,
            candidate_snapshot: candidate,
        }
    }

    #[test]
    fn gate_passes_for_valid_split_inputs_and_emits_required_logs() {
        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(decision.pass);
        assert!(!decision.rollback_required);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.evaluations.len(), 5);
        assert_eq!(
            decision.logs.last().map(|log| log.event.as_str()),
            Some("benchmark_split_decision")
        );
        assert!(decision.logs.iter().all(|log| {
            !log.trace_id.is_empty()
                && !log.decision_id.is_empty()
                && !log.policy_id.is_empty()
                && !log.component.is_empty()
                && !log.event.is_empty()
                && !log.outcome.is_empty()
        }));
    }

    #[test]
    fn gate_fails_when_baseline_variance_exceeds_threshold() {
        let mut candidate = candidate_snapshot();
        candidate.baseline_throughput_runs_ops_per_sec = vec![
            800_000, 1_200_000, 760_000, 1_240_000, 790_000, 1_210_000, 770_000, 1_250_000,
            810_000, 1_230_000,
        ];

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkSplitFailureCode::BaselineVarianceExceeded
                && finding.split == Some(BenchmarkSplit::Baseline)
        }));
    }

    #[test]
    fn gate_detects_adapter_sleep_regression() {
        let mut candidate = candidate_snapshot();
        let decision_metrics = candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::DecisionContracts)
            .expect("decision split present");
        decision_metrics.latency_ns.p95_ns = 1_300_000;
        decision_metrics.latency_ns.p99_ns = 1_380_000;

        let full_metrics = candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::FullIntegration)
            .expect("full split present");
        full_metrics.throughput_ops_per_sec = 900_000;

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkSplitFailureCode::LatencyRegressionExceeded
                && finding.split == Some(BenchmarkSplit::DecisionContracts)
        }));
    }

    #[test]
    fn split_isolation_without_evidence_matches_decision_throughput() {
        let mut candidate = candidate_snapshot();
        let decision_throughput = candidate
            .split_metrics
            .get(&BenchmarkSplit::DecisionContracts)
            .expect("decision split")
            .throughput_ops_per_sec;
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::EvidenceEmission)
            .expect("evidence split")
            .throughput_ops_per_sec = decision_throughput;
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::FullIntegration)
            .expect("full split")
            .throughput_ops_per_sec = decision_throughput;

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(decision.pass);
        let evidence_eval = decision
            .evaluations
            .iter()
            .find(|evaluation| evaluation.split == BenchmarkSplit::EvidenceEmission)
            .expect("evidence evaluation");
        assert_eq!(
            evidence_eval.candidate_metrics.throughput_ops_per_sec,
            decision_throughput
        );
    }

    #[test]
    fn decision_id_is_stable_across_baseline_run_ordering() {
        let previous = previous_snapshot();

        let candidate_a = candidate_snapshot();
        let mut candidate_b = candidate_snapshot();
        candidate_b.baseline_throughput_runs_ops_per_sec.reverse();

        let decision_a = evaluate_control_plane_benchmark_split(
            &input(previous.clone(), candidate_a),
            &BenchmarkSplitThresholds::default(),
        );
        let decision_b = evaluate_control_plane_benchmark_split(
            &input(previous, candidate_b),
            &BenchmarkSplitThresholds::default(),
        );

        assert_eq!(decision_a.decision_id, decision_b.decision_id);
        assert_eq!(decision_a.pass, decision_b.pass);
        assert_eq!(decision_a.findings, decision_b.findings);
    }

    #[test]
    fn gate_fails_when_split_missing() {
        let previous = previous_snapshot();
        let mut candidate = candidate_snapshot();
        candidate
            .split_metrics
            .remove(&BenchmarkSplit::FullIntegration);

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous, candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkSplitFailureCode::MissingSplitMetrics
                && finding.split == Some(BenchmarkSplit::FullIntegration)
        }));
    }
}
