//! Deterministic benchmark gate for sibling-repo integration overhead.
//!
//! Plan reference: Section 10.14 item 13 (`bd-1coe`).
//!
//! This gate validates that control-plane latency SLOs remain within budget
//! when sibling integrations are enabled (`frankentui`, `frankensqlite`,
//! `sqlmodel_rust`, `fastapi_rust`) and that integration overhead is bounded
//! relative to a no-integration control run.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const SIBLING_BENCHMARK_GATE_DOMAIN: &[u8] = b"FrankenEngine.SiblingIntegrationBenchmarkGate.v1";

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

/// Canonical sibling integrations covered by this gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SiblingIntegration {
    Frankentui,
    Frankensqlite,
    SqlmodelRust,
    FastapiRust,
}

impl SiblingIntegration {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Frankentui => "frankentui",
            Self::Frankensqlite => "frankensqlite",
            Self::SqlmodelRust => "sqlmodel_rust",
            Self::FastapiRust => "fastapi_rust",
        }
    }

    fn all_required() -> BTreeSet<Self> {
        BTreeSet::from([
            Self::Frankentui,
            Self::Frankensqlite,
            Self::SqlmodelRust,
            Self::FastapiRust,
        ])
    }
}

impl fmt::Display for SiblingIntegration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Control-plane operations with explicit p95/p99 SLOs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ControlPlaneOperation {
    EvidenceWrite,
    PolicyQuery,
    TelemetryIngestion,
    TuiDataUpdate,
}

impl ControlPlaneOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceWrite => "evidence_write",
            Self::PolicyQuery => "policy_query",
            Self::TelemetryIngestion => "telemetry_ingestion",
            Self::TuiDataUpdate => "tui_data_update",
        }
    }
}

impl fmt::Display for ControlPlaneOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Latency samples in nanoseconds for an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationLatencySamples {
    /// Control run with sibling integrations disabled.
    pub without_integrations_ns: Vec<u64>,
    /// Integrated run with sibling integrations enabled.
    pub with_integrations_ns: Vec<u64>,
}

impl OperationLatencySamples {
    fn sorted_without(&self) -> Vec<u64> {
        let mut sorted = self.without_integrations_ns.clone();
        sorted.sort_unstable();
        sorted
    }

    fn sorted_with(&self) -> Vec<u64> {
        let mut sorted = self.with_integrations_ns.clone();
        sorted.sort_unstable();
        sorted
    }
}

/// Benchmark snapshot for one run ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSnapshot {
    pub snapshot_id: String,
    pub benchmark_run_id: String,
    pub integrations: BTreeSet<SiblingIntegration>,
    pub operation_samples: BTreeMap<ControlPlaneOperation, OperationLatencySamples>,
}

impl BenchmarkSnapshot {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "benchmark_run_id".to_string(),
            CanonicalValue::String(self.benchmark_run_id.clone()),
        );
        map.insert(
            "integrations".to_string(),
            CanonicalValue::Array(
                self.integrations
                    .iter()
                    .copied()
                    .map(|integration| CanonicalValue::String(integration.as_str().to_string()))
                    .collect(),
            ),
        );

        let mut operations_map = BTreeMap::new();
        for (operation, samples) in &self.operation_samples {
            let mut operation_map = BTreeMap::new();
            operation_map.insert(
                "with_integrations_ns".to_string(),
                CanonicalValue::Array(
                    samples
                        .sorted_with()
                        .into_iter()
                        .map(CanonicalValue::U64)
                        .collect(),
                ),
            );
            operation_map.insert(
                "without_integrations_ns".to_string(),
                CanonicalValue::Array(
                    samples
                        .sorted_without()
                        .into_iter()
                        .map(CanonicalValue::U64)
                        .collect(),
                ),
            );
            operations_map.insert(
                operation.as_str().to_string(),
                CanonicalValue::Map(operation_map),
            );
        }
        map.insert(
            "operation_samples".to_string(),
            CanonicalValue::Map(operations_map),
        );
        map.insert(
            "snapshot_id".to_string(),
            CanonicalValue::String(self.snapshot_id.clone()),
        );
        CanonicalValue::Map(map)
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        hash_bytes(&deterministic_serde::encode_value(&self.canonical_value()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineLedgerEntry {
    pub epoch: u64,
    pub snapshot_hash: [u8; 32],
    pub snapshot: BenchmarkSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BaselineLedger {
    pub entries: Vec<BaselineLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineLedgerError {
    NonMonotonicEpoch {
        previous_epoch: u64,
        next_epoch: u64,
    },
    DuplicateSnapshotHash {
        snapshot_hash: [u8; 32],
    },
}

impl fmt::Display for BaselineLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicEpoch {
                previous_epoch,
                next_epoch,
            } => write!(
                f,
                "baseline epoch must be strictly increasing: previous={previous_epoch} next={next_epoch}"
            ),
            Self::DuplicateSnapshotHash { snapshot_hash } => write!(
                f,
                "baseline snapshot hash already recorded: {}",
                to_hex(snapshot_hash)
            ),
        }
    }
}

impl std::error::Error for BaselineLedgerError {}

impl BaselineLedger {
    pub fn record(
        &mut self,
        epoch: u64,
        snapshot: BenchmarkSnapshot,
    ) -> Result<[u8; 32], BaselineLedgerError> {
        if let Some(last) = self.entries.last()
            && epoch <= last.epoch
        {
            return Err(BaselineLedgerError::NonMonotonicEpoch {
                previous_epoch: last.epoch,
                next_epoch: epoch,
            });
        }

        let snapshot_hash = snapshot.snapshot_hash();
        if self
            .entries
            .iter()
            .any(|entry| entry.snapshot_hash == snapshot_hash)
        {
            return Err(BaselineLedgerError::DuplicateSnapshotHash { snapshot_hash });
        }

        self.entries.push(BaselineLedgerEntry {
            epoch,
            snapshot_hash,
            snapshot,
        });
        Ok(snapshot_hash)
    }

    pub fn latest(&self) -> Option<&BaselineLedgerEntry> {
        self.entries.last()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateInput {
    pub trace_id: String,
    pub policy_id: String,
    pub baseline: BenchmarkSnapshot,
    pub candidate: BenchmarkSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSloThreshold {
    pub p95_ns: u64,
    pub p99_ns: u64,
    /// Max tolerated increase vs baseline, in millionths (1_000_000 = 1.0x).
    pub max_regression_millionths: u64,
    /// Max tolerated overhead for integrated run vs no-integration run.
    pub max_integration_overhead_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateThresholds {
    pub required_integrations: BTreeSet<SiblingIntegration>,
    pub per_operation: BTreeMap<ControlPlaneOperation, OperationSloThreshold>,
}

impl Default for BenchmarkGateThresholds {
    fn default() -> Self {
        let mut per_operation = BTreeMap::new();
        per_operation.insert(
            ControlPlaneOperation::EvidenceWrite,
            OperationSloThreshold {
                p95_ns: 5_000_000,
                p99_ns: 10_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        per_operation.insert(
            ControlPlaneOperation::PolicyQuery,
            OperationSloThreshold {
                p95_ns: 3_000_000,
                p99_ns: 6_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        per_operation.insert(
            ControlPlaneOperation::TelemetryIngestion,
            OperationSloThreshold {
                p95_ns: 4_000_000,
                p99_ns: 8_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        per_operation.insert(
            ControlPlaneOperation::TuiDataUpdate,
            OperationSloThreshold {
                p95_ns: 7_000_000,
                p99_ns: 12_000_000,
                max_regression_millionths: 150_000,
                max_integration_overhead_millionths: 200_000,
            },
        );
        Self {
            required_integrations: SiblingIntegration::all_required(),
            per_operation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkGateFailureCode {
    MissingRequiredIntegration,
    MissingOperationSamples,
    EmptySamples,
    SloThresholdExceeded,
    RegressionThresholdExceeded,
    IntegrationOverheadExceeded,
}

impl fmt::Display for BenchmarkGateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredIntegration => f.write_str("missing_required_integration"),
            Self::MissingOperationSamples => f.write_str("missing_operation_samples"),
            Self::EmptySamples => f.write_str("empty_samples"),
            Self::SloThresholdExceeded => f.write_str("slo_threshold_exceeded"),
            Self::RegressionThresholdExceeded => f.write_str("regression_threshold_exceeded"),
            Self::IntegrationOverheadExceeded => f.write_str("integration_overhead_exceeded"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateFinding {
    pub code: BenchmarkGateFailureCode,
    pub operation: Option<ControlPlaneOperation>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationBenchmarkEvaluation {
    pub operation: ControlPlaneOperation,
    pub baseline_p95_ns: u64,
    pub baseline_p99_ns: u64,
    pub candidate_p95_ns: u64,
    pub candidate_p99_ns: u64,
    pub candidate_without_integrations_p95_ns: u64,
    pub candidate_without_integrations_p99_ns: u64,
    pub regression_p95_millionths: u64,
    pub regression_p99_millionths: u64,
    pub integration_overhead_p95_millionths: u64,
    pub integration_overhead_p99_millionths: u64,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub operation: Option<String>,
    pub candidate_p95_ns: Option<u64>,
    pub candidate_p99_ns: Option<u64>,
    pub baseline_p95_ns: Option<u64>,
    pub baseline_p99_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkGateDecision {
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
    pub baseline_snapshot_hash: [u8; 32],
    pub candidate_snapshot_hash: [u8; 32],
    pub evaluations: Vec<OperationBenchmarkEvaluation>,
    pub findings: Vec<BenchmarkGateFinding>,
    pub logs: Vec<BenchmarkGateLogEvent>,
}

fn percentile(sorted_samples: &[u64], percentile: usize) -> u64 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let rank = percentile
        .saturating_mul(sorted_samples.len())
        .div_ceil(100);
    let index = rank.saturating_sub(1).min(sorted_samples.len() - 1);
    sorted_samples[index]
}

fn ratio_millionths(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    numerator.saturating_mul(1_000_000) / denominator
}

fn overhead_millionths(with_integrations_ns: u64, without_integrations_ns: u64) -> u64 {
    if without_integrations_ns == 0 {
        return u64::MAX;
    }
    if with_integrations_ns <= without_integrations_ns {
        return 0;
    }
    with_integrations_ns
        .saturating_sub(without_integrations_ns)
        .saturating_mul(1_000_000)
        / without_integrations_ns
}

fn decision_canonical_value(
    input: &BenchmarkGateInput,
    baseline_hash: [u8; 32],
    candidate_hash: [u8; 32],
    pass: bool,
    evaluations: &[OperationBenchmarkEvaluation],
    findings: &[BenchmarkGateFinding],
) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "baseline_snapshot_hash".to_string(),
        CanonicalValue::Bytes(baseline_hash.to_vec()),
    );
    map.insert(
        "candidate_snapshot_hash".to_string(),
        CanonicalValue::Bytes(candidate_hash.to_vec()),
    );
    map.insert("pass".to_string(), CanonicalValue::Bool(pass));
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );

    map.insert(
        "evaluations".to_string(),
        CanonicalValue::Array(
            evaluations
                .iter()
                .map(|evaluation| {
                    let mut evaluation_map = BTreeMap::new();
                    evaluation_map.insert(
                        "baseline_p95_ns".to_string(),
                        CanonicalValue::U64(evaluation.baseline_p95_ns),
                    );
                    evaluation_map.insert(
                        "baseline_p99_ns".to_string(),
                        CanonicalValue::U64(evaluation.baseline_p99_ns),
                    );
                    evaluation_map.insert(
                        "candidate_p95_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_p95_ns),
                    );
                    evaluation_map.insert(
                        "candidate_p99_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_p99_ns),
                    );
                    evaluation_map.insert(
                        "candidate_without_integrations_p95_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_without_integrations_p95_ns),
                    );
                    evaluation_map.insert(
                        "candidate_without_integrations_p99_ns".to_string(),
                        CanonicalValue::U64(evaluation.candidate_without_integrations_p99_ns),
                    );
                    evaluation_map.insert(
                        "integration_overhead_p95_millionths".to_string(),
                        CanonicalValue::U64(evaluation.integration_overhead_p95_millionths),
                    );
                    evaluation_map.insert(
                        "integration_overhead_p99_millionths".to_string(),
                        CanonicalValue::U64(evaluation.integration_overhead_p99_millionths),
                    );
                    evaluation_map.insert(
                        "operation".to_string(),
                        CanonicalValue::String(evaluation.operation.as_str().to_string()),
                    );
                    evaluation_map
                        .insert("pass".to_string(), CanonicalValue::Bool(evaluation.pass));
                    evaluation_map.insert(
                        "regression_p95_millionths".to_string(),
                        CanonicalValue::U64(evaluation.regression_p95_millionths),
                    );
                    evaluation_map.insert(
                        "regression_p99_millionths".to_string(),
                        CanonicalValue::U64(evaluation.regression_p99_millionths),
                    );
                    CanonicalValue::Map(evaluation_map)
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
                        "operation".to_string(),
                        match finding.operation {
                            Some(operation) => {
                                CanonicalValue::String(operation.as_str().to_string())
                            }
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

/// Evaluate sibling integration benchmark results against deterministic SLO gates.
pub fn evaluate_sibling_integration_benchmark(
    input: &BenchmarkGateInput,
    thresholds: &BenchmarkGateThresholds,
) -> BenchmarkGateDecision {
    let baseline_hash = input.baseline.snapshot_hash();
    let candidate_hash = input.candidate.snapshot_hash();

    let mut findings = Vec::new();
    let mut evaluations = Vec::new();

    for required in &thresholds.required_integrations {
        if !input.baseline.integrations.contains(required) {
            findings.push(BenchmarkGateFinding {
                code: BenchmarkGateFailureCode::MissingRequiredIntegration,
                operation: None,
                detail: format!("baseline snapshot missing required integration `{required}`"),
            });
        }
        if !input.candidate.integrations.contains(required) {
            findings.push(BenchmarkGateFinding {
                code: BenchmarkGateFailureCode::MissingRequiredIntegration,
                operation: None,
                detail: format!("candidate snapshot missing required integration `{required}`"),
            });
        }
    }

    for (operation, operation_slo) in &thresholds.per_operation {
        let baseline_samples = input.baseline.operation_samples.get(operation);
        let candidate_samples = input.candidate.operation_samples.get(operation);
        match (baseline_samples, candidate_samples) {
            (Some(baseline_samples), Some(candidate_samples)) => {
                if baseline_samples.with_integrations_ns.is_empty()
                    || baseline_samples.without_integrations_ns.is_empty()
                    || candidate_samples.with_integrations_ns.is_empty()
                    || candidate_samples.without_integrations_ns.is_empty()
                {
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::EmptySamples,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` must include non-empty with/without sample vectors for baseline and candidate"
                        ),
                    });
                    continue;
                }

                let baseline_with_sorted = baseline_samples.sorted_with();
                let candidate_with_sorted = candidate_samples.sorted_with();
                let candidate_without_sorted = candidate_samples.sorted_without();

                let baseline_p95 = percentile(&baseline_with_sorted, 95);
                let baseline_p99 = percentile(&baseline_with_sorted, 99);
                let candidate_p95 = percentile(&candidate_with_sorted, 95);
                let candidate_p99 = percentile(&candidate_with_sorted, 99);
                let candidate_without_p95 = percentile(&candidate_without_sorted, 95);
                let candidate_without_p99 = percentile(&candidate_without_sorted, 99);

                let regression_p95 = ratio_millionths(candidate_p95, baseline_p95);
                let regression_p99 = ratio_millionths(candidate_p99, baseline_p99);
                let overhead_p95 =
                    overhead_millionths(candidate_p95, candidate_without_p95);
                let overhead_p99 =
                    overhead_millionths(candidate_p99, candidate_without_p99);

                let mut operation_pass = true;

                if candidate_p95 > operation_slo.p95_ns || candidate_p99 > operation_slo.p99_ns {
                    operation_pass = false;
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::SloThresholdExceeded,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` candidate p95/p99 exceeded SLO (p95 {} ns <= {} ns, p99 {} ns <= {} ns required)",
                            candidate_p95, operation_slo.p95_ns, candidate_p99, operation_slo.p99_ns
                        ),
                    });
                }

                let max_regression_ratio =
                    1_000_000u64.saturating_add(operation_slo.max_regression_millionths);
                if regression_p95 > max_regression_ratio || regression_p99 > max_regression_ratio {
                    operation_pass = false;
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::RegressionThresholdExceeded,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` regressed beyond threshold (p95 ratio {} ppm, p99 ratio {} ppm, max {} ppm)",
                            regression_p95, regression_p99, max_regression_ratio
                        ),
                    });
                }

                if overhead_p95 > operation_slo.max_integration_overhead_millionths
                    || overhead_p99 > operation_slo.max_integration_overhead_millionths
                {
                    operation_pass = false;
                    findings.push(BenchmarkGateFinding {
                        code: BenchmarkGateFailureCode::IntegrationOverheadExceeded,
                        operation: Some(*operation),
                        detail: format!(
                            "operation `{operation}` integration overhead exceeded threshold (p95 {} ppm, p99 {} ppm, max {} ppm)",
                            overhead_p95,
                            overhead_p99,
                            operation_slo.max_integration_overhead_millionths
                        ),
                    });
                }

                evaluations.push(OperationBenchmarkEvaluation {
                    operation: *operation,
                    baseline_p95_ns: baseline_p95,
                    baseline_p99_ns: baseline_p99,
                    candidate_p95_ns: candidate_p95,
                    candidate_p99_ns: candidate_p99,
                    candidate_without_integrations_p95_ns: candidate_without_p95,
                    candidate_without_integrations_p99_ns: candidate_without_p99,
                    regression_p95_millionths: regression_p95,
                    regression_p99_millionths: regression_p99,
                    integration_overhead_p95_millionths: overhead_p95,
                    integration_overhead_p99_millionths: overhead_p99,
                    pass: operation_pass,
                });
            }
            _ => findings.push(BenchmarkGateFinding {
                code: BenchmarkGateFailureCode::MissingOperationSamples,
                operation: Some(*operation),
                detail: format!(
                    "operation `{operation}` missing from baseline and/or candidate benchmark snapshot"
                ),
            }),
        }
    }

    let pass = findings.is_empty() && evaluations.iter().all(|evaluation| evaluation.pass);
    let decision_hash = hash_bytes(&deterministic_serde::encode_value(&CanonicalValue::Array(
        vec![
            CanonicalValue::Bytes(SIBLING_BENCHMARK_GATE_DOMAIN.to_vec()),
            decision_canonical_value(
                input,
                baseline_hash,
                candidate_hash,
                pass,
                &evaluations,
                &findings,
            ),
        ],
    )));
    let decision_id = format!("sib-bench-gate-{}", to_hex(&decision_hash[..16]));

    let mut logs = Vec::new();
    for evaluation in &evaluations {
        let maybe_failure = findings.iter().find_map(|finding| {
            if finding.operation == Some(evaluation.operation) {
                Some(finding.code.to_string())
            } else {
                None
            }
        });
        logs.push(BenchmarkGateLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "sibling_integration_benchmark_gate".to_string(),
            event: "operation_slo_check".to_string(),
            outcome: if evaluation.pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_code: maybe_failure,
            operation: Some(evaluation.operation.as_str().to_string()),
            candidate_p95_ns: Some(evaluation.candidate_p95_ns),
            candidate_p99_ns: Some(evaluation.candidate_p99_ns),
            baseline_p95_ns: Some(evaluation.baseline_p95_ns),
            baseline_p99_ns: Some(evaluation.baseline_p99_ns),
        });
    }
    logs.push(BenchmarkGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "sibling_integration_benchmark_gate".to_string(),
        event: "benchmark_gate_decision".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if pass {
            None
        } else {
            Some("benchmark_gate_failed".to_string())
        },
        operation: None,
        candidate_p95_ns: None,
        candidate_p99_ns: None,
        baseline_p95_ns: None,
        baseline_p99_ns: None,
    });

    BenchmarkGateDecision {
        decision_id,
        pass,
        rollback_required: !pass,
        baseline_snapshot_hash: baseline_hash,
        candidate_snapshot_hash: candidate_hash,
        evaluations,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_integrations() -> BTreeSet<SiblingIntegration> {
        SiblingIntegration::all_required()
    }

    fn make_samples(without: &[u64], with: &[u64]) -> OperationLatencySamples {
        OperationLatencySamples {
            without_integrations_ns: without.to_vec(),
            with_integrations_ns: with.to_vec(),
        }
    }

    fn base_snapshot() -> BenchmarkSnapshot {
        let mut operation_samples = BTreeMap::new();
        operation_samples.insert(
            ControlPlaneOperation::EvidenceWrite,
            make_samples(
                &[1_000_000, 1_020_000, 1_010_000, 1_050_000, 1_040_000],
                &[1_200_000, 1_220_000, 1_210_000, 1_260_000, 1_240_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[800_000, 820_000, 810_000, 830_000, 840_000],
                &[950_000, 960_000, 955_000, 980_000, 990_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TelemetryIngestion,
            make_samples(
                &[900_000, 910_000, 920_000, 930_000, 940_000],
                &[1_080_000, 1_090_000, 1_100_000, 1_120_000, 1_130_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TuiDataUpdate,
            make_samples(
                &[1_200_000, 1_220_000, 1_230_000, 1_240_000, 1_250_000],
                &[1_420_000, 1_430_000, 1_440_000, 1_460_000, 1_470_000],
            ),
        );
        BenchmarkSnapshot {
            snapshot_id: "baseline-snapshot-1".to_string(),
            benchmark_run_id: "baseline-run-1".to_string(),
            integrations: full_integrations(),
            operation_samples,
        }
    }

    fn candidate_snapshot_pass() -> BenchmarkSnapshot {
        let mut operation_samples = BTreeMap::new();
        operation_samples.insert(
            ControlPlaneOperation::EvidenceWrite,
            make_samples(
                &[1_010_000, 1_020_000, 1_030_000, 1_040_000, 1_050_000],
                &[1_220_000, 1_230_000, 1_240_000, 1_250_000, 1_260_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[810_000, 820_000, 825_000, 830_000, 835_000],
                &[970_000, 975_000, 980_000, 985_000, 990_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TelemetryIngestion,
            make_samples(
                &[910_000, 920_000, 930_000, 935_000, 940_000],
                &[1_090_000, 1_100_000, 1_110_000, 1_115_000, 1_120_000],
            ),
        );
        operation_samples.insert(
            ControlPlaneOperation::TuiDataUpdate,
            make_samples(
                &[1_210_000, 1_220_000, 1_230_000, 1_235_000, 1_240_000],
                &[1_430_000, 1_435_000, 1_440_000, 1_445_000, 1_450_000],
            ),
        );
        BenchmarkSnapshot {
            snapshot_id: "candidate-snapshot-pass".to_string(),
            benchmark_run_id: "candidate-run-pass".to_string(),
            integrations: full_integrations(),
            operation_samples,
        }
    }

    #[test]
    fn gate_passes_for_valid_candidate_and_emits_logs() {
        let input = BenchmarkGateInput {
            trace_id: "trace-bench-pass".to_string(),
            policy_id: "policy-bench-pass".to_string(),
            baseline: base_snapshot(),
            candidate: candidate_snapshot_pass(),
        };

        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(decision.pass);
        assert!(!decision.rollback_required);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.evaluations.len(), 4);
        assert_eq!(decision.logs.len(), 5);
        assert_eq!(
            decision.logs.last().map(|log| log.event.as_str()),
            Some("benchmark_gate_decision")
        );
    }

    #[test]
    fn gate_fails_when_candidate_missing_required_integration() {
        let mut candidate = candidate_snapshot_pass();
        candidate
            .integrations
            .remove(&SiblingIntegration::FastapiRust);

        let input = BenchmarkGateInput {
            trace_id: "trace-missing-integration".to_string(),
            policy_id: "policy-missing-integration".to_string(),
            baseline: base_snapshot(),
            candidate,
        };
        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(
            decision
                .findings
                .iter()
                .any(|finding| finding.code == BenchmarkGateFailureCode::MissingRequiredIntegration)
        );
    }

    #[test]
    fn gate_fails_when_regression_exceeds_threshold() {
        let mut candidate = candidate_snapshot_pass();
        candidate.operation_samples.insert(
            ControlPlaneOperation::PolicyQuery,
            make_samples(
                &[810_000, 820_000, 830_000, 840_000, 850_000],
                &[1_250_000, 1_260_000, 1_270_000, 1_280_000, 1_300_000],
            ),
        );

        let input = BenchmarkGateInput {
            trace_id: "trace-regression".to_string(),
            policy_id: "policy-regression".to_string(),
            baseline: base_snapshot(),
            candidate,
        };
        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!decision.pass);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkGateFailureCode::RegressionThresholdExceeded
                && finding.operation == Some(ControlPlaneOperation::PolicyQuery)
        }));
    }

    #[test]
    fn gate_fails_when_integration_overhead_exceeds_threshold() {
        let mut candidate = candidate_snapshot_pass();
        candidate.operation_samples.insert(
            ControlPlaneOperation::TelemetryIngestion,
            make_samples(
                &[900_000, 910_000, 920_000, 930_000, 940_000],
                &[1_600_000, 1_650_000, 1_700_000, 1_750_000, 1_800_000],
            ),
        );
        let input = BenchmarkGateInput {
            trace_id: "trace-overhead".to_string(),
            policy_id: "policy-overhead".to_string(),
            baseline: base_snapshot(),
            candidate,
        };
        let decision =
            evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
        assert!(!decision.pass);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkGateFailureCode::IntegrationOverheadExceeded
                && finding.operation == Some(ControlPlaneOperation::TelemetryIngestion)
        }));
    }

    #[test]
    fn decision_id_is_deterministic_across_sample_ordering() {
        let baseline = base_snapshot();
        let candidate = candidate_snapshot_pass();
        let input_a = BenchmarkGateInput {
            trace_id: "trace-deterministic".to_string(),
            policy_id: "policy-deterministic".to_string(),
            baseline: baseline.clone(),
            candidate: candidate.clone(),
        };

        let mut shuffled_candidate = candidate.clone();
        let telemetry = shuffled_candidate
            .operation_samples
            .get_mut(&ControlPlaneOperation::TelemetryIngestion)
            .expect("telemetry sample must exist");
        telemetry.with_integrations_ns.reverse();
        telemetry.without_integrations_ns.reverse();
        let input_b = BenchmarkGateInput {
            trace_id: "trace-deterministic".to_string(),
            policy_id: "policy-deterministic".to_string(),
            baseline,
            candidate: shuffled_candidate,
        };

        let decision_a =
            evaluate_sibling_integration_benchmark(&input_a, &BenchmarkGateThresholds::default());
        let decision_b =
            evaluate_sibling_integration_benchmark(&input_b, &BenchmarkGateThresholds::default());

        assert_eq!(decision_a.decision_id, decision_b.decision_id);
        assert_eq!(decision_a.pass, decision_b.pass);
        assert_eq!(decision_a.findings, decision_b.findings);
    }

    #[test]
    fn baseline_ledger_tracks_monotonic_epochs_and_rejects_duplicate_snapshots() {
        let mut ledger = BaselineLedger::default();
        let baseline = base_snapshot();
        let hash = ledger
            .record(1, baseline.clone())
            .expect("first baseline should record");
        assert_eq!(ledger.latest().expect("latest").snapshot_hash, hash);

        let non_monotonic = ledger.record(1, candidate_snapshot_pass());
        assert!(matches!(
            non_monotonic,
            Err(BaselineLedgerError::NonMonotonicEpoch { .. })
        ));

        let duplicate_hash = ledger.record(2, baseline);
        assert!(matches!(
            duplicate_hash,
            Err(BaselineLedgerError::DuplicateSnapshotHash { .. })
        ));
    }
}
