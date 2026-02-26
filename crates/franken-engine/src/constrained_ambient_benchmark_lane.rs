//! Constrained-vs-ambient benchmark lane evaluation for Section 10.6 (`bd-3qv`).
//!
//! This module quantifies proof-guided specialization uplift under equivalent
//! behavior requirements:
//! - constrained lane (PLAS/IFC proof-guided specialization active)
//! - ambient lane (generic dynamic checks, no proof-guided specialization)
//! - deterministic output digest equivalence gate
//! - throughput/latency/memory/allocation deltas
//! - per-proof specialization attribution deltas

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CONSTRAINED_AMBIENT_COMPONENT: &str = "constrained_ambient_benchmark_lane";
pub const CONSTRAINED_AMBIENT_SCHEMA_VERSION: &str = "franken-engine.constrained-ambient-lane.v1";

const ERROR_INVALID_REQUEST: &str = "FE-CABL-1001";
const ERROR_INVALID_METRIC: &str = "FE-CABL-1002";
const ERROR_WORKLOAD_SET_MISMATCH: &str = "FE-CABL-1003";
const ERROR_DIGEST_MISMATCH: &str = "FE-CABL-1004";
const ERROR_PERFORMANCE_REGRESSION: &str = "FE-CABL-1005";
const ERROR_ATTRIBUTION_GAP: &str = "FE-CABL-1006";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneWorkloadMetrics {
    pub workload_id: String,
    pub output_digest: String,
    pub throughput_ops_per_sec: u64,
    pub latency_p50_ns: u64,
    pub latency_p95_ns: u64,
    pub latency_p99_ns: u64,
    pub memory_peak_bytes: u64,
    pub allocation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAttributionSample {
    pub proof_id: String,
    pub specialization_id: String,
    pub constrained_throughput_ops_per_sec: u64,
    pub without_proof_throughput_ops_per_sec: u64,
    pub constrained_latency_p95_ns: u64,
    pub without_proof_latency_p95_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstrainedAmbientBenchmarkRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub benchmark_run_id: String,
    pub constrained_lane: Vec<LaneWorkloadMetrics>,
    pub ambient_lane: Vec<LaneWorkloadMetrics>,
    pub proof_attribution: Vec<ProofAttributionSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDeltaReport {
    pub workload_id: String,
    pub canonical_output_digest: String,
    pub throughput_delta_millionths: i64,
    pub latency_p50_improvement_millionths: i64,
    pub latency_p95_improvement_millionths: i64,
    pub latency_p99_improvement_millionths: i64,
    pub memory_improvement_millionths: i64,
    pub allocation_improvement_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAttributionReport {
    pub proof_id: String,
    pub specialization_id: String,
    pub throughput_gain_millionths: i64,
    pub latency_p95_improvement_millionths: i64,
    pub supports_uplift: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstrainedAmbientSummary {
    pub workload_count: u64,
    pub attribution_count: u64,
    pub mean_throughput_delta_millionths: i64,
    pub mean_latency_p95_improvement_millionths: i64,
    pub mean_memory_improvement_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstrainedAmbientEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub workload_id: Option<String>,
    pub proof_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstrainedAmbientBenchmarkDecision {
    pub schema_version: String,
    pub report_id: String,
    pub benchmark_run_id: String,
    pub outcome: String,
    pub blocked: bool,
    pub blockers: Vec<String>,
    pub error_code: Option<String>,
    pub workload_reports: Vec<WorkloadDeltaReport>,
    pub attribution_reports: Vec<ProofAttributionReport>,
    pub summary: ConstrainedAmbientSummary,
    pub events: Vec<ConstrainedAmbientEvent>,
}

impl ConstrainedAmbientBenchmarkDecision {
    pub fn allows_publication(&self) -> bool {
        self.outcome == "allow"
    }
}

#[derive(Debug, Error)]
pub enum ConstrainedAmbientError {
    #[error("invalid request field `{field}`: {detail}")]
    InvalidRequest { field: String, detail: String },
    #[error("invalid metric `{field}` for `{subject}`: {detail}")]
    InvalidMetric {
        field: String,
        subject: String,
        detail: String,
    },
}

impl ConstrainedAmbientError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => ERROR_INVALID_REQUEST,
            Self::InvalidMetric { .. } => ERROR_INVALID_METRIC,
        }
    }
}

#[derive(Debug)]
struct EvaluationResult {
    blockers: Vec<String>,
    error_code: Option<String>,
    workload_reports: Vec<WorkloadDeltaReport>,
    attribution_reports: Vec<ProofAttributionReport>,
}

/// Run constrained-vs-ambient lane evaluation with deterministic gating.
pub fn run_constrained_ambient_benchmark_lane(
    request: &ConstrainedAmbientBenchmarkRequest,
) -> ConstrainedAmbientBenchmarkDecision {
    let report_id = build_report_id(request);
    let mut events = vec![make_event(
        request,
        "constrained_ambient_evaluation_started",
        "pass",
        None,
        None,
        None,
    )];

    match evaluate_impl(request, &mut events) {
        Ok(evaluation) => {
            let blocked = !evaluation.blockers.is_empty();
            let outcome = if blocked { "deny" } else { "allow" };
            events.push(make_event(
                request,
                "constrained_ambient_evaluation_completed",
                outcome,
                evaluation.error_code.clone(),
                None,
                None,
            ));
            ConstrainedAmbientBenchmarkDecision {
                schema_version: CONSTRAINED_AMBIENT_SCHEMA_VERSION.to_string(),
                report_id,
                benchmark_run_id: request.benchmark_run_id.clone(),
                outcome: outcome.to_string(),
                blocked,
                blockers: evaluation.blockers,
                error_code: evaluation.error_code,
                summary: build_summary(
                    &evaluation.workload_reports,
                    &evaluation.attribution_reports,
                ),
                workload_reports: evaluation.workload_reports,
                attribution_reports: evaluation.attribution_reports,
                events,
            }
        }
        Err(error) => {
            let error_code = error.stable_code().to_string();
            events.push(make_event(
                request,
                "constrained_ambient_evaluation_completed",
                "fail",
                Some(error_code.clone()),
                None,
                None,
            ));
            ConstrainedAmbientBenchmarkDecision {
                schema_version: CONSTRAINED_AMBIENT_SCHEMA_VERSION.to_string(),
                report_id,
                benchmark_run_id: request.benchmark_run_id.clone(),
                outcome: "fail".to_string(),
                blocked: true,
                blockers: vec![error.to_string()],
                error_code: Some(error_code),
                summary: ConstrainedAmbientSummary {
                    workload_count: 0,
                    attribution_count: 0,
                    mean_throughput_delta_millionths: 0,
                    mean_latency_p95_improvement_millionths: 0,
                    mean_memory_improvement_millionths: 0,
                },
                workload_reports: Vec::new(),
                attribution_reports: Vec::new(),
                events,
            }
        }
    }
}

fn evaluate_impl(
    request: &ConstrainedAmbientBenchmarkRequest,
    events: &mut Vec<ConstrainedAmbientEvent>,
) -> Result<EvaluationResult, ConstrainedAmbientError> {
    validate_request(request)?;

    let constrained_map = index_workloads(&request.constrained_lane, "constrained_lane")?;
    let ambient_map = index_workloads(&request.ambient_lane, "ambient_lane")?;

    let constrained_ids = constrained_map.keys().cloned().collect::<BTreeSet<_>>();
    let ambient_ids = ambient_map.keys().cloned().collect::<BTreeSet<_>>();

    let mut blockers = Vec::new();
    let mut error_code = None;
    if constrained_ids != ambient_ids {
        blockers.push("constrained_lane and ambient_lane workload sets differ".to_string());
        error_code = Some(ERROR_WORKLOAD_SET_MISMATCH.to_string());
    }

    let mut workload_reports = Vec::new();
    for workload_id in constrained_ids.intersection(&ambient_ids) {
        let constrained = constrained_map
            .get(workload_id)
            .expect("intersection ids must exist");
        let ambient = ambient_map
            .get(workload_id)
            .expect("intersection ids must exist");

        if constrained.output_digest != ambient.output_digest {
            blockers.push(format!(
                "workload `{}` output digest mismatch: constrained={} ambient={}",
                workload_id, constrained.output_digest, ambient.output_digest
            ));
            set_error_code(&mut error_code, ERROR_DIGEST_MISMATCH);
        }

        let throughput_delta = delta_millionths(
            constrained.throughput_ops_per_sec,
            ambient.throughput_ops_per_sec,
        )?;
        let latency_p50_improvement =
            improvement_millionths(ambient.latency_p50_ns, constrained.latency_p50_ns)?;
        let latency_p95_improvement =
            improvement_millionths(ambient.latency_p95_ns, constrained.latency_p95_ns)?;
        let latency_p99_improvement =
            improvement_millionths(ambient.latency_p99_ns, constrained.latency_p99_ns)?;
        let memory_improvement =
            improvement_millionths(ambient.memory_peak_bytes, constrained.memory_peak_bytes)?;
        let allocation_improvement =
            improvement_millionths(ambient.allocation_count, constrained.allocation_count)?;

        if throughput_delta < 0
            || latency_p50_improvement < 0
            || latency_p95_improvement < 0
            || latency_p99_improvement < 0
        {
            blockers.push(format!(
                "workload `{}` regressed relative to ambient lane",
                workload_id
            ));
            set_error_code(&mut error_code, ERROR_PERFORMANCE_REGRESSION);
        }

        workload_reports.push(WorkloadDeltaReport {
            workload_id: workload_id.clone(),
            canonical_output_digest: constrained.output_digest.clone(),
            throughput_delta_millionths: throughput_delta,
            latency_p50_improvement_millionths: latency_p50_improvement,
            latency_p95_improvement_millionths: latency_p95_improvement,
            latency_p99_improvement_millionths: latency_p99_improvement,
            memory_improvement_millionths: memory_improvement,
            allocation_improvement_millionths: allocation_improvement,
        });
        events.push(make_event(
            request,
            "workload_compared",
            if throughput_delta >= 0
                && latency_p50_improvement >= 0
                && latency_p95_improvement >= 0
                && latency_p99_improvement >= 0
            {
                "pass"
            } else {
                "fail"
            },
            if throughput_delta >= 0
                && latency_p50_improvement >= 0
                && latency_p95_improvement >= 0
                && latency_p99_improvement >= 0
            {
                None
            } else {
                Some(ERROR_PERFORMANCE_REGRESSION.to_string())
            },
            Some(workload_id.clone()),
            None,
        ));
    }
    workload_reports.sort_by(|left, right| left.workload_id.cmp(&right.workload_id));

    let attribution_reports =
        evaluate_attribution(request, &mut blockers, &mut error_code, events)?;

    Ok(EvaluationResult {
        blockers,
        error_code,
        workload_reports,
        attribution_reports,
    })
}

fn evaluate_attribution(
    request: &ConstrainedAmbientBenchmarkRequest,
    blockers: &mut Vec<String>,
    error_code: &mut Option<String>,
    events: &mut Vec<ConstrainedAmbientEvent>,
) -> Result<Vec<ProofAttributionReport>, ConstrainedAmbientError> {
    let mut seen_keys = BTreeSet::new();
    let mut reports = Vec::new();
    for sample in &request.proof_attribution {
        let proof_id = sample.proof_id.trim();
        let specialization_id = sample.specialization_id.trim();
        if proof_id.is_empty() {
            return Err(ConstrainedAmbientError::InvalidRequest {
                field: "proof_attribution.proof_id".to_string(),
                detail: "proof_id must not be empty".to_string(),
            });
        }
        if specialization_id.is_empty() {
            return Err(ConstrainedAmbientError::InvalidRequest {
                field: "proof_attribution.specialization_id".to_string(),
                detail: "specialization_id must not be empty".to_string(),
            });
        }
        let dedupe_key = format!("{proof_id}::{specialization_id}");
        if !seen_keys.insert(dedupe_key) {
            return Err(ConstrainedAmbientError::InvalidRequest {
                field: "proof_attribution".to_string(),
                detail: format!(
                    "duplicate proof/specialization pair `{proof_id}`/`{specialization_id}`"
                ),
            });
        }

        validate_non_zero_metric(
            sample.constrained_throughput_ops_per_sec,
            "constrained_throughput_ops_per_sec",
            proof_id,
        )?;
        validate_non_zero_metric(
            sample.without_proof_throughput_ops_per_sec,
            "without_proof_throughput_ops_per_sec",
            proof_id,
        )?;
        validate_non_zero_metric(
            sample.constrained_latency_p95_ns,
            "constrained_latency_p95_ns",
            proof_id,
        )?;
        validate_non_zero_metric(
            sample.without_proof_latency_p95_ns,
            "without_proof_latency_p95_ns",
            proof_id,
        )?;

        let throughput_gain = delta_millionths(
            sample.constrained_throughput_ops_per_sec,
            sample.without_proof_throughput_ops_per_sec,
        )?;
        let latency_p95_improvement = improvement_millionths(
            sample.without_proof_latency_p95_ns,
            sample.constrained_latency_p95_ns,
        )?;
        let supports_uplift = throughput_gain > 0 || latency_p95_improvement > 0;
        if !supports_uplift {
            blockers.push(format!(
                "proof `{}` did not demonstrate measurable uplift for specialization `{}`",
                proof_id, specialization_id
            ));
            set_error_code(error_code, ERROR_ATTRIBUTION_GAP);
        }

        reports.push(ProofAttributionReport {
            proof_id: proof_id.to_string(),
            specialization_id: specialization_id.to_string(),
            throughput_gain_millionths: throughput_gain,
            latency_p95_improvement_millionths: latency_p95_improvement,
            supports_uplift,
        });
        events.push(make_event(
            request,
            "proof_attribution_evaluated",
            if supports_uplift { "pass" } else { "fail" },
            if supports_uplift {
                None
            } else {
                Some(ERROR_ATTRIBUTION_GAP.to_string())
            },
            None,
            Some(proof_id.to_string()),
        ));
    }

    if reports.is_empty() {
        return Err(ConstrainedAmbientError::InvalidRequest {
            field: "proof_attribution".to_string(),
            detail: "at least one proof attribution sample is required".to_string(),
        });
    }

    reports.sort_by(|left, right| {
        left.proof_id
            .cmp(&right.proof_id)
            .then(left.specialization_id.cmp(&right.specialization_id))
    });
    Ok(reports)
}

fn validate_request(
    request: &ConstrainedAmbientBenchmarkRequest,
) -> Result<(), ConstrainedAmbientError> {
    validate_non_empty_field(&request.trace_id, "trace_id")?;
    validate_non_empty_field(&request.decision_id, "decision_id")?;
    validate_non_empty_field(&request.policy_id, "policy_id")?;
    validate_non_empty_field(&request.benchmark_run_id, "benchmark_run_id")?;
    if request.constrained_lane.is_empty() {
        return Err(ConstrainedAmbientError::InvalidRequest {
            field: "constrained_lane".to_string(),
            detail: "at least one constrained lane workload is required".to_string(),
        });
    }
    if request.ambient_lane.is_empty() {
        return Err(ConstrainedAmbientError::InvalidRequest {
            field: "ambient_lane".to_string(),
            detail: "at least one ambient lane workload is required".to_string(),
        });
    }
    Ok(())
}

fn validate_non_empty_field(value: &str, field: &str) -> Result<(), ConstrainedAmbientError> {
    if value.trim().is_empty() {
        return Err(ConstrainedAmbientError::InvalidRequest {
            field: field.to_string(),
            detail: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn index_workloads<'a>(
    workloads: &'a [LaneWorkloadMetrics],
    field: &str,
) -> Result<BTreeMap<String, &'a LaneWorkloadMetrics>, ConstrainedAmbientError> {
    let mut map = BTreeMap::new();
    for workload in workloads {
        let workload_id = workload.workload_id.trim();
        if workload_id.is_empty() {
            return Err(ConstrainedAmbientError::InvalidRequest {
                field: format!("{field}.workload_id"),
                detail: "workload_id must not be empty".to_string(),
            });
        }
        validate_non_zero_metric(
            workload.throughput_ops_per_sec,
            "throughput_ops_per_sec",
            workload_id,
        )?;
        validate_non_zero_metric(workload.latency_p50_ns, "latency_p50_ns", workload_id)?;
        validate_non_zero_metric(workload.latency_p95_ns, "latency_p95_ns", workload_id)?;
        validate_non_zero_metric(workload.latency_p99_ns, "latency_p99_ns", workload_id)?;
        validate_non_zero_metric(workload.memory_peak_bytes, "memory_peak_bytes", workload_id)?;
        validate_non_zero_metric(workload.allocation_count, "allocation_count", workload_id)?;
        if workload.output_digest.trim().is_empty() {
            return Err(ConstrainedAmbientError::InvalidRequest {
                field: format!("{field}.output_digest"),
                detail: format!("workload `{workload_id}` has empty output_digest"),
            });
        }
        if map.insert(workload_id.to_string(), workload).is_some() {
            return Err(ConstrainedAmbientError::InvalidRequest {
                field: field.to_string(),
                detail: format!("duplicate workload_id `{workload_id}`"),
            });
        }
    }
    Ok(map)
}

fn validate_non_zero_metric(
    value: u64,
    metric: &str,
    subject: &str,
) -> Result<(), ConstrainedAmbientError> {
    if value == 0 {
        return Err(ConstrainedAmbientError::InvalidMetric {
            field: metric.to_string(),
            subject: subject.to_string(),
            detail: "must be > 0".to_string(),
        });
    }
    Ok(())
}

fn delta_millionths(candidate: u64, baseline: u64) -> Result<i64, ConstrainedAmbientError> {
    if baseline == 0 {
        return Err(ConstrainedAmbientError::InvalidMetric {
            field: "baseline".to_string(),
            subject: "delta_millionths".to_string(),
            detail: "baseline must be > 0".to_string(),
        });
    }
    let candidate = i128::from(candidate);
    let baseline = i128::from(baseline);
    let scaled = (candidate - baseline).saturating_mul(1_000_000_i128) / baseline;
    i64::try_from(scaled).map_err(|_| ConstrainedAmbientError::InvalidMetric {
        field: "delta_millionths".to_string(),
        subject: "conversion".to_string(),
        detail: "delta overflowed i64 range".to_string(),
    })
}

fn improvement_millionths(baseline: u64, optimized: u64) -> Result<i64, ConstrainedAmbientError> {
    delta_millionths(baseline, optimized)
}

fn build_summary(
    workload_reports: &[WorkloadDeltaReport],
    attribution_reports: &[ProofAttributionReport],
) -> ConstrainedAmbientSummary {
    ConstrainedAmbientSummary {
        workload_count: workload_reports.len() as u64,
        attribution_count: attribution_reports.len() as u64,
        mean_throughput_delta_millionths: mean_i64(
            workload_reports
                .iter()
                .map(|report| report.throughput_delta_millionths),
        ),
        mean_latency_p95_improvement_millionths: mean_i64(
            workload_reports
                .iter()
                .map(|report| report.latency_p95_improvement_millionths),
        ),
        mean_memory_improvement_millionths: mean_i64(
            workload_reports
                .iter()
                .map(|report| report.memory_improvement_millionths),
        ),
    }
}

fn mean_i64(values: impl Iterator<Item = i64>) -> i64 {
    let mut count = 0_i128;
    let mut total = 0_i128;
    for value in values {
        total += i128::from(value);
        count += 1;
    }
    if count == 0 {
        0
    } else {
        (total / count) as i64
    }
}

fn set_error_code(current: &mut Option<String>, code: &str) {
    if current.is_none() {
        *current = Some(code.to_string());
    }
}

fn build_report_id(request: &ConstrainedAmbientBenchmarkRequest) -> String {
    let mut hasher = Sha256::new();
    hash_update(&mut hasher, &request.benchmark_run_id);
    hash_update(&mut hasher, &request.trace_id);
    hash_update(&mut hasher, &request.decision_id);
    hash_update(&mut hasher, &request.policy_id);

    let mut constrained = request.constrained_lane.clone();
    constrained.sort_by(|left, right| left.workload_id.cmp(&right.workload_id));
    for workload in &constrained {
        hash_update(&mut hasher, &workload.workload_id);
        hash_update(&mut hasher, &workload.output_digest);
        hash_update(&mut hasher, &workload.throughput_ops_per_sec.to_string());
        hash_update(&mut hasher, &workload.latency_p50_ns.to_string());
        hash_update(&mut hasher, &workload.latency_p95_ns.to_string());
        hash_update(&mut hasher, &workload.latency_p99_ns.to_string());
        hash_update(&mut hasher, &workload.memory_peak_bytes.to_string());
        hash_update(&mut hasher, &workload.allocation_count.to_string());
    }

    let mut ambient = request.ambient_lane.clone();
    ambient.sort_by(|left, right| left.workload_id.cmp(&right.workload_id));
    for workload in &ambient {
        hash_update(&mut hasher, &workload.workload_id);
        hash_update(&mut hasher, &workload.output_digest);
        hash_update(&mut hasher, &workload.throughput_ops_per_sec.to_string());
        hash_update(&mut hasher, &workload.latency_p50_ns.to_string());
        hash_update(&mut hasher, &workload.latency_p95_ns.to_string());
        hash_update(&mut hasher, &workload.latency_p99_ns.to_string());
        hash_update(&mut hasher, &workload.memory_peak_bytes.to_string());
        hash_update(&mut hasher, &workload.allocation_count.to_string());
    }

    let mut attribution = request.proof_attribution.clone();
    attribution.sort_by(|left, right| {
        left.proof_id
            .cmp(&right.proof_id)
            .then(left.specialization_id.cmp(&right.specialization_id))
    });
    for sample in &attribution {
        hash_update(&mut hasher, &sample.proof_id);
        hash_update(&mut hasher, &sample.specialization_id);
        hash_update(
            &mut hasher,
            &sample.constrained_throughput_ops_per_sec.to_string(),
        );
        hash_update(
            &mut hasher,
            &sample.without_proof_throughput_ops_per_sec.to_string(),
        );
        hash_update(&mut hasher, &sample.constrained_latency_p95_ns.to_string());
        hash_update(
            &mut hasher,
            &sample.without_proof_latency_p95_ns.to_string(),
        );
    }

    let digest = hex::encode(hasher.finalize());
    format!("cabl_{}", &digest[..20])
}

fn hash_update(hasher: &mut Sha256, value: &str) {
    hasher.update(value.as_bytes());
    hasher.update([0x1f]);
}

fn make_event(
    request: &ConstrainedAmbientBenchmarkRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    workload_id: Option<String>,
    proof_id: Option<String>,
) -> ConstrainedAmbientEvent {
    ConstrainedAmbientEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: CONSTRAINED_AMBIENT_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        workload_id,
        proof_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_workload(id: &str, throughput: u64, latency_p50: u64) -> LaneWorkloadMetrics {
        LaneWorkloadMetrics {
            workload_id: id.into(),
            output_digest: format!("digest-{id}"),
            throughput_ops_per_sec: throughput,
            latency_p50_ns: latency_p50,
            latency_p95_ns: latency_p50 * 2,
            latency_p99_ns: latency_p50 * 4,
            memory_peak_bytes: 1_000_000,
            allocation_count: 500,
        }
    }

    fn test_attribution(proof_id: &str, spec_id: &str) -> ProofAttributionSample {
        ProofAttributionSample {
            proof_id: proof_id.into(),
            specialization_id: spec_id.into(),
            constrained_throughput_ops_per_sec: 2000,
            without_proof_throughput_ops_per_sec: 1000,
            constrained_latency_p95_ns: 500,
            without_proof_latency_p95_ns: 1000,
        }
    }

    fn valid_request() -> ConstrainedAmbientBenchmarkRequest {
        ConstrainedAmbientBenchmarkRequest {
            trace_id: "trace-1".into(),
            decision_id: "dec-1".into(),
            policy_id: "pol-1".into(),
            benchmark_run_id: "run-1".into(),
            constrained_lane: vec![test_workload("w1", 2000, 500)],
            ambient_lane: vec![test_workload("w1", 1000, 1000)],
            proof_attribution: vec![test_attribution("proof-1", "spec-1")],
        }
    }

    // ── ConstrainedAmbientError ───────────────────────────────────

    #[test]
    fn error_stable_code_invalid_request() {
        let e = ConstrainedAmbientError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        };
        assert_eq!(e.stable_code(), "FE-CABL-1001");
    }

    #[test]
    fn error_stable_code_invalid_metric() {
        let e = ConstrainedAmbientError::InvalidMetric {
            field: "f".into(),
            subject: "s".into(),
            detail: "d".into(),
        };
        assert_eq!(e.stable_code(), "FE-CABL-1002");
    }

    #[test]
    fn error_display_invalid_request() {
        let e = ConstrainedAmbientError::InvalidRequest {
            field: "trace_id".into(),
            detail: "empty".into(),
        };
        assert!(e.to_string().contains("trace_id"));
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn error_display_invalid_metric() {
        let e = ConstrainedAmbientError::InvalidMetric {
            field: "throughput".into(),
            subject: "w1".into(),
            detail: "must be > 0".into(),
        };
        assert!(e.to_string().contains("throughput"));
        assert!(e.to_string().contains("w1"));
    }

    // ── delta_millionths / improvement_millionths ─────────────────

    #[test]
    fn delta_millionths_positive() {
        let d = delta_millionths(2000, 1000).unwrap();
        assert_eq!(d, 1_000_000); // 100% improvement
    }

    #[test]
    fn delta_millionths_negative() {
        let d = delta_millionths(500, 1000).unwrap();
        assert_eq!(d, -500_000); // -50%
    }

    #[test]
    fn delta_millionths_equal() {
        let d = delta_millionths(100, 100).unwrap();
        assert_eq!(d, 0);
    }

    #[test]
    fn delta_millionths_zero_baseline_errors() {
        assert!(delta_millionths(100, 0).is_err());
    }

    #[test]
    fn improvement_millionths_uses_inverted_delta() {
        // improvement_millionths(baseline=1000, optimized=500) means
        // 500 is better than 1000 for latency → positive improvement
        let i = improvement_millionths(1000, 500).unwrap();
        assert_eq!(i, 1_000_000); // 100%
    }

    // ── mean_i64 ──────────────────────────────────────────────────

    #[test]
    fn mean_i64_basic() {
        assert_eq!(mean_i64([100, 200, 300].iter().copied()), 200);
    }

    #[test]
    fn mean_i64_empty() {
        assert_eq!(mean_i64(std::iter::empty()), 0);
    }

    #[test]
    fn mean_i64_single() {
        assert_eq!(mean_i64(std::iter::once(42)), 42);
    }

    // ── build_summary ─────────────────────────────────────────────

    #[test]
    fn summary_empty_reports() {
        let s = build_summary(&[], &[]);
        assert_eq!(s.workload_count, 0);
        assert_eq!(s.attribution_count, 0);
        assert_eq!(s.mean_throughput_delta_millionths, 0);
    }

    #[test]
    fn summary_with_reports() {
        let w = WorkloadDeltaReport {
            workload_id: "w1".into(),
            canonical_output_digest: "d".into(),
            throughput_delta_millionths: 500_000,
            latency_p50_improvement_millionths: 300_000,
            latency_p95_improvement_millionths: 200_000,
            latency_p99_improvement_millionths: 100_000,
            memory_improvement_millionths: 50_000,
            allocation_improvement_millionths: 25_000,
        };
        let a = ProofAttributionReport {
            proof_id: "p".into(),
            specialization_id: "s".into(),
            throughput_gain_millionths: 100_000,
            latency_p95_improvement_millionths: 50_000,
            supports_uplift: true,
        };
        let s = build_summary(&[w], &[a]);
        assert_eq!(s.workload_count, 1);
        assert_eq!(s.attribution_count, 1);
        assert_eq!(s.mean_throughput_delta_millionths, 500_000);
    }

    // ── ConstrainedAmbientBenchmarkDecision allows_publication ────

    #[test]
    fn decision_allows_publication_when_allow() {
        let d = ConstrainedAmbientBenchmarkDecision {
            schema_version: "v1".into(),
            report_id: "r".into(),
            benchmark_run_id: "b".into(),
            outcome: "allow".into(),
            blocked: false,
            blockers: vec![],
            error_code: None,
            workload_reports: vec![],
            attribution_reports: vec![],
            summary: ConstrainedAmbientSummary {
                workload_count: 0,
                attribution_count: 0,
                mean_throughput_delta_millionths: 0,
                mean_latency_p95_improvement_millionths: 0,
                mean_memory_improvement_millionths: 0,
            },
            events: vec![],
        };
        assert!(d.allows_publication());
    }

    #[test]
    fn decision_blocks_publication_when_deny() {
        let d = ConstrainedAmbientBenchmarkDecision {
            schema_version: "v1".into(),
            report_id: "r".into(),
            benchmark_run_id: "b".into(),
            outcome: "deny".into(),
            blocked: true,
            blockers: vec!["reason".into()],
            error_code: None,
            workload_reports: vec![],
            attribution_reports: vec![],
            summary: ConstrainedAmbientSummary {
                workload_count: 0,
                attribution_count: 0,
                mean_throughput_delta_millionths: 0,
                mean_latency_p95_improvement_millionths: 0,
                mean_memory_improvement_millionths: 0,
            },
            events: vec![],
        };
        assert!(!d.allows_publication());
    }

    // ── validate_request ──────────────────────────────────────────

    #[test]
    fn validate_request_valid() {
        assert!(validate_request(&valid_request()).is_ok());
    }

    #[test]
    fn validate_request_empty_trace_id() {
        let mut r = valid_request();
        r.trace_id = "".into();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_request_empty_decision_id() {
        let mut r = valid_request();
        r.decision_id = "  ".into();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_request_empty_policy_id() {
        let mut r = valid_request();
        r.policy_id = "".into();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_request_empty_benchmark_run_id() {
        let mut r = valid_request();
        r.benchmark_run_id = "".into();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_request_empty_constrained_lane() {
        let mut r = valid_request();
        r.constrained_lane.clear();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_request_empty_ambient_lane() {
        let mut r = valid_request();
        r.ambient_lane.clear();
        assert!(validate_request(&r).is_err());
    }

    // ── validate_non_zero_metric ──────────────────────────────────

    #[test]
    fn validate_non_zero_metric_ok() {
        assert!(validate_non_zero_metric(1, "throughput", "w1").is_ok());
    }

    #[test]
    fn validate_non_zero_metric_zero() {
        assert!(validate_non_zero_metric(0, "throughput", "w1").is_err());
    }

    // ── run_constrained_ambient_benchmark_lane ────────────────────

    #[test]
    fn full_evaluation_passing() {
        let decision = run_constrained_ambient_benchmark_lane(&valid_request());
        assert_eq!(decision.outcome, "allow");
        assert!(!decision.blocked);
        assert!(decision.blockers.is_empty());
        assert!(decision.allows_publication());
        assert_eq!(decision.schema_version, CONSTRAINED_AMBIENT_SCHEMA_VERSION);
    }

    #[test]
    fn full_evaluation_workload_set_mismatch() {
        let mut r = valid_request();
        r.ambient_lane[0].workload_id = "w2".into();
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("workload sets differ"))
        );
    }

    #[test]
    fn full_evaluation_digest_mismatch() {
        let mut r = valid_request();
        r.ambient_lane[0].output_digest = "different-digest".into();
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("digest mismatch"))
        );
    }

    #[test]
    fn full_evaluation_regression() {
        let mut r = valid_request();
        // Make constrained worse than ambient
        r.constrained_lane[0].throughput_ops_per_sec = 500;
        r.constrained_lane[0].latency_p50_ns = 2000;
        r.constrained_lane[0].latency_p95_ns = 4000;
        r.constrained_lane[0].latency_p99_ns = 8000;
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert!(decision.blockers.iter().any(|b| b.contains("regressed")));
    }

    #[test]
    fn full_evaluation_invalid_request() {
        let mut r = valid_request();
        r.trace_id = "".into();
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert_eq!(decision.outcome, "fail");
        assert!(decision.error_code.is_some());
    }

    #[test]
    fn full_evaluation_attribution_gap() {
        let mut r = valid_request();
        // Make constrained equal to without-proof → no uplift
        r.proof_attribution[0].constrained_throughput_ops_per_sec = 1000;
        r.proof_attribution[0].without_proof_throughput_ops_per_sec = 1000;
        r.proof_attribution[0].constrained_latency_p95_ns = 1000;
        r.proof_attribution[0].without_proof_latency_p95_ns = 1000;
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert!(decision.blockers.iter().any(|b| b.contains("uplift")));
    }

    #[test]
    fn full_evaluation_empty_proof_attribution() {
        let mut r = valid_request();
        r.proof_attribution.clear();
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert_eq!(decision.outcome, "fail");
    }

    #[test]
    fn full_evaluation_duplicate_proof_attribution() {
        let mut r = valid_request();
        r.proof_attribution
            .push(test_attribution("proof-1", "spec-1"));
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert_eq!(decision.outcome, "fail");
    }

    #[test]
    fn full_evaluation_zero_metric_in_workload() {
        let mut r = valid_request();
        r.constrained_lane[0].throughput_ops_per_sec = 0;
        let decision = run_constrained_ambient_benchmark_lane(&r);
        assert!(decision.blocked);
        assert_eq!(decision.outcome, "fail");
    }

    // ── build_report_id ───────────────────────────────────────────

    #[test]
    fn report_id_deterministic() {
        let r = valid_request();
        let id1 = build_report_id(&r);
        let id2 = build_report_id(&r);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("cabl_"));
        assert_eq!(id1.len(), 5 + 20);
    }

    #[test]
    fn report_id_changes_with_input() {
        let r1 = valid_request();
        let mut r2 = valid_request();
        r2.benchmark_run_id = "run-2".into();
        assert_ne!(build_report_id(&r1), build_report_id(&r2));
    }

    // ── set_error_code ────────────────────────────────────────────

    #[test]
    fn set_error_code_first_wins() {
        let mut code = None;
        set_error_code(&mut code, "A");
        set_error_code(&mut code, "B");
        assert_eq!(code.as_deref(), Some("A"));
    }

    // ── serde round-trips ─────────────────────────────────────────

    #[test]
    fn lane_workload_metrics_serde_round_trip() {
        let m = test_workload("w1", 100, 50);
        let json = serde_json::to_string(&m).unwrap();
        let back: LaneWorkloadMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn proof_attribution_sample_serde_round_trip() {
        let s = test_attribution("p1", "s1");
        let json = serde_json::to_string(&s).unwrap();
        let back: ProofAttributionSample = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn constrained_ambient_event_serde_round_trip() {
        let e = ConstrainedAmbientEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "o".into(),
            error_code: None,
            workload_id: None,
            proof_id: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ConstrainedAmbientEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn decision_serde_round_trip() {
        let decision = run_constrained_ambient_benchmark_lane(&valid_request());
        let json = serde_json::to_string(&decision).unwrap();
        let back: ConstrainedAmbientBenchmarkDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn workload_delta_report_serde_round_trip() {
        let r = WorkloadDeltaReport {
            workload_id: "w".into(),
            canonical_output_digest: "d".into(),
            throughput_delta_millionths: 100,
            latency_p50_improvement_millionths: 200,
            latency_p95_improvement_millionths: 300,
            latency_p99_improvement_millionths: 400,
            memory_improvement_millionths: 500,
            allocation_improvement_millionths: 600,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: WorkloadDeltaReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn proof_attribution_report_serde_round_trip() {
        let r = ProofAttributionReport {
            proof_id: "p".into(),
            specialization_id: "s".into(),
            throughput_gain_millionths: 100_000,
            latency_p95_improvement_millionths: 50_000,
            supports_uplift: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ProofAttributionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn constrained_ambient_summary_serde_round_trip() {
        let s = ConstrainedAmbientSummary {
            workload_count: 3,
            attribution_count: 2,
            mean_throughput_delta_millionths: 500_000,
            mean_latency_p95_improvement_millionths: 200_000,
            mean_memory_improvement_millionths: 100_000,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ConstrainedAmbientSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn constrained_ambient_error_is_std_error() {
        let e = ConstrainedAmbientError::InvalidRequest {
            field: "trace_id".into(),
            detail: "empty".into(),
        };
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn constrained_ambient_error_stable_code_distinct() {
        let codes = [
            ConstrainedAmbientError::InvalidRequest {
                field: "f".into(),
                detail: "d".into(),
            }
            .stable_code(),
            ConstrainedAmbientError::InvalidMetric {
                field: "f".into(),
                subject: "s".into(),
                detail: "d".into(),
            }
            .stable_code(),
        ];
        let set: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(set.len(), codes.len());
    }

    #[test]
    fn constrained_ambient_error_display_contains_fields() {
        let e = ConstrainedAmbientError::InvalidRequest {
            field: "trace_id".into(),
            detail: "must be non-empty".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("trace_id"));
        assert!(msg.contains("must be non-empty"));
    }

    #[test]
    fn constrained_ambient_error_display_metric_contains_subject() {
        let e = ConstrainedAmbientError::InvalidMetric {
            field: "throughput".into(),
            subject: "workload-1".into(),
            detail: "must be positive".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("throughput"));
        assert!(msg.contains("workload-1"));
        assert!(msg.contains("must be positive"));
    }
}
