//! Opportunity-matrix scoring for Section 10.6 (`bd-js4`).
//!
//! This module provides deterministic optimization-candidate scoring before
//! implementation begins. It combines:
//! - hotspot profile weight from flamegraph artifacts
//! - benchmark-derived pressure signal
//! - VOI-style expected gain per engineering hour
//! - security/risk/complexity penalties
//!
//! Scores are fixed-point millionths (`1_000_000 = 1.0`), enabling stable
//! ranking and threshold gating (`>= 2.0` score).

use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::benchmark_denominator::BenchmarkCase;
use crate::flamegraph_pipeline::{FlamegraphArtifact, FlamegraphKind};

pub const OPPORTUNITY_MATRIX_COMPONENT: &str = "opportunity_matrix";
pub const OPPORTUNITY_MATRIX_SCHEMA_VERSION: &str = "franken-engine.opportunity-matrix.v1";
pub const OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS: i64 = 2_000_000; // 2.0

const MIN_COMPLEXITY: u32 = 1;
const MIN_RISK_FLOOR_MILLIONTHS: i64 = 1_000; // 0.001
const MIN_EFFORT_HOURS_MILLIONTHS: i64 = 100_000; // 0.1h
const TARGET_SUITE_SPEEDUP_MILLIONTHS: i64 = 3_000_000; // 3.0x

const ERROR_INVALID_REQUEST: &str = "FE-OPPM-1001";
const ERROR_DUPLICATE_OPPORTUNITY_ID: &str = "FE-OPPM-1002";
const ERROR_INVALID_TIMESTAMP: &str = "FE-OPPM-1003";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotProfileEntry {
    pub module: String,
    pub function: String,
    pub sample_count: u64,
}

impl HotspotProfileEntry {
    pub fn key(&self) -> String {
        format!("{}::{}", self.module, self.function)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationCandidateInput {
    pub opportunity_id: String,
    pub target_module: String,
    pub target_function: String,
    pub estimated_speedup_millionths: i64,
    pub implementation_complexity: u32,
    pub regression_risk_millionths: i64,
    pub security_clearance_millionths: i64,
    pub engineering_effort_hours_millionths: i64,
    pub hotpath_weight_override_millionths: Option<i64>,
}

impl OptimizationCandidateInput {
    pub fn target_key(&self) -> String {
        format!("{}::{}", self.target_module, self.target_function)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityOutcomeObservation {
    pub opportunity_id: String,
    pub predicted_gain_millionths: i64,
    pub actual_gain_millionths: i64,
    pub completed_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrixRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub optimization_run_id: String,
    pub benchmark_pressure_millionths: i64,
    pub hotspots: Vec<HotspotProfileEntry>,
    pub candidates: Vec<OptimizationCandidateInput>,
    pub historical_outcomes: Vec<OpportunityOutcomeObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpportunityStatus {
    Selected,
    RejectedLowScore,
    RejectedSecurityClearance,
    RejectedMissingHotspot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoredOpportunity {
    pub opportunity_id: String,
    pub target_module: String,
    pub target_function: String,
    pub estimated_speedup_millionths: i64,
    pub hotpath_weight_millionths: i64,
    pub benchmark_pressure_millionths: i64,
    pub voi_millionths: i64,
    pub score_millionths: i64,
    pub threshold_met: bool,
    pub status: OpportunityStatus,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityHistoryRecord {
    pub opportunity_id: String,
    pub predicted_gain_millionths: i64,
    pub actual_gain_millionths: i64,
    pub signed_error_millionths: i64,
    pub absolute_error_millionths: i64,
    pub completed_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrixEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub opportunity_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrixDecision {
    pub schema_version: String,
    pub matrix_id: String,
    pub optimization_run_id: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub score_threshold_millionths: i64,
    pub benchmark_pressure_millionths: i64,
    pub ranked_opportunities: Vec<ScoredOpportunity>,
    pub selected_opportunity_ids: Vec<String>,
    pub historical_tracking: Vec<OpportunityHistoryRecord>,
    pub events: Vec<OpportunityMatrixEvent>,
}

impl OpportunityMatrixDecision {
    pub fn has_selected_opportunities(&self) -> bool {
        !self.selected_opportunity_ids.is_empty()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpportunityMatrixError {
    #[error("invalid request field `{field}`: {detail}")]
    InvalidRequest { field: String, detail: String },
    #[error("duplicate opportunity_id `{opportunity_id}`")]
    DuplicateOpportunityId { opportunity_id: String },
    #[error("invalid RFC3339 UTC timestamp `{value}`")]
    InvalidTimestamp { value: String },
}

impl OpportunityMatrixError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => ERROR_INVALID_REQUEST,
            Self::DuplicateOpportunityId { .. } => ERROR_DUPLICATE_OPPORTUNITY_ID,
            Self::InvalidTimestamp { .. } => ERROR_INVALID_TIMESTAMP,
        }
    }
}

/// Build hotspot profile entries from stored flamegraph artifacts.
///
/// Aggregation key is `(module, leaf_function)` from folded-stack rows.
pub fn hotspot_profile_from_flamegraphs(
    artifacts: &[FlamegraphArtifact],
) -> Vec<HotspotProfileEntry> {
    let mut aggregate: BTreeMap<(String, String), u64> = BTreeMap::new();

    for artifact in artifacts {
        if !matches!(
            artifact.kind,
            FlamegraphKind::Cpu
                | FlamegraphKind::Allocation
                | FlamegraphKind::DiffCpu
                | FlamegraphKind::DiffAllocation
        ) {
            continue;
        }

        for sample in &artifact.folded_stacks {
            let stack = sample.stack.trim();
            if stack.is_empty() {
                continue;
            }
            let mut parts = stack.split(';').filter(|part| !part.trim().is_empty());
            let module = parts.next().unwrap_or("unknown").trim().to_string();
            let function = stack
                .rsplit(';')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string();
            let key = (module, function);
            *aggregate.entry(key).or_insert(0) += sample.sample_count;
        }
    }

    let mut entries = aggregate
        .into_iter()
        .map(|((module, function), sample_count)| HotspotProfileEntry {
            module,
            function,
            sample_count,
        })
        .collect::<Vec<_>>();

    entries.sort_by(|a, b| {
        b.sample_count
            .cmp(&a.sample_count)
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.function.cmp(&b.function))
    });
    entries
}

/// Derive benchmark-pressure multiplier from benchmark denominator inputs.
///
/// Result is in `[1_000_000, 2_000_000]` where `1_000_000` is neutral and
/// larger values indicate higher pressure to prioritize wins.
pub fn benchmark_pressure_from_cases(node_cases: &[BenchmarkCase], bun_cases: &[BenchmarkCase]) -> i64 {
    let mut speeds = Vec::new();
    for case in node_cases.iter().chain(bun_cases.iter()) {
        if case.throughput_baseline_tps <= 0.0 {
            continue;
        }
        let speedup = case.throughput_franken_tps / case.throughput_baseline_tps;
        if speedup.is_finite() && speedup > 0.0 {
            speeds.push((speedup * 1_000_000.0).round() as i64);
        }
    }

    if speeds.is_empty() {
        return 1_000_000;
    }

    let observed = speeds.iter().sum::<i64>() / speeds.len() as i64;
    if observed >= TARGET_SUITE_SPEEDUP_MILLIONTHS {
        return 1_000_000;
    }

    let shortfall = TARGET_SUITE_SPEEDUP_MILLIONTHS - observed;
    let pressure = 1_000_000 + (shortfall * 1_000_000 / TARGET_SUITE_SPEEDUP_MILLIONTHS);
    pressure.clamp(1_000_000, 2_000_000)
}

/// Derive candidate skeletons directly from hotspot profile data.
pub fn derive_candidates_from_hotspots(
    hotspots: &[HotspotProfileEntry],
    benchmark_pressure_millionths: i64,
    default_complexity: u32,
    default_regression_risk_millionths: i64,
    default_security_clearance_millionths: i64,
    default_effort_hours_millionths: i64,
    max_candidates: usize,
) -> Vec<OptimizationCandidateInput> {
    let total_samples = hotspots.iter().map(|entry| entry.sample_count).sum::<u64>().max(1);
    hotspots
        .iter()
        .take(max_candidates)
        .map(|hotspot| {
            let hotpath_weight =
                ((hotspot.sample_count as i128 * 1_000_000i128) / total_samples as i128) as i64;
            let estimated_speedup =
                1_000_000 + ((benchmark_pressure_millionths * hotpath_weight) / 1_000_000);
            let opportunity_id = format!(
                "opp:{}:{}",
                sanitize_token(&hotspot.module),
                sanitize_token(&hotspot.function)
            );
            OptimizationCandidateInput {
                opportunity_id,
                target_module: hotspot.module.clone(),
                target_function: hotspot.function.clone(),
                estimated_speedup_millionths: estimated_speedup,
                implementation_complexity: default_complexity,
                regression_risk_millionths: default_regression_risk_millionths,
                security_clearance_millionths: default_security_clearance_millionths,
                engineering_effort_hours_millionths: default_effort_hours_millionths,
                hotpath_weight_override_millionths: Some(hotpath_weight),
            }
        })
        .collect()
}

/// Run deterministic opportunity-matrix scoring.
pub fn run_opportunity_matrix_scoring(
    request: &OpportunityMatrixRequest,
) -> OpportunityMatrixDecision {
    let matrix_id = build_matrix_id(request);
    let mut events = vec![make_event(
        request,
        "opportunity_matrix_started",
        "pass",
        None,
        None,
    )];

    match run_impl(request, &mut events) {
        Ok(computation) => {
            let ranked_opportunities = computation.ranked_opportunities;
            let selected_opportunity_ids = computation.selected_opportunity_ids;
            let historical_tracking = computation.historical_tracking;
            let outcome = if selected_opportunity_ids.is_empty() {
                "deny"
            } else {
                "allow"
            };
            events.push(make_event(
                request,
                "opportunity_matrix_completed",
                outcome,
                None,
                None,
            ));
            OpportunityMatrixDecision {
                schema_version: OPPORTUNITY_MATRIX_SCHEMA_VERSION.to_string(),
                matrix_id,
                optimization_run_id: request.optimization_run_id.clone(),
                outcome: outcome.to_string(),
                error_code: None,
                score_threshold_millionths: OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS,
                benchmark_pressure_millionths: request.benchmark_pressure_millionths,
                ranked_opportunities,
                selected_opportunity_ids,
                historical_tracking,
                events,
            }
        }
        Err(error) => {
            let error_code = error.stable_code().to_string();
            events.push(make_event(
                request,
                "opportunity_matrix_completed",
                "fail",
                Some(error_code.clone()),
                None,
            ));
            OpportunityMatrixDecision {
                schema_version: OPPORTUNITY_MATRIX_SCHEMA_VERSION.to_string(),
                matrix_id,
                optimization_run_id: request.optimization_run_id.clone(),
                outcome: "fail".to_string(),
                error_code: Some(error_code),
                score_threshold_millionths: OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS,
                benchmark_pressure_millionths: request.benchmark_pressure_millionths,
                ranked_opportunities: Vec::new(),
                selected_opportunity_ids: Vec::new(),
                historical_tracking: Vec::new(),
                events,
            }
        }
    }
}

fn run_impl(
    request: &OpportunityMatrixRequest,
    events: &mut Vec<OpportunityMatrixEvent>,
) -> Result<OpportunityMatrixComputation, OpportunityMatrixError> {
    validate_request(request)?;
    let hotspot_weights = hotspot_weight_map(&request.hotspots);

    let mut ranked = request
        .candidates
        .iter()
        .map(|candidate| {
            let mut rejection_reason = None;
            let target_key = candidate.target_key();
            let hotpath_weight = candidate
                .hotpath_weight_override_millionths
                .unwrap_or_else(|| hotspot_weights.get(&target_key).copied().unwrap_or(0))
                .clamp(0, 1_000_000);

            let status = if candidate.security_clearance_millionths <= 0 {
                rejection_reason = Some("SECURITY_CLEARANCE_ZERO".to_string());
                OpportunityStatus::RejectedSecurityClearance
            } else if hotpath_weight <= 0 {
                rejection_reason = Some("MISSING_HOTSPOT_WEIGHT".to_string());
                OpportunityStatus::RejectedMissingHotspot
            } else {
                OpportunityStatus::RejectedLowScore
            };

            let score_detail =
                compute_score_millionths(candidate, hotpath_weight, request.benchmark_pressure_millionths);
            let threshold_met = score_detail.score_millionths >= OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS;
            let final_status = if matches!(status, OpportunityStatus::RejectedLowScore) && threshold_met
            {
                OpportunityStatus::Selected
            } else {
                status
            };
            if matches!(final_status, OpportunityStatus::RejectedLowScore) {
                rejection_reason = Some("SCORE_BELOW_THRESHOLD".to_string());
            }

            events.push(make_event(
                request,
                "opportunity_scored",
                if matches!(final_status, OpportunityStatus::Selected) {
                    "allow"
                } else {
                    "deny"
                },
                None,
                Some(candidate.opportunity_id.clone()),
            ));

            ScoredOpportunity {
                opportunity_id: candidate.opportunity_id.clone(),
                target_module: candidate.target_module.clone(),
                target_function: candidate.target_function.clone(),
                estimated_speedup_millionths: candidate.estimated_speedup_millionths.max(0),
                hotpath_weight_millionths: hotpath_weight,
                benchmark_pressure_millionths: request.benchmark_pressure_millionths,
                voi_millionths: score_detail.voi_millionths,
                score_millionths: score_detail.score_millionths,
                threshold_met,
                status: final_status,
                rejection_reason,
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|a, b| {
        b.score_millionths
            .cmp(&a.score_millionths)
            .then_with(|| a.opportunity_id.cmp(&b.opportunity_id))
    });

    let selected_ids = ranked
        .iter()
        .filter(|candidate| matches!(candidate.status, OpportunityStatus::Selected))
        .map(|candidate| candidate.opportunity_id.clone())
        .collect::<Vec<_>>();

    let mut historical = request
        .historical_outcomes
        .iter()
        .map(|entry| OpportunityHistoryRecord {
            opportunity_id: entry.opportunity_id.clone(),
            predicted_gain_millionths: entry.predicted_gain_millionths,
            actual_gain_millionths: entry.actual_gain_millionths,
            signed_error_millionths: entry.actual_gain_millionths - entry.predicted_gain_millionths,
            absolute_error_millionths: (entry.actual_gain_millionths - entry.predicted_gain_millionths)
                .abs(),
            completed_at_utc: entry.completed_at_utc.clone(),
        })
        .collect::<Vec<_>>();

    historical.sort_by(|a, b| {
        a.completed_at_utc
            .cmp(&b.completed_at_utc)
            .then_with(|| a.opportunity_id.cmp(&b.opportunity_id))
    });

    Ok(OpportunityMatrixComputation {
        ranked_opportunities: ranked,
        selected_opportunity_ids: selected_ids,
        historical_tracking: historical,
    })
}

fn validate_request(request: &OpportunityMatrixRequest) -> Result<(), OpportunityMatrixError> {
    if request.trace_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "trace_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.decision_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "decision_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.policy_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "policy_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.optimization_run_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "optimization_run_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.candidates.is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "candidates".to_string(),
            detail: "must include at least one candidate".to_string(),
        });
    }
    if request.benchmark_pressure_millionths <= 0 {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "benchmark_pressure_millionths".to_string(),
            detail: "must be positive".to_string(),
        });
    }

    let mut seen = BTreeSet::new();
    for candidate in &request.candidates {
        if candidate.opportunity_id.trim().is_empty() {
            return Err(OpportunityMatrixError::InvalidRequest {
                field: "opportunity_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if !seen.insert(candidate.opportunity_id.clone()) {
            return Err(OpportunityMatrixError::DuplicateOpportunityId {
                opportunity_id: candidate.opportunity_id.clone(),
            });
        }
    }

    for historical in &request.historical_outcomes {
        if DateTime::parse_from_rfc3339(&historical.completed_at_utc).is_err() {
            return Err(OpportunityMatrixError::InvalidTimestamp {
                value: historical.completed_at_utc.clone(),
            });
        }
    }

    Ok(())
}

fn hotspot_weight_map(hotspots: &[HotspotProfileEntry]) -> BTreeMap<String, i64> {
    let total_samples = hotspots.iter().map(|entry| entry.sample_count).sum::<u64>().max(1);
    let mut map = BTreeMap::new();
    for hotspot in hotspots {
        let weight = ((hotspot.sample_count as i128 * 1_000_000i128) / total_samples as i128) as i64;
        map.insert(hotspot.key(), weight.clamp(0, 1_000_000));
    }
    map
}

#[derive(Debug, Clone, Copy)]
struct ScoreDetail {
    voi_millionths: i64,
    score_millionths: i64,
}

#[derive(Debug)]
struct OpportunityMatrixComputation {
    ranked_opportunities: Vec<ScoredOpportunity>,
    selected_opportunity_ids: Vec<String>,
    historical_tracking: Vec<OpportunityHistoryRecord>,
}

fn compute_score_millionths(
    candidate: &OptimizationCandidateInput,
    hotpath_weight_millionths: i64,
    benchmark_pressure_millionths: i64,
) -> ScoreDetail {
    let complexity = candidate.implementation_complexity.max(MIN_COMPLEXITY) as i128;
    let risk = candidate
        .regression_risk_millionths
        .clamp(MIN_RISK_FLOOR_MILLIONTHS, 1_000_000) as i128;
    let effort = candidate
        .engineering_effort_hours_millionths
        .max(MIN_EFFORT_HOURS_MILLIONTHS) as i128;
    let security = candidate.security_clearance_millionths.clamp(0, 1_000_000) as i128;
    let estimated_speedup = candidate.estimated_speedup_millionths.max(0) as i128;
    let benchmark_pressure = benchmark_pressure_millionths.max(1) as i128;
    let hotpath_weight = hotpath_weight_millionths.max(0) as i128;

    // Benchmark-adjusted speedup multiplier.
    let adjusted_speedup = (estimated_speedup * benchmark_pressure) / 1_000_000;
    // Expected weighted gain.
    let base_gain = (adjusted_speedup * hotpath_weight) / 1_000_000;
    // VOI: expected gain per engineering hour.
    let voi = (base_gain * 1_000_000) / effort;
    // Penalize security ambiguity and regression risk.
    let sec_adjusted = (voi * security) / 1_000_000;
    let score = (sec_adjusted * 1_000_000) / (risk * complexity);

    ScoreDetail {
        voi_millionths: clamp_i128_to_i64(voi),
        score_millionths: clamp_i128_to_i64(score),
    }
}

fn build_matrix_id(request: &OpportunityMatrixRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.trace_id.as_bytes());
    hasher.update(request.decision_id.as_bytes());
    hasher.update(request.policy_id.as_bytes());
    hasher.update(request.optimization_run_id.as_bytes());
    hasher.update(request.benchmark_pressure_millionths.to_le_bytes());
    for hotspot in &request.hotspots {
        hasher.update(hotspot.module.as_bytes());
        hasher.update(hotspot.function.as_bytes());
        hasher.update(hotspot.sample_count.to_le_bytes());
    }
    for candidate in &request.candidates {
        hasher.update(candidate.opportunity_id.as_bytes());
        hasher.update(candidate.target_module.as_bytes());
        hasher.update(candidate.target_function.as_bytes());
        hasher.update(candidate.estimated_speedup_millionths.to_le_bytes());
        hasher.update(candidate.implementation_complexity.to_le_bytes());
        hasher.update(candidate.regression_risk_millionths.to_le_bytes());
        hasher.update(candidate.security_clearance_millionths.to_le_bytes());
        hasher.update(candidate.engineering_effort_hours_millionths.to_le_bytes());
    }
    let digest = hasher.finalize();
    format!("opm-{:x}", digest)
}

fn make_event(
    request: &OpportunityMatrixRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    opportunity_id: Option<String>,
) -> OpportunityMatrixEvent {
    OpportunityMatrixEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: OPPORTUNITY_MATRIX_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        opportunity_id,
    }
}

fn sanitize_token(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn clamp_i128_to_i64(value: i128) -> i64 {
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, module: &str, function: &str) -> OptimizationCandidateInput {
        OptimizationCandidateInput {
            opportunity_id: id.to_string(),
            target_module: module.to_string(),
            target_function: function.to_string(),
            estimated_speedup_millionths: 2_500_000,
            implementation_complexity: 2,
            regression_risk_millionths: 250_000,
            security_clearance_millionths: 1_000_000,
            engineering_effort_hours_millionths: 1_000_000,
            hotpath_weight_override_millionths: None,
        }
    }

    fn base_request() -> OpportunityMatrixRequest {
        OpportunityMatrixRequest {
            trace_id: "trace-opp".to_string(),
            decision_id: "decision-opp".to_string(),
            policy_id: "policy-opp".to_string(),
            optimization_run_id: "run-001".to_string(),
            benchmark_pressure_millionths: 1_250_000,
            hotspots: vec![
                HotspotProfileEntry {
                    module: "vm".to_string(),
                    function: "dispatch".to_string(),
                    sample_count: 90,
                },
                HotspotProfileEntry {
                    module: "vm".to_string(),
                    function: "gc_tick".to_string(),
                    sample_count: 10,
                },
            ],
            candidates: vec![
                candidate("opp-vm-dispatch", "vm", "dispatch"),
                candidate("opp-vm-gc", "vm", "gc_tick"),
            ],
            historical_outcomes: vec![OpportunityOutcomeObservation {
                opportunity_id: "opp-vm-dispatch".to_string(),
                predicted_gain_millionths: 400_000,
                actual_gain_millionths: 350_000,
                completed_at_utc: "2026-02-22T12:30:00Z".to_string(),
            }],
        }
    }

    #[test]
    fn deterministic_scoring_and_stable_ranking() {
        let request = base_request();
        let decision_a = run_opportunity_matrix_scoring(&request);
        let decision_b = run_opportunity_matrix_scoring(&request);
        assert_eq!(decision_a.ranked_opportunities, decision_b.ranked_opportunities);
        assert_eq!(decision_a.selected_opportunity_ids, decision_b.selected_opportunity_ids);
        assert!(decision_a.has_selected_opportunities());
        assert_eq!(
            decision_a.ranked_opportunities[0].opportunity_id,
            "opp-vm-dispatch"
        );
    }

    #[test]
    fn threshold_filter_rejects_low_score_candidates() {
        let mut request = base_request();
        request.candidates[0].estimated_speedup_millionths = 1_050_000;
        request.candidates[0].engineering_effort_hours_millionths = 20_000_000;
        request.candidates[0].regression_risk_millionths = 900_000;
        request.candidates[0].implementation_complexity = 5;
        request.candidates[1] = request.candidates[0].clone();
        request.candidates[1].opportunity_id = "opp-vm-gc".to_string();
        request.candidates[1].target_function = "gc_tick".to_string();

        let decision = run_opportunity_matrix_scoring(&request);
        assert_eq!(decision.outcome, "deny");
        assert!(decision.selected_opportunity_ids.is_empty());
        assert!(decision
            .ranked_opportunities
            .iter()
            .all(|candidate| !candidate.threshold_met));
    }

    #[test]
    fn security_clearance_zero_is_rejected() {
        let mut request = base_request();
        request.candidates[0].security_clearance_millionths = 0;
        let decision = run_opportunity_matrix_scoring(&request);
        let candidate = decision
            .ranked_opportunities
            .iter()
            .find(|candidate| candidate.opportunity_id == "opp-vm-dispatch")
            .expect("candidate should exist");
        assert_eq!(
            candidate.status,
            OpportunityStatus::RejectedSecurityClearance
        );
        assert!(!candidate.threshold_met);
    }

    #[test]
    fn zero_denominator_inputs_are_floored_without_panic() {
        let mut request = base_request();
        request.candidates[0].implementation_complexity = 0;
        request.candidates[0].regression_risk_millionths = 0;
        request.candidates[0].engineering_effort_hours_millionths = 0;
        let decision = run_opportunity_matrix_scoring(&request);
        assert_eq!(decision.outcome, "allow");
        assert!(decision
            .ranked_opportunities
            .iter()
            .all(|entry| entry.score_millionths >= 0));
    }

    #[test]
    fn benchmark_pressure_increases_when_suite_under_target() {
        let fast = BenchmarkCase {
            workload_id: "w1".to_string(),
            throughput_franken_tps: 400.0,
            throughput_baseline_tps: 100.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        let slow = BenchmarkCase {
            workload_id: "w2".to_string(),
            throughput_franken_tps: 150.0,
            throughput_baseline_tps: 100.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        let pressure = benchmark_pressure_from_cases(&[slow], &[fast]);
        assert!(pressure > 1_000_000);
        assert!(pressure <= 2_000_000);
    }

    #[test]
    fn derive_candidates_from_hotspots_emits_stable_ids() {
        let hotspots = vec![
            HotspotProfileEntry {
                module: "vm-core".to_string(),
                function: "dispatch.loop".to_string(),
                sample_count: 80,
            },
            HotspotProfileEntry {
                module: "gc".to_string(),
                function: "scan".to_string(),
                sample_count: 20,
            },
        ];
        let derived = derive_candidates_from_hotspots(
            &hotspots,
            1_300_000,
            2,
            200_000,
            1_000_000,
            2_000_000,
            2,
        );
        assert_eq!(derived.len(), 2);
        assert_eq!(derived[0].opportunity_id, "opp:vm-core:dispatch_loop");
        assert_eq!(derived[1].opportunity_id, "opp:gc:scan");
    }
}
