//! Deterministic hot-path profiling and tier-up eligibility policy.
//!
//! This module consumes `bytecode_vm::ExecutionReport` traces and derives a
//! replay-stable hotspot profile plus tier-up candidate decisions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytecode_vm::{ExecutionReport, VmEvent};

const COMPONENT: &str = "tier_up_profiler";
const MILLIONTHS_DENOMINATOR: u64 = 1_000_000;

pub const TIER_UP_POLICY_SCHEMA_VERSION: &str = "franken-engine.tier-up-policy.v1";

/// Deterministic policy for deciding tier-up eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpPolicy {
    pub policy_id: String,
    pub min_total_steps: u64,
    pub min_invocations_per_path: u64,
    pub min_cache_hit_rate_millionths: i64,
    pub max_candidates: usize,
    pub profile_top_k: usize,
    pub require_cache_signal: bool,
}

impl Default for TierUpPolicy {
    fn default() -> Self {
        Self {
            policy_id: "policy-tier-up-v1".to_string(),
            min_total_steps: 64,
            min_invocations_per_path: 16,
            min_cache_hit_rate_millionths: 600_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
        }
    }
}

impl TierUpPolicy {
    pub fn policy_hash(&self) -> String {
        sha256_hex(self)
    }
}

#[derive(Debug, Clone)]
struct PathAccumulator {
    ip: u32,
    opcode: String,
    invocations: u64,
    cache_hits: u64,
    cache_misses: u64,
}

/// One deterministic hot-path aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotPathSample {
    pub ip: u32,
    pub opcode: String,
    pub invocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate_millionths: i64,
}

impl HotPathSample {
    fn cache_observations(&self) -> u64 {
        self.cache_hits + self.cache_misses
    }
}

/// Deterministic profile derived from VM execution events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotPathProfile {
    pub trace_id: String,
    pub total_steps: u64,
    pub observed_instruction_events: u64,
    pub top_paths: Vec<HotPathSample>,
    pub profile_hash: String,
}

/// Tier-up candidate admitted by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpCandidate {
    pub ip: u32,
    pub opcode: String,
    pub invocations: u64,
    pub cache_hit_rate_millionths: i64,
    pub rationale: String,
}

/// Path rejected by the policy with explicit reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpRejection {
    pub ip: u32,
    pub opcode: String,
    pub invocations: u64,
    pub cache_hit_rate_millionths: i64,
    pub reason: String,
}

/// Structured tier-up decision event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpDecisionEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub reason: String,
}

/// Final deterministic tier-up decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpDecision {
    pub schema_version: String,
    pub trace_id: String,
    pub policy_hash: String,
    pub eligible: bool,
    pub selected_candidates: Vec<TierUpCandidate>,
    pub rejected_paths: Vec<TierUpRejection>,
    pub profile: HotPathProfile,
    pub decision_hash: String,
    pub events: Vec<TierUpDecisionEvent>,
}

/// Build a deterministic hot-path profile from a VM execution report.
pub fn build_hot_path_profile(report: &ExecutionReport, top_k: usize) -> HotPathProfile {
    let mut aggregates = BTreeMap::<(u32, String), PathAccumulator>::new();
    let mut observed_instruction_events = 0u64;

    for event in &report.events {
        if !is_tiering_candidate_event(event) {
            continue;
        }

        observed_instruction_events += 1;
        let key = (event.ip, event.opcode.clone());
        let entry = aggregates.entry(key).or_insert_with(|| PathAccumulator {
            ip: event.ip,
            opcode: event.opcode.clone(),
            invocations: 0,
            cache_hits: 0,
            cache_misses: 0,
        });

        entry.invocations += 1;
        match event.cache_hit {
            Some(true) => entry.cache_hits += 1,
            Some(false) => entry.cache_misses += 1,
            None => {}
        }
    }

    let mut top_paths = aggregates
        .into_values()
        .map(|entry| HotPathSample {
            ip: entry.ip,
            opcode: entry.opcode,
            invocations: entry.invocations,
            cache_hits: entry.cache_hits,
            cache_misses: entry.cache_misses,
            cache_hit_rate_millionths: cache_hit_rate_millionths(
                entry.cache_hits,
                entry.cache_misses,
            ),
        })
        .collect::<Vec<_>>();

    top_paths.sort_by(|left, right| {
        right
            .invocations
            .cmp(&left.invocations)
            .then_with(|| left.ip.cmp(&right.ip))
            .then_with(|| left.opcode.cmp(&right.opcode))
    });
    top_paths.truncate(normalize_limit(top_k));

    #[derive(Serialize)]
    struct ProfileEnvelope<'a> {
        trace_id: &'a str,
        total_steps: u64,
        observed_instruction_events: u64,
        top_paths: &'a [HotPathSample],
    }

    let profile_hash = sha256_hex(&ProfileEnvelope {
        trace_id: &report.trace_id,
        total_steps: report.steps,
        observed_instruction_events,
        top_paths: &top_paths,
    });

    HotPathProfile {
        trace_id: report.trace_id.clone(),
        total_steps: report.steps,
        observed_instruction_events,
        top_paths,
        profile_hash,
    }
}

/// Evaluate deterministic tier-up eligibility for one report and policy.
pub fn evaluate_tier_up_eligibility(
    report: &ExecutionReport,
    policy: &TierUpPolicy,
) -> TierUpDecision {
    let profile = build_hot_path_profile(report, policy.profile_top_k);
    let policy_hash = policy.policy_hash();
    let mut selected_candidates = Vec::<TierUpCandidate>::new();
    let mut rejected_paths = Vec::<TierUpRejection>::new();
    let mut events = vec![make_event(
        &report.trace_id,
        "tier_up_started",
        "pass",
        "tier_up_policy_evaluation_started",
    )];

    if report.steps < policy.min_total_steps {
        events.push(make_event(
            &report.trace_id,
            "tier_up_completed",
            "deny",
            "insufficient_total_steps",
        ));

        let mut decision = TierUpDecision {
            schema_version: TIER_UP_POLICY_SCHEMA_VERSION.to_string(),
            trace_id: report.trace_id.clone(),
            policy_hash,
            eligible: false,
            selected_candidates,
            rejected_paths,
            profile,
            decision_hash: String::new(),
            events,
        };
        decision.decision_hash = compute_decision_hash(&decision);
        return decision;
    }

    for path in &profile.top_paths {
        if path.invocations < policy.min_invocations_per_path {
            rejected_paths.push(TierUpRejection {
                ip: path.ip,
                opcode: path.opcode.clone(),
                invocations: path.invocations,
                cache_hit_rate_millionths: path.cache_hit_rate_millionths,
                reason: "insufficient_invocations".to_string(),
            });
            continue;
        }

        let cache_observations = path.cache_observations();
        if policy.require_cache_signal && cache_observations == 0 {
            rejected_paths.push(TierUpRejection {
                ip: path.ip,
                opcode: path.opcode.clone(),
                invocations: path.invocations,
                cache_hit_rate_millionths: path.cache_hit_rate_millionths,
                reason: "missing_cache_signal".to_string(),
            });
            continue;
        }

        if cache_observations > 0
            && path.cache_hit_rate_millionths < policy.min_cache_hit_rate_millionths
        {
            rejected_paths.push(TierUpRejection {
                ip: path.ip,
                opcode: path.opcode.clone(),
                invocations: path.invocations,
                cache_hit_rate_millionths: path.cache_hit_rate_millionths,
                reason: "cache_hit_rate_below_threshold".to_string(),
            });
            continue;
        }

        selected_candidates.push(TierUpCandidate {
            ip: path.ip,
            opcode: path.opcode.clone(),
            invocations: path.invocations,
            cache_hit_rate_millionths: path.cache_hit_rate_millionths,
            rationale: "hot_path_meets_tier_up_thresholds".to_string(),
        });
    }

    selected_candidates.truncate(normalize_limit(policy.max_candidates));
    let eligible = !selected_candidates.is_empty();

    events.push(make_event(
        &report.trace_id,
        "tier_up_completed",
        if eligible { "allow" } else { "deny" },
        if eligible {
            "eligible_candidates_found"
        } else {
            "no_candidates_met_policy"
        },
    ));

    let mut decision = TierUpDecision {
        schema_version: TIER_UP_POLICY_SCHEMA_VERSION.to_string(),
        trace_id: report.trace_id.clone(),
        policy_hash,
        eligible,
        selected_candidates,
        rejected_paths,
        profile,
        decision_hash: String::new(),
        events,
    };
    decision.decision_hash = compute_decision_hash(&decision);
    decision
}

fn compute_decision_hash(decision: &TierUpDecision) -> String {
    #[derive(Serialize)]
    struct DecisionEnvelope<'a> {
        schema_version: &'a str,
        trace_id: &'a str,
        policy_hash: &'a str,
        eligible: bool,
        selected_candidates: &'a [TierUpCandidate],
        rejected_paths: &'a [TierUpRejection],
        profile: &'a HotPathProfile,
        events: &'a [TierUpDecisionEvent],
    }

    sha256_hex(&DecisionEnvelope {
        schema_version: &decision.schema_version,
        trace_id: &decision.trace_id,
        policy_hash: &decision.policy_hash,
        eligible: decision.eligible,
        selected_candidates: &decision.selected_candidates,
        rejected_paths: &decision.rejected_paths,
        profile: &decision.profile,
        events: &decision.events,
    })
}

fn cache_hit_rate_millionths(cache_hits: u64, cache_misses: u64) -> i64 {
    let observed = cache_hits + cache_misses;
    if observed == 0 {
        return 0;
    }

    ((u128::from(cache_hits) * u128::from(MILLIONTHS_DENOMINATOR)) / u128::from(observed)) as i64
}

fn is_tiering_candidate_event(event: &VmEvent) -> bool {
    event.event == "instruction"
        && event.outcome == "ok"
        && event.opcode != "budget"
        && event.opcode != "eof"
}

fn make_event(trace_id: &str, event: &str, outcome: &str, reason: &str) -> TierUpDecisionEvent {
    TierUpDecisionEvent {
        trace_id: trace_id.to_string(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        reason: reason.to_string(),
    }
}

fn normalize_limit(value: usize) -> usize {
    value.max(1)
}

fn sha256_hex<T: Serialize>(value: &T) -> String {
    let payload = serde_json::to_vec(value).expect("tier_up_profiler payload must serialize");
    let digest = Sha256::digest(payload);
    hex::encode(digest)
}
