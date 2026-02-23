//! Third-party verifier toolkit primitives for externally auditable claims.
//!
//! This module keeps verification deterministic and artifact-driven so
//! independent operators can validate benchmark, replay, and containment
//! claims without a running FrankenEngine control plane.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::benchmark_denominator::{
    PublicationContext, PublicationGateInput, evaluate_publication_gate,
};
use crate::causal_replay::CounterfactualConfig;
use crate::engine_object_id::EngineObjectId;
use crate::incident_replay_bundle::{BundleVerifier, CheckOutcome, IncidentReplayBundle};
use crate::quarantine_mesh_gate::GateValidationResult;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{VERIFICATION_KEY_LEN, VerificationKey};

pub const THIRD_PARTY_VERIFIER_COMPONENT: &str = "third_party_verifier";
pub const DEFAULT_CONTAINMENT_LATENCY_SLA_NS: u64 = 500_000_000;

pub const EXIT_CODE_VERIFIED: i32 = 0;
pub const EXIT_CODE_PARTIALLY_VERIFIED: i32 = 24;
pub const EXIT_CODE_FAILED: i32 = 25;
pub const EXIT_CODE_INCONCLUSIVE: i32 = 26;

const EPSILON: f64 = 1e-12;
const CODE_BENCHMARK_EVAL: &str = "FE-TPV-BENCH-0001";
const CODE_BENCHMARK_SCORE: &str = "FE-TPV-BENCH-0002";
const CODE_BENCHMARK_PUBLISH: &str = "FE-TPV-BENCH-0003";
const CODE_BENCHMARK_BLOCKERS: &str = "FE-TPV-BENCH-0004";
const CODE_BENCHMARK_FAIRNESS: &str = "FE-TPV-BENCH-0005";
const CODE_REPLAY_PARSE: &str = "FE-TPV-REPLAY-0001";
const CODE_REPLAY_VERIFY: &str = "FE-TPV-REPLAY-0002";
const CODE_CONTAINMENT_COUNTS: &str = "FE-TPV-CONT-0001";
const CODE_CONTAINMENT_CRITERIA: &str = "FE-TPV-CONT-0002";
const CODE_CONTAINMENT_SLA: &str = "FE-TPV-CONT-0003";
const CODE_CONTAINMENT_INVARIANT: &str = "FE-TPV-CONT-0004";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Verified,
    PartiallyVerified,
    Failed,
    Inconclusive,
}

impl VerificationVerdict {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Verified => EXIT_CODE_VERIFIED,
            Self::PartiallyVerified => EXIT_CODE_PARTIALLY_VERIFIED,
            Self::Failed => EXIT_CODE_FAILED,
            Self::Inconclusive => EXIT_CODE_INCONCLUSIVE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheckResult {
    pub name: String,
    pub passed: bool,
    pub error_code: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyVerificationReport {
    pub claim_type: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub verdict: VerificationVerdict,
    pub checks: Vec<VerificationCheckResult>,
    pub events: Vec<VerifierEvent>,
}

impl ThirdPartyVerificationReport {
    pub fn exit_code(&self) -> i32 {
        self.verdict.exit_code()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimedBenchmarkOutcome {
    pub score_vs_node: f64,
    pub score_vs_bun: f64,
    pub publish_allowed: bool,
    #[serde(default)]
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkClaimBundle {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub input: PublicationGateInput,
    pub claimed: ClaimedBenchmarkOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayClaimBundle {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub verification_timestamp_ns: u64,
    pub current_epoch: u64,
    pub bundle: IncidentReplayBundle,
    #[serde(default)]
    pub signature_verification_key_hex: Option<String>,
    #[serde(default)]
    pub receipt_verification_keys_hex: BTreeMap<String, String>,
    #[serde(default)]
    pub counterfactual_configs: Vec<CounterfactualConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentClaimBundle {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub result: GateValidationResult,
    #[serde(default = "default_containment_latency_sla_ns")]
    pub detection_latency_sla_ns: u64,
}

fn default_containment_latency_sla_ns() -> u64 {
    DEFAULT_CONTAINMENT_LATENCY_SLA_NS
}

pub fn verify_benchmark_claim(bundle: &BenchmarkClaimBundle) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(
        bundle,
        "benchmark_verification_started",
        "pass",
        None,
    )];

    let ctx = PublicationContext::new(
        bundle.trace_id.clone(),
        bundle.decision_id.clone(),
        bundle.policy_id.clone(),
    );

    match evaluate_publication_gate(&bundle.input, &ctx) {
        Ok(recomputed) => {
            compare_float_check(
                &mut checks,
                "score_vs_node_matches",
                bundle.claimed.score_vs_node,
                recomputed.score_vs_node,
                CODE_BENCHMARK_SCORE,
            );
            compare_float_check(
                &mut checks,
                "score_vs_bun_matches",
                bundle.claimed.score_vs_bun,
                recomputed.score_vs_bun,
                CODE_BENCHMARK_SCORE,
            );

            if bundle.claimed.publish_allowed == recomputed.publish_allowed {
                pass_check(
                    &mut checks,
                    "publish_allowed_matches",
                    "claimed publish decision matches recomputed decision".to_string(),
                );
            } else {
                fail_check(
                    &mut checks,
                    "publish_allowed_matches",
                    CODE_BENCHMARK_PUBLISH,
                    format!(
                        "claimed publish_allowed={} but recomputed={}",
                        bundle.claimed.publish_allowed, recomputed.publish_allowed
                    ),
                );
            }

            let claimed_blockers = normalize_strings(&bundle.claimed.blockers);
            let actual_blockers = normalize_strings(&recomputed.blockers);
            if claimed_blockers == actual_blockers {
                pass_check(
                    &mut checks,
                    "blocker_set_matches",
                    "claimed blockers match recomputed blockers".to_string(),
                );
            } else {
                fail_check(
                    &mut checks,
                    "blocker_set_matches",
                    CODE_BENCHMARK_BLOCKERS,
                    format!(
                        "claimed blockers {:?} differ from recomputed {:?}",
                        claimed_blockers, actual_blockers
                    ),
                );
            }

            let node_ids = workload_id_set(&bundle.input.node_cases);
            let bun_ids = workload_id_set(&bundle.input.bun_cases);
            if node_ids == bun_ids {
                pass_check(
                    &mut checks,
                    "cross_runtime_workload_set_matches",
                    "node and bun workload sets are identical".to_string(),
                );
            } else {
                fail_check(
                    &mut checks,
                    "cross_runtime_workload_set_matches",
                    CODE_BENCHMARK_FAIRNESS,
                    format!(
                        "node workload ids {:?} differ from bun workload ids {:?}",
                        node_ids, bun_ids
                    ),
                );
            }
        }
        Err(error) => fail_check(
            &mut checks,
            "benchmark_gate_recompute",
            CODE_BENCHMARK_EVAL,
            format!("failed to recompute benchmark publication gate: {error}"),
        ),
    }

    let verdict = verdict_from_checks(&checks, false);
    events.push(event_with_verdict(
        bundle,
        "benchmark_verification_completed",
        verdict,
    ));
    append_failure_events(bundle, &checks, &mut events);

    build_report(bundle, "benchmark", verdict, checks, events)
}

pub fn verify_replay_claim(bundle: &ReplayClaimBundle) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(bundle, "replay_verification_started", "pass", None)];
    let mut saw_skipped = false;
    let verifier = BundleVerifier::new();

    append_report_checks(
        "integrity",
        &verifier.verify_integrity(&bundle.bundle, bundle.verification_timestamp_ns),
        &mut checks,
        &mut saw_skipped,
    );
    append_report_checks(
        "fidelity",
        &verifier.verify_replay(&bundle.bundle, bundle.verification_timestamp_ns),
        &mut checks,
        &mut saw_skipped,
    );

    if let Some(key_hex) = &bundle.signature_verification_key_hex {
        match parse_verification_key_hex(key_hex) {
            Ok(key) => append_report_checks(
                "signature",
                &verifier.verify_signature(&bundle.bundle, &key, bundle.verification_timestamp_ns),
                &mut checks,
                &mut saw_skipped,
            ),
            Err(error) => fail_check(
                &mut checks,
                "signature_key_parse",
                CODE_REPLAY_PARSE,
                error,
            ),
        }
    }

    if !bundle.receipt_verification_keys_hex.is_empty() {
        match parse_receipt_verification_keys(&bundle.receipt_verification_keys_hex) {
            Ok(keys) => append_report_checks(
                "receipts",
                &verifier.verify_receipts(
                    &bundle.bundle,
                    &keys,
                    SecurityEpoch::from_raw(bundle.current_epoch),
                    bundle.verification_timestamp_ns,
                ),
                &mut checks,
                &mut saw_skipped,
            ),
            Err(error) => fail_check(
                &mut checks,
                "receipt_key_parse",
                CODE_REPLAY_PARSE,
                error,
            ),
        }
    }

    if !bundle.counterfactual_configs.is_empty() {
        append_report_checks(
            "counterfactual",
            &verifier.verify_counterfactual(
                &bundle.bundle,
                &bundle.counterfactual_configs,
                bundle.verification_timestamp_ns,
            ),
            &mut checks,
            &mut saw_skipped,
        );
    }

    let verdict = verdict_from_checks(&checks, saw_skipped);
    events.push(event_with_verdict(
        bundle,
        "replay_verification_completed",
        verdict,
    ));
    append_failure_events(bundle, &checks, &mut events);

    build_report(bundle, "replay", verdict, checks, events)
}

pub fn verify_containment_claim(bundle: &ContainmentClaimBundle) -> ThirdPartyVerificationReport {
    let mut checks = Vec::new();
    let mut events = vec![event(
        bundle,
        "containment_verification_started",
        "pass",
        None,
    )];

    let total = bundle.result.scenarios.len();
    if total == bundle.result.total_scenarios {
        pass_check(
            &mut checks,
            "scenario_count_matches",
            format!("scenarios={} and total_scenarios={}", total, bundle.result.total_scenarios),
        );
    } else {
        fail_check(
            &mut checks,
            "scenario_count_matches",
            CODE_CONTAINMENT_COUNTS,
            format!(
                "scenarios={} but total_scenarios={}",
                total, bundle.result.total_scenarios
            ),
        );
    }

    let passed_count = bundle.result.scenarios.iter().filter(|s| s.passed).count();
    if passed_count == bundle.result.passed_scenarios {
        pass_check(
            &mut checks,
            "passed_count_matches",
            format!(
                "passed_scenarios={} and computed={}",
                bundle.result.passed_scenarios, passed_count
            ),
        );
    } else {
        fail_check(
            &mut checks,
            "passed_count_matches",
            CODE_CONTAINMENT_COUNTS,
            format!(
                "passed_scenarios={} but computed={}",
                bundle.result.passed_scenarios, passed_count
            ),
        );
    }

    let computed_overall = passed_count == total;
    if computed_overall == bundle.result.passed {
        pass_check(
            &mut checks,
            "overall_pass_flag_matches",
            format!(
                "result.passed={} and computed={}",
                bundle.result.passed, computed_overall
            ),
        );
    } else {
        fail_check(
            &mut checks,
            "overall_pass_flag_matches",
            CODE_CONTAINMENT_COUNTS,
            format!(
                "result.passed={} but computed={}",
                bundle.result.passed, computed_overall
            ),
        );
    }

    for scenario in &bundle.result.scenarios {
        let criteria_all_pass = scenario.criteria.iter().all(|c| c.passed);
        if criteria_all_pass == scenario.passed {
            pass_check(
                &mut checks,
                format!("criteria_consistency:{}", scenario.scenario_id),
                "scenario pass flag matches criterion outcomes".to_string(),
            );
        } else {
            fail_check(
                &mut checks,
                format!("criteria_consistency:{}", scenario.scenario_id),
                CODE_CONTAINMENT_CRITERIA,
                "scenario pass flag does not match criterion outcomes".to_string(),
            );
        }

        if scenario.passed && scenario.detection_latency_ns > bundle.detection_latency_sla_ns {
            fail_check(
                &mut checks,
                format!("latency_sla:{}", scenario.scenario_id),
                CODE_CONTAINMENT_SLA,
                format!(
                    "detection latency {}ns exceeds SLA {}ns",
                    scenario.detection_latency_ns, bundle.detection_latency_sla_ns
                ),
            );
        } else {
            pass_check(
                &mut checks,
                format!("latency_sla:{}", scenario.scenario_id),
                format!(
                    "detection latency {}ns within SLA {}ns",
                    scenario.detection_latency_ns, bundle.detection_latency_sla_ns
                ),
            );
        }

        if scenario.passed && !scenario.isolation_verified {
            fail_check(
                &mut checks,
                format!("isolation_verified:{}", scenario.scenario_id),
                CODE_CONTAINMENT_INVARIANT,
                "isolation invariant not satisfied".to_string(),
            );
        } else {
            pass_check(
                &mut checks,
                format!("isolation_verified:{}", scenario.scenario_id),
                format!("isolation_verified={}", scenario.isolation_verified),
            );
        }

        if scenario.passed && !scenario.recovery_verified {
            fail_check(
                &mut checks,
                format!("recovery_verified:{}", scenario.scenario_id),
                CODE_CONTAINMENT_INVARIANT,
                "recovery invariant not satisfied".to_string(),
            );
        } else {
            pass_check(
                &mut checks,
                format!("recovery_verified:{}", scenario.scenario_id),
                format!("recovery_verified={}", scenario.recovery_verified),
            );
        }
    }

    let verdict = verdict_from_checks(&checks, false);
    events.push(event_with_verdict(
        bundle,
        "containment_verification_completed",
        verdict,
    ));
    append_failure_events(bundle, &checks, &mut events);

    build_report(bundle, "containment", verdict, checks, events)
}

pub fn render_report_summary(report: &ThirdPartyVerificationReport) -> String {
    let failed = report.checks.iter().filter(|check| !check.passed).count();
    format!(
        "claim_type={} verdict={:?} checks={} failed={} exit_code={}",
        report.claim_type,
        report.verdict,
        report.checks.len(),
        failed,
        report.exit_code(),
    )
}

fn append_report_checks(
    phase: &str,
    report: &crate::incident_replay_bundle::VerificationReport,
    checks: &mut Vec<VerificationCheckResult>,
    saw_skipped: &mut bool,
) {
    for check in &report.checks {
        let name = format!("{phase}:{}", check.name);
        match &check.outcome {
            CheckOutcome::Pass => pass_check(checks, name, "pass".to_string()),
            CheckOutcome::Fail { reason } => {
                fail_check(checks, name, CODE_REPLAY_VERIFY, reason.clone())
            }
            CheckOutcome::Skipped { reason } => {
                *saw_skipped = true;
                checks.push(VerificationCheckResult {
                    name,
                    passed: true,
                    error_code: None,
                    detail: format!("skipped: {reason}"),
                });
            }
        }
    }
}

fn compare_float_check(
    checks: &mut Vec<VerificationCheckResult>,
    name: &str,
    claimed: f64,
    recomputed: f64,
    code: &str,
) {
    if (claimed - recomputed).abs() <= EPSILON {
        pass_check(
            checks,
            name.to_string(),
            format!("claimed={claimed:.12} recomputed={recomputed:.12}"),
        );
    } else {
        fail_check(
            checks,
            name.to_string(),
            code,
            format!("claimed={claimed:.12} recomputed={recomputed:.12}"),
        );
    }
}

fn verdict_from_checks(checks: &[VerificationCheckResult], saw_skipped: bool) -> VerificationVerdict {
    if checks.is_empty() {
        return VerificationVerdict::Inconclusive;
    }
    if checks.iter().any(|check| !check.passed) {
        return VerificationVerdict::Failed;
    }
    if saw_skipped {
        return VerificationVerdict::PartiallyVerified;
    }
    VerificationVerdict::Verified
}

fn pass_check(checks: &mut Vec<VerificationCheckResult>, name: impl Into<String>, detail: String) {
    checks.push(VerificationCheckResult {
        name: name.into(),
        passed: true,
        error_code: None,
        detail,
    });
}

fn fail_check(
    checks: &mut Vec<VerificationCheckResult>,
    name: impl Into<String>,
    error_code: &str,
    detail: String,
) {
    checks.push(VerificationCheckResult {
        name: name.into(),
        passed: false,
        error_code: Some(error_code.to_string()),
        detail,
    });
}

fn normalize_strings(values: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn workload_id_set(cases: &[crate::benchmark_denominator::BenchmarkCase]) -> BTreeSet<String> {
    cases
        .iter()
        .map(|case| case.workload_id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect()
}

fn parse_verification_key_hex(raw_hex: &str) -> Result<VerificationKey, String> {
    let trimmed = raw_hex.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|error| format!("failed to decode verification key hex '{trimmed}': {error}"))?;
    if bytes.len() != VERIFICATION_KEY_LEN {
        return Err(format!(
            "verification key hex must decode to {VERIFICATION_KEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; VERIFICATION_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(VerificationKey::from_bytes(key))
}

fn parse_receipt_verification_keys(
    raw: &BTreeMap<String, String>,
) -> Result<BTreeMap<EngineObjectId, VerificationKey>, String> {
    let mut parsed = BTreeMap::new();
    for (signer_id_hex, key_hex) in raw {
        let signer_id = EngineObjectId::from_hex(signer_id_hex.trim())
            .map_err(|error| format!("invalid signer id '{signer_id_hex}': {error}"))?;
        let key = parse_verification_key_hex(key_hex)?;
        parsed.insert(signer_id, key);
    }
    Ok(parsed)
}

fn event<T: ClaimContext>(
    ctx: &T,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
) -> VerifierEvent {
    VerifierEvent {
        trace_id: ctx.trace_id().to_string(),
        decision_id: ctx.decision_id().to_string(),
        policy_id: ctx.policy_id().to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(str::to_string),
    }
}

fn event_with_verdict<T: ClaimContext>(
    ctx: &T,
    event_name: &str,
    verdict: VerificationVerdict,
) -> VerifierEvent {
    let outcome = match verdict {
        VerificationVerdict::Verified => "pass",
        VerificationVerdict::PartiallyVerified => "partial",
        VerificationVerdict::Failed => "fail",
        VerificationVerdict::Inconclusive => "inconclusive",
    };
    event(ctx, event_name, outcome, None)
}

fn append_failure_events<T: ClaimContext>(
    ctx: &T,
    checks: &[VerificationCheckResult],
    events: &mut Vec<VerifierEvent>,
) {
    for check in checks.iter().filter(|check| !check.passed) {
        events.push(event(
            ctx,
            &format!("check_failed:{}", check.name),
            "fail",
            check.error_code.as_deref(),
        ));
    }
}

fn build_report<T: ClaimContext>(
    ctx: &T,
    claim_type: &str,
    verdict: VerificationVerdict,
    checks: Vec<VerificationCheckResult>,
    events: Vec<VerifierEvent>,
) -> ThirdPartyVerificationReport {
    ThirdPartyVerificationReport {
        claim_type: claim_type.to_string(),
        trace_id: ctx.trace_id().to_string(),
        decision_id: ctx.decision_id().to_string(),
        policy_id: ctx.policy_id().to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        verdict,
        checks,
        events,
    }
}

trait ClaimContext {
    fn trace_id(&self) -> &str;
    fn decision_id(&self) -> &str;
    fn policy_id(&self) -> &str;
}

impl ClaimContext for BenchmarkClaimBundle {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

impl ClaimContext for ReplayClaimBundle {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

impl ClaimContext for ContainmentClaimBundle {
    fn trace_id(&self) -> &str {
        &self.trace_id
    }

    fn decision_id(&self) -> &str {
        &self.decision_id
    }

    fn policy_id(&self) -> &str {
        &self.policy_id
    }
}
