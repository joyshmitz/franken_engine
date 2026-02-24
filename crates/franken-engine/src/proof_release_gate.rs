//! Release gate for proof-carrying optimization pipeline readiness.
//!
//! This module does not implement optimization passes. It validates that a
//! delivered optimization pipeline satisfies release-gate requirements:
//! - every optimization pass emits a proof artifact
//! - artifacts are replayable by an independent verifier
//! - failed proofs force unoptimized fallback with receipt
//! - replay time stays within a bounded multiplier
//! - artifacts are content-addressed for evidence/replay integration
//!
//! Plan reference: Section 10.9 item 4 (`bd-2rx`), implementation ownership
//! for pipeline itself in 10.12.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const PROOF_RELEASE_GATE_DOMAIN: &[u8] = b"FrankenEngine.ProofReleaseGate.v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationProofArtifact {
    pub optimization_pass: String,
    pub optimization_applied: bool,
    pub pre_ir_hash: [u8; 32],
    pub post_ir_hash: [u8; 32],
    pub ir_diff_size_bytes: u64,
    pub proof_hash: [u8; 32],
    pub verifier_version: String,
    pub proof_generation_time_ns: u64,
    pub verification_time_ns: u64,
    pub independent_replay_verified: bool,
    pub replay_command: String,
    pub proof_verified: bool,
    pub fallback_triggered: bool,
    pub fallback_receipt_id: Option<String>,
}

impl OptimizationProofArtifact {
    fn has_required_bundle_fields(&self) -> bool {
        !self.optimization_pass.trim().is_empty()
            && !self.verifier_version.trim().is_empty()
            && !self.replay_command.trim().is_empty()
            && self.ir_diff_size_bytes > 0
            && self.proof_generation_time_ns > 0
            && self.verification_time_ns > 0
            && self.proof_hash != [0u8; 32]
            && self.pre_ir_hash != [0u8; 32]
            && self.post_ir_hash != [0u8; 32]
    }

    fn fallback_is_valid(&self) -> bool {
        if self.proof_verified {
            return true;
        }
        !self.optimization_applied
            && self.fallback_triggered
            && self
                .fallback_receipt_id
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "fallback_receipt_id".to_string(),
            match &self.fallback_receipt_id {
                Some(v) => CanonicalValue::String(v.clone()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "fallback_triggered".to_string(),
            CanonicalValue::Bool(self.fallback_triggered),
        );
        map.insert(
            "independent_replay_verified".to_string(),
            CanonicalValue::Bool(self.independent_replay_verified),
        );
        map.insert(
            "ir_diff_size_bytes".to_string(),
            CanonicalValue::U64(self.ir_diff_size_bytes),
        );
        map.insert(
            "optimization_applied".to_string(),
            CanonicalValue::Bool(self.optimization_applied),
        );
        map.insert(
            "optimization_pass".to_string(),
            CanonicalValue::String(self.optimization_pass.clone()),
        );
        map.insert(
            "post_ir_hash".to_string(),
            CanonicalValue::Bytes(self.post_ir_hash.to_vec()),
        );
        map.insert(
            "pre_ir_hash".to_string(),
            CanonicalValue::Bytes(self.pre_ir_hash.to_vec()),
        );
        map.insert(
            "proof_generation_time_ns".to_string(),
            CanonicalValue::U64(self.proof_generation_time_ns),
        );
        map.insert(
            "proof_hash".to_string(),
            CanonicalValue::Bytes(self.proof_hash.to_vec()),
        );
        map.insert(
            "proof_verified".to_string(),
            CanonicalValue::Bool(self.proof_verified),
        );
        map.insert(
            "replay_command".to_string(),
            CanonicalValue::String(self.replay_command.clone()),
        );
        map.insert(
            "verification_time_ns".to_string(),
            CanonicalValue::U64(self.verification_time_ns),
        );
        map.insert(
            "verifier_version".to_string(),
            CanonicalValue::String(self.verifier_version.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofChainBundle {
    pub candidate_version: String,
    pub compilation_id: String,
    pub original_compile_time_ns: u64,
    pub replay_time_ns: u64,
    pub archive_root: [u8; 32],
    pub archive_uri: String,
    pub artifacts: Vec<OptimizationProofArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateInput {
    pub trace_id: String,
    pub policy_id: String,
    pub expected_optimization_passes: BTreeSet<String>,
    pub bundle: ProofChainBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGateThresholds {
    pub max_replay_multiplier_millionths: u64,
}

impl Default for ReleaseGateThresholds {
    fn default() -> Self {
        Self {
            // 5x replay bound from bead definition.
            max_replay_multiplier_millionths: 5_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateFailureCode {
    MissingProofArtifact,
    MissingBundleField,
    ProofVerificationFailed,
    FallbackPathInvalid,
    IndependentReplayFailed,
    ReplayMultiplierExceeded,
    ArchiveNotContentAddressed,
}

impl fmt::Display for GateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProofArtifact => f.write_str("missing_proof_artifact"),
            Self::MissingBundleField => f.write_str("missing_bundle_field"),
            Self::ProofVerificationFailed => f.write_str("proof_verification_failed"),
            Self::FallbackPathInvalid => f.write_str("fallback_path_invalid"),
            Self::IndependentReplayFailed => f.write_str("independent_replay_failed"),
            Self::ReplayMultiplierExceeded => f.write_str("replay_multiplier_exceeded"),
            Self::ArchiveNotContentAddressed => f.write_str("archive_not_content_addressed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFinding {
    pub code: GateFailureCode,
    pub optimization_pass: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub optimization_pass: Option<String>,
    pub proof_status: Option<String>,
    pub proof_hash: Option<String>,
    pub fallback_triggered: Option<bool>,
    pub verification_time_ns: Option<u64>,
    pub ir_diff_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDecisionArtifact {
    pub decision_id: String,
    pub candidate_version: String,
    pub pass: bool,
    pub replay_multiplier_millionths: u64,
    pub rollback_token: String,
    pub findings: Vec<GateFinding>,
    pub logs: Vec<ProofGateLogEvent>,
}

fn is_content_addressed_archive(uri: &str, root: &[u8; 32]) -> bool {
    uri.starts_with("cas://") && *root != [0u8; 32]
}

fn compute_replay_multiplier_millionths(replay_ns: u64, compile_ns: u64) -> u64 {
    if compile_ns == 0 {
        return u64::MAX;
    }
    replay_ns.saturating_mul(1_000_000) / compile_ns
}

fn canonical_decision_value(
    input: &ReleaseGateInput,
    findings: &[GateFinding],
    pass: bool,
    replay_multiplier_millionths: u64,
) -> CanonicalValue {
    let mut map = std::collections::BTreeMap::new();
    let mut expected_passes: Vec<String> =
        input.expected_optimization_passes.iter().cloned().collect();
    expected_passes.sort();
    let expected_array = expected_passes
        .into_iter()
        .map(CanonicalValue::String)
        .collect::<Vec<_>>();
    let artifact_values = input
        .bundle
        .artifacts
        .iter()
        .map(OptimizationProofArtifact::canonical_value)
        .collect::<Vec<_>>();
    let finding_values = findings
        .iter()
        .map(|finding| {
            let mut inner = std::collections::BTreeMap::new();
            inner.insert(
                "code".to_string(),
                CanonicalValue::String(finding.code.to_string()),
            );
            inner.insert(
                "detail".to_string(),
                CanonicalValue::String(finding.detail.clone()),
            );
            inner.insert(
                "optimization_pass".to_string(),
                match &finding.optimization_pass {
                    Some(pass_name) => CanonicalValue::String(pass_name.clone()),
                    None => CanonicalValue::Null,
                },
            );
            CanonicalValue::Map(inner)
        })
        .collect::<Vec<_>>();

    map.insert(
        "archive_root".to_string(),
        CanonicalValue::Bytes(input.bundle.archive_root.to_vec()),
    );
    map.insert(
        "archive_uri".to_string(),
        CanonicalValue::String(input.bundle.archive_uri.clone()),
    );
    map.insert(
        "artifacts".to_string(),
        CanonicalValue::Array(artifact_values),
    );
    map.insert(
        "candidate_version".to_string(),
        CanonicalValue::String(input.bundle.candidate_version.clone()),
    );
    map.insert(
        "compilation_id".to_string(),
        CanonicalValue::String(input.bundle.compilation_id.clone()),
    );
    map.insert(
        "expected_optimization_passes".to_string(),
        CanonicalValue::Array(expected_array),
    );
    map.insert(
        "findings".to_string(),
        CanonicalValue::Array(finding_values),
    );
    map.insert("pass".to_string(), CanonicalValue::Bool(pass));
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert(
        "replay_multiplier_millionths".to_string(),
        CanonicalValue::U64(replay_multiplier_millionths),
    );
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );
    CanonicalValue::Map(map)
}

fn decision_id_for(
    input: &ReleaseGateInput,
    findings: &[GateFinding],
    pass: bool,
    replay_multiplier_millionths: u64,
) -> String {
    let material = canonical_decision_value(input, findings, pass, replay_multiplier_millionths);
    let encoded = deterministic_serde::encode_value(&material);
    let mut preimage = Vec::with_capacity(PROOF_RELEASE_GATE_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(PROOF_RELEASE_GATE_DOMAIN);
    preimage.extend_from_slice(&encoded);
    to_hex(&hash_bytes(&preimage))
}

pub fn evaluate_release_gate(
    input: &ReleaseGateInput,
    thresholds: &ReleaseGateThresholds,
) -> PromotionDecisionArtifact {
    let mut findings: Vec<GateFinding> = Vec::new();
    let present_passes: BTreeSet<String> = input
        .bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.optimization_pass.clone())
        .collect();

    for expected in &input.expected_optimization_passes {
        if !present_passes.contains(expected) {
            findings.push(GateFinding {
                code: GateFailureCode::MissingProofArtifact,
                optimization_pass: Some(expected.clone()),
                detail: "expected optimization pass has no proof artifact".to_string(),
            });
        }
    }

    for artifact in &input.bundle.artifacts {
        if !artifact.has_required_bundle_fields() {
            findings.push(GateFinding {
                code: GateFailureCode::MissingBundleField,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "artifact bundle missing required fields".to_string(),
            });
        }

        if !artifact.proof_verified && artifact.optimization_applied {
            findings.push(GateFinding {
                code: GateFailureCode::ProofVerificationFailed,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "optimization applied despite failed proof verification".to_string(),
            });
        }

        if !artifact.fallback_is_valid() {
            findings.push(GateFinding {
                code: GateFailureCode::FallbackPathInvalid,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "proof failure did not trigger valid unoptimized fallback".to_string(),
            });
        }

        if artifact.proof_verified && !artifact.independent_replay_verified {
            findings.push(GateFinding {
                code: GateFailureCode::IndependentReplayFailed,
                optimization_pass: Some(artifact.optimization_pass.clone()),
                detail: "proof artifact did not pass independent replay verification".to_string(),
            });
        }
    }

    let replay_multiplier_millionths = compute_replay_multiplier_millionths(
        input.bundle.replay_time_ns,
        input.bundle.original_compile_time_ns,
    );
    if replay_multiplier_millionths > thresholds.max_replay_multiplier_millionths {
        findings.push(GateFinding {
            code: GateFailureCode::ReplayMultiplierExceeded,
            optimization_pass: None,
            detail: format!(
                "replay multiplier {} exceeds threshold {}",
                replay_multiplier_millionths, thresholds.max_replay_multiplier_millionths
            ),
        });
    }

    if !is_content_addressed_archive(&input.bundle.archive_uri, &input.bundle.archive_root) {
        findings.push(GateFinding {
            code: GateFailureCode::ArchiveNotContentAddressed,
            optimization_pass: None,
            detail: "artifact archive must be content-addressed (`cas://`) with non-zero root"
                .to_string(),
        });
    }

    let pass = findings.is_empty();
    let decision_id = decision_id_for(input, &findings, pass, replay_multiplier_millionths);
    let rollback_token = format!("rollback-{}", &decision_id[..16]);

    let mut logs = Vec::new();
    for artifact in &input.bundle.artifacts {
        logs.push(ProofGateLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "proof_release_gate".to_string(),
            event: "optimization_proof_evaluated".to_string(),
            outcome: if artifact.proof_verified {
                "verified"
            } else {
                "failed"
            }
            .to_string(),
            error_code: if artifact.proof_verified {
                None
            } else {
                Some("proof_verification_failed".to_string())
            },
            optimization_pass: Some(artifact.optimization_pass.clone()),
            proof_status: Some(if artifact.proof_verified {
                "verified".to_string()
            } else {
                "failed".to_string()
            }),
            proof_hash: Some(to_hex(&artifact.proof_hash)),
            fallback_triggered: Some(artifact.fallback_triggered),
            verification_time_ns: Some(artifact.verification_time_ns),
            ir_diff_size_bytes: Some(artifact.ir_diff_size_bytes),
        });
    }

    logs.push(ProofGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "proof_release_gate".to_string(),
        event: "release_gate_decision".to_string(),
        outcome: if pass { "pass" } else { "fail" }.to_string(),
        error_code: findings.first().map(|f| f.code.to_string()),
        optimization_pass: None,
        proof_status: None,
        proof_hash: None,
        fallback_triggered: None,
        verification_time_ns: None,
        ir_diff_size_bytes: None,
    });

    PromotionDecisionArtifact {
        decision_id,
        candidate_version: input.bundle.candidate_version.clone(),
        pass,
        replay_multiplier_millionths,
        rollback_token,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(label: &str) -> [u8; 32] {
        hash_bytes(label.as_bytes())
    }

    fn ok_artifact(pass_name: &str) -> OptimizationProofArtifact {
        OptimizationProofArtifact {
            optimization_pass: pass_name.to_string(),
            optimization_applied: true,
            pre_ir_hash: hash("pre"),
            post_ir_hash: hash("post"),
            ir_diff_size_bytes: 48,
            proof_hash: hash("proof"),
            verifier_version: "verifier-v1".to_string(),
            proof_generation_time_ns: 1_000,
            verification_time_ns: 2_000,
            independent_replay_verified: true,
            replay_command: format!("verify --pass {pass_name}"),
            proof_verified: true,
            fallback_triggered: false,
            fallback_receipt_id: None,
        }
    }

    fn base_input() -> ReleaseGateInput {
        let mut expected = BTreeSet::new();
        expected.insert("inline".to_string());
        expected.insert("dce".to_string());

        ReleaseGateInput {
            trace_id: "trace-gate-1".to_string(),
            policy_id: "policy-opt-gate".to_string(),
            expected_optimization_passes: expected,
            bundle: ProofChainBundle {
                candidate_version: "candidate-2026-02-20".to_string(),
                compilation_id: "compile-0001".to_string(),
                original_compile_time_ns: 50_000_000,
                replay_time_ns: 200_000_000,
                archive_root: hash("archive-root"),
                archive_uri: "cas://proof-chain/compile-0001".to_string(),
                artifacts: vec![ok_artifact("inline"), ok_artifact("dce")],
            },
        }
    }

    #[test]
    fn release_gate_passes_for_complete_replayable_pipeline() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(decision.pass);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.logs.len(), 3); // 2 artifacts + 1 summary
        assert_eq!(decision.replay_multiplier_millionths, 4_000_000);
    }

    #[test]
    fn release_gate_fails_when_expected_pass_artifact_missing() {
        let mut input = base_input();
        input.bundle.artifacts = vec![ok_artifact("inline")];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingProofArtifact)
        );
    }

    #[test]
    fn release_gate_fails_when_proof_fails_but_optimization_applied() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = true;
        input.bundle.artifacts[0].fallback_triggered = false;
        input.bundle.artifacts[0].fallback_receipt_id = None;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ProofVerificationFailed)
        );
    }

    #[test]
    fn release_gate_requires_fallback_receipt_on_failed_proof() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = false;
        input.bundle.artifacts[0].fallback_receipt_id = None;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
        );
    }

    #[test]
    fn release_gate_fails_when_replay_multiplier_exceeds_threshold() {
        let mut input = base_input();
        input.bundle.replay_time_ns = 700_000_000;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
        );
    }

    #[test]
    fn release_gate_decision_is_deterministic() {
        let input = base_input();
        let a = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let b = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert_eq!(a.decision_id, b.decision_id);
        assert_eq!(a, b);
    }

    // ── GateFailureCode ─────────────────────────────────────────────

    #[test]
    fn gate_failure_code_display() {
        assert_eq!(
            format!("{}", GateFailureCode::MissingProofArtifact),
            "missing_proof_artifact"
        );
        assert_eq!(
            format!("{}", GateFailureCode::MissingBundleField),
            "missing_bundle_field"
        );
        assert_eq!(
            format!("{}", GateFailureCode::ProofVerificationFailed),
            "proof_verification_failed"
        );
        assert_eq!(
            format!("{}", GateFailureCode::FallbackPathInvalid),
            "fallback_path_invalid"
        );
        assert_eq!(
            format!("{}", GateFailureCode::IndependentReplayFailed),
            "independent_replay_failed"
        );
        assert_eq!(
            format!("{}", GateFailureCode::ReplayMultiplierExceeded),
            "replay_multiplier_exceeded"
        );
        assert_eq!(
            format!("{}", GateFailureCode::ArchiveNotContentAddressed),
            "archive_not_content_addressed"
        );
    }

    #[test]
    fn gate_failure_code_ordering() {
        assert!(GateFailureCode::MissingProofArtifact < GateFailureCode::MissingBundleField);
        assert!(
            GateFailureCode::ReplayMultiplierExceeded
                < GateFailureCode::ArchiveNotContentAddressed
        );
    }

    #[test]
    fn gate_failure_code_serde_roundtrip() {
        for code in [
            GateFailureCode::MissingProofArtifact,
            GateFailureCode::MissingBundleField,
            GateFailureCode::ProofVerificationFailed,
            GateFailureCode::FallbackPathInvalid,
            GateFailureCode::IndependentReplayFailed,
            GateFailureCode::ReplayMultiplierExceeded,
            GateFailureCode::ArchiveNotContentAddressed,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: GateFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    // ── ReleaseGateThresholds ───────────────────────────────────────

    #[test]
    fn thresholds_default() {
        let t = ReleaseGateThresholds::default();
        assert_eq!(t.max_replay_multiplier_millionths, 5_000_000);
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = ReleaseGateThresholds {
            max_replay_multiplier_millionths: 3_000_000,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: ReleaseGateThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // ── compute_replay_multiplier ───────────────────────────────────

    #[test]
    fn replay_multiplier_normal() {
        assert_eq!(
            compute_replay_multiplier_millionths(200_000_000, 50_000_000),
            4_000_000
        );
    }

    #[test]
    fn replay_multiplier_zero_compile_time() {
        assert_eq!(
            compute_replay_multiplier_millionths(100, 0),
            u64::MAX
        );
    }

    #[test]
    fn replay_multiplier_one_to_one() {
        assert_eq!(
            compute_replay_multiplier_millionths(100, 100),
            1_000_000
        );
    }

    // ── is_content_addressed_archive ────────────────────────────────

    #[test]
    fn content_addressed_archive_valid() {
        assert!(is_content_addressed_archive("cas://foo", &hash("x")));
    }

    #[test]
    fn content_addressed_archive_wrong_scheme() {
        assert!(!is_content_addressed_archive("https://foo", &hash("x")));
    }

    #[test]
    fn content_addressed_archive_zero_root() {
        assert!(!is_content_addressed_archive("cas://foo", &[0u8; 32]));
    }

    // ── artifact validation ─────────────────────────────────────────

    #[test]
    fn artifact_missing_bundle_fields_detected() {
        let mut input = base_input();
        input.bundle.artifacts[0].optimization_pass = "  ".to_string();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn artifact_zero_proof_hash_is_missing_field() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_hash = [0u8; 32];
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::MissingBundleField)
        );
    }

    #[test]
    fn independent_replay_not_verified_fails() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = true;
        input.bundle.artifacts[0].independent_replay_verified = false;
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::IndependentReplayFailed)
        );
    }

    #[test]
    fn archive_not_content_addressed_fails() {
        let mut input = base_input();
        input.bundle.archive_uri = "https://not-cas".to_string();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(!decision.pass);
        assert!(
            decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ArchiveNotContentAddressed)
        );
    }

    // ── valid fallback path ─────────────────────────────────────────

    #[test]
    fn valid_fallback_with_receipt_passes() {
        let mut input = base_input();
        // Proof failed but correct fallback
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = true;
        input.bundle.artifacts[0].fallback_receipt_id = Some("receipt-001".to_string());
        // This still has independent_replay_verified=true but proof_verified=false
        // → IndependentReplayFailed won't fire because the check is `proof_verified && !independent_replay_verified`
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // Should not have FallbackPathInvalid or ProofVerificationFailed
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
        );
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ProofVerificationFailed)
        );
    }

    // ── decision artifact structure ─────────────────────────────────

    #[test]
    fn decision_has_rollback_token() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert!(decision.rollback_token.starts_with("rollback-"));
        assert_eq!(decision.rollback_token.len(), "rollback-".len() + 16);
    }

    #[test]
    fn decision_candidate_version() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        assert_eq!(decision.candidate_version, "candidate-2026-02-20");
    }

    #[test]
    fn decision_logs_include_per_artifact_and_summary() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        // 2 artifacts + 1 summary
        assert_eq!(decision.logs.len(), 3);
        let summary = &decision.logs[2];
        assert_eq!(summary.event, "release_gate_decision");
        assert_eq!(summary.outcome, "pass");
    }

    #[test]
    fn decision_log_failed_proof_has_error_code() {
        let mut input = base_input();
        input.bundle.artifacts[0].proof_verified = false;
        input.bundle.artifacts[0].optimization_applied = false;
        input.bundle.artifacts[0].fallback_triggered = true;
        input.bundle.artifacts[0].fallback_receipt_id = Some("r".to_string());
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let log = &decision.logs[0];
        assert_eq!(log.outcome, "failed");
        assert_eq!(
            log.error_code.as_deref(),
            Some("proof_verification_failed")
        );
    }

    // ── serde roundtrips ────────────────────────────────────────────

    #[test]
    fn optimization_proof_artifact_serde() {
        let artifact = ok_artifact("inline");
        let json = serde_json::to_string(&artifact).unwrap();
        let back: OptimizationProofArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back, artifact);
    }

    #[test]
    fn proof_chain_bundle_serde() {
        let input = base_input();
        let json = serde_json::to_string(&input.bundle).unwrap();
        let back: ProofChainBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input.bundle);
    }

    #[test]
    fn promotion_decision_artifact_serde() {
        let input = base_input();
        let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
        let json = serde_json::to_string(&decision).unwrap();
        let back: PromotionDecisionArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back, decision);
    }

    #[test]
    fn gate_finding_serde() {
        let finding = GateFinding {
            code: GateFailureCode::MissingProofArtifact,
            optimization_pass: Some("inline".to_string()),
            detail: "missing artifact".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: GateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    // ── custom thresholds ───────────────────────────────────────────

    #[test]
    fn custom_replay_threshold_allows_higher_multiplier() {
        let mut input = base_input();
        input.bundle.replay_time_ns = 700_000_000; // 14x > 5x default
        let thresholds = ReleaseGateThresholds {
            max_replay_multiplier_millionths: 15_000_000, // 15x
        };
        let decision = evaluate_release_gate(&input, &thresholds);
        assert!(
            !decision
                .findings
                .iter()
                .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
        );
    }
}
