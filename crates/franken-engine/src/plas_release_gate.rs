//! Deterministic release gate for PLAS cohort activation.
//!
//! Validates that prioritized extension cohorts run with PLAS active authority
//! control, signed capability witnesses, escrow-path replay evidence, and
//! revocation/traceability guarantees.
//!
//! Plan reference: Section 10.9 item 6 (`bd-2n3`) with implementation ownership
//! in Section 10.15.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_witness::{
    CapabilityEscrowReceiptRecord, PublicationEntryKind, PublishedWitnessArtifact,
    WitnessPublicationPipeline,
};
use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::Capability;
use crate::signature_preimage::VerificationKey;

const PLAS_RELEASE_GATE_COMPONENT: &str = "plas_release_gate";

/// PLAS activation state for a prioritized cohort extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasActivationMode {
    Active,
    Shadow,
    AuditOnly,
    Disabled,
}

impl PlasActivationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Shadow => "shadow",
            Self::AuditOnly => "audit_only",
            Self::Disabled => "disabled",
        }
    }
}

impl fmt::Display for PlasActivationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Escrow replay evidence for one grant decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasEscrowReplayEvidence {
    pub receipt_id: String,
    pub replay_decision_kind: String,
    pub replay_outcome: String,
    pub replay_policy_id: String,
    pub deterministic_replay: bool,
    pub replay_trace_id: String,
}

impl PlasEscrowReplayEvidence {
    fn normalize(&mut self) {
        self.receipt_id = self.receipt_id.trim().to_string();
        self.replay_decision_kind = self.replay_decision_kind.trim().to_string();
        self.replay_outcome = self.replay_outcome.trim().to_string();
        self.replay_policy_id = self.replay_policy_id.trim().to_string();
        self.replay_trace_id = self.replay_trace_id.trim().to_string();
    }
}

/// Grant record for release-gate validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasGrantCheckRecord {
    pub capability: Capability,
    pub receipt: CapabilityEscrowReceiptRecord,
    pub witness_artifact: PublishedWitnessArtifact,
    pub replay_evidence: Option<PlasEscrowReplayEvidence>,
}

impl PlasGrantCheckRecord {
    fn normalize(&mut self) {
        normalize_receipt(&mut self.receipt);
        if let Some(replay) = &mut self.replay_evidence {
            replay.normalize();
        }
    }

    fn sort_key(&self) -> (u64, String, String) {
        (
            self.receipt.timestamp_ns,
            self.receipt.receipt_id.clone(),
            self.capability.as_str().to_string(),
        )
    }
}

/// Revocation round-trip record for release-gate validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasRevocationCheckRecord {
    pub capability: Capability,
    pub receipt: CapabilityEscrowReceiptRecord,
    pub witness_artifact: PublishedWitnessArtifact,
}

impl PlasRevocationCheckRecord {
    fn normalize(&mut self) {
        normalize_receipt(&mut self.receipt);
    }

    fn sort_key(&self) -> (u64, String, String) {
        (
            self.receipt.timestamp_ns,
            self.receipt.receipt_id.clone(),
            self.capability.as_str().to_string(),
        )
    }
}

/// One prioritized extension entry in the PLAS release-gate cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasCohortExtension {
    pub extension_id: EngineObjectId,
    pub activation_mode: PlasActivationMode,
    #[serde(default)]
    pub manifest_capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub active_capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub grants: Vec<PlasGrantCheckRecord>,
    #[serde(default)]
    pub revocations: Vec<PlasRevocationCheckRecord>,
}

impl PlasCohortExtension {
    fn normalize(&mut self) {
        self.grants
            .iter_mut()
            .for_each(PlasGrantCheckRecord::normalize);
        self.revocations
            .iter_mut()
            .for_each(PlasRevocationCheckRecord::normalize);
        self.grants.sort_by_key(PlasGrantCheckRecord::sort_key);
        self.revocations
            .sort_by_key(PlasRevocationCheckRecord::sort_key);
    }
}

/// Gate input for PLAS release readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub cohort_id: String,
    pub extensions: Vec<PlasCohortExtension>,
}

impl PlasReleaseGateInput {
    fn normalize(&mut self) {
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.cohort_id = self.cohort_id.trim().to_string();

        self.extensions
            .iter_mut()
            .for_each(PlasCohortExtension::normalize);
        self.extensions
            .sort_by_key(|entry| entry.extension_id.to_string());
    }

    fn validate(&self) -> Result<(), PlasReleaseGateError> {
        if self.trace_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.cohort_id.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "cohort_id must not be empty".to_string(),
            });
        }
        if self.extensions.is_empty() {
            return Err(PlasReleaseGateError::InvalidInput {
                detail: "at least one cohort extension is required".to_string(),
            });
        }

        let mut seen_extension_ids = BTreeSet::new();
        for extension in &self.extensions {
            let extension_key = extension.extension_id.to_string();
            if !seen_extension_ids.insert(extension_key.clone()) {
                return Err(PlasReleaseGateError::InvalidInput {
                    detail: format!("duplicate extension in cohort input: {extension_key}"),
                });
            }
        }
        Ok(())
    }
}

/// Trust-anchor material used for independent witness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateTrustAnchors {
    pub witness_verification_key: VerificationKey,
    pub transparency_log_verification_key: VerificationKey,
}

/// Explicit failure taxonomy for PLAS release-gate checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasReleaseGateFailureCode {
    CohortPlasNotActive,
    CohortCoverageMissingGrantExercise,
    MissingCapabilityWitness,
    WitnessSignatureVerificationFailed,
    EscrowReplayEvidenceMissing,
    EscrowReplayMismatch,
    RevocationWitnessMissing,
    RevocationEscrowEventMissing,
    AmbientAuthorityDetected,
}

impl PlasReleaseGateFailureCode {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::CohortPlasNotActive => "cohort_plas_not_active",
            Self::CohortCoverageMissingGrantExercise => "cohort_coverage_missing_grant_exercise",
            Self::MissingCapabilityWitness => "missing_capability_witness",
            Self::WitnessSignatureVerificationFailed => "witness_signature_verification_failed",
            Self::EscrowReplayEvidenceMissing => "escrow_replay_evidence_missing",
            Self::EscrowReplayMismatch => "escrow_replay_mismatch",
            Self::RevocationWitnessMissing => "revocation_witness_missing",
            Self::RevocationEscrowEventMissing => "revocation_escrow_event_missing",
            Self::AmbientAuthorityDetected => "ambient_authority_detected",
        }
    }
}

impl fmt::Display for PlasReleaseGateFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Structured finding for one gate failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateFinding {
    pub code: PlasReleaseGateFailureCode,
    pub extension_id: String,
    pub receipt_id: Option<String>,
    pub detail: String,
}

/// Structured gate log event with stable keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: Option<String>,
    pub receipt_id: Option<String>,
    pub capability: Option<String>,
}

/// Deterministic decision artifact for PLAS release-gate checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasReleaseGateDecisionArtifact {
    pub decision_id: String,
    pub cohort_id: String,
    pub pass: bool,
    pub checked_extensions: u64,
    pub checked_grants: u64,
    pub checked_revocations: u64,
    pub findings: Vec<PlasReleaseGateFinding>,
    pub logs: Vec<PlasReleaseGateLogEvent>,
    pub decision_hash: ContentHash,
}

/// Errors for invalid gate input or deterministic artifact serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlasReleaseGateError {
    InvalidInput { detail: String },
    Serialization { detail: String },
}

impl fmt::Display for PlasReleaseGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { detail } => write!(f, "invalid PLAS release gate input: {detail}"),
            Self::Serialization { detail } => write!(f, "serialization failure: {detail}"),
        }
    }
}

impl std::error::Error for PlasReleaseGateError {}

/// Evaluate PLAS release-gate readiness for a prioritized extension cohort.
pub fn evaluate_plas_release_gate(
    input: &PlasReleaseGateInput,
    trust_anchors: &PlasReleaseGateTrustAnchors,
) -> Result<PlasReleaseGateDecisionArtifact, PlasReleaseGateError> {
    let mut normalized = input.clone();
    normalized.normalize();
    normalized.validate()?;

    let mut findings = Vec::new();
    let mut logs = Vec::new();
    let mut checked_grants = 0u64;
    let mut checked_revocations = 0u64;

    for extension in &normalized.extensions {
        let extension_label = extension.extension_id.to_string();

        if extension.activation_mode != PlasActivationMode::Active {
            add_finding(
                &mut findings,
                PlasReleaseGateFailureCode::CohortPlasNotActive,
                &extension_label,
                None,
                format!(
                    "extension must run with PLAS active, got {}",
                    extension.activation_mode
                ),
            );
            push_log(
                &mut logs,
                &normalized,
                "cohort_activation",
                "fail",
                Some(PlasReleaseGateFailureCode::CohortPlasNotActive.error_code()),
                Some(&extension_label),
                None,
                None,
            );
        } else {
            push_log(
                &mut logs,
                &normalized,
                "cohort_activation",
                "pass",
                None,
                Some(&extension_label),
                None,
                None,
            );
        }

        if extension.grants.is_empty() {
            add_finding(
                &mut findings,
                PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise,
                &extension_label,
                None,
                "cohort extension has no exercised PLAS grant".to_string(),
            );
            push_log(
                &mut logs,
                &normalized,
                "cohort_grant_coverage",
                "fail",
                Some(PlasReleaseGateFailureCode::CohortCoverageMissingGrantExercise.error_code()),
                Some(&extension_label),
                None,
                None,
            );
        }

        let mut traced_capabilities = BTreeSet::new();
        let mut granted_capabilities = BTreeSet::new();
        let mut seen_grant_receipts = BTreeSet::new();

        for grant in &extension.grants {
            checked_grants = checked_grants.saturating_add(1);
            let capability_label = grant.capability.as_str().to_string();
            let receipt_id = grant.receipt.receipt_id.trim().to_string();

            if !seen_grant_receipts.insert(receipt_id.clone()) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::MissingCapabilityWitness,
                    &extension_label,
                    Some(&receipt_id),
                    "duplicate grant receipt_id in cohort input".to_string(),
                );
            }

            let grant_receipt_valid = validate_grant_receipt(
                &grant.receipt,
                &extension.extension_id,
                &capability_label,
                &normalized.policy_id,
            );
            if let Err(detail) = grant_receipt_valid {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::MissingCapabilityWitness,
                    &extension_label,
                    Some(&receipt_id),
                    detail,
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "grant_witness_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::MissingCapabilityWitness.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            let witness = &grant.witness_artifact.witness;
            let witness_has_fields = witness.extension_id == extension.extension_id
                && witness.timestamp_ns > 0
                && !witness.required_capabilities.is_empty()
                && witness.required_capabilities.contains(&grant.capability)
                && !witness.synthesizer_signature.is_empty()
                && !grant.witness_artifact.signature_bundle.is_empty();
            if !witness_has_fields {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::MissingCapabilityWitness,
                    &extension_label,
                    Some(&receipt_id),
                    "signed capability witness is missing required grant fields".to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "grant_witness_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::MissingCapabilityWitness.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            if let Err(err) = WitnessPublicationPipeline::verify_artifact(
                &grant.witness_artifact,
                &trust_anchors.witness_verification_key,
                &trust_anchors.transparency_log_verification_key,
            ) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed,
                    &extension_label,
                    Some(&receipt_id),
                    format!("witness/trust-anchor verification failed: {err}"),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "grant_witness_validation",
                    "fail",
                    Some(
                        PlasReleaseGateFailureCode::WitnessSignatureVerificationFailed.error_code(),
                    ),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            traced_capabilities.extend(witness.required_capabilities.iter().cloned());
            granted_capabilities.insert(grant.capability.clone());

            push_log(
                &mut logs,
                &normalized,
                "grant_witness_validation",
                "pass",
                None,
                Some(&extension_label),
                Some(&receipt_id),
                Some(&capability_label),
            );

            let Some(replay) = &grant.replay_evidence else {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "missing escrow replay evidence for grant".to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "escrow_replay_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::EscrowReplayEvidenceMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            };

            let replay_matches = replay.deterministic_replay
                && replay.receipt_id == grant.receipt.receipt_id
                && replay.replay_decision_kind == grant.receipt.decision_kind
                && replay.replay_outcome == grant.receipt.outcome
                && replay.replay_policy_id == grant.receipt.policy_id;
            if !replay_matches {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::EscrowReplayMismatch,
                    &extension_label,
                    Some(&receipt_id),
                    "escrow replay does not deterministically reproduce the original grant"
                        .to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "escrow_replay_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::EscrowReplayMismatch.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            push_log(
                &mut logs,
                &normalized,
                "escrow_replay_validation",
                "pass",
                None,
                Some(&extension_label),
                Some(&receipt_id),
                Some(&capability_label),
            );
        }

        let mut seen_revocation_receipts = BTreeSet::new();
        for revocation in &extension.revocations {
            checked_revocations = checked_revocations.saturating_add(1);
            let capability_label = revocation.capability.as_str().to_string();
            let receipt_id = revocation.receipt.receipt_id.trim().to_string();

            if !seen_revocation_receipts.insert(receipt_id.clone()) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "duplicate revocation receipt_id in cohort input".to_string(),
                );
            }

            if !granted_capabilities.contains(&revocation.capability) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "revocation capability has no corresponding grant in cohort evidence"
                        .to_string(),
                );
            }

            if let Err(detail) = validate_revocation_receipt(
                &revocation.receipt,
                &extension.extension_id,
                &capability_label,
                &normalized.policy_id,
            ) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationEscrowEventMissing,
                    &extension_label,
                    Some(&receipt_id),
                    detail,
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "revocation_round_trip_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::RevocationEscrowEventMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            if !revocation.witness_artifact.is_revoked() {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationWitnessMissing,
                    &extension_label,
                    Some(&receipt_id),
                    "revocation receipt missing signed revocation witness proof".to_string(),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "revocation_round_trip_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            if let Some(bundle) = &revocation.witness_artifact.revocation_proof {
                let reason_is_empty = bundle
                    .log_entry
                    .revocation_reason
                    .as_ref()
                    .map(|reason| reason.trim().is_empty())
                    .unwrap_or(true);
                if bundle.log_entry.kind != PublicationEntryKind::Revoke || reason_is_empty {
                    add_finding(
                        &mut findings,
                        PlasReleaseGateFailureCode::RevocationWitnessMissing,
                        &extension_label,
                        Some(&receipt_id),
                        "revocation witness proof is malformed".to_string(),
                    );
                    push_log(
                        &mut logs,
                        &normalized,
                        "revocation_round_trip_validation",
                        "fail",
                        Some(PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code()),
                        Some(&extension_label),
                        Some(&receipt_id),
                        Some(&capability_label),
                    );
                    continue;
                }
            }

            if let Err(err) = WitnessPublicationPipeline::verify_artifact(
                &revocation.witness_artifact,
                &trust_anchors.witness_verification_key,
                &trust_anchors.transparency_log_verification_key,
            ) {
                add_finding(
                    &mut findings,
                    PlasReleaseGateFailureCode::RevocationWitnessMissing,
                    &extension_label,
                    Some(&receipt_id),
                    format!("revocation witness verification failed: {err}"),
                );
                push_log(
                    &mut logs,
                    &normalized,
                    "revocation_round_trip_validation",
                    "fail",
                    Some(PlasReleaseGateFailureCode::RevocationWitnessMissing.error_code()),
                    Some(&extension_label),
                    Some(&receipt_id),
                    Some(&capability_label),
                );
                continue;
            }

            push_log(
                &mut logs,
                &normalized,
                "revocation_round_trip_validation",
                "pass",
                None,
                Some(&extension_label),
                Some(&receipt_id),
                Some(&capability_label),
            );
        }

        for active_capability in &extension.active_capabilities {
            if traced_capabilities.contains(active_capability) {
                continue;
            }
            add_finding(
                &mut findings,
                PlasReleaseGateFailureCode::AmbientAuthorityDetected,
                &extension_label,
                None,
                format!(
                    "active capability `{}` is not traceable to any signed capability witness",
                    active_capability
                ),
            );
            push_log(
                &mut logs,
                &normalized,
                "ambient_authority_scan",
                "fail",
                Some(PlasReleaseGateFailureCode::AmbientAuthorityDetected.error_code()),
                Some(&extension_label),
                None,
                Some(active_capability.as_str()),
            );
        }

        if extension
            .active_capabilities
            .iter()
            .all(|capability| traced_capabilities.contains(capability))
        {
            push_log(
                &mut logs,
                &normalized,
                "ambient_authority_scan",
                "pass",
                None,
                Some(&extension_label),
                None,
                None,
            );
        }
    }

    findings.sort_by(|a, b| {
        a.code
            .cmp(&b.code)
            .then(a.extension_id.cmp(&b.extension_id))
            .then(a.receipt_id.cmp(&b.receipt_id))
            .then(a.detail.cmp(&b.detail))
    });

    let pass = findings.is_empty();
    push_log(
        &mut logs,
        &normalized,
        "release_gate_decision",
        if pass { "pass" } else { "fail" },
        if pass {
            None
        } else {
            Some("plas_release_gate_failed")
        },
        None,
        None,
        None,
    );

    let checked_extensions = normalized.extensions.len() as u64;
    let decision_hash = compute_decision_hash(
        &normalized,
        pass,
        checked_extensions,
        checked_grants,
        checked_revocations,
        &findings,
        &logs,
    )?;

    Ok(PlasReleaseGateDecisionArtifact {
        decision_id: normalized.decision_id,
        cohort_id: normalized.cohort_id,
        pass,
        checked_extensions,
        checked_grants,
        checked_revocations,
        findings,
        logs,
        decision_hash,
    })
}

fn normalize_receipt(receipt: &mut CapabilityEscrowReceiptRecord) {
    receipt.receipt_id = receipt.receipt_id.trim().to_string();
    receipt.decision_kind = receipt.decision_kind.trim().to_string();
    receipt.outcome = receipt.outcome.trim().to_string();
    receipt.trace_id = receipt.trace_id.trim().to_string();
    receipt.decision_id = receipt.decision_id.trim().to_string();
    receipt.policy_id = receipt.policy_id.trim().to_string();
    receipt.error_code = receipt
        .error_code
        .take()
        .map(|code| code.trim().to_string())
        .filter(|code| !code.is_empty());
}

fn validate_grant_receipt(
    receipt: &CapabilityEscrowReceiptRecord,
    extension_id: &EngineObjectId,
    capability_label: &str,
    expected_policy_id: &str,
) -> Result<(), String> {
    if receipt.receipt_id.is_empty() {
        return Err("grant receipt_id must not be empty".to_string());
    }
    if receipt.extension_id != *extension_id {
        return Err("grant receipt extension_id does not match cohort extension".to_string());
    }
    if receipt.timestamp_ns == 0 {
        return Err("grant receipt timestamp_ns must be > 0".to_string());
    }
    if receipt.decision_kind != "grant" {
        return Err("grant receipt decision_kind must be `grant`".to_string());
    }
    if receipt.outcome.is_empty() {
        return Err("grant receipt outcome must not be empty".to_string());
    }
    if receipt.policy_id != expected_policy_id {
        return Err("grant receipt policy_id does not match gate policy_id".to_string());
    }
    if receipt.capability.as_ref().map(Capability::as_str) != Some(capability_label) {
        return Err("grant receipt capability does not match grant capability".to_string());
    }
    Ok(())
}

fn validate_revocation_receipt(
    receipt: &CapabilityEscrowReceiptRecord,
    extension_id: &EngineObjectId,
    capability_label: &str,
    expected_policy_id: &str,
) -> Result<(), String> {
    if receipt.receipt_id.is_empty() {
        return Err("revocation receipt_id must not be empty".to_string());
    }
    if receipt.extension_id != *extension_id {
        return Err("revocation receipt extension_id does not match cohort extension".to_string());
    }
    if receipt.timestamp_ns == 0 {
        return Err("revocation receipt timestamp_ns must be > 0".to_string());
    }
    if receipt.decision_kind != "revoke" {
        return Err("revocation receipt decision_kind must be `revoke`".to_string());
    }
    if receipt.outcome.is_empty() {
        return Err("revocation receipt outcome must not be empty".to_string());
    }
    if receipt.policy_id != expected_policy_id {
        return Err("revocation receipt policy_id does not match gate policy_id".to_string());
    }
    if receipt.capability.as_ref().map(Capability::as_str) != Some(capability_label) {
        return Err("revocation receipt capability does not match revoked capability".to_string());
    }
    Ok(())
}

fn add_finding(
    findings: &mut Vec<PlasReleaseGateFinding>,
    code: PlasReleaseGateFailureCode,
    extension_id: &str,
    receipt_id: Option<&str>,
    detail: String,
) {
    findings.push(PlasReleaseGateFinding {
        code,
        extension_id: extension_id.to_string(),
        receipt_id: receipt_id.map(str::to_string),
        detail,
    });
}

#[allow(clippy::too_many_arguments)]
fn push_log(
    logs: &mut Vec<PlasReleaseGateLogEvent>,
    input: &PlasReleaseGateInput,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
    extension_id: Option<&str>,
    receipt_id: Option<&str>,
    capability: Option<&str>,
) {
    logs.push(PlasReleaseGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: PLAS_RELEASE_GATE_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(str::to_string),
        extension_id: extension_id.map(str::to_string),
        receipt_id: receipt_id.map(str::to_string),
        capability: capability.map(str::to_string),
    });
}

fn compute_decision_hash(
    input: &PlasReleaseGateInput,
    pass: bool,
    checked_extensions: u64,
    checked_grants: u64,
    checked_revocations: u64,
    findings: &[PlasReleaseGateFinding],
    logs: &[PlasReleaseGateLogEvent],
) -> Result<ContentHash, PlasReleaseGateError> {
    let payload = serde_json::to_vec(&(
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
        &input.cohort_id,
        pass,
        checked_extensions,
        checked_grants,
        checked_revocations,
        findings,
        logs,
    ))
    .map_err(|err| PlasReleaseGateError::Serialization {
        detail: err.to_string(),
    })?;
    Ok(ContentHash::compute(&payload))
}
