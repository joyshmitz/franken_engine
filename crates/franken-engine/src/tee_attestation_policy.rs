//! TEE attestation policy contract for decision-receipt emitters.
//!
//! Defines a machine-readable policy schema containing:
//! - approved measurements per TEE platform
//! - attestation freshness windows for standard/high-impact decisions
//! - ordered revocation sources with fallback semantics
//! - platform trust roots with pinning + rotation metadata
//!
//! The policy is fail-closed at load time: parse/validation failures halt
//! receipt emission. Temporary trust-root additions require signed override
//! artifacts and all policy transitions append structured governance events.
//!
//! Plan references: Section 10.15 (9I.1), bead bd-2xu5.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

const TEE_ATTESTATION_POLICY_SCHEMA_DEF: &[u8] = b"FrankenEngine.TeeAttestationPolicy.v1";
const TRUST_ROOT_OVERRIDE_ARTIFACT_SCHEMA_DEF: &[u8] =
    b"FrankenEngine.TrustRootOverrideArtifact.v1";
const POLICY_ZONE: &str = "tee-attestation";
const COMPONENT_NAME: &str = "tee_attestation_policy";

fn tee_attestation_policy_schema_id() -> SchemaId {
    SchemaId::from_definition(TEE_ATTESTATION_POLICY_SCHEMA_DEF)
}

fn trust_root_override_artifact_schema_id() -> SchemaId {
    SchemaId::from_definition(TRUST_ROOT_OVERRIDE_ARTIFACT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// TeePlatform
// ---------------------------------------------------------------------------

/// Supported TEE platforms for decision-receipt attestation binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeePlatform {
    IntelSgx,
    ArmTrustZone,
    ArmCca,
    AmdSev,
}

impl TeePlatform {
    pub const ALL: [Self; 4] = [
        Self::IntelSgx,
        Self::ArmTrustZone,
        Self::ArmCca,
        Self::AmdSev,
    ];
}

impl fmt::Display for TeePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntelSgx => f.write_str("intel_sgx"),
            Self::ArmTrustZone => f.write_str("arm_trustzone"),
            Self::ArmCca => f.write_str("arm_cca"),
            Self::AmdSev => f.write_str("amd_sev"),
        }
    }
}

// ---------------------------------------------------------------------------
// MeasurementDigest
// ---------------------------------------------------------------------------

/// Hash algorithm used for a platform measurement digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl MeasurementAlgorithm {
    fn digest_len_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for MeasurementAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("sha256"),
            Self::Sha384 => f.write_str("sha384"),
            Self::Sha512 => f.write_str("sha512"),
        }
    }
}

/// Measurement digest approved for a specific platform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MeasurementDigest {
    pub algorithm: MeasurementAlgorithm,
    /// Lowercase hex-encoded digest bytes.
    pub digest_hex: String,
}

impl MeasurementDigest {
    fn canonicalize(&mut self) {
        self.digest_hex = self.digest_hex.to_ascii_lowercase();
    }

    fn validate_for_platform(
        &self,
        platform: TeePlatform,
    ) -> Result<(), TeeAttestationPolicyError> {
        let expected_hex_len = self.algorithm.digest_len_bytes() * 2;
        if self.digest_hex.len() != expected_hex_len {
            return Err(TeeAttestationPolicyError::InvalidMeasurementDigest {
                platform,
                digest: self.digest_hex.clone(),
                expected_hex_len,
            });
        }
        if !is_hex_ascii(&self.digest_hex) {
            return Err(TeeAttestationPolicyError::InvalidMeasurementDigest {
                platform,
                digest: self.digest_hex.clone(),
                expected_hex_len,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Freshness windows
// ---------------------------------------------------------------------------

/// Maximum accepted quote age in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFreshnessWindow {
    /// Maximum quote age for standard decisions.
    pub standard_max_age_secs: u64,
    /// Maximum quote age for high-impact decisions.
    pub high_impact_max_age_secs: u64,
}

impl AttestationFreshnessWindow {
    fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.standard_max_age_secs == 0
            || self.high_impact_max_age_secs == 0
            || self.high_impact_max_age_secs > self.standard_max_age_secs
        {
            return Err(TeeAttestationPolicyError::InvalidFreshnessWindow {
                standard_max_age_secs: self.standard_max_age_secs,
                high_impact_max_age_secs: self.high_impact_max_age_secs,
            });
        }
        Ok(())
    }

    fn max_age_for(&self, impact: DecisionImpact) -> u64 {
        match impact {
            DecisionImpact::Standard => self.standard_max_age_secs,
            DecisionImpact::HighImpact => self.high_impact_max_age_secs,
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation source policy
// ---------------------------------------------------------------------------

/// Revocation endpoint family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSourceType {
    IntelPcs,
    ManufacturerCrl,
    InternalLedger,
    Other(String),
}

/// Fallback behavior when a revocation source is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFallback {
    /// Attempt the next source in configured order.
    TryNextSource,
    /// Fail closed immediately.
    FailClosed,
}

/// One revocation-check endpoint in ordered fallback sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSource {
    pub source_id: String,
    pub source_type: RevocationSourceType,
    pub endpoint: String,
    pub on_unavailable: RevocationFallback,
}

impl RevocationSource {
    fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.source_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidRevocationSource {
                reason: "source_id is empty".to_string(),
            });
        }
        if self.endpoint.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidRevocationSource {
                reason: format!("endpoint is empty for source '{}'", self.source_id),
            });
        }
        if let RevocationSourceType::Other(name) = &self.source_type
            && name.trim().is_empty()
        {
            return Err(TeeAttestationPolicyError::InvalidRevocationSource {
                reason: format!("source '{}' has empty custom source_type", self.source_id),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trust roots
// ---------------------------------------------------------------------------

/// Pinning/rotation semantics for a platform trust root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootPinning {
    /// Hard pin: trust only this root ID unless policy explicitly changes.
    Pinned,
    /// Root can rotate inside a named rotation group.
    Rotating { rotation_group: String },
}

/// Source of a configured trust root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootSource {
    /// Present in baseline policy document.
    Policy,
    /// Temporary operator override with signed justification.
    TemporaryOverride {
        override_id: String,
        justification_artifact_id: String,
    },
}

/// One trust root accepted for a platform's attestation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformTrustRoot {
    pub root_id: String,
    pub platform: TeePlatform,
    /// PEM payload or equivalent encoded trust anchor.
    pub trust_anchor_pem: String,
    pub valid_from_epoch: SecurityEpoch,
    pub valid_until_epoch: Option<SecurityEpoch>,
    pub pinning: TrustRootPinning,
    pub source: TrustRootSource,
}

impl PlatformTrustRoot {
    fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.root_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: self.root_id.clone(),
                reason: "root_id is empty".to_string(),
            });
        }
        if self.trust_anchor_pem.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: self.root_id.clone(),
                reason: "trust_anchor_pem is empty".to_string(),
            });
        }
        if let Some(until) = self.valid_until_epoch
            && until.as_u64() < self.valid_from_epoch.as_u64()
        {
            return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: self.root_id.clone(),
                reason: "valid_until_epoch is before valid_from_epoch".to_string(),
            });
        }
        if let TrustRootPinning::Rotating { rotation_group } = &self.pinning {
            if rotation_group.trim().is_empty() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "rotating root has empty rotation_group".to_string(),
                });
            }
            if self.valid_until_epoch.is_none() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "rotating root must set valid_until_epoch".to_string(),
                });
            }
        }
        if let TrustRootSource::TemporaryOverride {
            override_id,
            justification_artifact_id,
        } = &self.source
        {
            if override_id.trim().is_empty() || justification_artifact_id.trim().is_empty() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "temporary override metadata is incomplete".to_string(),
                });
            }
            if self.valid_until_epoch.is_none() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "temporary override root must set valid_until_epoch".to_string(),
                });
            }
        }
        Ok(())
    }

    fn active_at_epoch(&self, epoch: SecurityEpoch) -> bool {
        if epoch.as_u64() < self.valid_from_epoch.as_u64() {
            return false;
        }
        match self.valid_until_epoch {
            Some(until) => epoch.as_u64() <= until.as_u64(),
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy schema
// ---------------------------------------------------------------------------

/// Machine-readable TEE attestation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestationPolicy {
    /// Additive schema version for policy contract compatibility.
    pub schema_version: u32,
    /// Security epoch at which this policy becomes authoritative.
    pub policy_epoch: SecurityEpoch,
    /// Approved measurement digests per supported platform.
    pub approved_measurements: BTreeMap<TeePlatform, Vec<MeasurementDigest>>,
    /// Quote freshness policy.
    pub freshness_window: AttestationFreshnessWindow,
    /// Ordered revocation sources (fallback order is significant).
    pub revocation_sources: Vec<RevocationSource>,
    /// Trust roots accepted for quote-chain verification.
    pub platform_trust_roots: Vec<PlatformTrustRoot>,
}

impl TeeAttestationPolicy {
    /// Parse, canonicalize, and validate from JSON.
    pub fn from_json(policy_json: &str) -> Result<Self, TeeAttestationPolicyError> {
        let mut parsed: Self = serde_json::from_str(policy_json).map_err(|e| {
            TeeAttestationPolicyError::ParseFailed {
                detail: e.to_string(),
            }
        })?;
        parsed.canonicalize_in_place();
        parsed.validate()?;
        Ok(parsed)
    }

    /// Encode policy to canonical JSON (sorted deterministic collections).
    pub fn to_canonical_json(&self) -> Result<String, TeeAttestationPolicyError> {
        let mut clone = self.clone();
        clone.canonicalize_in_place();
        serde_json::to_string(&clone).map_err(|e| TeeAttestationPolicyError::SerializationFailed {
            detail: e.to_string(),
        })
    }

    /// Deterministically derive a policy object ID.
    pub fn derive_policy_id(&self) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        let canonical_json = self.to_canonical_json()?;
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            POLICY_ZONE,
            &tee_attestation_policy_schema_id(),
            canonical_json.as_bytes(),
        )
        .map_err(|e| TeeAttestationPolicyError::IdDerivationFailed {
            detail: e.to_string(),
        })
    }

    /// Validate policy invariants.
    pub fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        self.freshness_window.validate()?;

        for platform in TeePlatform::ALL {
            let Some(measurements) = self.approved_measurements.get(&platform) else {
                return Err(TeeAttestationPolicyError::MissingMeasurementsForPlatform { platform });
            };
            if measurements.is_empty() {
                return Err(TeeAttestationPolicyError::MissingMeasurementsForPlatform { platform });
            }
            let mut seen = BTreeSet::new();
            for digest in measurements {
                digest.validate_for_platform(platform)?;
                let key = (digest.algorithm, digest.digest_hex.clone());
                if !seen.insert(key) {
                    return Err(TeeAttestationPolicyError::DuplicateMeasurementDigest {
                        platform,
                        digest: digest.digest_hex.clone(),
                    });
                }
            }
        }

        if self.revocation_sources.is_empty() {
            return Err(TeeAttestationPolicyError::EmptyRevocationSources);
        }
        let mut seen_source_ids = BTreeSet::new();
        let mut has_fail_closed_source = false;
        for source in &self.revocation_sources {
            source.validate()?;
            if !seen_source_ids.insert(source.source_id.clone()) {
                return Err(TeeAttestationPolicyError::DuplicateRevocationSource {
                    source_id: source.source_id.clone(),
                });
            }
            if source.on_unavailable == RevocationFallback::FailClosed {
                has_fail_closed_source = true;
            }
        }
        if !has_fail_closed_source {
            return Err(TeeAttestationPolicyError::RevocationFallbackBypass);
        }

        if self.platform_trust_roots.is_empty() {
            return Err(TeeAttestationPolicyError::MissingTrustRoots);
        }
        let mut seen_root_keys = BTreeSet::new();
        let mut has_pinned_for_platform: BTreeMap<TeePlatform, bool> =
            TeePlatform::ALL.into_iter().map(|p| (p, false)).collect();
        for root in &self.platform_trust_roots {
            root.validate()?;
            let dedup_key = (root.platform, root.root_id.clone());
            if !seen_root_keys.insert(dedup_key) {
                return Err(TeeAttestationPolicyError::DuplicateTrustRoot {
                    platform: root.platform,
                    root_id: root.root_id.clone(),
                });
            }
            if matches!(root.pinning, TrustRootPinning::Pinned)
                && root.active_at_epoch(self.policy_epoch)
            {
                has_pinned_for_platform.insert(root.platform, true);
            }
        }
        for platform in TeePlatform::ALL {
            if !has_pinned_for_platform
                .get(&platform)
                .copied()
                .unwrap_or(false)
            {
                return Err(TeeAttestationPolicyError::MissingPinnedTrustRoot { platform });
            }
        }

        Ok(())
    }

    /// Validate one quote against this policy at runtime epoch.
    pub fn evaluate_quote(
        &self,
        quote: &AttestationQuote,
        impact: DecisionImpact,
        runtime_epoch: SecurityEpoch,
    ) -> Result<(), TeeAttestationPolicyError> {
        quote.measurement.validate_for_platform(quote.platform)?;

        let approved = self.approved_measurements.get(&quote.platform).ok_or(
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: quote.platform,
            },
        )?;
        let measurement_approved = approved.iter().any(|candidate| {
            candidate.algorithm == quote.measurement.algorithm
                && candidate.digest_hex == quote.measurement.digest_hex
        });
        if !measurement_approved {
            return Err(TeeAttestationPolicyError::UnknownMeasurementDigest {
                platform: quote.platform,
                digest: quote.measurement.digest_hex.clone(),
            });
        }

        let max_age_secs = self.freshness_window.max_age_for(impact);
        if quote.quote_age_secs > max_age_secs {
            return Err(TeeAttestationPolicyError::AttestationStale {
                quote_age_secs: quote.quote_age_secs,
                max_age_secs,
            });
        }

        let root_match = self
            .platform_trust_roots
            .iter()
            .find(|root| root.platform == quote.platform && root.root_id == quote.trust_root_id);
        let Some(root) = root_match else {
            return Err(TeeAttestationPolicyError::UnknownTrustRoot {
                platform: quote.platform,
                root_id: quote.trust_root_id.clone(),
            });
        };
        if !root.active_at_epoch(runtime_epoch) {
            return Err(TeeAttestationPolicyError::ExpiredTrustRoot {
                root_id: root.root_id.clone(),
                runtime_epoch,
                valid_until_epoch: root.valid_until_epoch,
            });
        }

        for source in &self.revocation_sources {
            let observation = quote
                .revocation_observations
                .get(&source.source_id)
                .copied()
                .unwrap_or(RevocationProbeStatus::Unavailable);
            match observation {
                RevocationProbeStatus::Good => return Ok(()),
                RevocationProbeStatus::Revoked => {
                    return Err(TeeAttestationPolicyError::RevokedBySource {
                        source_id: source.source_id.clone(),
                    });
                }
                RevocationProbeStatus::Unavailable => {
                    if source.on_unavailable == RevocationFallback::FailClosed {
                        return Err(TeeAttestationPolicyError::RevocationSourceUnavailable {
                            source_id: source.source_id.clone(),
                        });
                    }
                }
            }
        }

        Err(TeeAttestationPolicyError::RevocationEvidenceUnavailable)
    }

    fn canonicalize_in_place(&mut self) {
        for measurements in self.approved_measurements.values_mut() {
            for digest in measurements.iter_mut() {
                digest.canonicalize();
            }
            measurements.sort();
            measurements.dedup();
        }
        for root in &mut self.platform_trust_roots {
            root.root_id = root.root_id.trim().to_string();
        }
        self.platform_trust_roots.sort_by(|a, b| {
            (a.platform, a.root_id.as_str()).cmp(&(b.platform, b.root_id.as_str()))
        });
    }
}

// ---------------------------------------------------------------------------
// Quote model
// ---------------------------------------------------------------------------

/// Impact class for decision-receipt emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionImpact {
    Standard,
    HighImpact,
}

/// Revocation source result at quote verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationProbeStatus {
    Good,
    Revoked,
    Unavailable,
}

/// Input quote attributes evaluated by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuote {
    pub platform: TeePlatform,
    pub measurement: MeasurementDigest,
    pub quote_age_secs: u64,
    pub trust_root_id: String,
    pub revocation_observations: BTreeMap<String, RevocationProbeStatus>,
}

// ---------------------------------------------------------------------------
// Signed override artifacts
// ---------------------------------------------------------------------------

/// Unsigned payload for temporary trust-root override authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootOverrideArtifactInput {
    pub actor: String,
    pub justification: String,
    pub evidence_refs: Vec<String>,
    pub target_platform: TeePlatform,
    pub target_root_id: String,
    pub issued_epoch: SecurityEpoch,
    pub expires_epoch: SecurityEpoch,
}

/// Signed justification artifact for temporary trust-root additions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTrustRootOverrideArtifact {
    pub artifact_id: String,
    pub actor: String,
    pub justification: String,
    pub evidence_refs: Vec<String>,
    pub target_platform: TeePlatform,
    pub target_root_id: String,
    pub issued_epoch: SecurityEpoch,
    pub expires_epoch: SecurityEpoch,
    pub signature: Signature,
}

impl SignedTrustRootOverrideArtifact {
    /// Create and sign a new override artifact.
    pub fn create_signed(
        signer: &SigningKey,
        mut input: TrustRootOverrideArtifactInput,
    ) -> Result<Self, TeeAttestationPolicyError> {
        if input.actor.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "actor is empty".to_string(),
            });
        }
        if input.justification.trim().is_empty() {
            return Err(TeeAttestationPolicyError::OverrideJustificationMissing);
        }
        if input.target_root_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "target_root_id is empty".to_string(),
            });
        }
        if input.expires_epoch.as_u64() <= input.issued_epoch.as_u64() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "expires_epoch must be after issued_epoch".to_string(),
            });
        }
        input.evidence_refs.sort();
        input.evidence_refs.dedup();

        let mut artifact = Self {
            artifact_id: String::new(),
            actor: input.actor,
            justification: input.justification,
            evidence_refs: input.evidence_refs,
            target_platform: input.target_platform,
            target_root_id: input.target_root_id,
            issued_epoch: input.issued_epoch,
            expires_epoch: input.expires_epoch,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let id_preimage = artifact.preimage_bytes();
        artifact.artifact_id = ContentHash::compute(&id_preimage).to_hex();
        let signature_preimage = artifact.preimage_bytes();
        artifact.signature = sign_preimage(signer, &signature_preimage).map_err(|e| {
            TeeAttestationPolicyError::OverrideSignatureInvalid {
                detail: e.to_string(),
            }
        })?;
        Ok(artifact)
    }

    /// Verify artifact signature and freshness.
    pub fn verify(
        &self,
        verifier: &VerificationKey,
        current_epoch: SecurityEpoch,
    ) -> Result<(), TeeAttestationPolicyError> {
        if self.justification.trim().is_empty() {
            return Err(TeeAttestationPolicyError::OverrideJustificationMissing);
        }
        if current_epoch.as_u64() > self.expires_epoch.as_u64() {
            return Err(TeeAttestationPolicyError::OverrideExpired {
                current_epoch,
                expires_epoch: self.expires_epoch,
            });
        }
        let preimage = self.preimage_bytes();
        verify_signature(verifier, &preimage, &self.signature).map_err(|e| {
            TeeAttestationPolicyError::OverrideSignatureInvalid {
                detail: e.to_string(),
            }
        })?;
        Ok(())
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let unsigned_map = self.unsigned_value();
        let value_bytes = crate::deterministic_serde::encode_value(&unsigned_map);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(ObjectDomain::PolicyObject.tag());
        preimage.extend_from_slice(trust_root_override_artifact_schema_id().as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }

    fn unsigned_value(&self) -> crate::deterministic_serde::CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "actor".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.actor.clone()),
        );
        map.insert(
            "artifact_id".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.artifact_id.clone()),
        );
        map.insert(
            "evidence_refs".to_string(),
            crate::deterministic_serde::CanonicalValue::Array(
                self.evidence_refs
                    .iter()
                    .map(|s| crate::deterministic_serde::CanonicalValue::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "expires_epoch".to_string(),
            crate::deterministic_serde::CanonicalValue::U64(self.expires_epoch.as_u64()),
        );
        map.insert(
            "issued_epoch".to_string(),
            crate::deterministic_serde::CanonicalValue::U64(self.issued_epoch.as_u64()),
        );
        map.insert(
            "justification".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.justification.clone()),
        );
        map.insert(
            "signature".to_string(),
            crate::deterministic_serde::CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "target_platform".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.target_platform.to_string()),
        );
        map.insert(
            "target_root_id".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.target_root_id.clone()),
        );
        crate::deterministic_serde::CanonicalValue::Map(map)
    }
}

/// Request to add one temporary trust root via signed override artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporaryTrustRootOverride {
    pub override_id: String,
    pub trust_root: PlatformTrustRoot,
    pub artifact: SignedTrustRootOverrideArtifact,
}

impl TemporaryTrustRootOverride {
    fn validate(
        &self,
        verifier: &VerificationKey,
        current_epoch: SecurityEpoch,
    ) -> Result<(), TeeAttestationPolicyError> {
        if self.override_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "override_id is empty".to_string(),
            });
        }
        self.artifact.verify(verifier, current_epoch)?;
        if self.trust_root.platform != self.artifact.target_platform
            || self.trust_root.root_id != self.artifact.target_root_id
        {
            return Err(TeeAttestationPolicyError::OverrideTargetMismatch {
                expected_platform: self.trust_root.platform,
                expected_root_id: self.trust_root.root_id.clone(),
                actual_platform: self.artifact.target_platform,
                actual_root_id: self.artifact.target_root_id.clone(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Governance event ledger
// ---------------------------------------------------------------------------

/// Structured policy-governance event entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGovernanceEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub metadata: BTreeMap<String, String>,
}

/// Runtime policy store with fail-closed load semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationPolicyStore {
    active_policy: Option<TeeAttestationPolicy>,
    governance_ledger: Vec<PolicyGovernanceEvent>,
    receipt_emission_halted: bool,
    last_error_code: Option<String>,
}

impl Default for TeeAttestationPolicyStore {
    fn default() -> Self {
        Self {
            active_policy: None,
            governance_ledger: Vec::new(),
            receipt_emission_halted: true,
            last_error_code: Some("policy_not_loaded".to_string()),
        }
    }
}

impl TeeAttestationPolicyStore {
    pub fn active_policy(&self) -> Option<&TeeAttestationPolicy> {
        self.active_policy.as_ref()
    }

    pub fn governance_ledger(&self) -> &[PolicyGovernanceEvent] {
        &self.governance_ledger
    }

    pub fn receipt_emission_halted(&self) -> bool {
        self.receipt_emission_halted
    }

    pub fn last_error_code(&self) -> Option<&str> {
        self.last_error_code.as_deref()
    }

    /// Parse + load policy from JSON. On error, enter fail-closed halt.
    pub fn load_policy_json(
        &mut self,
        policy_json: &str,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        match TeeAttestationPolicy::from_json(policy_json) {
            Ok(policy) => self.load_policy(policy, trace_id, decision_id),
            Err(err) => {
                self.receipt_emission_halted = true;
                self.last_error_code = Some(err.error_code().to_string());
                let mut metadata = BTreeMap::new();
                metadata.insert("reason".to_string(), err.to_string());
                self.append_event(PolicyGovernanceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.to_string(),
                    policy_id: "policy-unavailable".to_string(),
                    component: COMPONENT_NAME.to_string(),
                    event: "policy_load_failed".to_string(),
                    outcome: "deny".to_string(),
                    error_code: err.error_code().to_string(),
                    metadata,
                });
                Err(err)
            }
        }
    }

    /// Load a validated policy object.
    pub fn load_policy(
        &mut self,
        policy: TeeAttestationPolicy,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        policy.validate()?;
        if let Some(current) = self.active_policy.as_ref()
            && policy.policy_epoch.as_u64() < current.policy_epoch.as_u64()
        {
            let err = TeeAttestationPolicyError::PolicyEpochRegression {
                current: current.policy_epoch,
                attempted: policy.policy_epoch,
            };
            self.receipt_emission_halted = true;
            self.last_error_code = Some(err.error_code().to_string());
            let mut metadata = BTreeMap::new();
            metadata.insert("reason".to_string(), err.to_string());
            self.append_event(PolicyGovernanceEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: "policy-unavailable".to_string(),
                component: COMPONENT_NAME.to_string(),
                event: "policy_load_failed".to_string(),
                outcome: "deny".to_string(),
                error_code: err.error_code().to_string(),
                metadata,
            });
            return Err(err);
        }

        let policy_id = policy.derive_policy_id()?;
        self.active_policy = Some(policy.clone());
        self.receipt_emission_halted = false;
        self.last_error_code = None;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "policy_epoch".to_string(),
            policy.policy_epoch.as_u64().to_string(),
        );
        metadata.insert(
            "schema_version".to_string(),
            policy.schema_version.to_string(),
        );
        self.append_event(PolicyGovernanceEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_hex(),
            component: COMPONENT_NAME.to_string(),
            event: "policy_loaded".to_string(),
            outcome: "allow".to_string(),
            error_code: "ok".to_string(),
            metadata,
        });
        Ok(policy_id)
    }

    /// Apply temporary trust-root override with signed justification artifact.
    pub fn apply_temporary_trust_root_override(
        &mut self,
        request: TemporaryTrustRootOverride,
        verifier: &VerificationKey,
        current_epoch: SecurityEpoch,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        let current_policy = self
            .active_policy
            .as_ref()
            .cloned()
            .ok_or(TeeAttestationPolicyError::NoActivePolicy)?;
        request.validate(verifier, current_epoch)?;

        let mut candidate = current_policy;
        let mut root = request.trust_root.clone();
        root.source = TrustRootSource::TemporaryOverride {
            override_id: request.override_id.clone(),
            justification_artifact_id: request.artifact.artifact_id.clone(),
        };
        let capped_expiry = match root.valid_until_epoch {
            Some(until) => {
                SecurityEpoch::from_raw(until.as_u64().min(request.artifact.expires_epoch.as_u64()))
            }
            None => request.artifact.expires_epoch,
        };
        root.valid_until_epoch = Some(capped_expiry);

        if let Some(existing_idx) = candidate.platform_trust_roots.iter().position(|existing| {
            existing.platform == root.platform && existing.root_id == root.root_id
        }) {
            candidate.platform_trust_roots[existing_idx] = root;
        } else {
            candidate.platform_trust_roots.push(root);
        }
        candidate.canonicalize_in_place();
        candidate.validate()?;
        let policy_id = candidate.derive_policy_id()?;

        self.active_policy = Some(candidate);
        self.receipt_emission_halted = false;
        self.last_error_code = None;
        let mut metadata = BTreeMap::new();
        metadata.insert("override_id".to_string(), request.override_id);
        metadata.insert(
            "justification_artifact_id".to_string(),
            request.artifact.artifact_id,
        );
        metadata.insert(
            "expires_epoch".to_string(),
            request.artifact.expires_epoch.as_u64().to_string(),
        );
        self.append_event(PolicyGovernanceEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_hex(),
            component: COMPONENT_NAME.to_string(),
            event: "temporary_trust_root_override_applied".to_string(),
            outcome: "allow".to_string(),
            error_code: "ok".to_string(),
            metadata,
        });
        Ok(policy_id)
    }

    /// Validate a quote against active policy and append governance event.
    pub fn evaluate_quote(
        &mut self,
        quote: &AttestationQuote,
        impact: DecisionImpact,
        runtime_epoch: SecurityEpoch,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<(), TeeAttestationPolicyError> {
        if self.receipt_emission_halted {
            let err = TeeAttestationPolicyError::ReceiptEmissionHalted;
            self.append_event(PolicyGovernanceEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: "policy-unavailable".to_string(),
                component: COMPONENT_NAME.to_string(),
                event: "quote_evaluation_failed".to_string(),
                outcome: "deny".to_string(),
                error_code: err.error_code().to_string(),
                metadata: BTreeMap::new(),
            });
            return Err(err);
        }
        let Some(policy) = self.active_policy.clone() else {
            let err = TeeAttestationPolicyError::NoActivePolicy;
            self.append_event(PolicyGovernanceEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: "policy-unavailable".to_string(),
                component: COMPONENT_NAME.to_string(),
                event: "quote_evaluation_failed".to_string(),
                outcome: "deny".to_string(),
                error_code: err.error_code().to_string(),
                metadata: BTreeMap::new(),
            });
            return Err(err);
        };
        let policy_id = policy.derive_policy_id()?;
        match policy.evaluate_quote(quote, impact, runtime_epoch) {
            Ok(()) => {
                let mut metadata = BTreeMap::new();
                metadata.insert("platform".to_string(), quote.platform.to_string());
                metadata.insert("trust_root_id".to_string(), quote.trust_root_id.clone());
                self.append_event(PolicyGovernanceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.to_string(),
                    policy_id: policy_id.to_hex(),
                    component: COMPONENT_NAME.to_string(),
                    event: "quote_accepted".to_string(),
                    outcome: "allow".to_string(),
                    error_code: "ok".to_string(),
                    metadata,
                });
                Ok(())
            }
            Err(err) => {
                let mut metadata = BTreeMap::new();
                metadata.insert("platform".to_string(), quote.platform.to_string());
                metadata.insert("trust_root_id".to_string(), quote.trust_root_id.clone());
                metadata.insert("reason".to_string(), err.to_string());
                self.append_event(PolicyGovernanceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.to_string(),
                    policy_id: policy_id.to_hex(),
                    component: COMPONENT_NAME.to_string(),
                    event: "quote_rejected".to_string(),
                    outcome: "deny".to_string(),
                    error_code: err.error_code().to_string(),
                    metadata,
                });
                Err(err)
            }
        }
    }

    fn append_event(&mut self, entry: PolicyGovernanceEvent) {
        self.governance_ledger.push(entry);
    }
}

// ---------------------------------------------------------------------------
// Decision-receipt emitter sync policy
// ---------------------------------------------------------------------------

/// Lightweight receipt-emitter state tracking policy-epoch sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceiptEmitter {
    pub emitter_id: String,
    pub last_synced_policy_epoch: Option<SecurityEpoch>,
}

impl DecisionReceiptEmitter {
    pub fn new(emitter_id: impl Into<String>) -> Self {
        Self {
            emitter_id: emitter_id.into(),
            last_synced_policy_epoch: None,
        }
    }

    /// Pull current policy epoch from store.
    pub fn sync_policy(
        &mut self,
        store: &TeeAttestationPolicyStore,
    ) -> Result<SecurityEpoch, TeeAttestationPolicyError> {
        if store.receipt_emission_halted {
            return Err(TeeAttestationPolicyError::ReceiptEmissionHalted);
        }
        let epoch = store
            .active_policy()
            .map(|policy| policy.policy_epoch)
            .ok_or(TeeAttestationPolicyError::NoActivePolicy)?;
        self.last_synced_policy_epoch = Some(epoch);
        Ok(epoch)
    }

    /// Ensure emitter is synced not more than one epoch behind.
    pub fn can_emit(
        &self,
        runtime_epoch: SecurityEpoch,
        store: &TeeAttestationPolicyStore,
    ) -> Result<(), TeeAttestationPolicyError> {
        if store.receipt_emission_halted {
            return Err(TeeAttestationPolicyError::ReceiptEmissionHalted);
        }
        let active_epoch = store
            .active_policy()
            .map(|policy| policy.policy_epoch)
            .ok_or(TeeAttestationPolicyError::NoActivePolicy)?;
        let synced_epoch =
            self.last_synced_policy_epoch
                .ok_or(TeeAttestationPolicyError::EmitterNotSynced {
                    emitter_id: self.emitter_id.clone(),
                })?;
        if active_epoch.as_u64() > synced_epoch.as_u64().saturating_add(1) {
            return Err(TeeAttestationPolicyError::EmitterPolicyStale {
                emitter_id: self.emitter_id.clone(),
                synced_epoch,
                required_epoch: active_epoch,
            });
        }
        if runtime_epoch.as_u64() > synced_epoch.as_u64().saturating_add(1) {
            return Err(TeeAttestationPolicyError::EmitterPolicyStale {
                emitter_id: self.emitter_id.clone(),
                synced_epoch,
                required_epoch: runtime_epoch,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from TEE attestation policy loading/validation/evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeAttestationPolicyError {
    ParseFailed {
        detail: String,
    },
    SerializationFailed {
        detail: String,
    },
    MissingMeasurementsForPlatform {
        platform: TeePlatform,
    },
    InvalidMeasurementDigest {
        platform: TeePlatform,
        digest: String,
        expected_hex_len: usize,
    },
    DuplicateMeasurementDigest {
        platform: TeePlatform,
        digest: String,
    },
    InvalidFreshnessWindow {
        standard_max_age_secs: u64,
        high_impact_max_age_secs: u64,
    },
    EmptyRevocationSources,
    InvalidRevocationSource {
        reason: String,
    },
    DuplicateRevocationSource {
        source_id: String,
    },
    RevocationFallbackBypass,
    MissingTrustRoots,
    InvalidTrustRoot {
        root_id: String,
        reason: String,
    },
    DuplicateTrustRoot {
        platform: TeePlatform,
        root_id: String,
    },
    MissingPinnedTrustRoot {
        platform: TeePlatform,
    },
    PolicyEpochRegression {
        current: SecurityEpoch,
        attempted: SecurityEpoch,
    },
    IdDerivationFailed {
        detail: String,
    },
    ReceiptEmissionHalted,
    NoActivePolicy,
    UnknownMeasurementDigest {
        platform: TeePlatform,
        digest: String,
    },
    AttestationStale {
        quote_age_secs: u64,
        max_age_secs: u64,
    },
    UnknownTrustRoot {
        platform: TeePlatform,
        root_id: String,
    },
    ExpiredTrustRoot {
        root_id: String,
        runtime_epoch: SecurityEpoch,
        valid_until_epoch: Option<SecurityEpoch>,
    },
    RevokedBySource {
        source_id: String,
    },
    RevocationSourceUnavailable {
        source_id: String,
    },
    RevocationEvidenceUnavailable,
    InvalidOverrideArtifact {
        reason: String,
    },
    OverrideJustificationMissing,
    OverrideExpired {
        current_epoch: SecurityEpoch,
        expires_epoch: SecurityEpoch,
    },
    OverrideSignatureInvalid {
        detail: String,
    },
    OverrideTargetMismatch {
        expected_platform: TeePlatform,
        expected_root_id: String,
        actual_platform: TeePlatform,
        actual_root_id: String,
    },
    EmitterNotSynced {
        emitter_id: String,
    },
    EmitterPolicyStale {
        emitter_id: String,
        synced_epoch: SecurityEpoch,
        required_epoch: SecurityEpoch,
    },
}

impl TeeAttestationPolicyError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ParseFailed { .. } => "tee_policy_parse_failed",
            Self::SerializationFailed { .. } => "tee_policy_serialize_failed",
            Self::MissingMeasurementsForPlatform { .. } => "tee_policy_missing_measurements",
            Self::InvalidMeasurementDigest { .. } => "tee_policy_invalid_measurement_digest",
            Self::DuplicateMeasurementDigest { .. } => "tee_policy_duplicate_measurement_digest",
            Self::InvalidFreshnessWindow { .. } => "tee_policy_invalid_freshness_window",
            Self::EmptyRevocationSources => "tee_policy_empty_revocation_sources",
            Self::InvalidRevocationSource { .. } => "tee_policy_invalid_revocation_source",
            Self::DuplicateRevocationSource { .. } => "tee_policy_duplicate_revocation_source",
            Self::RevocationFallbackBypass => "tee_policy_revocation_bypass_config",
            Self::MissingTrustRoots => "tee_policy_missing_trust_roots",
            Self::InvalidTrustRoot { .. } => "tee_policy_invalid_trust_root",
            Self::DuplicateTrustRoot { .. } => "tee_policy_duplicate_trust_root",
            Self::MissingPinnedTrustRoot { .. } => "tee_policy_missing_pinned_trust_root",
            Self::PolicyEpochRegression { .. } => "tee_policy_epoch_regression",
            Self::IdDerivationFailed { .. } => "tee_policy_id_derivation_failed",
            Self::ReceiptEmissionHalted => "tee_policy_emission_halted",
            Self::NoActivePolicy => "tee_policy_not_loaded",
            Self::UnknownMeasurementDigest { .. } => "tee_policy_measurement_not_approved",
            Self::AttestationStale { .. } => "tee_policy_attestation_stale",
            Self::UnknownTrustRoot { .. } => "tee_policy_unknown_trust_root",
            Self::ExpiredTrustRoot { .. } => "tee_policy_expired_trust_root",
            Self::RevokedBySource { .. } => "tee_policy_revoked",
            Self::RevocationSourceUnavailable { .. } => "tee_policy_revocation_source_unavailable",
            Self::RevocationEvidenceUnavailable => "tee_policy_revocation_evidence_unavailable",
            Self::InvalidOverrideArtifact { .. } => "tee_policy_override_artifact_invalid",
            Self::OverrideJustificationMissing => "tee_policy_override_justification_missing",
            Self::OverrideExpired { .. } => "tee_policy_override_expired",
            Self::OverrideSignatureInvalid { .. } => "tee_policy_override_signature_invalid",
            Self::OverrideTargetMismatch { .. } => "tee_policy_override_target_mismatch",
            Self::EmitterNotSynced { .. } => "tee_policy_emitter_not_synced",
            Self::EmitterPolicyStale { .. } => "tee_policy_emitter_stale",
        }
    }
}

impl fmt::Display for TeeAttestationPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseFailed { detail } => write!(f, "policy parse failed: {detail}"),
            Self::SerializationFailed { detail } => {
                write!(f, "policy serialization failed: {detail}")
            }
            Self::MissingMeasurementsForPlatform { platform } => {
                write!(f, "missing approved measurements for platform {platform}")
            }
            Self::InvalidMeasurementDigest {
                platform,
                digest,
                expected_hex_len,
            } => write!(
                f,
                "invalid measurement digest for {platform}: digest='{digest}', expected_hex_len={expected_hex_len}"
            ),
            Self::DuplicateMeasurementDigest { platform, digest } => {
                write!(f, "duplicate measurement digest for {platform}: {digest}")
            }
            Self::InvalidFreshnessWindow {
                standard_max_age_secs,
                high_impact_max_age_secs,
            } => write!(
                f,
                "invalid freshness window: standard_max_age_secs={standard_max_age_secs}, high_impact_max_age_secs={high_impact_max_age_secs}"
            ),
            Self::EmptyRevocationSources => f.write_str("revocation source list is empty"),
            Self::InvalidRevocationSource { reason } => {
                write!(f, "invalid revocation source: {reason}")
            }
            Self::DuplicateRevocationSource { source_id } => {
                write!(f, "duplicate revocation source: {source_id}")
            }
            Self::RevocationFallbackBypass => {
                f.write_str("revocation configuration has no fail-closed source")
            }
            Self::MissingTrustRoots => f.write_str("platform trust root set is empty"),
            Self::InvalidTrustRoot { root_id, reason } => {
                write!(f, "invalid trust root '{root_id}': {reason}")
            }
            Self::DuplicateTrustRoot { platform, root_id } => {
                write!(f, "duplicate trust root for {platform}: {root_id}")
            }
            Self::MissingPinnedTrustRoot { platform } => {
                write!(f, "no active pinned trust root for {platform}")
            }
            Self::PolicyEpochRegression { current, attempted } => {
                write!(
                    f,
                    "policy epoch regression: current={current}, attempted={attempted}"
                )
            }
            Self::IdDerivationFailed { detail } => {
                write!(f, "policy ID derivation failed: {detail}")
            }
            Self::ReceiptEmissionHalted => f.write_str("receipt emission halted (fail-closed)"),
            Self::NoActivePolicy => f.write_str("no active TEE attestation policy loaded"),
            Self::UnknownMeasurementDigest { platform, digest } => {
                write!(
                    f,
                    "measurement digest not approved for {platform}: {digest}"
                )
            }
            Self::AttestationStale {
                quote_age_secs,
                max_age_secs,
            } => write!(
                f,
                "attestation quote is stale: age_secs={quote_age_secs}, max_age_secs={max_age_secs}"
            ),
            Self::UnknownTrustRoot { platform, root_id } => {
                write!(f, "unknown trust root for {platform}: {root_id}")
            }
            Self::ExpiredTrustRoot {
                root_id,
                runtime_epoch,
                valid_until_epoch,
            } => write!(
                f,
                "trust root '{root_id}' not active at runtime {runtime_epoch} (valid_until={valid_until_epoch:?})"
            ),
            Self::RevokedBySource { source_id } => {
                write!(f, "quote revoked by source {source_id}")
            }
            Self::RevocationSourceUnavailable { source_id } => {
                write!(
                    f,
                    "revocation source unavailable (fail-closed): {source_id}"
                )
            }
            Self::RevocationEvidenceUnavailable => {
                f.write_str("revocation evidence unavailable across configured fallback chain")
            }
            Self::InvalidOverrideArtifact { reason } => {
                write!(f, "invalid trust-root override artifact: {reason}")
            }
            Self::OverrideJustificationMissing => {
                f.write_str("override artifact missing signed justification")
            }
            Self::OverrideExpired {
                current_epoch,
                expires_epoch,
            } => write!(
                f,
                "override artifact expired: current_epoch={current_epoch}, expires_epoch={expires_epoch}"
            ),
            Self::OverrideSignatureInvalid { detail } => {
                write!(f, "override signature verification failed: {detail}")
            }
            Self::OverrideTargetMismatch {
                expected_platform,
                expected_root_id,
                actual_platform,
                actual_root_id,
            } => write!(
                f,
                "override target mismatch: expected {expected_platform}:{expected_root_id}, got {actual_platform}:{actual_root_id}"
            ),
            Self::EmitterNotSynced { emitter_id } => {
                write!(f, "emitter '{emitter_id}' has not synced policy epoch")
            }
            Self::EmitterPolicyStale {
                emitter_id,
                synced_epoch,
                required_epoch,
            } => write!(
                f,
                "emitter '{emitter_id}' stale policy epoch: synced={synced_epoch}, required={required_epoch}"
            ),
        }
    }
}

impl std::error::Error for TeeAttestationPolicyError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_hex_ascii(s: &str) -> bool {
    s.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_hex(byte: u8, bytes: usize) -> String {
        let mut out = String::with_capacity(bytes * 2);
        for _ in 0..bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn sample_policy(epoch: u64) -> TeeAttestationPolicy {
        let mut approved = BTreeMap::new();
        approved.insert(
            TeePlatform::IntelSgx,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x11, 48),
            }],
        );
        approved.insert(
            TeePlatform::ArmTrustZone,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0x22, 32),
            }],
        );
        approved.insert(
            TeePlatform::ArmCca,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0x44, 32),
            }],
        );
        approved.insert(
            TeePlatform::AmdSev,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x33, 48),
            }],
        );

        TeeAttestationPolicy {
            schema_version: 1,
            policy_epoch: SecurityEpoch::from_raw(epoch),
            approved_measurements: approved,
            freshness_window: AttestationFreshnessWindow {
                standard_max_age_secs: 300,
                high_impact_max_age_secs: 60,
            },
            revocation_sources: vec![
                RevocationSource {
                    source_id: "intel_pcs".to_string(),
                    source_type: RevocationSourceType::IntelPcs,
                    endpoint: "https://intel.example/pcs".to_string(),
                    on_unavailable: RevocationFallback::TryNextSource,
                },
                RevocationSource {
                    source_id: "manufacturer_crl".to_string(),
                    source_type: RevocationSourceType::ManufacturerCrl,
                    endpoint: "https://manufacturer.example/crl".to_string(),
                    on_unavailable: RevocationFallback::TryNextSource,
                },
                RevocationSource {
                    source_id: "internal_ledger".to_string(),
                    source_type: RevocationSourceType::InternalLedger,
                    endpoint: "sqlite://revocations".to_string(),
                    on_unavailable: RevocationFallback::FailClosed,
                },
            ],
            platform_trust_roots: vec![
                PlatformTrustRoot {
                    root_id: "sgx-root-a".to_string(),
                    platform: TeePlatform::IntelSgx,
                    trust_anchor_pem: "-----BEGIN CERT-----SGX-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "tz-root-a".to_string(),
                    platform: TeePlatform::ArmTrustZone,
                    trust_anchor_pem: "-----BEGIN CERT-----TZ-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "cca-root-a".to_string(),
                    platform: TeePlatform::ArmCca,
                    trust_anchor_pem: "-----BEGIN CERT-----CCA-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "sev-root-a".to_string(),
                    platform: TeePlatform::AmdSev,
                    trust_anchor_pem: "-----BEGIN CERT-----SEV-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
            ],
        }
    }

    fn quote_for_sgx() -> AttestationQuote {
        let mut rev = BTreeMap::new();
        rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
        rev.insert(
            "manufacturer_crl".to_string(),
            RevocationProbeStatus::Unavailable,
        );
        rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

        AttestationQuote {
            platform: TeePlatform::IntelSgx,
            measurement: MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x11, 48),
            },
            quote_age_secs: 12,
            trust_root_id: "sgx-root-a".to_string(),
            revocation_observations: rev,
        }
    }

    #[test]
    fn policy_round_trip_canonical_json() {
        let policy = sample_policy(7);
        let json = policy.to_canonical_json().expect("serialize");
        let parsed = TeeAttestationPolicy::from_json(&json).expect("parse");
        assert_eq!(policy, parsed);
    }

    #[test]
    fn policy_id_is_deterministic() {
        let p1 = sample_policy(3);
        let p2 = sample_policy(3);
        assert_eq!(
            p1.derive_policy_id().expect("id 1"),
            p2.derive_policy_id().expect("id 2")
        );
    }

    #[test]
    fn policy_requires_measurements_for_all_platforms() {
        let mut policy = sample_policy(1);
        policy.approved_measurements.remove(&TeePlatform::AmdSev);
        let err = policy.validate().expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: TeePlatform::AmdSev
            }
        ));
    }

    #[test]
    fn freshness_window_rejects_inverted_thresholds() {
        let mut policy = sample_policy(1);
        policy.freshness_window = AttestationFreshnessWindow {
            standard_max_age_secs: 10,
            high_impact_max_age_secs: 20,
        };
        let err = policy.validate().expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
        ));
    }

    #[test]
    fn unknown_measurement_digest_is_rejected() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.measurement.digest_hex = digest_hex(0x44, 48);
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::UnknownMeasurementDigest { .. }
        ));
    }

    #[test]
    fn high_impact_freshness_boundary_enforced() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.quote_age_secs = 61;
        let err = policy
            .evaluate_quote(
                &quote,
                DecisionImpact::HighImpact,
                SecurityEpoch::from_raw(1),
            )
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::AttestationStale { .. }
        ));
    }

    #[test]
    fn revocation_fallback_uses_ordered_try_next_chain() {
        let policy = sample_policy(1);
        let quote = quote_for_sgx();
        policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .expect("fallback should reach internal ledger success");
    }

    #[test]
    fn revocation_fail_closed_source_blocks_on_unavailable() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.revocation_observations.insert(
            "internal_ledger".to_string(),
            RevocationProbeStatus::Unavailable,
        );
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
        ));
    }

    #[test]
    fn trust_root_must_be_active_at_runtime_epoch() {
        let mut policy = sample_policy(1);
        policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(2));
        let quote = quote_for_sgx();
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(3))
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::ExpiredTrustRoot { .. }
        ));
    }

    #[test]
    fn load_failure_halts_emission_fail_closed() {
        let mut store = TeeAttestationPolicyStore::default();
        let err = store
            .load_policy_json(
                r#"{"schema_version":"bad"}"#,
                "trace-fail-1",
                "decision-fail-1",
            )
            .expect_err("must fail");
        assert_eq!(err.error_code(), "tee_policy_parse_failed");
        assert!(store.receipt_emission_halted());
    }

    #[test]
    fn signed_override_applies_temporary_root() {
        let mut store = TeeAttestationPolicyStore::default();
        let policy = sample_policy(10);
        store
            .load_policy(policy.clone(), "trace-load-1", "decision-load-1")
            .expect("policy load");

        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator-1".to_string(),
                justification: "temporary manufacturer root during incident".to_string(),
                evidence_refs: vec!["evidence-1".to_string(), "evidence-2".to_string()],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "sgx-root-temp".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(12),
            },
        )
        .expect("artifact");

        let request = TemporaryTrustRootOverride {
            override_id: "ovr-1".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-temp".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Rotating {
                    rotation_group: "sgx-rollover".to_string(),
                },
                source: TrustRootSource::Policy,
            },
            artifact,
        };

        store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(10),
                "trace-ovr-1",
                "decision-ovr-1",
            )
            .expect("override apply");

        let active = store.active_policy().expect("active policy");
        let has_temp = active.platform_trust_roots.iter().any(|root| {
            root.platform == TeePlatform::IntelSgx
                && root.root_id == "sgx-root-temp"
                && matches!(root.source, TrustRootSource::TemporaryOverride { .. })
        });
        assert!(has_temp);
    }

    #[test]
    fn override_signature_must_verify() {
        let mut store = TeeAttestationPolicyStore::default();
        store
            .load_policy(sample_policy(10), "trace-load-2", "decision-load-2")
            .expect("policy load");

        let signing_key = SigningKey::from_bytes([8u8; 32]);
        let verifier = signing_key.verification_key();
        let mut artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator-2".to_string(),
                justification: "temporary roll".to_string(),
                evidence_refs: vec!["evidence-z".to_string()],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "sgx-root-temp-2".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(11),
            },
        )
        .expect("artifact");
        artifact.justification = "tampered".to_string();

        let request = TemporaryTrustRootOverride {
            override_id: "ovr-2".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-temp-2".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP-2".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: Some(SecurityEpoch::from_raw(11)),
                pinning: TrustRootPinning::Rotating {
                    rotation_group: "sgx-rollover".to_string(),
                },
                source: TrustRootSource::Policy,
            },
            artifact,
        };

        let err = store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(10),
                "trace-ovr-2",
                "decision-ovr-2",
            )
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::OverrideSignatureInvalid { .. }
        ));
    }

    #[test]
    fn governance_events_emit_stable_fields() {
        let mut store = TeeAttestationPolicyStore::default();
        let policy = sample_policy(5);
        store
            .load_policy(policy, "trace-audit-1", "decision-audit-1")
            .expect("load");
        let quote = quote_for_sgx();
        store
            .evaluate_quote(
                &quote,
                DecisionImpact::Standard,
                SecurityEpoch::from_raw(5),
                "trace-audit-2",
                "decision-audit-2",
            )
            .expect("quote ok");
        let entries = store.governance_ledger();
        assert!(entries.len() >= 2);
        let last = entries.last().expect("last event");
        assert!(!last.trace_id.is_empty());
        assert!(!last.decision_id.is_empty());
        assert!(!last.policy_id.is_empty());
        assert_eq!(last.component, COMPONENT_NAME);
        assert!(!last.event.is_empty());
        assert!(!last.outcome.is_empty());
        assert!(!last.error_code.is_empty());
    }

    #[test]
    fn tee_platform_all_covers_four_variants() {
        assert_eq!(TeePlatform::ALL.len(), 4);
        assert_eq!(TeePlatform::IntelSgx.to_string(), "intel_sgx");
        assert_eq!(TeePlatform::ArmTrustZone.to_string(), "arm_trustzone");
        assert_eq!(TeePlatform::ArmCca.to_string(), "arm_cca");
        assert_eq!(TeePlatform::AmdSev.to_string(), "amd_sev");
    }
}
