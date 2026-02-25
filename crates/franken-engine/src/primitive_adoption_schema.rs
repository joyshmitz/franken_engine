//! Primitive adoption schema and activation gate checks.
//!
//! This module encodes FRX-16.1 requirements as machine-checkable structures
//! that can be used by gates and governance automation.

use serde::{Deserialize, Serialize};

/// Capability tier for an advanced primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveTier {
    S,
    A,
    B,
    C,
}

impl PrimitiveTier {
    /// S/A tiers are considered frontier/high-risk and require explicit reuse scan.
    #[must_use]
    pub const fn requires_reuse_scan(self) -> bool {
        matches!(self, Self::S | Self::A)
    }
}

/// Outcome of crate reuse scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseDecision {
    AdoptExistingCrate,
    BuildNew,
    NotApplicable,
}

/// Verification metadata proving the primitive was vetted before activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecklist {
    pub checklist_version: String,
    pub primary_paper_verified: bool,
    pub independent_replication_completed: bool,
    pub verification_notes: String,
}

/// EV/relevance/risk scoring tuple (fixed-point millionths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvRelevanceRiskScore {
    pub ev_millionths: i64,
    pub relevance_millionths: u32,
    pub risk_millionths: u32,
}

/// Deterministic fallback trigger and budget summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackBudget {
    pub trigger: String,
    pub deterministic_mode: String,
    pub max_retry_count: u32,
    pub time_budget_ms: u64,
    pub memory_budget_mb: u32,
}

/// Crate-reuse scan result and adopt-vs-build rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReuseScan {
    pub catalog_version: String,
    pub decision: ReuseDecision,
    pub candidate_crates: Vec<String>,
    pub rationale: String,
}

/// Full machine-readable adoption record for one primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimitiveAdoptionRecord {
    pub primitive_id: String,
    pub tier: PrimitiveTier,
    pub verification: Option<VerificationChecklist>,
    pub score: EvRelevanceRiskScore,
    pub fallback: Option<FallbackBudget>,
    pub reuse_scan: Option<ReuseScan>,
    pub adopt_vs_build_rationale: String,
}

/// Deterministic validation error taxonomy for FRX-16.1 activation checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrimitiveAdoptionValidationError {
    MissingVerificationMetadata,
    MissingFallbackMetadata,
    MissingReuseScanOutcome,
    InvalidScoreRange { field: &'static str },
    InvalidMetadataField { field: &'static str },
}

impl PrimitiveAdoptionValidationError {
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingVerificationMetadata => "FE-FRX-16-VERIFY-0001",
            Self::MissingFallbackMetadata => "FE-FRX-16-FALLBACK-0001",
            Self::MissingReuseScanOutcome => "FE-FRX-16-REUSE-0001",
            Self::InvalidScoreRange { .. } => "FE-FRX-16-SCORE-0001",
            Self::InvalidMetadataField { .. } => "FE-FRX-16-METADATA-0001",
        }
    }
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

impl PrimitiveAdoptionRecord {
    /// Validate FRX-16.1 activation gate requirements.
    pub fn validate_for_activation(&self) -> Result<(), PrimitiveAdoptionValidationError> {
        if !non_empty(self.primitive_id.as_str()) {
            return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id",
            });
        }
        if !non_empty(self.adopt_vs_build_rationale.as_str()) {
            return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "adopt_vs_build_rationale",
            });
        }

        if self.score.relevance_millionths > 1_000_000 {
            return Err(PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths",
            });
        }
        if self.score.risk_millionths > 1_000_000 {
            return Err(PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "risk_millionths",
            });
        }

        let verification = self
            .verification
            .as_ref()
            .ok_or(PrimitiveAdoptionValidationError::MissingVerificationMetadata)?;
        if !verification.primary_paper_verified
            || !non_empty(verification.checklist_version.as_str())
            || !non_empty(verification.verification_notes.as_str())
        {
            return Err(PrimitiveAdoptionValidationError::MissingVerificationMetadata);
        }

        let fallback = self
            .fallback
            .as_ref()
            .ok_or(PrimitiveAdoptionValidationError::MissingFallbackMetadata)?;
        if !non_empty(fallback.trigger.as_str())
            || !non_empty(fallback.deterministic_mode.as_str())
            || fallback.time_budget_ms == 0
            || fallback.memory_budget_mb == 0
        {
            return Err(PrimitiveAdoptionValidationError::MissingFallbackMetadata);
        }

        if self.tier.requires_reuse_scan() {
            let reuse = self
                .reuse_scan
                .as_ref()
                .ok_or(PrimitiveAdoptionValidationError::MissingReuseScanOutcome)?;
            if !non_empty(reuse.catalog_version.as_str()) || !non_empty(reuse.rationale.as_str()) {
                return Err(PrimitiveAdoptionValidationError::MissingReuseScanOutcome);
            }
            if matches!(reuse.decision, ReuseDecision::AdoptExistingCrate)
                && reuse.candidate_crates.is_empty()
            {
                return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                    field: "candidate_crates",
                });
            }
        }

        Ok(())
    }
}
