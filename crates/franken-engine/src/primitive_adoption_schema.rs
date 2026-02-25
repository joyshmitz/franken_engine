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
    InvalidScoreRange { field: String },
    InvalidMetadataField { field: String },
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
                field: "primitive_id".to_string(),
            });
        }
        if !non_empty(self.adopt_vs_build_rationale.as_str()) {
            return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "adopt_vs_build_rationale".to_string(),
            });
        }

        if self.score.relevance_millionths > 1_000_000 {
            return Err(PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths".to_string(),
            });
        }
        if self.score.risk_millionths > 1_000_000 {
            return Err(PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "risk_millionths".to_string(),
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
                    field: "candidate_crates".to_string(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_verification() -> VerificationChecklist {
        VerificationChecklist {
            checklist_version: "v1.0".into(),
            primary_paper_verified: true,
            independent_replication_completed: true,
            verification_notes: "Verified against reference impl".into(),
        }
    }

    fn valid_score() -> EvRelevanceRiskScore {
        EvRelevanceRiskScore {
            ev_millionths: 500_000,
            relevance_millionths: 800_000,
            risk_millionths: 200_000,
        }
    }

    fn valid_fallback() -> FallbackBudget {
        FallbackBudget {
            trigger: "timeout_or_divergence".into(),
            deterministic_mode: "scalar_fallback".into(),
            max_retry_count: 3,
            time_budget_ms: 100,
            memory_budget_mb: 16,
        }
    }

    fn valid_reuse_scan() -> ReuseScan {
        ReuseScan {
            catalog_version: "2026-Q1".into(),
            decision: ReuseDecision::BuildNew,
            candidate_crates: vec![],
            rationale: "No existing crate meets determinism requirements".into(),
        }
    }

    fn valid_record_tier_s() -> PrimitiveAdoptionRecord {
        PrimitiveAdoptionRecord {
            primitive_id: "prim-001".into(),
            tier: PrimitiveTier::S,
            verification: Some(valid_verification()),
            score: valid_score(),
            fallback: Some(valid_fallback()),
            reuse_scan: Some(valid_reuse_scan()),
            adopt_vs_build_rationale: "Build new for determinism guarantees".into(),
        }
    }

    fn valid_record_tier_c() -> PrimitiveAdoptionRecord {
        PrimitiveAdoptionRecord {
            primitive_id: "prim-low".into(),
            tier: PrimitiveTier::C,
            verification: Some(valid_verification()),
            score: valid_score(),
            fallback: Some(valid_fallback()),
            reuse_scan: None,
            adopt_vs_build_rationale: "Standard utility, no reuse scan needed".into(),
        }
    }

    // -- PrimitiveTier --

    #[test]
    fn tier_s_requires_reuse_scan() {
        assert!(PrimitiveTier::S.requires_reuse_scan());
    }

    #[test]
    fn tier_a_requires_reuse_scan() {
        assert!(PrimitiveTier::A.requires_reuse_scan());
    }

    #[test]
    fn tier_b_no_reuse_scan() {
        assert!(!PrimitiveTier::B.requires_reuse_scan());
    }

    #[test]
    fn tier_c_no_reuse_scan() {
        assert!(!PrimitiveTier::C.requires_reuse_scan());
    }

    #[test]
    fn tier_serde_roundtrip() {
        for tier in [
            PrimitiveTier::S,
            PrimitiveTier::A,
            PrimitiveTier::B,
            PrimitiveTier::C,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: PrimitiveTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn tier_serde_snake_case() {
        let json = serde_json::to_string(&PrimitiveTier::S).unwrap();
        assert!(json.contains("s") || json.contains("S"));
    }

    // -- ReuseDecision --

    #[test]
    fn reuse_decision_serde_roundtrip() {
        for d in [
            ReuseDecision::AdoptExistingCrate,
            ReuseDecision::BuildNew,
            ReuseDecision::NotApplicable,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: ReuseDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    // -- VerificationChecklist --

    #[test]
    fn verification_checklist_serde_roundtrip() {
        let v = valid_verification();
        let json = serde_json::to_string(&v).unwrap();
        let back: VerificationChecklist = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- EvRelevanceRiskScore --

    #[test]
    fn score_serde_roundtrip() {
        let s = valid_score();
        let json = serde_json::to_string(&s).unwrap();
        let back: EvRelevanceRiskScore = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn score_boundary_values() {
        let s = EvRelevanceRiskScore {
            ev_millionths: i64::MAX,
            relevance_millionths: 1_000_000,
            risk_millionths: 0,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: EvRelevanceRiskScore = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- FallbackBudget --

    #[test]
    fn fallback_budget_serde_roundtrip() {
        let fb = valid_fallback();
        let json = serde_json::to_string(&fb).unwrap();
        let back: FallbackBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }

    // -- ReuseScan --

    #[test]
    fn reuse_scan_serde_roundtrip() {
        let rs = valid_reuse_scan();
        let json = serde_json::to_string(&rs).unwrap();
        let back: ReuseScan = serde_json::from_str(&json).unwrap();
        assert_eq!(rs, back);
    }

    #[test]
    fn reuse_scan_with_candidates() {
        let rs = ReuseScan {
            catalog_version: "2026-Q1".into(),
            decision: ReuseDecision::AdoptExistingCrate,
            candidate_crates: vec!["sha2".into(), "sha3".into()],
            rationale: "sha2 meets determinism bar".into(),
        };
        let json = serde_json::to_string(&rs).unwrap();
        let back: ReuseScan = serde_json::from_str(&json).unwrap();
        assert_eq!(rs.candidate_crates.len(), back.candidate_crates.len());
    }

    // -- PrimitiveAdoptionValidationError --

    #[test]
    fn error_codes_unique() {
        let errors = [
            PrimitiveAdoptionValidationError::MissingVerificationMetadata,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths".to_string(),
            },
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string(),
            },
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.error_code()).collect();
        let mut deduped = codes.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(codes.len(), deduped.len());
    }

    #[test]
    fn error_codes_start_with_prefix() {
        let err = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
        assert!(err.error_code().starts_with("FE-FRX-16"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let err = PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk_millionths".to_string(),
        };
        let val = serde_json::to_value(&err).unwrap();
        let back: PrimitiveAdoptionValidationError = serde_json::from_value(val).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn validation_error_tagged_serde() {
        let err = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"kind\""));
        assert!(json.contains("missing_verification_metadata"));
    }

    // -- PrimitiveAdoptionRecord --

    #[test]
    fn record_serde_roundtrip() {
        let r = valid_record_tier_s();
        let json = serde_json::to_string(&r).unwrap();
        let back: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- validate_for_activation: happy paths --

    #[test]
    fn validate_tier_s_valid() {
        let r = valid_record_tier_s();
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validate_tier_a_valid() {
        let mut r = valid_record_tier_s();
        r.tier = PrimitiveTier::A;
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validate_tier_b_no_reuse_scan_ok() {
        let mut r = valid_record_tier_c();
        r.tier = PrimitiveTier::B;
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validate_tier_c_no_reuse_scan_ok() {
        let r = valid_record_tier_c();
        assert!(r.validate_for_activation().is_ok());
    }

    // -- validate_for_activation: empty primitive_id --

    #[test]
    fn validate_empty_primitive_id() {
        let mut r = valid_record_tier_c();
        r.primitive_id = "".into();
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string()
            }
        );
    }

    #[test]
    fn validate_whitespace_primitive_id() {
        let mut r = valid_record_tier_c();
        r.primitive_id = "   ".into();
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string()
            }
        );
    }

    // -- validate_for_activation: empty rationale --

    #[test]
    fn validate_empty_rationale() {
        let mut r = valid_record_tier_c();
        r.adopt_vs_build_rationale = "".into();
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "adopt_vs_build_rationale".to_string()
            }
        );
    }

    // -- validate_for_activation: score range --

    #[test]
    fn validate_relevance_over_million() {
        let mut r = valid_record_tier_c();
        r.score.relevance_millionths = 1_000_001;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths".to_string()
            }
        );
    }

    #[test]
    fn validate_risk_over_million() {
        let mut r = valid_record_tier_c();
        r.score.risk_millionths = 1_000_001;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "risk_millionths".to_string()
            }
        );
    }

    #[test]
    fn validate_relevance_exactly_million_ok() {
        let mut r = valid_record_tier_c();
        r.score.relevance_millionths = 1_000_000;
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validate_risk_exactly_million_ok() {
        let mut r = valid_record_tier_c();
        r.score.risk_millionths = 1_000_000;
        assert!(r.validate_for_activation().is_ok());
    }

    // -- validate_for_activation: missing verification --

    #[test]
    fn validate_missing_verification() {
        let mut r = valid_record_tier_c();
        r.verification = None;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingVerificationMetadata
        );
    }

    #[test]
    fn validate_unverified_paper() {
        let mut r = valid_record_tier_c();
        let mut v = valid_verification();
        v.primary_paper_verified = false;
        r.verification = Some(v);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingVerificationMetadata
        );
    }

    #[test]
    fn validate_empty_checklist_version() {
        let mut r = valid_record_tier_c();
        let mut v = valid_verification();
        v.checklist_version = "".into();
        r.verification = Some(v);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingVerificationMetadata
        );
    }

    #[test]
    fn validate_empty_verification_notes() {
        let mut r = valid_record_tier_c();
        let mut v = valid_verification();
        v.verification_notes = "  ".into();
        r.verification = Some(v);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingVerificationMetadata
        );
    }

    // -- validate_for_activation: missing fallback --

    #[test]
    fn validate_missing_fallback() {
        let mut r = valid_record_tier_c();
        r.fallback = None;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata
        );
    }

    #[test]
    fn validate_empty_trigger() {
        let mut r = valid_record_tier_c();
        let mut fb = valid_fallback();
        fb.trigger = "".into();
        r.fallback = Some(fb);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata
        );
    }

    #[test]
    fn validate_empty_deterministic_mode() {
        let mut r = valid_record_tier_c();
        let mut fb = valid_fallback();
        fb.deterministic_mode = "".into();
        r.fallback = Some(fb);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata
        );
    }

    #[test]
    fn validate_zero_time_budget() {
        let mut r = valid_record_tier_c();
        let mut fb = valid_fallback();
        fb.time_budget_ms = 0;
        r.fallback = Some(fb);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata
        );
    }

    #[test]
    fn validate_zero_memory_budget() {
        let mut r = valid_record_tier_c();
        let mut fb = valid_fallback();
        fb.memory_budget_mb = 0;
        r.fallback = Some(fb);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata
        );
    }

    // -- validate_for_activation: reuse scan for S/A --

    #[test]
    fn validate_tier_s_missing_reuse_scan() {
        let mut r = valid_record_tier_s();
        r.reuse_scan = None;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome
        );
    }

    #[test]
    fn validate_tier_a_missing_reuse_scan() {
        let mut r = valid_record_tier_s();
        r.tier = PrimitiveTier::A;
        r.reuse_scan = None;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome
        );
    }

    #[test]
    fn validate_reuse_scan_empty_catalog_version() {
        let mut r = valid_record_tier_s();
        let mut rs = valid_reuse_scan();
        rs.catalog_version = "".into();
        r.reuse_scan = Some(rs);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome
        );
    }

    #[test]
    fn validate_reuse_scan_empty_rationale() {
        let mut r = valid_record_tier_s();
        let mut rs = valid_reuse_scan();
        rs.rationale = "".into();
        r.reuse_scan = Some(rs);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome
        );
    }

    #[test]
    fn validate_adopt_decision_empty_candidates() {
        let mut r = valid_record_tier_s();
        let mut rs = valid_reuse_scan();
        rs.decision = ReuseDecision::AdoptExistingCrate;
        rs.candidate_crates = vec![];
        r.reuse_scan = Some(rs);
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "candidate_crates".to_string()
            }
        );
    }

    #[test]
    fn validate_adopt_decision_with_candidates_ok() {
        let mut r = valid_record_tier_s();
        let mut rs = valid_reuse_scan();
        rs.decision = ReuseDecision::AdoptExistingCrate;
        rs.candidate_crates = vec!["sha2".into()];
        r.reuse_scan = Some(rs);
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validate_build_new_empty_candidates_ok() {
        let r = valid_record_tier_s();
        assert_eq!(
            r.reuse_scan.as_ref().unwrap().decision,
            ReuseDecision::BuildNew
        );
        assert!(r.reuse_scan.as_ref().unwrap().candidate_crates.is_empty());
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validate_not_applicable_reuse_ok() {
        let mut r = valid_record_tier_s();
        let mut rs = valid_reuse_scan();
        rs.decision = ReuseDecision::NotApplicable;
        r.reuse_scan = Some(rs);
        assert!(r.validate_for_activation().is_ok());
    }

    // -- non_empty helper --

    #[test]
    fn non_empty_rejects_empty() {
        assert!(!non_empty(""));
    }

    #[test]
    fn non_empty_rejects_whitespace() {
        assert!(!non_empty("   "));
        assert!(!non_empty("\t\n"));
    }

    #[test]
    fn non_empty_accepts_content() {
        assert!(non_empty("hello"));
        assert!(non_empty(" x "));
    }
}
