use std::{fs, path::PathBuf};

#[path = "../src/primitive_adoption_schema.rs"]
mod primitive_adoption_schema;

use primitive_adoption_schema::{
    EvRelevanceRiskScore, FallbackBudget, PrimitiveAdoptionRecord,
    PrimitiveAdoptionValidationError, PrimitiveTier, ReuseDecision, ReuseScan,
    VerificationChecklist,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn valid_record(tier: PrimitiveTier) -> PrimitiveAdoptionRecord {
    PrimitiveAdoptionRecord {
        primitive_id: "frx.primitive.lockfree_scheduler.v1".to_string(),
        tier,
        verification: Some(VerificationChecklist {
            checklist_version: "v1".to_string(),
            primary_paper_verified: true,
            independent_replication_completed: true,
            verification_notes: "replicated against reference corpus".to_string(),
        }),
        score: EvRelevanceRiskScore {
            ev_millionths: 250_000,
            relevance_millionths: 900_000,
            risk_millionths: 180_000,
        },
        fallback: Some(FallbackBudget {
            trigger: "calibration_drift".to_string(),
            deterministic_mode: "safe_mode_serial".to_string(),
            max_retry_count: 1,
            time_budget_ms: 50,
            memory_budget_mb: 128,
        }),
        reuse_scan: Some(ReuseScan {
            catalog_version: "crate-catalog-2026-02-25".to_string(),
            decision: ReuseDecision::AdoptExistingCrate,
            candidate_crates: vec!["crossbeam".to_string()],
            rationale: "adopted for proven lock-free queue semantics".to_string(),
        }),
        adopt_vs_build_rationale: "adopt existing implementation unless verification fails"
            .to_string(),
    }
}

#[test]
fn primitive_adoption_schema_doc_has_required_sections() {
    let path = repo_root().join("docs/FRX_PRIMITIVE_ADOPTION_SCHEMA_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Primitive Adoption Schema v1",
        "## Scope",
        "## Required Metadata",
        "## Activation Gate Rules",
        "## Crate Reuse Scan Contract",
        "## Structured Logging Contract",
        "## Operator Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "primitive adoption doc missing section: {section}"
        );
    }
}

#[test]
fn primitive_adoption_schema_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_primitive_adoption_schema_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.primitive.adoption.schema.v1")
    );
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.16.1"));
    assert_eq!(
        value["activation_gate"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_verification_metadata"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_fallback_metadata"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_reuse_scan_outcome"].as_bool(),
        Some(true)
    );
}

#[test]
fn activation_allows_valid_s_tier_record() {
    let record = valid_record(PrimitiveTier::S);
    assert_eq!(record.validate_for_activation(), Ok(()));
}

#[test]
fn missing_verification_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::S);
    record.verification = None;

    let error = record.validate_for_activation().unwrap_err();
    assert_eq!(
        error,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
    assert_eq!(error.error_code(), "FE-FRX-16-VERIFY-0001");
}

#[test]
fn missing_fallback_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::A);
    record.fallback = None;

    let error = record.validate_for_activation().unwrap_err();
    assert_eq!(
        error,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
    assert_eq!(error.error_code(), "FE-FRX-16-FALLBACK-0001");
}

#[test]
fn missing_reuse_scan_blocks_s_tier_activation() {
    let mut record = valid_record(PrimitiveTier::S);
    record.reuse_scan = None;

    let error = record.validate_for_activation().unwrap_err();
    assert_eq!(
        error,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
    assert_eq!(error.error_code(), "FE-FRX-16-REUSE-0001");
}

#[test]
fn b_tier_can_activate_without_reuse_scan() {
    let mut record = valid_record(PrimitiveTier::B);
    record.reuse_scan = None;

    assert_eq!(record.validate_for_activation(), Ok(()));
}
