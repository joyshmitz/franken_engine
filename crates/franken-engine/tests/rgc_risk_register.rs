#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde::Deserialize;

const RISK_REGISTER_SCHEMA_VERSION: &str = "rgc.risk-register.v1";
const RISK_REGISTER_JSON: &str = include_str!("../../../docs/rgc_risk_register_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RiskRegister {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: RiskTrack,
    review_policy: ReviewPolicy,
    risks: Vec<RiskEntry>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RiskTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReviewPolicy {
    fail_closed_on_stale_review: bool,
    stale_threshold_days: u64,
    milestone_reviews: Vec<MilestoneReview>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MilestoneReview {
    milestone: String,
    gate_id: String,
    required_reviewers: Vec<String>,
    cadence: String,
    required_evidence_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RiskEntry {
    risk_id: String,
    title: String,
    domain: String,
    likelihood: u8,
    impact: u8,
    risk_level: String,
    owner_role: String,
    mitigation_beads: Vec<String>,
    mitigation_summary: String,
    rollback_plan: String,
    last_reviewed_utc: String,
    next_review_due_utc: String,
    milestones_pending: Vec<String>,
    open_actions: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_risk_register() -> RiskRegister {
    serde_json::from_str(RISK_REGISTER_JSON).expect("risk register json must parse")
}

#[test]
fn rgc_013_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_RISK_REGISTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Risk Register V1",
        "## Purpose",
        "## Risk Model",
        "## Top-20 Coverage",
        "## High-Risk Mitigation Linkage",
        "## Milestone Review Cadence",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_013_register_is_versioned_and_track_bound() {
    let register = parse_risk_register();

    assert_eq!(register.schema_version, RISK_REGISTER_SCHEMA_VERSION);
    assert_eq!(register.bead_id, "bd-1lsy.1.3");
    assert_eq!(register.generated_by, "bd-1lsy.1.3");
    assert_eq!(register.track.id, "RGC-013");
    assert_eq!(register.track.name, "Risk Register and Mitigation Map");
    assert!(register.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_013_top_twenty_risks_have_owner_and_mitigation_path() {
    let register = parse_risk_register();

    assert!(
        register.risks.len() >= 20,
        "expected at least 20 risks, found {}",
        register.risks.len()
    );

    let mut ids = BTreeSet::new();

    for risk in &register.risks {
        assert!(
            ids.insert(risk.risk_id.clone()),
            "duplicate risk id {}",
            risk.risk_id
        );
        assert!(!risk.title.trim().is_empty());
        assert!(!risk.domain.trim().is_empty());
        assert!((1..=5).contains(&risk.likelihood));
        assert!((1..=5).contains(&risk.impact));
        assert!(["high", "medium", "low"].contains(&risk.risk_level.as_str()));
        assert!(!risk.owner_role.trim().is_empty());
        assert!(!risk.mitigation_summary.trim().is_empty());
        assert!(!risk.rollback_plan.trim().is_empty());
        assert!(
            !risk.mitigation_beads.is_empty(),
            "{} missing mitigation bead mapping",
            risk.risk_id
        );
        assert!(
            risk.mitigation_beads
                .iter()
                .all(|bead_id| bead_id.starts_with("bd-1lsy.")),
            "{} must only map to concrete RGC beads",
            risk.risk_id
        );
        assert!(risk.last_reviewed_utc.ends_with('Z'));
        assert!(risk.next_review_due_utc.ends_with('Z'));
        assert!(
            risk.last_reviewed_utc <= risk.next_review_due_utc,
            "{} has invalid review chronology",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_high_risks_link_to_one_or_more_concrete_beads() {
    let register = parse_risk_register();

    let high_risks: Vec<&RiskEntry> = register
        .risks
        .iter()
        .filter(|risk| risk.risk_level == "high")
        .collect();

    assert!(!high_risks.is_empty(), "expected at least one high risk");

    for risk in high_risks {
        assert!(
            !risk.mitigation_beads.is_empty(),
            "high risk {} missing mitigation beads",
            risk.risk_id
        );
        assert!(
            !risk.open_actions.is_empty(),
            "high risk {} should have open actions",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_review_policy_covers_every_milestone_gate() {
    let register = parse_risk_register();

    assert!(register.review_policy.fail_closed_on_stale_review);
    assert_eq!(register.review_policy.stale_threshold_days, 14);

    let expected: BTreeSet<&str> = ["M1", "M2", "M3", "M4", "M5"].into_iter().collect();
    let actual: BTreeSet<&str> = register
        .review_policy
        .milestone_reviews
        .iter()
        .map(|review| review.milestone.as_str())
        .collect();

    assert_eq!(actual, expected);

    for review in &register.review_policy.milestone_reviews {
        assert!(!review.gate_id.trim().is_empty());
        assert!(!review.required_reviewers.is_empty());
        assert!(!review.cadence.trim().is_empty());
        assert!(!review.required_evidence_fields.is_empty());
        for field in ["trace_id", "decision_id", "risk_ids_reviewed", "actions"] {
            assert!(
                review
                    .required_evidence_fields
                    .iter()
                    .any(|candidate| candidate == field),
                "{} missing required evidence field {}",
                review.milestone,
                field
            );
        }
    }
}

#[test]
fn rgc_013_all_risks_are_reviewed_at_milestones() {
    let register = parse_risk_register();
    let valid_milestones: BTreeSet<&str> = ["M1", "M2", "M3", "M4", "M5"].into_iter().collect();

    for risk in &register.risks {
        assert!(
            !risk.milestones_pending.is_empty(),
            "{} must be tracked in at least one milestone review",
            risk.risk_id
        );
        assert!(
            risk.milestones_pending
                .iter()
                .all(|milestone| valid_milestones.contains(milestone.as_str())),
            "{} includes unknown milestone in pending set",
            risk.risk_id
        );
    }
}

#[test]
fn rgc_013_operator_verification_commands_are_present() {
    let register = parse_risk_register();
    assert!(!register.operator_verification.is_empty());

    let joined = register.operator_verification.join("\n");
    assert!(joined.contains("jq empty docs/rgc_risk_register_v1.json"));
    assert!(joined.contains("cargo test -p frankenengine-engine --test rgc_risk_register"));
    assert!(joined.contains("run_phase_a_exit_gate.sh check"));
}
