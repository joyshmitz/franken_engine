#![forbid(unsafe_code)]

use std::{
    collections::{BTreeSet, HashSet},
    fs,
    path::PathBuf,
};

use serde::Deserialize;

const GATEBOOK_SCHEMA_VERSION: &str = "frx.release-operations-gatebook.v1";
const GATEBOOK_JSON: &str = include_str!("../../../docs/frx_release_operations_gatebook_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReleaseOperationsGatebookContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    consumes_cut_line_artifacts: CutLineConsumption,
    release_packet_channels: Vec<ReleasePacketChannel>,
    stage_checklists: Vec<StageChecklist>,
    communication_discipline: CommunicationDiscipline,
    claim_publication_record: ClaimPublicationRecord,
    fail_closed_rules: Vec<String>,
    required_structured_log_fields: Vec<String>,
    prerequisites: Vec<Prerequisite>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CutLineConsumption {
    source_contract: String,
    required_cut_lines: Vec<String>,
    require_signed_decisions: bool,
    require_monotonic_stage_progression: bool,
    fail_closed_on_missing_stage_decision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReleasePacketChannel {
    channel_id: String,
    source_bead: String,
    required: bool,
    signed_required: bool,
    max_age_ns: u64,
    failure_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StageChecklist {
    stage: String,
    min_cut_line: String,
    required_channels: Vec<String>,
    required_checklist_items: Vec<String>,
    publication_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CommunicationDiscipline {
    incident_response: IncidentResponse,
    rollback_communications: RollbackCommunications,
    publication_communications: PublicationCommunications,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentResponse {
    required_fields: Vec<String>,
    require_escalation_acknowledgement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RollbackCommunications {
    required_fields: Vec<String>,
    require_operator_acknowledgement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PublicationCommunications {
    required_fields: Vec<String>,
    require_signed_statement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ClaimPublicationRecord {
    required_fields: Vec<String>,
    require_reproducibility_bundle_links: bool,
    require_release_packet_digest: bool,
    block_on_incomplete_record: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Prerequisite {
    bead_id: String,
    reason: String,
    status: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ReleaseOperationsGatebookContract {
    serde_json::from_str(GATEBOOK_JSON).expect("release operations gatebook JSON must parse")
}

#[test]
fn frx_09_2_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_RELEASE_OPERATIONS_GATEBOOK_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# FRX Release Operations Gatebook and Publication Workflow V1",
        "## Scope",
        "## FRX-12 Consumption Contract",
        "## Release Packet Channels",
        "## Stage Checklists and Publication Workflow",
        "## Incident-Response and Rollback Communication Discipline",
        "## Claim Publication and Reproducibility Linkage",
        "## Fail-Closed Validation Rules",
        "## Deterministic Logging and Artifact Contract",
        "## Dependencies and Prerequisites",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "fail-closed",
        "release packet",
        "cut-line",
        "rollback",
        "publication",
        "reproducibility",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "missing required phrase in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_09_2_contract_is_machine_readable_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, GATEBOOK_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.9.2");
    assert_eq!(contract.generated_by, "bd-mjh3.9.2");
    assert_eq!(contract.track.id, "FRX-09.2");
    assert!(contract.track.name.contains("Release Operations"));
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_09_2_cut_line_consumption_and_channels_are_fail_closed() {
    let contract = parse_contract();

    let expected_cut_lines: BTreeSet<&str> =
        ["C0", "C1", "C2", "C3", "C4", "C5"].into_iter().collect();
    let observed_cut_lines: BTreeSet<&str> = contract
        .consumes_cut_line_artifacts
        .required_cut_lines
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(observed_cut_lines, expected_cut_lines);

    assert!(
        contract
            .consumes_cut_line_artifacts
            .source_contract
            .contains("cut-line-automation")
    );
    assert!(
        contract
            .consumes_cut_line_artifacts
            .require_signed_decisions
    );
    assert!(
        contract
            .consumes_cut_line_artifacts
            .require_monotonic_stage_progression
    );
    assert!(
        contract
            .consumes_cut_line_artifacts
            .fail_closed_on_missing_stage_decision
    );

    let mut channel_ids = HashSet::new();
    for channel in &contract.release_packet_channels {
        assert!(channel_ids.insert(channel.channel_id.as_str()));
        assert!(
            channel.required,
            "channel must be required: {}",
            channel.channel_id
        );
        assert!(
            channel.signed_required,
            "channel must require signatures: {}",
            channel.channel_id
        );
        assert!(channel.max_age_ns > 0);
        assert_eq!(channel.failure_code, "FE-FRX-09-2-RELEASE-OPS-0001");
        assert!(channel.source_bead.starts_with("bd-mjh3."));
    }

    for required in [
        "cut_line_decision_bundle",
        "ga_readiness_claim_bundle",
        "proof_carrying_artifact_gate",
        "pilot_rollout_harness",
        "tail_latency_memory_hardening",
        "observability_demotion",
        "catastrophic_tail_tournament",
        "twin_rollback_synthesizer",
        "test_evidence_integrator",
    ] {
        assert!(
            channel_ids.contains(required),
            "missing required channel: {required}"
        );
    }
}

#[test]
fn frx_09_2_stage_checklists_are_progressive_and_complete() {
    let contract = parse_contract();

    assert_eq!(contract.stage_checklists.len(), 3);

    let mut seen_stages = HashSet::new();
    let channel_ids: HashSet<&str> = contract
        .release_packet_channels
        .iter()
        .map(|channel| channel.channel_id.as_str())
        .collect();

    for checklist in &contract.stage_checklists {
        assert!(seen_stages.insert(checklist.stage.as_str()));
        assert!(
            matches!(checklist.stage.as_str(), "alpha" | "beta" | "ga"),
            "unexpected stage {}",
            checklist.stage
        );
        assert!(
            matches!(checklist.min_cut_line.as_str(), "C2" | "C3" | "C4"),
            "unexpected cut-line {}",
            checklist.min_cut_line
        );
        assert!(!checklist.required_channels.is_empty());
        assert!(!checklist.required_checklist_items.is_empty());
        assert!(!checklist.publication_mode.trim().is_empty());

        for channel in &checklist.required_channels {
            assert!(
                channel_ids.contains(channel.as_str()),
                "stage {} references unknown channel {}",
                checklist.stage,
                channel
            );
        }
    }

    let alpha = contract
        .stage_checklists
        .iter()
        .find(|checklist| checklist.stage == "alpha")
        .expect("alpha checklist missing");
    let beta = contract
        .stage_checklists
        .iter()
        .find(|checklist| checklist.stage == "beta")
        .expect("beta checklist missing");
    let ga = contract
        .stage_checklists
        .iter()
        .find(|checklist| checklist.stage == "ga")
        .expect("ga checklist missing");

    assert_eq!(alpha.min_cut_line, "C2");
    assert_eq!(beta.min_cut_line, "C3");
    assert_eq!(ga.min_cut_line, "C4");

    assert!(
        ga.required_channels.len() >= beta.required_channels.len()
            && beta.required_channels.len() >= alpha.required_channels.len(),
        "required channel sets must grow or stay equal as stages progress"
    );
}

#[test]
fn frx_09_2_communication_and_publication_contracts_are_explicit() {
    let contract = parse_contract();

    let incident_fields: BTreeSet<&str> = contract
        .communication_discipline
        .incident_response
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "incident_id",
        "severity",
        "decision_id",
        "owner",
        "escalation_path",
        "first_response_deadline_s",
    ] {
        assert!(
            incident_fields.contains(field),
            "missing incident field {field}"
        );
    }
    assert!(
        contract
            .communication_discipline
            .incident_response
            .require_escalation_acknowledgement
    );

    let rollback_fields: BTreeSet<&str> = contract
        .communication_discipline
        .rollback_communications
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "rollback_id",
        "trigger_signal",
        "rollback_command",
        "safe_mode_target",
        "eta_recovery_s",
    ] {
        assert!(
            rollback_fields.contains(field),
            "missing rollback field {field}"
        );
    }
    assert!(
        contract
            .communication_discipline
            .rollback_communications
            .require_operator_acknowledgement
    );

    let publication_fields: BTreeSet<&str> = contract
        .communication_discipline
        .publication_communications
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "claim_id",
        "release_stage",
        "bundle_digest",
        "public_statement_ref",
    ] {
        assert!(
            publication_fields.contains(field),
            "missing publication communication field {field}"
        );
    }
    assert!(
        contract
            .communication_discipline
            .publication_communications
            .require_signed_statement
    );

    let claim_fields: BTreeSet<&str> = contract
        .claim_publication_record
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "claim_id",
        "stage_gate_decision_id",
        "reproducibility_bundle_id",
        "evidence_bundle_ids",
        "release_packet_digest",
        "replay_command",
        "publication_timestamp_utc",
        "signer",
        "signature_ref",
    ] {
        assert!(
            claim_fields.contains(field),
            "missing claim publication field {field}"
        );
    }

    assert!(
        contract
            .claim_publication_record
            .require_reproducibility_bundle_links
    );
    assert!(
        contract
            .claim_publication_record
            .require_release_packet_digest
    );
    assert!(contract.claim_publication_record.block_on_incomplete_record);
}

#[test]
fn frx_09_2_fail_closed_rules_and_logging_fields_are_complete() {
    let contract = parse_contract();

    let rules: BTreeSet<&str> = contract
        .fail_closed_rules
        .iter()
        .map(String::as_str)
        .collect();
    for required_rule in [
        "missing_required_channel",
        "stale_channel_artifact",
        "missing_or_invalid_signature",
        "stage_checklist_failure",
        "missing_publication_record_field",
        "release_packet_digest_mismatch",
    ] {
        assert!(rules.contains(required_rule));
    }

    let log_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "release_stage",
        "publication_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(log_fields.contains(field), "missing log field {field}");
    }
}

#[test]
fn frx_09_2_prerequisites_and_operator_verification_are_declared() {
    let contract = parse_contract();

    assert_eq!(contract.prerequisites.len(), 6);
    let prerequisite_ids: BTreeSet<&str> = contract
        .prerequisites
        .iter()
        .map(|entry| entry.bead_id.as_str())
        .collect();
    let expected_ids: BTreeSet<&str> = [
        "bd-mjh3.20.6",
        "bd-mjh3.12.7",
        "bd-mjh3.12.5",
        "bd-mjh3.5.4",
        "bd-mjh3.9.1",
        "bd-mjh3.6.4",
    ]
    .into_iter()
    .collect();
    assert_eq!(prerequisite_ids, expected_ids);

    let statuses: BTreeSet<&str> = contract
        .prerequisites
        .iter()
        .map(|entry| entry.status.as_str())
        .collect();
    assert!(statuses.contains("closed"));
    assert!(statuses.contains("in_progress"));
    assert!(statuses.contains("open"));

    for entry in &contract.prerequisites {
        assert!(!entry.reason.trim().is_empty());
    }

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("run_frx_release_operations_gatebook_suite.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("frx_release_operations_gatebook_replay.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry == "jq empty docs/frx_release_operations_gatebook_v1.json")
    );
}
