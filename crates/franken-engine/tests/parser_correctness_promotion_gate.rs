use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WaiverRecord {
    waiver_id: String,
    approved_by: String,
    remediation_due_utc: String,
    rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DriftRecord {
    drift_id: String,
    fixture_id: String,
    severity: String,
    status: String,
    owner: String,
    detected_at_utc: String,
    replay_command: String,
    waiver: Option<WaiverRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvidenceVector {
    lane_id: String,
    status: String,
    artifact_manifest: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_unresolved_high_count: usize,
    expected_waiver_count: usize,
    expected_blockers: Vec<String>,
    expected_failing_fixture_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserCorrectnessPromotionGateFixture {
    schema_version: String,
    gate_version: String,
    high_severity_levels: Vec<String>,
    required_evidence_lanes: Vec<String>,
    structured_log_required_keys: Vec<String>,
    drift_records: Vec<DriftRecord>,
    evidence_vectors: Vec<EvidenceVector>,
    expected_gate: ExpectedGate,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    unresolved_high_count: usize,
    waiver_count: usize,
    blockers: Vec<String>,
    failing_fixture_ids: Vec<String>,
}

fn load_fixture() -> ParserCorrectnessPromotionGateFixture {
    let path = Path::new("tests/fixtures/parser_correctness_promotion_gate_v1.json");
    let bytes = fs::read(path).expect("read parser correctness promotion gate fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser correctness promotion gate fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_CORRECTNESS_PROMOTION_GATE.md");
    fs::read_to_string(path).expect("read parser correctness promotion gate doc")
}

fn unresolved_high_drifts<'a>(
    fixture: &'a ParserCorrectnessPromotionGateFixture,
) -> Vec<&'a DriftRecord> {
    let high_set = fixture
        .high_severity_levels
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    fixture
        .drift_records
        .iter()
        .filter(|drift| {
            high_set.contains(drift.severity.as_str())
                && drift.status != "resolved"
                && drift.status != "waived"
        })
        .collect()
}

fn count_waivers(fixture: &ParserCorrectnessPromotionGateFixture) -> usize {
    fixture
        .drift_records
        .iter()
        .filter(|drift| drift.status == "waived")
        .count()
}

fn collect_waiver_issues(fixture: &ParserCorrectnessPromotionGateFixture) -> Vec<String> {
    let mut issues = Vec::new();

    for drift in fixture
        .drift_records
        .iter()
        .filter(|drift| drift.status == "waived")
    {
        let Some(waiver) = drift.waiver.as_ref() else {
            issues.push(format!("invalid_waiver:{}:missing_record", drift.drift_id));
            continue;
        };

        if waiver.waiver_id.trim().is_empty()
            || waiver.approved_by.trim().is_empty()
            || waiver.rationale.trim().is_empty()
        {
            issues.push(format!("invalid_waiver:{}:missing_fields", drift.drift_id));
        }

        if waiver.remediation_due_utc <= drift.detected_at_utc {
            issues.push(format!(
                "invalid_waiver:{}:invalid_due_date",
                drift.drift_id
            ));
        }
    }

    issues
}

fn evaluate_gate(fixture: &ParserCorrectnessPromotionGateFixture) -> GateEvaluation {
    let unresolved = unresolved_high_drifts(fixture);
    let waiver_count = count_waivers(fixture);
    let waiver_issues = collect_waiver_issues(fixture);

    let evidence_by_lane = fixture
        .evidence_vectors
        .iter()
        .map(|vector| (vector.lane_id.as_str(), vector.status.as_str()))
        .collect::<BTreeMap<_, _>>();

    let mut blockers = Vec::new();
    for drift in &unresolved {
        blockers.push(format!("unresolved_high_drift:{}", drift.drift_id));
    }

    for lane in &fixture.required_evidence_lanes {
        match evidence_by_lane.get(lane.as_str()) {
            None => blockers.push(format!("evidence_missing:{lane}")),
            Some(status) if *status != "pass" => {
                blockers.push(format!("evidence_not_green:{lane}:{status}"));
            }
            Some(_) => {}
        }
    }

    blockers.extend(waiver_issues);
    blockers.sort();
    blockers.dedup();

    let mut failing_fixture_ids = unresolved
        .iter()
        .map(|drift| drift.fixture_id.clone())
        .collect::<Vec<_>>();
    failing_fixture_ids.sort();
    failing_fixture_ids.dedup();

    let outcome = if blockers.is_empty() {
        "promote"
    } else {
        "hold"
    };

    GateEvaluation {
        outcome: outcome.to_string(),
        unresolved_high_count: unresolved.len(),
        waiver_count,
        blockers,
        failing_fixture_ids,
    }
}

fn emit_structured_event(
    fixture: &ParserCorrectnessPromotionGateFixture,
    evaluation: &GateEvaluation,
) -> serde_json::Value {
    let drift_inventory = fixture
        .drift_records
        .iter()
        .map(|drift| drift.drift_id.clone())
        .collect::<Vec<_>>();
    let waiver_inventory = fixture
        .drift_records
        .iter()
        .filter(|drift| drift.status == "waived")
        .filter_map(|drift| drift.waiver.as_ref().map(|waiver| waiver.waiver_id.clone()))
        .collect::<Vec<_>>();

    let replay_pointers = fixture
        .drift_records
        .iter()
        .map(|drift| drift.replay_command.clone())
        .chain(
            fixture
                .evidence_vectors
                .iter()
                .map(|vector| vector.replay_command.clone()),
        )
        .chain(
            fixture
                .replay_scenarios
                .iter()
                .map(|scenario| scenario.replay_command.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-correctness-promotion-gate-v1",
        "decision_id": "decision-parser-correctness-promotion-gate-v1",
        "policy_id": "policy-parser-correctness-promotion-gate-v1",
        "component": "parser_correctness_promotion_gate",
        "event": "correctness_gate_evaluated",
        "outcome": evaluation.outcome,
        "error_code": if evaluation.outcome == "promote" {
            serde_json::Value::Null
        } else {
            serde_json::Value::String("FE-PARSER-CORRECTNESS-GATE-0001".to_string())
        },
        "drift_inventory": drift_inventory,
        "waiver_inventory": waiver_inventory,
        "failing_fixture_ids": evaluation.failing_fixture_ids,
        "replay_pointers": replay_pointers,
        "blockers": evaluation.blockers,
    })
}

#[test]
fn parser_correctness_doc_has_required_sections() {
    let doc = load_doc();

    for section in [
        "# Parser Correctness Promotion Gate (`bd-2mds.1.8.2`)",
        "## Promotion Policy",
        "## Evidence Requirements",
        "## Drift and Waiver Semantics",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
    ] {
        assert!(doc.contains(section), "missing section: {section}");
    }

    for command in [
        "./scripts/run_parser_correctness_promotion_gate.sh ci",
        "./scripts/e2e/parser_correctness_promotion_gate_replay.sh",
    ] {
        assert!(
            doc.contains(command),
            "missing command reference: {command}"
        );
    }
}

#[test]
fn parser_correctness_fixture_contract_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-correctness-promotion-gate.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");

    let high_levels = fixture
        .high_severity_levels
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(high_levels.contains("high"));
    assert!(high_levels.contains("critical"));

    let required_lanes = fixture
        .required_evidence_lanes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(required_lanes.contains("parser_oracle"));
    assert!(required_lanes.contains("event_ast_equivalence"));
    assert!(required_lanes.contains("parallel_fallback_parity"));
    assert!(required_lanes.contains("differential_harness"));

    for drift in &fixture.drift_records {
        assert!(!drift.drift_id.trim().is_empty());
        assert!(!drift.fixture_id.trim().is_empty());
        assert!(!drift.owner.trim().is_empty());
        assert!(
            ["open", "resolved", "waived"].contains(&drift.status.as_str()),
            "unexpected drift status: {}",
            drift.status
        );
        assert!(
            ["critical", "high", "medium", "low"].contains(&drift.severity.as_str()),
            "unexpected drift severity: {}",
            drift.severity
        );
    }

    for vector in &fixture.evidence_vectors {
        assert!(!vector.lane_id.trim().is_empty());
        assert!(!vector.artifact_manifest.trim().is_empty());
        assert!(
            ["pass", "fail", "missing"].contains(&vector.status.as_str()),
            "unexpected evidence status: {}",
            vector.status
        );
    }

    assert!(!fixture.replay_scenarios.is_empty());
}

#[test]
fn parser_correctness_unresolved_high_and_waiver_counts_match_expected() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    assert_eq!(
        evaluation.unresolved_high_count,
        fixture.expected_gate.expected_unresolved_high_count
    );
    assert_eq!(
        evaluation.waiver_count,
        fixture.expected_gate.expected_waiver_count
    );

    let waiver_issues = collect_waiver_issues(&fixture);
    assert!(waiver_issues.is_empty(), "waiver issues: {waiver_issues:?}");
}

#[test]
fn parser_correctness_gate_evaluation_matches_expected_fixture() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    assert_eq!(evaluation.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(evaluation.blockers, fixture.expected_gate.expected_blockers);
    assert_eq!(
        evaluation.failing_fixture_ids,
        fixture.expected_gate.expected_failing_fixture_ids
    );
}

#[test]
fn parser_correctness_structured_event_has_required_fields() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);

    for key in &fixture.structured_log_required_keys {
        assert!(
            event.get(key).is_some(),
            "missing structured log key in emitted event: {key}"
        );
    }

    assert_eq!(
        event
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .expect("outcome string"),
        fixture.expected_gate.expected_outcome
    );

    assert_eq!(
        event
            .get("failing_fixture_ids")
            .and_then(serde_json::Value::as_array)
            .expect("failing_fixture_ids array")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>(),
        fixture
            .expected_gate
            .expected_failing_fixture_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

#[test]
fn parser_correctness_replay_scenarios_reference_wrapper_commands() {
    let fixture = load_fixture();

    for scenario in &fixture.replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(scenario.replay_command.starts_with("./scripts/e2e/"));
        assert!(scenario.replay_command.ends_with(".sh"));
        assert!(
            ["hold", "promote"].contains(&scenario.expected_outcome.as_str()),
            "unexpected expected_outcome: {}",
            scenario.expected_outcome
        );
    }
}
