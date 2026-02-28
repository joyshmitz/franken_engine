use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct GatingPolicy {
    minimum_passed_verifiers: u32,
    max_open_risk_score_millionths: u64,
    fail_on_evidence_statuses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EvidenceArtifact {
    evidence_id: String,
    status: String,
    required: bool,
    manifest_path: String,
    replay_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceStatus {
    Pass,
    InProgress,
    Fail,
    Missing,
}

impl EvidenceStatus {
    fn parse(raw: &str) -> Self {
        match raw {
            "pass" => Self::Pass,
            "in_progress" => Self::InProgress,
            "fail" => Self::Fail,
            "missing" => Self::Missing,
            other => panic!("unknown evidence status: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn parse(raw: &str) -> Self {
        match raw {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            other => panic!("unknown severity: {other}"),
        }
    }

    fn weight(self) -> u64 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResidualRisk {
    risk_id: String,
    severity: String,
    likelihood_millionths: u32,
    impact_millionths: u32,
    owner: String,
    mitigation: String,
    trigger_threshold: String,
    rollback_trigger_id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct RollbackTrigger {
    trigger_id: String,
    metric: String,
    comparison: String,
    threshold_millionths: u32,
    recovery_command: String,
    blast_radius_assumption: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationOutcome {
    Pass,
    Hold,
    Fail,
}

impl VerificationOutcome {
    fn parse(raw: &str) -> Self {
        match raw {
            "pass" => Self::Pass,
            "hold" => Self::Hold,
            "fail" => Self::Fail,
            other => panic!("unknown verification outcome: {other}"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct IndependentVerification {
    verifier_id: String,
    outcome: String,
    manifest_path: String,
    replay_command: String,
    signed_off: bool,
}

#[derive(Debug, Deserialize)]
struct ClaimReplayCommand {
    claim_id: String,
    replay_command: String,
    expected_outcome: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_fail_reasons: Vec<String>,
    expected_hold_reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ParserFinalReadinessDossierFixture {
    schema_version: String,
    dossier_version: String,
    log_schema_version: String,
    dossier_id: String,
    bead_id: String,
    required_log_keys: Vec<String>,
    blocked_dependency_ids: Vec<String>,
    gating_policy: GatingPolicy,
    evidence_artifacts: Vec<EvidenceArtifact>,
    residual_risks: Vec<ResidualRisk>,
    rollback_triggers: Vec<RollbackTrigger>,
    independent_verification: Vec<IndependentVerification>,
    claim_replay_commands: Vec<ClaimReplayCommand>,
    expected_gate: ExpectedGate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RankedRisk {
    risk_id: String,
    score_millionths: u64,
    severity_weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    fail_reasons: Vec<String>,
    hold_reasons: Vec<String>,
    passed_verifiers: usize,
    ranked_open_risks: Vec<RankedRisk>,
    risk_register_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReadinessEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    dossier_id: String,
    risk_register_hash: String,
    replay_command: String,
    blocked_dependency_count: usize,
    hold_reason_count: usize,
    fail_reason_count: usize,
}

fn load_fixture() -> ParserFinalReadinessDossierFixture {
    let path = Path::new("tests/fixtures/parser_final_readiness_dossier_v1.json");
    let bytes = fs::read(path).expect("read parser final readiness dossier fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser final readiness dossier fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_FINAL_READINESS_DOSSIER.md");
    fs::read_to_string(path).expect("read parser final readiness dossier doc")
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn comparison_matches(raw: &str) -> bool {
    matches!(raw, ">" | ">=" | "<" | "<=")
}

fn open_risk_score_millionths(risk: &ResidualRisk) -> u64 {
    let likelihood = u64::from(risk.likelihood_millionths);
    let impact = u64::from(risk.impact_millionths);
    likelihood.saturating_mul(impact) / 1_000_000_u64
}

fn rank_open_risks(risks: &[ResidualRisk]) -> Vec<RankedRisk> {
    let mut ranked = risks
        .iter()
        .filter(|risk| risk.status == "open")
        .map(|risk| {
            let severity = Severity::parse(risk.severity.as_str());
            RankedRisk {
                risk_id: risk.risk_id.clone(),
                score_millionths: open_risk_score_millionths(risk),
                severity_weight: severity.weight(),
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by_key(|entry| {
        (
            Reverse(entry.score_millionths),
            Reverse(entry.severity_weight),
            entry.risk_id.clone(),
        )
    });
    ranked
}

fn compute_risk_register_hash(risks: &[ResidualRisk]) -> String {
    let mut rows = risks
        .iter()
        .map(|risk| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                risk.risk_id,
                risk.severity,
                risk.likelihood_millionths,
                risk.impact_millionths,
                risk.owner,
                risk.status,
                risk.rollback_trigger_id,
                risk.trigger_threshold
            )
        })
        .collect::<Vec<_>>();
    rows.sort();
    let joined = rows.join("\n");
    format!("fnv1a64:{:016x}", fnv1a64(joined.as_bytes()))
}

fn evaluate_dossier(fixture: &ParserFinalReadinessDossierFixture) -> GateEvaluation {
    let fail_statuses = fixture
        .gating_policy
        .fail_on_evidence_statuses
        .iter()
        .map(|status| EvidenceStatus::parse(status))
        .collect::<BTreeSet<_>>();

    let trigger_by_id = fixture
        .rollback_triggers
        .iter()
        .map(|trigger| (trigger.trigger_id.as_str(), trigger))
        .collect::<BTreeMap<_, _>>();

    let mut fail_reasons = BTreeSet::new();
    let mut hold_reasons = BTreeSet::new();

    for evidence in &fixture.evidence_artifacts {
        let status = EvidenceStatus::parse(evidence.status.as_str());

        if evidence.required {
            if fail_statuses.contains(&status) {
                fail_reasons.insert(format!("required_evidence_failed:{}", evidence.evidence_id));
            }

            if status == EvidenceStatus::InProgress {
                hold_reasons.insert(format!("evidence_in_progress:{}", evidence.evidence_id));
            }
        }

        if evidence.manifest_path.trim().is_empty() {
            fail_reasons.insert(format!(
                "evidence_manifest_missing:{}",
                evidence.evidence_id
            ));
        }
        if evidence.replay_command.trim().is_empty() {
            fail_reasons.insert(format!("evidence_replay_missing:{}", evidence.evidence_id));
        }
    }

    let ranked_open_risks = rank_open_risks(&fixture.residual_risks);
    let max_open_risk_score = ranked_open_risks
        .first()
        .map(|risk| risk.score_millionths)
        .unwrap_or(0);

    if max_open_risk_score > fixture.gating_policy.max_open_risk_score_millionths {
        hold_reasons.insert(format!(
            "open_risk_score_above_threshold:{}>{}",
            max_open_risk_score, fixture.gating_policy.max_open_risk_score_millionths
        ));
    }

    for risk in &fixture.residual_risks {
        if risk.owner.trim().is_empty() {
            fail_reasons.insert(format!("risk_owner_missing:{}", risk.risk_id));
        }
        if risk.mitigation.trim().is_empty() {
            fail_reasons.insert(format!("risk_mitigation_missing:{}", risk.risk_id));
        }
        if risk.trigger_threshold.trim().is_empty() {
            fail_reasons.insert(format!("risk_trigger_threshold_missing:{}", risk.risk_id));
        }

        if risk.status == "open" && !trigger_by_id.contains_key(risk.rollback_trigger_id.as_str()) {
            fail_reasons.insert(format!(
                "rollback_trigger_missing_for_open_risk:{}:{}",
                risk.risk_id, risk.rollback_trigger_id
            ));
        }
    }

    for trigger in &fixture.rollback_triggers {
        if trigger.metric.trim().is_empty() {
            fail_reasons.insert(format!(
                "rollback_trigger_metric_missing:{}",
                trigger.trigger_id
            ));
        }
        if !comparison_matches(trigger.comparison.as_str()) {
            fail_reasons.insert(format!(
                "rollback_trigger_comparison_invalid:{}:{}",
                trigger.trigger_id, trigger.comparison
            ));
        }
        if trigger.recovery_command.trim().is_empty() {
            fail_reasons.insert(format!(
                "rollback_trigger_command_missing:{}",
                trigger.trigger_id
            ));
        }
        if trigger.blast_radius_assumption.trim().is_empty() {
            fail_reasons.insert(format!(
                "rollback_trigger_blast_radius_missing:{}",
                trigger.trigger_id
            ));
        }

        // Trigger thresholds must stay within millionths contract bounds.
        if trigger.threshold_millionths > 1_000_000 {
            fail_reasons.insert(format!(
                "rollback_trigger_threshold_out_of_bounds:{}:{}",
                trigger.trigger_id, trigger.threshold_millionths
            ));
        }
    }

    let mut seen_claim_ids = BTreeSet::new();
    let mut seen_replay_commands = BTreeSet::new();
    for claim in &fixture.claim_replay_commands {
        if !seen_claim_ids.insert(claim.claim_id.clone()) {
            fail_reasons.insert(format!("duplicate_claim_id:{}", claim.claim_id));
        }
        if claim.replay_command.trim().is_empty() {
            fail_reasons.insert(format!("claim_replay_missing:{}", claim.claim_id));
        }
        if !seen_replay_commands.insert(claim.replay_command.clone()) {
            fail_reasons.insert(format!("duplicate_claim_replay:{}", claim.replay_command));
        }
        if claim.expected_outcome.trim().is_empty() {
            fail_reasons.insert(format!("claim_expected_outcome_missing:{}", claim.claim_id));
        }
    }

    let mut passed_verifiers = 0usize;
    for verifier in &fixture.independent_verification {
        let outcome = VerificationOutcome::parse(verifier.outcome.as_str());
        if verifier.manifest_path.trim().is_empty() {
            fail_reasons.insert(format!(
                "verifier_manifest_missing:{}",
                verifier.verifier_id
            ));
        }
        if verifier.replay_command.trim().is_empty() {
            fail_reasons.insert(format!("verifier_replay_missing:{}", verifier.verifier_id));
        }

        if outcome == VerificationOutcome::Fail {
            fail_reasons.insert(format!(
                "independent_verification_failed:{}",
                verifier.verifier_id
            ));
        }

        if verifier.signed_off && outcome == VerificationOutcome::Pass {
            passed_verifiers = passed_verifiers.saturating_add(1);
        }
    }

    if passed_verifiers < fixture.gating_policy.minimum_passed_verifiers as usize {
        hold_reasons.insert(format!(
            "independent_verifier_floor_not_met:{}<{}",
            passed_verifiers, fixture.gating_policy.minimum_passed_verifiers
        ));
    }

    let outcome = if fail_reasons.is_empty() {
        if hold_reasons.is_empty() {
            "pass"
        } else {
            "hold"
        }
    } else {
        "fail"
    }
    .to_string();

    GateEvaluation {
        outcome,
        fail_reasons: fail_reasons.into_iter().collect::<Vec<_>>(),
        hold_reasons: hold_reasons.into_iter().collect::<Vec<_>>(),
        passed_verifiers,
        ranked_open_risks,
        risk_register_hash: compute_risk_register_hash(&fixture.residual_risks),
    }
}

fn emit_structured_event(
    fixture: &ParserFinalReadinessDossierFixture,
    evaluation: &GateEvaluation,
) -> ReadinessEvent {
    ReadinessEvent {
        schema_version: fixture.log_schema_version.clone(),
        trace_id: format!("trace-{}", fixture.dossier_id),
        decision_id: format!("decision-{}", fixture.dossier_id),
        policy_id: "policy-parser-final-readiness-dossier-v1".to_string(),
        component: "parser_final_readiness_dossier_gate".to_string(),
        event: "final_readiness_dossier_evaluated".to_string(),
        outcome: evaluation.outcome.clone(),
        error_code: if evaluation.outcome == "fail" {
            Some("FE-PARSER-FINAL-DOSSIER-0001".to_string())
        } else {
            None
        },
        dossier_id: fixture.dossier_id.clone(),
        risk_register_hash: evaluation.risk_register_hash.clone(),
        replay_command: "./scripts/run_parser_final_readiness_dossier.sh ci".to_string(),
        blocked_dependency_count: fixture.blocked_dependency_ids.len(),
        hold_reason_count: evaluation.hold_reasons.len(),
        fail_reason_count: evaluation.fail_reasons.len(),
    }
}

#[test]
fn parser_final_readiness_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Final Readiness Dossier (`bd-2mds.1.8.4`)",
        "## Required Evidence Linkage",
        "## Risk Register Contract",
        "## Rollback Posture Contract",
        "## Independent Verification Contract",
        "## Structured Log Contract",
        "./scripts/run_parser_final_readiness_dossier.sh ci",
    ] {
        assert!(
            doc.contains(section),
            "required section missing from final readiness dossier doc: {section}"
        );
    }
}

#[test]
fn parser_final_readiness_fixture_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-final-readiness-dossier.v1"
    );
    assert_eq!(fixture.dossier_version, "0.1.0");
    assert_eq!(
        fixture.log_schema_version,
        "franken-engine.parser-log-event.v1"
    );
    assert_eq!(fixture.bead_id, "bd-2mds.1.8.4");

    for dep in [
        "bd-2mds.1.8.2",
        "bd-2mds.1.8.3",
        "bd-2mds.1.7.4",
        "bd-2mds.1.10.4",
    ] {
        assert!(
            fixture.blocked_dependency_ids.iter().any(|id| id == dep),
            "missing blocked dependency id: {dep}"
        );
    }

    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "dossier_id",
        "risk_register_hash",
        "replay_command",
    ] {
        assert!(
            fixture
                .required_log_keys
                .iter()
                .any(|required| required == key),
            "required log key missing: {key}"
        );
    }

    assert!(!fixture.evidence_artifacts.is_empty());
    for evidence in &fixture.evidence_artifacts {
        assert!(!evidence.evidence_id.trim().is_empty());
        let _status = EvidenceStatus::parse(evidence.status.as_str());
        assert!(!evidence.manifest_path.trim().is_empty());
        assert!(!evidence.replay_command.trim().is_empty());
    }

    assert!(!fixture.residual_risks.is_empty());
    for risk in &fixture.residual_risks {
        let _severity = Severity::parse(risk.severity.as_str());
        assert!(!risk.owner.trim().is_empty());
        assert!(!risk.mitigation.trim().is_empty());
        assert!(!risk.trigger_threshold.trim().is_empty());
        assert!(risk.likelihood_millionths <= 1_000_000);
        assert!(risk.impact_millionths <= 1_000_000);
    }

    assert!(!fixture.rollback_triggers.is_empty());
    for trigger in &fixture.rollback_triggers {
        assert!(!trigger.trigger_id.trim().is_empty());
        assert!(comparison_matches(trigger.comparison.as_str()));
        assert!(!trigger.recovery_command.trim().is_empty());
        assert!(!trigger.blast_radius_assumption.trim().is_empty());
        assert!(trigger.threshold_millionths <= 1_000_000);
    }

    let mut claim_ids = BTreeSet::new();
    let mut replay_commands = BTreeSet::new();
    for claim in &fixture.claim_replay_commands {
        assert!(claim_ids.insert(claim.claim_id.clone()));
        assert!(!claim.replay_command.trim().is_empty());
        assert!(replay_commands.insert(claim.replay_command.clone()));
        assert!(!claim.expected_outcome.trim().is_empty());
    }
}

#[test]
fn parser_final_readiness_evaluator_matches_expected_hold_contract() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);

    assert_eq!(evaluation.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(
        evaluation.fail_reasons,
        fixture.expected_gate.expected_fail_reasons
    );
    assert_eq!(
        evaluation.hold_reasons,
        fixture.expected_gate.expected_hold_reasons
    );

    assert_eq!(evaluation.passed_verifiers, 1);
    assert!(evaluation.fail_reasons.is_empty());
    assert!(!evaluation.hold_reasons.is_empty());
}

#[test]
fn parser_final_readiness_risk_ranking_is_deterministic() {
    let fixture = load_fixture();
    let first = rank_open_risks(&fixture.residual_risks);
    let second = rank_open_risks(&fixture.residual_risks);

    assert_eq!(first, second, "open-risk ranking must be deterministic");
    assert!(!first.is_empty(), "fixture must include open risks");

    for window in first.windows(2) {
        let a = &window[0];
        let b = &window[1];
        assert!(
            a.score_millionths >= b.score_millionths,
            "risk scores must be sorted descending"
        );
    }
}

#[test]
fn parser_final_readiness_structured_event_has_required_keys() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);
    let value = serde_json::to_value(event).expect("serialize readiness event");
    let object = value.as_object().expect("event json object");

    for key in &fixture.required_log_keys {
        assert!(
            object.contains_key(key),
            "readiness event missing required key `{key}`"
        );

        let field = object
            .get(key)
            .expect("required key should exist in event object");

        if key == "error_code" {
            assert!(
                field.is_null() || field.as_str().is_some(),
                "error_code must be null or string"
            );
        } else {
            let text = field.as_str().unwrap_or_default();
            assert!(
                !text.trim().is_empty(),
                "required key `{key}` must be non-empty"
            );
        }
    }

    assert_eq!(
        object
            .get("blocked_dependency_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        fixture.blocked_dependency_ids.len() as u64
    );
    assert!(
        object
            .get("risk_register_hash")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .starts_with("fnv1a64:"),
        "risk register hash must be deterministic fnv1a64 fingerprint"
    );
}
