use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use frankenengine_engine::milestone_release_test_evidence_integrator::{
    EvidenceArtifactLink, EvidenceSignal, EvidenceSource, IntegratorPolicy,
    MilestoneQualitySummary, SignatureStatus, TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION,
    TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION, TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE,
    TestEvidenceIntegratorInput, apply_to_release_checklist, emit_integration_events,
    integrate_milestone_release_test_evidence, to_cut_line_gate_inputs,
};

use frankenengine_engine::cut_line_automation::{CutLine, GateCategory};
use frankenengine_engine::release_checklist_gate::ReleaseChecklist;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = read_to_string(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct IntegratorContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    required_signal_sources: Vec<String>,
    cut_line_quality_thresholds_millionths: BTreeMap<String, i64>,
    staleness_policy: StalenessPolicy,
    release_workflow: ReleaseWorkflow,
    queue_risk_contract: QueueRiskContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StalenessPolicy {
    max_signal_age_ns: u64,
    min_schema_major: u32,
    require_signed_artifacts: bool,
    max_flake_burden_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct ReleaseWorkflow {
    auto_apply_to_release_checklist: bool,
    fail_closed_on_missing_signals: bool,
    signed_link_required: bool,
}

#[derive(Debug, Deserialize)]
struct QueueRiskContract {
    emit_machine_readable_summary: bool,
    risk_field: String,
}

fn signed_artifact(prefix: &str, now_ns: u64) -> EvidenceArtifactLink {
    EvidenceArtifactLink {
        artifact_id: format!("{prefix}-artifact"),
        path: format!("artifacts/{prefix}/run_manifest.json"),
        sha256: format!("{prefix}-sha-abcdef1234567890"),
        signature_status: SignatureStatus::Signed,
        signer: Some("maintainer@franken.engine".to_string()),
        signature_ref: Some(format!("sig:{prefix}")),
        generated_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
    }
}

fn baseline_signal(source: EvidenceSource, score: i64, now_ns: u64) -> EvidenceSignal {
    let mut metadata = BTreeMap::new();
    if source == EvidenceSource::FlakeQuarantineWorkflow {
        metadata.insert("flake_burden_millionths".to_string(), "85000".to_string());
    }

    EvidenceSignal {
        source,
        passed: true,
        score_millionths: score,
        collected_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
        evidence_refs: vec![format!("docs/{}.json", source.as_str())],
        artifact_links: vec![signed_artifact(source.as_str(), now_ns)],
        metadata,
    }
}

fn baseline_input(now_ns: u64) -> TestEvidenceIntegratorInput {
    let previous_summary = MilestoneQualitySummary {
        cut_line: CutLine::C4,
        aggregate_score_millionths: 930_000,
        unit_depth_score_millionths: 920_000,
        e2e_stability_score_millionths: 930_000,
        logging_integrity_score_millionths: 940_000,
        flake_resilience_score_millionths: 935_000,
        artifact_integrity_score_millionths: 935_000,
        delta_from_previous_millionths: BTreeMap::new(),
    };

    TestEvidenceIntegratorInput {
        cut_line: CutLine::C4,
        release_tag: "v0.9.0-rc2".to_string(),
        now_ns,
        trace_id: "trace-frx-20-6".to_string(),
        decision_id: "decision-frx-20-6".to_string(),
        policy_id: "policy-frx-20-6-v1".to_string(),
        signals: EvidenceSource::REQUIRED
            .iter()
            .map(|source| baseline_signal(*source, 980_000, now_ns))
            .collect(),
        previous_summary: Some(previous_summary),
    }
}

#[test]
fn frx_20_6_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_MILESTONE_RELEASE_TEST_EVIDENCE_INTEGRATOR_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# FRX Milestone/Release Test-Evidence Integrator v1",
        "## Scope",
        "## Required Signal Sources",
        "## Fail-Closed Validation Rules",
        "## Cut-Line and Release Workflow Binding",
        "## Signed Evidence Linkage",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }

    for phrase in [
        "fail-closed",
        "missing",
        "stale",
        "signed",
        "queue_risk_millionths",
        "bd-mjh3.20.6",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_20_6_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_milestone_release_test_evidence_integrator_v1.json");
    let contract: IntegratorContract = load_json(&path);

    assert_eq!(
        contract.schema_version,
        TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.bead_id, "bd-mjh3.20.6");
    assert_eq!(contract.generated_by, "bd-mjh3.20.6");

    let required_sources: BTreeSet<_> = contract
        .required_signal_sources
        .iter()
        .map(String::as_str)
        .collect();
    for source in [
        "unit_depth_gate",
        "end_to_end_scenario_matrix",
        "test_logging_schema",
        "flake_quarantine_workflow",
        "proof_carrying_artifact_gate",
    ] {
        assert!(
            required_sources.contains(source),
            "missing source: {source}"
        );
    }

    for cut_line in ["C1", "C2", "C3", "C4", "C5"] {
        assert!(
            contract
                .cut_line_quality_thresholds_millionths
                .contains_key(cut_line),
            "missing cut-line threshold for {cut_line}"
        );
    }

    assert!(contract.staleness_policy.max_signal_age_ns > 0);
    assert!(contract.staleness_policy.require_signed_artifacts);
    assert!(contract.staleness_policy.min_schema_major >= 1);
    assert!(contract.staleness_policy.max_flake_burden_millionths <= 250_000);

    assert!(contract.release_workflow.auto_apply_to_release_checklist);
    assert!(contract.release_workflow.fail_closed_on_missing_signals);
    assert!(contract.release_workflow.signed_link_required);

    assert!(contract.queue_risk_contract.emit_machine_readable_summary);
    assert_eq!(
        contract.queue_risk_contract.risk_field,
        "queue_risk_millionths"
    );

    assert!(
        contract.operator_verification.iter().any(|entry| entry
            .contains("run_frx_milestone_release_test_evidence_integrator_suite.sh ci")),
        "operator verification must include suite command"
    );
}

#[test]
fn frx_20_6_integration_is_fail_closed_on_missing_signal() {
    let mut input = baseline_input(10_000);
    input
        .signals
        .retain(|signal| signal.source != EvidenceSource::TestLoggingSchema);

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert_eq!(
        decision.error_code,
        Some(TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.to_string())
    );
    assert!(
        decision
            .blockers
            .iter()
            .any(|finding| finding.message.contains("missing required signal"))
    );
}

#[test]
fn frx_20_6_integration_is_fail_closed_on_unsigned_artifacts() {
    let mut input = baseline_input(20_000);
    input
        .signals
        .iter_mut()
        .filter(|signal| signal.source == EvidenceSource::ProofCarryingArtifactGate)
        .for_each(|signal| {
            signal.artifact_links[0].signature_status = SignatureStatus::Unsigned;
            signal.artifact_links[0].signer = None;
            signal.artifact_links[0].signature_ref = None;
        });

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|finding| finding.message.contains("not signed"))
    );
}

#[test]
fn frx_20_6_integration_emits_quality_summary_and_signed_links() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(decision.allows_promotion());
    assert_eq!(decision.error_code, None);
    assert!(decision.quality_summary.aggregate_score_millionths >= 970_000);
    assert!(!decision.signed_evidence_links.is_empty());
    assert!(
        decision
            .quality_summary
            .delta_from_previous_millionths
            .contains_key("aggregate")
    );

    let events = emit_integration_events(&decision);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].schema_version,
        TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION
    );
    assert_eq!(events[0].outcome, "allow");
}

#[test]
fn frx_20_6_cut_line_inputs_cover_expected_categories() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);

    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::CompilerCorrectness)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::RuntimeParity)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::DeterministicReplay)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::ObservabilityIntegrity)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::FlakeBurden)
    );
}

#[test]
fn frx_20_6_release_checklist_binding_is_automatic_and_fail_closed() {
    let mut input = baseline_input(50_000);
    input
        .signals
        .iter_mut()
        .filter(|signal| signal.source == EvidenceSource::FlakeQuarantineWorkflow)
        .for_each(|signal| {
            signal.passed = false;
            signal.score_millionths = 700_000;
            signal
                .metadata
                .insert("flake_burden_millionths".to_string(), "200000".to_string());
        });

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = ReleaseChecklist {
        schema_version: "franken-engine.release-checklist.v1".to_string(),
        release_tag: "v0.9.0-rc2".to_string(),
        generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
        trace_id: "trace-frx-20-6".to_string(),
        decision_id: "decision-frx-20-6".to_string(),
        policy_id: "policy-frx-20-6-v1".to_string(),
        items: Vec::new(),
    };

    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    let security_conformance = checklist
        .items
        .iter()
        .find(|item| item.item_id == "security.conformance_suite")
        .expect("missing security.conformance_suite");
    assert_eq!(security_conformance.status.as_str(), "pass");

    let adversarial = checklist
        .items
        .iter()
        .find(|item| item.item_id == "security.adversarial_corpus")
        .expect("missing security.adversarial_corpus");
    assert_eq!(adversarial.status.as_str(), "fail");
    assert!(!adversarial.artifact_refs.is_empty());
}
