//! FRX-20.6 milestone/release test-evidence integrator.
//!
//! Integrates FRX-20.{2,3,4,5} + FRX-5.4 outputs into cut-line and release
//! workflows with fail-closed semantics for missing, stale, or unsigned
//! evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::cut_line_automation::{CutLine, GateCategory, GateInput};
use crate::hash_tiers::ContentHash;
use crate::release_checklist_gate::{
    ArtifactRef, ChecklistCategory, ChecklistItem, ChecklistItemStatus, ReleaseChecklist,
};

pub const TEST_EVIDENCE_INTEGRATOR_COMPONENT: &str =
    "frx_milestone_release_test_evidence_integrator";
pub const TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION: &str =
    "frx.milestone-release-test-evidence-integrator.contract.v1";
pub const TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION: &str =
    "frx.milestone-release-test-evidence-integrator.event.v1";
pub const TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE: &str = "FE-FRX-20-6-TEST-EVIDENCE-INTEGRATOR-0001";

const MILLION: i64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    UnitDepthGate,
    EndToEndScenarioMatrix,
    TestLoggingSchema,
    FlakeQuarantineWorkflow,
    ProofCarryingArtifactGate,
}

impl EvidenceSource {
    pub const REQUIRED: [Self; 5] = [
        Self::UnitDepthGate,
        Self::EndToEndScenarioMatrix,
        Self::TestLoggingSchema,
        Self::FlakeQuarantineWorkflow,
        Self::ProofCarryingArtifactGate,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnitDepthGate => "unit_depth_gate",
            Self::EndToEndScenarioMatrix => "end_to_end_scenario_matrix",
            Self::TestLoggingSchema => "test_logging_schema",
            Self::FlakeQuarantineWorkflow => "flake_quarantine_workflow",
            Self::ProofCarryingArtifactGate => "proof_carrying_artifact_gate",
        }
    }

    #[must_use]
    pub fn gate_categories(self) -> &'static [GateCategory] {
        match self {
            Self::UnitDepthGate => &[GateCategory::CompilerCorrectness],
            Self::EndToEndScenarioMatrix => &[
                GateCategory::RuntimeParity,
                GateCategory::DeterministicReplay,
            ],
            Self::TestLoggingSchema => &[GateCategory::ObservabilityIntegrity],
            Self::FlakeQuarantineWorkflow => &[GateCategory::FlakeBurden],
            Self::ProofCarryingArtifactGate => &[
                GateCategory::GovernanceCompliance,
                GateCategory::HandoffReadiness,
            ],
        }
    }

    #[must_use]
    pub fn release_checklist_binding(self) -> (&'static str, ChecklistCategory) {
        match self {
            Self::UnitDepthGate => ("security.conformance_suite", ChecklistCategory::Security),
            Self::EndToEndScenarioMatrix => (
                "operational.diagnostics_cli_test",
                ChecklistCategory::Operational,
            ),
            Self::TestLoggingSchema => (
                "operational.evidence_export_test",
                ChecklistCategory::Operational,
            ),
            Self::FlakeQuarantineWorkflow => {
                ("security.adversarial_corpus", ChecklistCategory::Security)
            }
            Self::ProofCarryingArtifactGate => (
                "reproducibility.manifest_json",
                ChecklistCategory::Reproducibility,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Signed,
    Unsigned,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactLink {
    pub artifact_id: String,
    pub path: String,
    pub sha256: String,
    pub signature_status: SignatureStatus,
    pub signer: Option<String>,
    pub signature_ref: Option<String>,
    pub generated_at_ns: u64,
    pub schema_major: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSignal {
    pub source: EvidenceSource,
    pub passed: bool,
    pub score_millionths: i64,
    pub collected_at_ns: u64,
    pub schema_major: u32,
    pub evidence_refs: Vec<String>,
    pub artifact_links: Vec<EvidenceArtifactLink>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegratorPolicy {
    pub max_signal_age_ns: u64,
    pub min_schema_major: u32,
    pub require_signed_artifacts: bool,
    pub max_flake_burden_millionths: u32,
    pub minimum_cut_line_scores_millionths: BTreeMap<String, i64>,
}

impl IntegratorPolicy {
    #[must_use]
    pub fn threshold_for_cut_line(&self, cut_line: CutLine) -> i64 {
        self.minimum_cut_line_scores_millionths
            .get(cut_line.as_str())
            .copied()
            .unwrap_or(930_000)
    }
}

impl Default for IntegratorPolicy {
    fn default() -> Self {
        let mut thresholds = BTreeMap::new();
        thresholds.insert("C0".to_string(), 900_000);
        thresholds.insert("C1".to_string(), 930_000);
        thresholds.insert("C2".to_string(), 940_000);
        thresholds.insert("C3".to_string(), 950_000);
        thresholds.insert("C4".to_string(), 965_000);
        thresholds.insert("C5".to_string(), 975_000);

        Self {
            max_signal_age_ns: 3_600_000_000_000,
            min_schema_major: 1,
            require_signed_artifacts: true,
            max_flake_burden_millionths: 120_000,
            minimum_cut_line_scores_millionths: thresholds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationFinding {
    pub source: Option<EvidenceSource>,
    pub error_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvidenceLink {
    pub evidence_source: EvidenceSource,
    pub gate_category: String,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub signer: String,
    pub signature_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneQualitySummary {
    pub cut_line: CutLine,
    pub aggregate_score_millionths: i64,
    pub unit_depth_score_millionths: i64,
    pub e2e_stability_score_millionths: i64,
    pub logging_integrity_score_millionths: i64,
    pub flake_resilience_score_millionths: i64,
    pub artifact_integrity_score_millionths: i64,
    pub delta_from_previous_millionths: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEvidenceIntegrationDecision {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub cut_line: CutLine,
    pub release_tag: String,
    pub evaluated_at_ns: u64,
    pub outcome: String,
    pub error_code: Option<String>,
    pub queue_risk_millionths: i64,
    pub blockers: Vec<IntegrationFinding>,
    pub signed_evidence_links: Vec<SignedEvidenceLink>,
    pub quality_summary: MilestoneQualitySummary,
}

impl TestEvidenceIntegrationDecision {
    #[must_use]
    pub fn allows_promotion(&self) -> bool {
        self.outcome == "allow"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEvidenceIntegratorEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub cut_line: String,
    pub release_tag: String,
    pub blocker_count: usize,
    pub aggregate_score_millionths: i64,
    pub queue_risk_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEvidenceIntegratorInput {
    pub cut_line: CutLine,
    pub release_tag: String,
    pub now_ns: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub signals: Vec<EvidenceSignal>,
    pub previous_summary: Option<MilestoneQualitySummary>,
}

fn finding(source: Option<EvidenceSource>, message: impl Into<String>) -> IntegrationFinding {
    IntegrationFinding {
        source,
        error_code: TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.to_string(),
        message: message.into(),
    }
}

fn validate_signal(
    signal: &EvidenceSignal,
    now_ns: u64,
    policy: &IntegratorPolicy,
) -> Vec<IntegrationFinding> {
    let mut findings = Vec::new();

    if !(0..=MILLION).contains(&signal.score_millionths) {
        findings.push(finding(
            Some(signal.source),
            format!(
                "score_millionths out of range for {}: {}",
                signal.source.as_str(),
                signal.score_millionths
            ),
        ));
    }

    if signal.evidence_refs.is_empty() {
        findings.push(finding(
            Some(signal.source),
            format!(
                "{} missing evidence_refs (fail-closed)",
                signal.source.as_str()
            ),
        ));
    }

    if signal.artifact_links.is_empty() {
        findings.push(finding(
            Some(signal.source),
            format!(
                "{} missing artifact links (fail-closed)",
                signal.source.as_str()
            ),
        ));
    }

    if signal.schema_major < policy.min_schema_major {
        findings.push(finding(
            Some(signal.source),
            format!(
                "{} schema_major {} below minimum {}",
                signal.source.as_str(),
                signal.schema_major,
                policy.min_schema_major
            ),
        ));
    }

    if signal.collected_at_ns > now_ns {
        findings.push(finding(
            Some(signal.source),
            format!(
                "{} collected_at_ns is in the future",
                signal.source.as_str()
            ),
        ));
    } else {
        let age = now_ns.saturating_sub(signal.collected_at_ns);
        if age > policy.max_signal_age_ns {
            findings.push(finding(
                Some(signal.source),
                format!(
                    "{} signal stale: age_ns={} max_age_ns={}",
                    signal.source.as_str(),
                    age,
                    policy.max_signal_age_ns
                ),
            ));
        }
    }

    if signal.source == EvidenceSource::FlakeQuarantineWorkflow
        && let Some(raw) = signal.metadata.get("flake_burden_millionths")
    {
        match raw.parse::<u32>() {
            Ok(value) if value > policy.max_flake_burden_millionths => findings.push(finding(
                Some(signal.source),
                format!(
                    "flake burden {} exceeds max {}",
                    value, policy.max_flake_burden_millionths
                ),
            )),
            Ok(_) => {}
            Err(_) => findings.push(finding(
                Some(signal.source),
                format!("invalid flake_burden_millionths value: {raw}"),
            )),
        }
    }

    for artifact in &signal.artifact_links {
        if artifact.artifact_id.trim().is_empty() {
            findings.push(finding(
                Some(signal.source),
                format!("{} artifact missing artifact_id", signal.source.as_str()),
            ));
        }

        if artifact.path.trim().is_empty() {
            findings.push(finding(
                Some(signal.source),
                format!("{} artifact missing path", signal.source.as_str()),
            ));
        }

        if artifact.sha256.trim().is_empty() {
            findings.push(finding(
                Some(signal.source),
                format!(
                    "{} artifact {} missing sha256",
                    signal.source.as_str(),
                    artifact.artifact_id
                ),
            ));
        }

        if artifact.generated_at_ns > now_ns {
            findings.push(finding(
                Some(signal.source),
                format!(
                    "{} artifact {} generated_at_ns is in the future",
                    signal.source.as_str(),
                    artifact.artifact_id
                ),
            ));
        } else {
            let age = now_ns.saturating_sub(artifact.generated_at_ns);
            if age > policy.max_signal_age_ns {
                findings.push(finding(
                    Some(signal.source),
                    format!(
                        "{} artifact {} stale: age_ns={} max_age_ns={}",
                        signal.source.as_str(),
                        artifact.artifact_id,
                        age,
                        policy.max_signal_age_ns
                    ),
                ));
            }
        }

        if artifact.schema_major < policy.min_schema_major {
            findings.push(finding(
                Some(signal.source),
                format!(
                    "{} artifact {} schema_major {} below minimum {}",
                    signal.source.as_str(),
                    artifact.artifact_id,
                    artifact.schema_major,
                    policy.min_schema_major
                ),
            ));
        }

        if policy.require_signed_artifacts {
            if artifact.signature_status != SignatureStatus::Signed {
                findings.push(finding(
                    Some(signal.source),
                    format!(
                        "{} artifact {} not signed (status={:?})",
                        signal.source.as_str(),
                        artifact.artifact_id,
                        artifact.signature_status
                    ),
                ));
            }
            if artifact
                .signer
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            {
                findings.push(finding(
                    Some(signal.source),
                    format!(
                        "{} artifact {} missing signer",
                        signal.source.as_str(),
                        artifact.artifact_id
                    ),
                ));
            }
            if artifact
                .signature_ref
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            {
                findings.push(finding(
                    Some(signal.source),
                    format!(
                        "{} artifact {} missing signature_ref",
                        signal.source.as_str(),
                        artifact.artifact_id
                    ),
                ));
            }
        }
    }

    findings
}

fn source_score(
    by_source: &BTreeMap<EvidenceSource, &EvidenceSignal>,
    source: EvidenceSource,
) -> i64 {
    by_source
        .get(&source)
        .map_or(0, |signal| signal.score_millionths)
}

fn clamp_millionths(value: i64) -> i64 {
    value.clamp(0, MILLION)
}

fn source_has_blocker(blockers: &[IntegrationFinding], source: EvidenceSource) -> bool {
    blockers
        .iter()
        .any(|finding| finding.source == Some(source))
}

#[must_use]
pub fn integrate_milestone_release_test_evidence(
    input: &TestEvidenceIntegratorInput,
    policy: &IntegratorPolicy,
) -> TestEvidenceIntegrationDecision {
    let mut blockers = Vec::new();
    let mut by_source: BTreeMap<EvidenceSource, &EvidenceSignal> = BTreeMap::new();

    for signal in &input.signals {
        if by_source.insert(signal.source, signal).is_some() {
            blockers.push(finding(
                Some(signal.source),
                format!(
                    "duplicate evidence signal provided for {}",
                    signal.source.as_str()
                ),
            ));
        }
    }

    for required in EvidenceSource::REQUIRED {
        match by_source.get(&required) {
            Some(signal) => blockers.extend(validate_signal(signal, input.now_ns, policy)),
            None => blockers.push(finding(
                Some(required),
                format!("missing required signal {}", required.as_str()),
            )),
        }
    }

    let unit_depth_score = source_score(&by_source, EvidenceSource::UnitDepthGate);
    let e2e_score = source_score(&by_source, EvidenceSource::EndToEndScenarioMatrix);
    let logging_score = source_score(&by_source, EvidenceSource::TestLoggingSchema);
    let flake_score = source_score(&by_source, EvidenceSource::FlakeQuarantineWorkflow);
    let artifact_score = source_score(&by_source, EvidenceSource::ProofCarryingArtifactGate);

    let aggregate_score = clamp_millionths(
        (unit_depth_score * 30
            + e2e_score * 30
            + logging_score * 20
            + flake_score * 10
            + artifact_score * 10)
            / 100,
    );

    let threshold = policy.threshold_for_cut_line(input.cut_line);
    if aggregate_score < threshold {
        blockers.push(finding(
            None,
            format!(
                "aggregate_score_millionths {} below cut-line {} threshold {}",
                aggregate_score,
                input.cut_line.as_str(),
                threshold
            ),
        ));
    }

    let mut signed_evidence_links = Vec::new();
    for source in EvidenceSource::REQUIRED {
        if let Some(signal) = by_source.get(&source) {
            let mut artifacts = signal.artifact_links.clone();
            artifacts.sort_by(|left, right| {
                left.artifact_id
                    .cmp(&right.artifact_id)
                    .then_with(|| left.path.cmp(&right.path))
            });
            if let Some(artifact) = artifacts
                .iter()
                .find(|artifact| artifact.signature_status == SignatureStatus::Signed)
            {
                for category in source.gate_categories() {
                    signed_evidence_links.push(SignedEvidenceLink {
                        evidence_source: source,
                        gate_category: category.as_str().to_string(),
                        artifact_id: artifact.artifact_id.clone(),
                        artifact_sha256: artifact.sha256.clone(),
                        signer: artifact
                            .signer
                            .clone()
                            .unwrap_or_else(|| "unknown-signer".to_string()),
                        signature_ref: artifact.signature_ref.clone().unwrap_or_default(),
                    });
                }
            }
        }
    }

    let mut delta_from_previous_millionths = BTreeMap::new();
    if let Some(previous) = &input.previous_summary {
        delta_from_previous_millionths.insert(
            "aggregate".to_string(),
            aggregate_score - previous.aggregate_score_millionths,
        );
        delta_from_previous_millionths.insert(
            "unit_depth".to_string(),
            unit_depth_score - previous.unit_depth_score_millionths,
        );
        delta_from_previous_millionths.insert(
            "e2e_stability".to_string(),
            e2e_score - previous.e2e_stability_score_millionths,
        );
        delta_from_previous_millionths.insert(
            "logging_integrity".to_string(),
            logging_score - previous.logging_integrity_score_millionths,
        );
        delta_from_previous_millionths.insert(
            "flake_resilience".to_string(),
            flake_score - previous.flake_resilience_score_millionths,
        );
        delta_from_previous_millionths.insert(
            "artifact_integrity".to_string(),
            artifact_score - previous.artifact_integrity_score_millionths,
        );
    }

    let quality_summary = MilestoneQualitySummary {
        cut_line: input.cut_line,
        aggregate_score_millionths: aggregate_score,
        unit_depth_score_millionths: unit_depth_score,
        e2e_stability_score_millionths: e2e_score,
        logging_integrity_score_millionths: logging_score,
        flake_resilience_score_millionths: flake_score,
        artifact_integrity_score_millionths: artifact_score,
        delta_from_previous_millionths,
    };

    let queue_risk_millionths = clamp_millionths(MILLION - aggregate_score);
    let allows = blockers.is_empty();

    TestEvidenceIntegrationDecision {
        schema_version: TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION.to_string(),
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: TEST_EVIDENCE_INTEGRATOR_COMPONENT.to_string(),
        cut_line: input.cut_line,
        release_tag: input.release_tag.clone(),
        evaluated_at_ns: input.now_ns,
        outcome: if allows {
            "allow".to_string()
        } else {
            "deny".to_string()
        },
        error_code: if allows {
            None
        } else {
            Some(TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.to_string())
        },
        queue_risk_millionths,
        blockers,
        signed_evidence_links,
        quality_summary,
    }
}

#[must_use]
pub fn emit_integration_events(
    decision: &TestEvidenceIntegrationDecision,
) -> Vec<TestEvidenceIntegratorEvent> {
    vec![TestEvidenceIntegratorEvent {
        schema_version: TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: decision.trace_id.clone(),
        decision_id: decision.decision_id.clone(),
        policy_id: decision.policy_id.clone(),
        component: TEST_EVIDENCE_INTEGRATOR_COMPONENT.to_string(),
        event: "integration_completed".to_string(),
        outcome: decision.outcome.clone(),
        error_code: decision.error_code.clone(),
        cut_line: decision.cut_line.as_str().to_string(),
        release_tag: decision.release_tag.clone(),
        blocker_count: decision.blockers.len(),
        aggregate_score_millionths: decision.quality_summary.aggregate_score_millionths,
        queue_risk_millionths: decision.queue_risk_millionths,
    }]
}

fn signal_evidence_hash(signal: &EvidenceSignal) -> ContentHash {
    let mut canonical = format!(
        "{}|{}|{}|{}",
        signal.source.as_str(),
        signal.passed,
        signal.score_millionths,
        signal.collected_at_ns
    );
    for artifact in &signal.artifact_links {
        canonical.push('|');
        canonical.push_str(&artifact.artifact_id);
        canonical.push('|');
        canonical.push_str(&artifact.sha256);
    }
    ContentHash::compute(canonical.as_bytes())
}

#[must_use]
pub fn to_cut_line_gate_inputs(
    decision: &TestEvidenceIntegrationDecision,
    signals: &[EvidenceSignal],
) -> Vec<GateInput> {
    let mut out = Vec::new();
    let mut ordered = signals.to_vec();
    ordered.sort_by_key(|signal| signal.source);

    for signal in ordered {
        let blocked = source_has_blocker(&decision.blockers, signal.source);
        let mut metadata = signal.metadata.clone();
        metadata.insert("source".to_string(), signal.source.as_str().to_string());

        for category in signal.source.gate_categories() {
            let mut refs = signal.evidence_refs.clone();
            refs.extend(
                signal
                    .artifact_links
                    .iter()
                    .map(|artifact| artifact.path.clone()),
            );
            refs.sort();
            refs.dedup();

            out.push(GateInput {
                category: *category,
                score_millionths: Some(clamp_millionths(signal.score_millionths)),
                passed: signal.passed && !blocked,
                evidence_hash: signal_evidence_hash(&signal),
                evidence_refs: refs,
                collected_at_ns: signal.collected_at_ns,
                schema_major: signal.schema_major,
                metadata: metadata.clone(),
            });
        }
    }

    out
}

fn artifact_refs_for_source(
    source: EvidenceSource,
    decision: &TestEvidenceIntegrationDecision,
    signals: &[EvidenceSignal],
) -> Vec<ArtifactRef> {
    let mut refs = Vec::new();

    if let Some(signal) = signals.iter().find(|signal| signal.source == source) {
        refs.extend(signal.artifact_links.iter().map(|artifact| ArtifactRef {
            artifact_id: artifact.artifact_id.clone(),
            path: artifact.path.clone(),
            sha256: Some(artifact.sha256.clone()),
        }));
    }

    for signed in decision
        .signed_evidence_links
        .iter()
        .filter(|signed| signed.evidence_source == source)
    {
        refs.push(ArtifactRef {
            artifact_id: signed.artifact_id.clone(),
            path: format!("signed:{}", signed.signature_ref),
            sha256: Some(signed.artifact_sha256.clone()),
        });
    }

    let mut seen = BTreeSet::new();
    refs.into_iter()
        .filter(|reference| seen.insert(format!("{}|{}", reference.artifact_id, reference.path)))
        .collect()
}

pub fn apply_to_release_checklist(
    checklist: &mut ReleaseChecklist,
    decision: &TestEvidenceIntegrationDecision,
    signals: &[EvidenceSignal],
) {
    for source in EvidenceSource::REQUIRED {
        let (item_id, category) = source.release_checklist_binding();
        let source_blocked = source_has_blocker(&decision.blockers, source);
        let source_signal = signals.iter().find(|signal| signal.source == source);
        let passed = source_signal.is_some_and(|signal| signal.passed) && !source_blocked;
        let status = if passed {
            ChecklistItemStatus::Pass
        } else {
            ChecklistItemStatus::Fail
        };
        let artifact_refs = artifact_refs_for_source(source, decision, signals);

        if let Some(existing) = checklist
            .items
            .iter_mut()
            .find(|item| item.item_id == item_id)
        {
            existing.category = category;
            existing.required = true;
            existing.status = status;
            existing.waiver = None;
            existing.artifact_refs = artifact_refs;
        } else {
            checklist.items.push(ChecklistItem {
                item_id: item_id.to_string(),
                category,
                required: true,
                status,
                artifact_refs,
                waiver: None,
            });
        }
    }

    checklist
        .items
        .sort_by(|left, right| left.item_id.cmp(&right.item_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_artifact(prefix: &str, now_ns: u64) -> EvidenceArtifactLink {
        EvidenceArtifactLink {
            artifact_id: format!("{prefix}-artifact"),
            path: format!("artifacts/{prefix}/run_manifest.json"),
            sha256: format!("{prefix}abcdef1234567890"),
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
            metadata.insert("flake_burden_millionths".to_string(), "90000".to_string());
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
        TestEvidenceIntegratorInput {
            cut_line: CutLine::C4,
            release_tag: "v0.9.0-rc1".to_string(),
            now_ns,
            trace_id: "trace-frx-20-6".to_string(),
            decision_id: "decision-frx-20-6".to_string(),
            policy_id: "policy-frx-20-6-v1".to_string(),
            signals: EvidenceSource::REQUIRED
                .iter()
                .map(|source| baseline_signal(*source, 980_000, now_ns))
                .collect(),
            previous_summary: None,
        }
    }

    #[test]
    fn integrate_allows_with_complete_signed_inputs() {
        let input = baseline_input(10_000);
        let policy = IntegratorPolicy::default();
        let decision = integrate_milestone_release_test_evidence(&input, &policy);

        assert!(decision.allows_promotion());
        assert_eq!(decision.error_code, None);
        assert!(!decision.signed_evidence_links.is_empty());
        assert!(decision.quality_summary.aggregate_score_millionths >= 960_000);
    }

    #[test]
    fn integrate_fails_closed_when_source_missing() {
        let mut input = baseline_input(20_000);
        input
            .signals
            .retain(|signal| signal.source != EvidenceSource::TestLoggingSchema);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

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
    fn cut_line_gate_inputs_include_expected_categories() {
        let input = baseline_input(30_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
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
                .any(|gate| gate.category == GateCategory::ObservabilityIntegrity)
        );
        assert!(
            gate_inputs
                .iter()
                .any(|gate| gate.category == GateCategory::FlakeBurden)
        );
    }

    #[test]
    fn apply_to_release_checklist_marks_bound_items() {
        let input = baseline_input(40_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

        let mut checklist = ReleaseChecklist {
            schema_version: "franken-engine.release-checklist.v1".to_string(),
            release_tag: "v0.9.0-rc1".to_string(),
            generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
            trace_id: "trace-frx-20-6".to_string(),
            decision_id: "decision-frx-20-6".to_string(),
            policy_id: "policy-frx-20-6-v1".to_string(),
            items: Vec::new(),
        };

        apply_to_release_checklist(&mut checklist, &decision, &input.signals);

        for id in [
            "security.conformance_suite",
            "operational.diagnostics_cli_test",
            "operational.evidence_export_test",
            "security.adversarial_corpus",
            "reproducibility.manifest_json",
        ] {
            let item = checklist
                .items
                .iter()
                .find(|item| item.item_id == id)
                .unwrap_or_else(|| panic!("missing checklist item {id}"));
            assert_eq!(item.status, ChecklistItemStatus::Pass);
            assert!(!item.artifact_refs.is_empty());
        }
    }

    // ── Enrichment tests ──────────────────────────────────────────────

    #[test]
    fn evidence_source_as_str_all_variants() {
        assert_eq!(EvidenceSource::UnitDepthGate.as_str(), "unit_depth_gate");
        assert_eq!(
            EvidenceSource::EndToEndScenarioMatrix.as_str(),
            "end_to_end_scenario_matrix"
        );
        assert_eq!(
            EvidenceSource::TestLoggingSchema.as_str(),
            "test_logging_schema"
        );
        assert_eq!(
            EvidenceSource::FlakeQuarantineWorkflow.as_str(),
            "flake_quarantine_workflow"
        );
        assert_eq!(
            EvidenceSource::ProofCarryingArtifactGate.as_str(),
            "proof_carrying_artifact_gate"
        );
    }

    #[test]
    fn evidence_source_required_contains_all_five() {
        assert_eq!(EvidenceSource::REQUIRED.len(), 5);
        let set: BTreeSet<EvidenceSource> = EvidenceSource::REQUIRED.iter().copied().collect();
        assert!(set.contains(&EvidenceSource::UnitDepthGate));
        assert!(set.contains(&EvidenceSource::EndToEndScenarioMatrix));
        assert!(set.contains(&EvidenceSource::TestLoggingSchema));
        assert!(set.contains(&EvidenceSource::FlakeQuarantineWorkflow));
        assert!(set.contains(&EvidenceSource::ProofCarryingArtifactGate));
    }

    #[test]
    fn evidence_source_gate_categories_unit_depth() {
        let cats = EvidenceSource::UnitDepthGate.gate_categories();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0], GateCategory::CompilerCorrectness);
    }

    #[test]
    fn evidence_source_gate_categories_e2e_matrix() {
        let cats = EvidenceSource::EndToEndScenarioMatrix.gate_categories();
        assert_eq!(cats.len(), 2);
        assert_eq!(cats[0], GateCategory::RuntimeParity);
        assert_eq!(cats[1], GateCategory::DeterministicReplay);
    }

    #[test]
    fn evidence_source_gate_categories_proof_carrying_artifact() {
        let cats = EvidenceSource::ProofCarryingArtifactGate.gate_categories();
        assert_eq!(cats.len(), 2);
        assert_eq!(cats[0], GateCategory::GovernanceCompliance);
        assert_eq!(cats[1], GateCategory::HandoffReadiness);
    }

    #[test]
    fn evidence_source_release_checklist_bindings() {
        let (id, cat) = EvidenceSource::UnitDepthGate.release_checklist_binding();
        assert_eq!(id, "security.conformance_suite");
        assert_eq!(cat, ChecklistCategory::Security);

        let (id, cat) = EvidenceSource::EndToEndScenarioMatrix.release_checklist_binding();
        assert_eq!(id, "operational.diagnostics_cli_test");
        assert_eq!(cat, ChecklistCategory::Operational);

        let (id, cat) = EvidenceSource::TestLoggingSchema.release_checklist_binding();
        assert_eq!(id, "operational.evidence_export_test");
        assert_eq!(cat, ChecklistCategory::Operational);

        let (id, cat) = EvidenceSource::FlakeQuarantineWorkflow.release_checklist_binding();
        assert_eq!(id, "security.adversarial_corpus");
        assert_eq!(cat, ChecklistCategory::Security);

        let (id, cat) = EvidenceSource::ProofCarryingArtifactGate.release_checklist_binding();
        assert_eq!(id, "reproducibility.manifest_json");
        assert_eq!(cat, ChecklistCategory::Reproducibility);
    }

    #[test]
    fn evidence_source_serde_roundtrip() {
        for source in EvidenceSource::REQUIRED {
            let json = serde_json::to_string(&source).unwrap();
            let back: EvidenceSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, source);
        }
    }

    #[test]
    fn signature_status_serde_roundtrip() {
        for status in [
            SignatureStatus::Signed,
            SignatureStatus::Unsigned,
            SignatureStatus::Invalid,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: SignatureStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn integrator_policy_default_values() {
        let policy = IntegratorPolicy::default();
        assert_eq!(policy.max_signal_age_ns, 3_600_000_000_000);
        assert_eq!(policy.min_schema_major, 1);
        assert!(policy.require_signed_artifacts);
        assert_eq!(policy.max_flake_burden_millionths, 120_000);
        assert_eq!(
            policy.minimum_cut_line_scores_millionths.len(),
            6,
            "C0..C5 thresholds"
        );
    }

    #[test]
    fn integrator_policy_threshold_known_cut_lines() {
        let policy = IntegratorPolicy::default();
        assert_eq!(policy.threshold_for_cut_line(CutLine::C0), 900_000);
        assert_eq!(policy.threshold_for_cut_line(CutLine::C1), 930_000);
        assert_eq!(policy.threshold_for_cut_line(CutLine::C2), 940_000);
        assert_eq!(policy.threshold_for_cut_line(CutLine::C3), 950_000);
        assert_eq!(policy.threshold_for_cut_line(CutLine::C4), 965_000);
        assert_eq!(policy.threshold_for_cut_line(CutLine::C5), 975_000);
    }

    #[test]
    fn validate_signal_rejects_score_out_of_range_negative() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.score_millionths = -1;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(findings.iter().any(|f| f.message.contains("out of range")));
    }

    #[test]
    fn validate_signal_rejects_score_over_million() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.score_millionths = 1_000_001;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(findings.iter().any(|f| f.message.contains("out of range")));
    }

    #[test]
    fn validate_signal_rejects_empty_evidence_refs() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.evidence_refs.clear();
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("missing evidence_refs"))
        );
    }

    #[test]
    fn validate_signal_rejects_empty_artifact_links() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links.clear();
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("missing artifact links"))
        );
    }

    #[test]
    fn validate_signal_rejects_schema_below_minimum() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy {
            min_schema_major: 2,
            ..Default::default()
        };
        let signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("schema_major") && f.message.contains("below minimum"))
        );
    }

    #[test]
    fn validate_signal_rejects_future_collected_at() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.collected_at_ns = now_ns + 1;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(findings.iter().any(|f| f.message.contains("in the future")));
    }

    #[test]
    fn validate_signal_rejects_stale_signal() {
        let now_ns = 10_000_000_000_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.collected_at_ns = 1; // Very old
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(findings.iter().any(|f| f.message.contains("stale")));
    }

    #[test]
    fn validate_signal_rejects_high_flake_burden() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::FlakeQuarantineWorkflow, 980_000, now_ns);
        signal
            .metadata
            .insert("flake_burden_millionths".to_string(), "999999".to_string());
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("flake burden") && f.message.contains("exceeds max"))
        );
    }

    #[test]
    fn validate_signal_rejects_invalid_flake_burden_string() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::FlakeQuarantineWorkflow, 980_000, now_ns);
        signal.metadata.insert(
            "flake_burden_millionths".to_string(),
            "not_a_number".to_string(),
        );
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("invalid flake_burden_millionths"))
        );
    }

    #[test]
    fn validate_signal_rejects_unsigned_artifact_when_required() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        assert!(policy.require_signed_artifacts);
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].signature_status = SignatureStatus::Unsigned;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(findings.iter().any(|f| f.message.contains("not signed")));
    }

    #[test]
    fn validate_signal_rejects_artifact_missing_signer() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].signer = None;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("missing signer"))
        );
    }

    #[test]
    fn validate_signal_rejects_artifact_missing_signature_ref() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].signature_ref = None;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("missing signature_ref"))
        );
    }

    #[test]
    fn validate_signal_rejects_artifact_empty_id() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].artifact_id = "  ".to_string();
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("missing artifact_id"))
        );
    }

    #[test]
    fn validate_signal_rejects_artifact_empty_sha256() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].sha256 = "".to_string();
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("missing sha256"))
        );
    }

    #[test]
    fn validate_signal_rejects_future_artifact_generated_at() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].generated_at_ns = now_ns + 100;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("in the future") && f.message.contains("artifact"))
        );
    }

    #[test]
    fn validate_signal_rejects_stale_artifact() {
        let now_ns = 10_000_000_000_000u64;
        let policy = IntegratorPolicy::default();
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].generated_at_ns = 1;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("stale") && f.message.contains("artifact"))
        );
    }

    #[test]
    fn integrate_rejects_duplicate_evidence_signal() {
        let now_ns = 60_000u64;
        let mut input = baseline_input(now_ns);
        input.signals.push(baseline_signal(
            EvidenceSource::UnitDepthGate,
            990_000,
            now_ns,
        ));
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert!(
            decision
                .blockers
                .iter()
                .any(|f| f.message.contains("duplicate evidence signal"))
        );
    }

    #[test]
    fn integrate_aggregate_score_below_threshold_blocks() {
        let now_ns = 60_000u64;
        let mut input = baseline_input(now_ns);
        // Set all scores to 500_000 — aggregate will be 500_000 < 965_000 (C4)
        for signal in &mut input.signals {
            signal.score_millionths = 500_000;
        }
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert!(!decision.allows_promotion());
        assert!(
            decision
                .blockers
                .iter()
                .any(|f| f.message.contains("below cut-line"))
        );
    }

    #[test]
    fn integrate_score_weighting_30_30_20_10_10() {
        let now_ns = 60_000u64;
        let mut input = baseline_input(now_ns);
        // Unit=1M, E2E=0, Logging=0, Flake=0, Artifact=0
        for signal in &mut input.signals {
            signal.score_millionths = 0;
        }
        input
            .signals
            .iter_mut()
            .find(|s| s.source == EvidenceSource::UnitDepthGate)
            .unwrap()
            .score_millionths = 1_000_000;
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        // Weighted: 1M*30/100 = 300_000
        assert_eq!(decision.quality_summary.aggregate_score_millionths, 300_000);
    }

    #[test]
    fn integrate_queue_risk_is_complement_of_aggregate() {
        let input = baseline_input(70_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert_eq!(
            decision.queue_risk_millionths,
            1_000_000 - decision.quality_summary.aggregate_score_millionths
        );
    }

    #[test]
    fn integrate_delta_from_previous_computed() {
        let now_ns = 70_000u64;
        let mut input = baseline_input(now_ns);
        input.previous_summary = Some(MilestoneQualitySummary {
            cut_line: CutLine::C3,
            aggregate_score_millionths: 900_000,
            unit_depth_score_millionths: 900_000,
            e2e_stability_score_millionths: 900_000,
            logging_integrity_score_millionths: 900_000,
            flake_resilience_score_millionths: 900_000,
            artifact_integrity_score_millionths: 900_000,
            delta_from_previous_millionths: BTreeMap::new(),
        });
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        let deltas = &decision.quality_summary.delta_from_previous_millionths;
        assert!(deltas.contains_key("aggregate"));
        assert!(deltas.contains_key("unit_depth"));
        assert!(deltas.contains_key("e2e_stability"));
        assert!(deltas.contains_key("logging_integrity"));
        assert!(deltas.contains_key("flake_resilience"));
        assert!(deltas.contains_key("artifact_integrity"));
        // All current scores are 980_000; previous 900_000 → delta positive
        assert_eq!(deltas["unit_depth"], 80_000);
    }

    #[test]
    fn integrate_no_previous_summary_means_no_deltas() {
        let input = baseline_input(70_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert!(
            decision
                .quality_summary
                .delta_from_previous_millionths
                .is_empty()
        );
    }

    #[test]
    fn decision_allows_promotion_true_and_false() {
        let allow_decision = TestEvidenceIntegrationDecision {
            schema_version: "v1".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            cut_line: CutLine::C0,
            release_tag: "v1".to_string(),
            evaluated_at_ns: 0,
            outcome: "allow".to_string(),
            error_code: None,
            queue_risk_millionths: 0,
            blockers: vec![],
            signed_evidence_links: vec![],
            quality_summary: MilestoneQualitySummary {
                cut_line: CutLine::C0,
                aggregate_score_millionths: 0,
                unit_depth_score_millionths: 0,
                e2e_stability_score_millionths: 0,
                logging_integrity_score_millionths: 0,
                flake_resilience_score_millionths: 0,
                artifact_integrity_score_millionths: 0,
                delta_from_previous_millionths: BTreeMap::new(),
            },
        };
        assert!(allow_decision.allows_promotion());

        let deny_decision = TestEvidenceIntegrationDecision {
            outcome: "deny".to_string(),
            ..allow_decision
        };
        assert!(!deny_decision.allows_promotion());
    }

    #[test]
    fn emit_integration_events_fields() {
        let input = baseline_input(80_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        let events = emit_integration_events(&decision);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(
            event.schema_version,
            TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION
        );
        assert_eq!(event.trace_id, decision.trace_id);
        assert_eq!(event.decision_id, decision.decision_id);
        assert_eq!(event.event, "integration_completed");
        assert_eq!(event.outcome, decision.outcome);
        assert_eq!(event.blocker_count, decision.blockers.len());
        assert_eq!(
            event.aggregate_score_millionths,
            decision.quality_summary.aggregate_score_millionths
        );
    }

    #[test]
    fn signal_evidence_hash_deterministic() {
        let now_ns = 80_000u64;
        let signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        let hash1 = signal_evidence_hash(&signal);
        let hash2 = signal_evidence_hash(&signal);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn signal_evidence_hash_changes_with_score() {
        let now_ns = 80_000u64;
        let signal_a = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        let signal_b = baseline_signal(EvidenceSource::UnitDepthGate, 970_000, now_ns);
        assert_ne!(
            signal_evidence_hash(&signal_a),
            signal_evidence_hash(&signal_b)
        );
    }

    #[test]
    fn gate_inputs_blocked_signal_has_passed_false() {
        let now_ns = 90_000u64;
        let mut input = baseline_input(now_ns);
        // Make one signal fail validation (stale)
        input
            .signals
            .iter_mut()
            .find(|s| s.source == EvidenceSource::TestLoggingSchema)
            .unwrap()
            .collected_at_ns = 0; // extremely old → stale
        input.now_ns = 10_000_000_000_000;
        // Also update other signals so they are not stale
        for signal in &mut input.signals {
            if signal.source != EvidenceSource::TestLoggingSchema {
                signal.collected_at_ns = input.now_ns - 100;
                signal.artifact_links[0].generated_at_ns = input.now_ns - 100;
            }
        }
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
        // Logging schema source should have passed=false due to blocker
        let logging_gate = gate_inputs
            .iter()
            .find(|g| g.category == GateCategory::ObservabilityIntegrity)
            .unwrap();
        assert!(!logging_gate.passed);
    }

    #[test]
    fn gate_inputs_metadata_includes_source() {
        let input = baseline_input(90_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
        for gate in &gate_inputs {
            assert!(
                gate.metadata.contains_key("source"),
                "gate input missing 'source' metadata"
            );
        }
    }

    #[test]
    fn checklist_items_sorted_by_id_after_apply() {
        let input = baseline_input(100_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        let mut checklist = ReleaseChecklist {
            schema_version: "franken-engine.release-checklist.v1".to_string(),
            release_tag: "v0.9.0-rc1".to_string(),
            generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
            trace_id: "trace-frx-20-6".to_string(),
            decision_id: "decision-frx-20-6".to_string(),
            policy_id: "policy-frx-20-6-v1".to_string(),
            items: Vec::new(),
        };
        apply_to_release_checklist(&mut checklist, &decision, &input.signals);
        let ids: Vec<&str> = checklist.items.iter().map(|i| i.item_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn checklist_updates_existing_items() {
        let input = baseline_input(100_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        let mut checklist = ReleaseChecklist {
            schema_version: "franken-engine.release-checklist.v1".to_string(),
            release_tag: "v0.9.0-rc1".to_string(),
            generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
            trace_id: "trace-frx-20-6".to_string(),
            decision_id: "decision-frx-20-6".to_string(),
            policy_id: "policy-frx-20-6-v1".to_string(),
            items: vec![ChecklistItem {
                item_id: "security.conformance_suite".to_string(),
                category: ChecklistCategory::Reproducibility,
                required: false,
                status: ChecklistItemStatus::Fail,
                artifact_refs: vec![],
                waiver: None,
            }],
        };
        apply_to_release_checklist(&mut checklist, &decision, &input.signals);
        // Should update existing not duplicate
        let count = checklist
            .items
            .iter()
            .filter(|i| i.item_id == "security.conformance_suite")
            .count();
        assert_eq!(count, 1);
        let item = checklist
            .items
            .iter()
            .find(|i| i.item_id == "security.conformance_suite")
            .unwrap();
        assert_eq!(item.status, ChecklistItemStatus::Pass);
        assert_eq!(item.category, ChecklistCategory::Security);
        assert!(item.required);
    }

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(
            TEST_EVIDENCE_INTEGRATOR_COMPONENT,
            "frx_milestone_release_test_evidence_integrator"
        );
        assert!(TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION.contains("v1"));
        assert!(TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION.contains("v1"));
        assert!(TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.starts_with("FE-FRX-"));
    }

    #[test]
    fn finding_helper_sets_error_code() {
        let f = finding(Some(EvidenceSource::UnitDepthGate), "test message");
        assert_eq!(f.error_code, TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE);
        assert_eq!(f.message, "test message");
        assert_eq!(f.source, Some(EvidenceSource::UnitDepthGate));
    }

    #[test]
    fn finding_helper_accepts_none_source() {
        let f = finding(None, "global issue");
        assert_eq!(f.source, None);
        assert_eq!(f.message, "global issue");
    }

    #[test]
    fn clamp_millionths_clamps_both_ends() {
        assert_eq!(clamp_millionths(-100), 0);
        assert_eq!(clamp_millionths(0), 0);
        assert_eq!(clamp_millionths(500_000), 500_000);
        assert_eq!(clamp_millionths(1_000_000), 1_000_000);
        assert_eq!(clamp_millionths(2_000_000), 1_000_000);
    }

    #[test]
    fn source_has_blocker_returns_true_for_matching_source() {
        let blockers = vec![finding(Some(EvidenceSource::UnitDepthGate), "problem")];
        assert!(source_has_blocker(&blockers, EvidenceSource::UnitDepthGate));
        assert!(!source_has_blocker(
            &blockers,
            EvidenceSource::TestLoggingSchema
        ));
    }

    #[test]
    fn source_score_returns_zero_for_missing_source() {
        let map: BTreeMap<EvidenceSource, &EvidenceSignal> = BTreeMap::new();
        assert_eq!(source_score(&map, EvidenceSource::UnitDepthGate), 0);
    }

    #[test]
    fn validate_signal_ok_when_signed_not_required() {
        let now_ns = 50_000u64;
        let policy = IntegratorPolicy {
            require_signed_artifacts: false,
            ..IntegratorPolicy::default()
        };
        let mut signal = baseline_signal(EvidenceSource::UnitDepthGate, 980_000, now_ns);
        signal.artifact_links[0].signature_status = SignatureStatus::Unsigned;
        signal.artifact_links[0].signer = None;
        signal.artifact_links[0].signature_ref = None;
        let findings = validate_signal(&signal, now_ns, &policy);
        assert!(
            findings.is_empty(),
            "no findings when signing not required: {findings:?}"
        );
    }

    #[test]
    fn integrate_decision_schema_version_matches_constant() {
        let input = baseline_input(100_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        assert_eq!(
            decision.schema_version,
            TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION
        );
        assert_eq!(decision.component, TEST_EVIDENCE_INTEGRATOR_COMPONENT);
    }

    #[test]
    fn integrate_signed_evidence_links_populated() {
        let input = baseline_input(100_000);
        let decision =
            integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
        // Each source has at least one signed artifact, and some sources produce
        // 2 gate categories (E2E → RuntimeParity + DeterministicReplay,
        // Proof → GovernanceCompliance + HandoffReadiness), so total > 5
        assert!(decision.signed_evidence_links.len() >= 5);
        for link in &decision.signed_evidence_links {
            assert!(!link.artifact_id.is_empty());
            assert!(!link.artifact_sha256.is_empty());
            assert!(!link.signer.is_empty());
        }
    }

    #[test]
    fn integration_finding_serde_roundtrip() {
        let f = IntegrationFinding {
            source: Some(EvidenceSource::UnitDepthGate),
            error_code: "ERR-001".to_string(),
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: IntegrationFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn milestone_quality_summary_serde_roundtrip() {
        let summary = MilestoneQualitySummary {
            cut_line: CutLine::C3,
            aggregate_score_millionths: 950_000,
            unit_depth_score_millionths: 980_000,
            e2e_stability_score_millionths: 970_000,
            logging_integrity_score_millionths: 960_000,
            flake_resilience_score_millionths: 940_000,
            artifact_integrity_score_millionths: 930_000,
            delta_from_previous_millionths: BTreeMap::new(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: MilestoneQualitySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }
}
