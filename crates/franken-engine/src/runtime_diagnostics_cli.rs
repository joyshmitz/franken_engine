//! Runtime diagnostics and evidence export surfaces.
//!
//! This module provides deterministic, machine-readable runtime diagnostics and
//! evidence export APIs that can be wrapped by CLI entrypoints.
//!
//! Plan reference: Section 10.8 item 1 (`bd-2mm`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::containment_executor::{ContainmentReceipt, ContainmentState};
use crate::evidence_ledger::{DecisionType, EvidenceEntry};
use crate::expected_loss_selector::ContainmentAction;
use crate::hostcall_telemetry::{HostcallResult, HostcallTelemetryRecord};
use crate::security_epoch::SecurityEpoch;

const COMPONENT: &str = "runtime_diagnostics_cli";

/// Stable log envelope required by plan acceptance criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Severity used by evidence export filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for EvidenceSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => f.write_str("info"),
            Self::Warning => f.write_str("warning"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

/// Parse severity from CLI/user input.
pub fn parse_evidence_severity(input: &str) -> Option<EvidenceSeverity> {
    match input.trim().to_ascii_lowercase().as_str() {
        "info" => Some(EvidenceSeverity::Info),
        "warning" => Some(EvidenceSeverity::Warning),
        "critical" => Some(EvidenceSeverity::Critical),
        _ => None,
    }
}

/// Parse decision type from CLI/user input.
pub fn parse_decision_type(input: &str) -> Option<DecisionType> {
    match input.trim().to_ascii_lowercase().as_str() {
        "security_action" => Some(DecisionType::SecurityAction),
        "policy_update" => Some(DecisionType::PolicyUpdate),
        "epoch_transition" => Some(DecisionType::EpochTransition),
        "revocation" => Some(DecisionType::Revocation),
        "extension_lifecycle" => Some(DecisionType::ExtensionLifecycle),
        "capability_decision" => Some(DecisionType::CapabilityDecision),
        "contract_evaluation" => Some(DecisionType::ContractEvaluation),
        "remote_authorization" => Some(DecisionType::RemoteAuthorization),
        _ => None,
    }
}

/// Loaded extension state in the diagnostics input surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExtensionState {
    pub extension_id: String,
    pub containment_state: ContainmentState,
}

/// GC pressure sample for one extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPressureSample {
    pub extension_id: String,
    pub used_bytes: u64,
    pub budget_bytes: u64,
}

/// Scheduler lane sample used to compute utilization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerLaneSample {
    pub lane: String,
    pub queue_depth: u64,
    pub max_depth: u64,
    pub tasks_submitted: u64,
    pub tasks_scheduled: u64,
    pub tasks_completed: u64,
    pub tasks_timed_out: u64,
}

/// Deterministic runtime-state input consumed by diagnostics collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateInput {
    pub snapshot_timestamp_ns: u64,
    pub loaded_extensions: Vec<RuntimeExtensionState>,
    pub active_policies: Vec<String>,
    pub security_epoch: SecurityEpoch,
    pub gc_pressure: Vec<GcPressureSample>,
    pub scheduler_lanes: Vec<SchedulerLaneSample>,
}

/// Hostcall telemetry envelope with explicit trace/policy linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallTelemetryEnvelope {
    pub trace_id: String,
    pub policy_id: String,
    pub record: HostcallTelemetryRecord,
}

/// Containment receipt envelope with explicit trace/policy linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReceiptEnvelope {
    pub trace_id: String,
    pub policy_id: String,
    pub receipt: ContainmentReceipt,
}

/// Replay artifact pointer exported by incident tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayArtifactRecord {
    pub trace_id: String,
    pub extension_id: String,
    pub timestamp_ns: u64,
    pub artifact_id: String,
    pub replay_pointer: String,
}

/// Unified input file schema consumed by the diagnostics CLI binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDiagnosticsCliInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub runtime_state: RuntimeStateInput,
    pub evidence_entries: Vec<EvidenceEntry>,
    pub hostcall_records: Vec<HostcallTelemetryEnvelope>,
    pub containment_receipts: Vec<ContainmentReceiptEnvelope>,
    pub replay_artifacts: Vec<ReplayArtifactRecord>,
}

/// GC pressure diagnostics row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPressureDiagnostics {
    pub extension_id: String,
    pub used_bytes: u64,
    pub budget_bytes: u64,
    pub pressure_millionths: u64,
    pub over_budget: bool,
}

/// Scheduler lane diagnostics row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerLaneDiagnostics {
    pub lane: String,
    pub queue_depth: u64,
    pub max_depth: u64,
    pub utilization_millionths: u64,
    pub tasks_submitted: u64,
    pub tasks_scheduled: u64,
    pub tasks_completed: u64,
    pub tasks_timed_out: u64,
}

/// Output of diagnostics collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDiagnosticsOutput {
    pub snapshot_timestamp_ns: u64,
    pub loaded_extensions: Vec<RuntimeExtensionState>,
    pub active_policies: Vec<String>,
    pub security_epoch: SecurityEpoch,
    pub gc_pressure: Vec<GcPressureDiagnostics>,
    pub scheduler_lanes: Vec<SchedulerLaneDiagnostics>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Collect a deterministic runtime diagnostics snapshot.
pub fn collect_runtime_diagnostics(
    input: &RuntimeStateInput,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> RuntimeDiagnosticsOutput {
    let mut loaded_extensions = input.loaded_extensions.clone();
    loaded_extensions.sort_by(|left, right| left.extension_id.cmp(&right.extension_id));

    let active_policies = input
        .active_policies
        .iter()
        .map(|policy| policy.trim())
        .filter(|policy| !policy.is_empty())
        .map(std::string::ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut gc_pressure = input
        .gc_pressure
        .iter()
        .map(|sample| {
            let pressure_millionths =
                compute_pressure_millionths(sample.used_bytes, sample.budget_bytes);
            GcPressureDiagnostics {
                extension_id: sample.extension_id.clone(),
                used_bytes: sample.used_bytes,
                budget_bytes: sample.budget_bytes,
                pressure_millionths,
                over_budget: sample.budget_bytes > 0 && sample.used_bytes > sample.budget_bytes,
            }
        })
        .collect::<Vec<_>>();
    gc_pressure.sort_by(|left, right| left.extension_id.cmp(&right.extension_id));

    let mut scheduler_lanes = input
        .scheduler_lanes
        .iter()
        .map(|lane| SchedulerLaneDiagnostics {
            lane: lane.lane.clone(),
            queue_depth: lane.queue_depth,
            max_depth: lane.max_depth,
            utilization_millionths: compute_pressure_millionths(lane.queue_depth, lane.max_depth),
            tasks_submitted: lane.tasks_submitted,
            tasks_scheduled: lane.tasks_scheduled,
            tasks_completed: lane.tasks_completed,
            tasks_timed_out: lane.tasks_timed_out,
        })
        .collect::<Vec<_>>();
    scheduler_lanes.sort_by(|left, right| left.lane.cmp(&right.lane));

    let logs = vec![StructuredLogEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: COMPONENT.to_string(),
        event: "runtime_diagnostics_snapshot".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    RuntimeDiagnosticsOutput {
        snapshot_timestamp_ns: input.snapshot_timestamp_ns,
        loaded_extensions,
        active_policies,
        security_epoch: input.security_epoch,
        gc_pressure,
        scheduler_lanes,
        logs,
    }
}

/// Render diagnostics output in a deterministic human-readable form.
pub fn render_diagnostics_summary(output: &RuntimeDiagnosticsOutput) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "snapshot_timestamp_ns: {}",
        output.snapshot_timestamp_ns
    ));
    lines.push(format!(
        "security_epoch: {}",
        output.security_epoch.as_u64()
    ));
    lines.push(format!(
        "loaded_extensions: {}",
        output.loaded_extensions.len()
    ));
    for extension in &output.loaded_extensions {
        lines.push(format!(
            "  - {} [{}]",
            extension.extension_id, extension.containment_state
        ));
    }
    lines.push(format!("active_policies: {}", output.active_policies.len()));
    for policy in &output.active_policies {
        lines.push(format!("  - {}", policy));
    }
    lines.push(format!("gc_pressure_rows: {}", output.gc_pressure.len()));
    for gc in &output.gc_pressure {
        lines.push(format!(
            "  - {} pressure={} over_budget={}",
            gc.extension_id, gc.pressure_millionths, gc.over_budget
        ));
    }
    lines.push(format!("scheduler_lanes: {}", output.scheduler_lanes.len()));
    for lane in &output.scheduler_lanes {
        lines.push(format!(
            "  - {} queue_depth={} utilization={}",
            lane.lane, lane.queue_depth, lane.utilization_millionths
        ));
    }
    lines.join("\n")
}

/// Evidence export filter surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportFilter {
    pub extension_id: Option<String>,
    pub trace_id: Option<String>,
    pub start_timestamp_ns: Option<u64>,
    pub end_timestamp_ns: Option<u64>,
    pub severity: Option<EvidenceSeverity>,
    pub decision_type: Option<DecisionType>,
}

impl EvidenceExportFilter {
    fn matches_timestamp(&self, timestamp_ns: u64) -> bool {
        if let Some(start) = self.start_timestamp_ns
            && timestamp_ns < start
        {
            return false;
        }
        if let Some(end) = self.end_timestamp_ns
            && timestamp_ns > end
        {
            return false;
        }
        true
    }

    fn matches_extension(&self, extension_id: &Option<String>) -> bool {
        match (&self.extension_id, extension_id) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    fn matches_trace(&self, trace_id: &str) -> bool {
        self.trace_id
            .as_deref()
            .is_none_or(|expected| expected == trace_id)
    }

    fn matches_severity(&self, severity: EvidenceSeverity) -> bool {
        self.severity.is_none_or(|expected| expected == severity)
    }

    fn matches_decision_type(&self, decision_type: Option<DecisionType>) -> bool {
        match (self.decision_type, decision_type) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
        }
    }
}

/// Canonical record kind exported by the evidence CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRecordKind {
    DecisionReceipt,
    HostcallTelemetry,
    ContainmentAction,
    PolicyChange,
    ReplayArtifact,
}

impl fmt::Display for EvidenceRecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionReceipt => f.write_str("decision_receipt"),
            Self::HostcallTelemetry => f.write_str("hostcall_telemetry"),
            Self::ContainmentAction => f.write_str("containment_action"),
            Self::PolicyChange => f.write_str("policy_change"),
            Self::ReplayArtifact => f.write_str("replay_artifact"),
        }
    }
}

/// One exported evidence record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceExportRecord {
    pub kind: EvidenceRecordKind,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub extension_id: Option<String>,
    pub timestamp_ns: u64,
    pub severity: EvidenceSeverity,
    pub decision_type: Option<DecisionType>,
    pub payload: Value,
}

/// Export summary for operator and CI checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportSummary {
    pub total_records: usize,
    pub counts_by_kind: BTreeMap<String, u64>,
    pub counts_by_severity: BTreeMap<String, u64>,
}

/// Output from evidence export command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceExportOutput {
    pub filter: EvidenceExportFilter,
    pub records: Vec<EvidenceExportRecord>,
    pub summary: EvidenceExportSummary,
    pub logs: Vec<StructuredLogEvent>,
}

/// Export deterministic evidence records from all supported sources.
pub fn export_evidence_bundle(
    input: &RuntimeDiagnosticsCliInput,
    filter: EvidenceExportFilter,
) -> EvidenceExportOutput {
    let mut records = Vec::new();

    for entry in &input.evidence_entries {
        let extension_id = entry.metadata.get("extension_id").cloned();
        let kind = if matches!(
            entry.decision_type,
            DecisionType::PolicyUpdate | DecisionType::EpochTransition
        ) {
            EvidenceRecordKind::PolicyChange
        } else {
            EvidenceRecordKind::DecisionReceipt
        };

        let record = EvidenceExportRecord {
            kind,
            trace_id: entry.trace_id.clone(),
            decision_id: Some(entry.decision_id.clone()),
            policy_id: Some(entry.policy_id.clone()),
            extension_id,
            timestamp_ns: entry.timestamp_ns,
            severity: severity_from_evidence_entry(entry),
            decision_type: Some(entry.decision_type),
            payload: serde_json::to_value(entry).expect("evidence entry must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    for envelope in &input.hostcall_records {
        let record = EvidenceExportRecord {
            kind: EvidenceRecordKind::HostcallTelemetry,
            trace_id: envelope.trace_id.clone(),
            decision_id: envelope.record.decision_id.clone(),
            policy_id: Some(envelope.policy_id.clone()),
            extension_id: Some(envelope.record.extension_id.clone()),
            timestamp_ns: envelope.record.timestamp_ns,
            severity: severity_from_hostcall(&envelope.record.result_status),
            decision_type: None,
            payload: serde_json::to_value(&envelope.record)
                .expect("hostcall record must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    for envelope in &input.containment_receipts {
        let record = EvidenceExportRecord {
            kind: EvidenceRecordKind::ContainmentAction,
            trace_id: envelope.trace_id.clone(),
            decision_id: envelope.receipt.metadata.get("decision_id").cloned(),
            policy_id: Some(envelope.policy_id.clone()),
            extension_id: Some(envelope.receipt.target_extension_id.clone()),
            timestamp_ns: envelope.receipt.timestamp_ns,
            severity: severity_from_containment_action(envelope.receipt.action),
            decision_type: Some(DecisionType::SecurityAction),
            payload: serde_json::to_value(&envelope.receipt)
                .expect("containment receipt must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    for artifact in &input.replay_artifacts {
        let record = EvidenceExportRecord {
            kind: EvidenceRecordKind::ReplayArtifact,
            trace_id: artifact.trace_id.clone(),
            decision_id: None,
            policy_id: None,
            extension_id: Some(artifact.extension_id.clone()),
            timestamp_ns: artifact.timestamp_ns,
            severity: EvidenceSeverity::Info,
            decision_type: None,
            payload: serde_json::to_value(artifact).expect("replay artifact must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    records.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then(left.kind.cmp(&right.kind))
            .then(left.trace_id.cmp(&right.trace_id))
            .then(left.decision_id.cmp(&right.decision_id))
            .then(left.extension_id.cmp(&right.extension_id))
    });

    let mut counts_by_kind = BTreeMap::new();
    let mut counts_by_severity = BTreeMap::new();
    for record in &records {
        *counts_by_kind.entry(record.kind.to_string()).or_insert(0) += 1;
        *counts_by_severity
            .entry(record.severity.to_string())
            .or_insert(0) += 1;
    }

    let logs = vec![StructuredLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "evidence_export".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    EvidenceExportOutput {
        filter,
        summary: EvidenceExportSummary {
            total_records: records.len(),
            counts_by_kind,
            counts_by_severity,
        },
        records,
        logs,
    }
}

/// Render evidence export output in deterministic human-readable form.
pub fn render_evidence_summary(output: &EvidenceExportOutput) -> String {
    let mut lines = Vec::new();
    if output.records.is_empty() {
        lines.push("No evidence entries found for the specified filters.".to_string());
        return lines.join("\n");
    }

    lines.push(format!("total_records: {}", output.summary.total_records));
    lines.push("counts_by_kind:".to_string());
    for (kind, count) in &output.summary.counts_by_kind {
        lines.push(format!("  - {}={}", kind, count));
    }
    lines.push("counts_by_severity:".to_string());
    for (severity, count) in &output.summary.counts_by_severity {
        lines.push(format!("  - {}={}", severity, count));
    }
    lines.join("\n")
}

fn compute_pressure_millionths(used: u64, budget: u64) -> u64 {
    if budget == 0 {
        if used == 0 {
            return 0;
        }
        return 1_000_000;
    }

    let ratio = used.saturating_mul(1_000_000) / budget;
    ratio.min(1_000_000)
}

fn matches_export_filter(filter: &EvidenceExportFilter, record: &EvidenceExportRecord) -> bool {
    filter.matches_trace(&record.trace_id)
        && filter.matches_extension(&record.extension_id)
        && filter.matches_timestamp(record.timestamp_ns)
        && filter.matches_severity(record.severity)
        && filter.matches_decision_type(record.decision_type)
}

fn severity_from_evidence_entry(entry: &EvidenceEntry) -> EvidenceSeverity {
    match entry.decision_type {
        DecisionType::Revocation | DecisionType::EpochTransition => EvidenceSeverity::Critical,
        DecisionType::PolicyUpdate => EvidenceSeverity::Warning,
        DecisionType::SecurityAction => {
            let action = entry.chosen_action.action_name.to_ascii_lowercase();
            match action.as_str() {
                "terminate" | "quarantine" | "suspend" => EvidenceSeverity::Critical,
                "sandbox" | "challenge" => EvidenceSeverity::Warning,
                _ => EvidenceSeverity::Info,
            }
        }
        _ => EvidenceSeverity::Info,
    }
}

fn severity_from_hostcall(result: &HostcallResult) -> EvidenceSeverity {
    match result {
        HostcallResult::Success => EvidenceSeverity::Info,
        HostcallResult::Denied { .. } => EvidenceSeverity::Warning,
        HostcallResult::Error { .. } | HostcallResult::Timeout => EvidenceSeverity::Critical,
    }
}

fn severity_from_containment_action(action: ContainmentAction) -> EvidenceSeverity {
    match action {
        ContainmentAction::Allow => EvidenceSeverity::Info,
        ContainmentAction::Challenge | ContainmentAction::Sandbox => EvidenceSeverity::Warning,
        ContainmentAction::Suspend
        | ContainmentAction::Terminate
        | ContainmentAction::Quarantine => EvidenceSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::containment_executor::ContainmentReceipt;
    use crate::evidence_ledger::{
        CandidateAction, ChosenAction, DecisionType, EvidenceEntryBuilder, InMemoryLedger, Witness,
    };
    use crate::expected_loss_selector::ContainmentAction;
    use crate::hash_tiers::ContentHash;
    use crate::hostcall_telemetry::{
        FlowLabel, HostcallResult, HostcallType, RecordInput, RecorderConfig, ResourceDelta,
        TelemetryRecorder,
    };

    fn sample_runtime_state() -> RuntimeStateInput {
        RuntimeStateInput {
            snapshot_timestamp_ns: 1_000,
            loaded_extensions: vec![
                RuntimeExtensionState {
                    extension_id: "ext-b".to_string(),
                    containment_state: ContainmentState::Running,
                },
                RuntimeExtensionState {
                    extension_id: "ext-a".to_string(),
                    containment_state: ContainmentState::Sandboxed,
                },
            ],
            active_policies: vec![
                "policy-z".to_string(),
                "policy-a".to_string(),
                "policy-z".to_string(),
            ],
            security_epoch: SecurityEpoch::from_raw(7),
            gc_pressure: vec![
                GcPressureSample {
                    extension_id: "ext-b".to_string(),
                    used_bytes: 700,
                    budget_bytes: 1_000,
                },
                GcPressureSample {
                    extension_id: "ext-a".to_string(),
                    used_bytes: 500,
                    budget_bytes: 400,
                },
            ],
            scheduler_lanes: vec![
                SchedulerLaneSample {
                    lane: "ready".to_string(),
                    queue_depth: 20,
                    max_depth: 100,
                    tasks_submitted: 50,
                    tasks_scheduled: 40,
                    tasks_completed: 35,
                    tasks_timed_out: 1,
                },
                SchedulerLaneSample {
                    lane: "cancel".to_string(),
                    queue_depth: 1,
                    max_depth: 10,
                    tasks_submitted: 3,
                    tasks_scheduled: 3,
                    tasks_completed: 3,
                    tasks_timed_out: 0,
                },
            ],
        }
    }

    fn sample_evidence_entries() -> Vec<EvidenceEntry> {
        let mut out = Vec::new();

        let security = EvidenceEntryBuilder::new(
            "trace-1",
            "dec-1",
            "policy-a",
            SecurityEpoch::from_raw(7),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(101)
        .candidate(CandidateAction::new("sandbox", 120_000))
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 120_000,
            rationale: "min-loss".to_string(),
        })
        .witness(Witness {
            witness_id: "w-1".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.91".to_string(),
        })
        .meta("extension_id", "ext-a")
        .build()
        .expect("security entry should build");
        out.push(security);

        let policy_change = EvidenceEntryBuilder::new(
            "trace-1",
            "dec-2",
            "policy-a",
            SecurityEpoch::from_raw(7),
            DecisionType::PolicyUpdate,
        )
        .timestamp_ns(102)
        .candidate(CandidateAction::new("rotate", 1))
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 1,
            rationale: "refresh key".to_string(),
        })
        .build()
        .expect("policy entry should build");
        out.push(policy_change);

        out
    }

    fn sample_hostcall_envelopes() -> Vec<HostcallTelemetryEnvelope> {
        let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
        let record_id = recorder
            .record(
                103,
                RecordInput {
                    extension_id: "ext-a".to_string(),
                    hostcall_type: HostcallType::FsRead,
                    capability_used: crate::capability::RuntimeCapability::FsRead,
                    arguments_hash: ContentHash::compute(b"args"),
                    result_status: HostcallResult::Denied {
                        reason: "policy".to_string(),
                    },
                    duration_ns: 2_000,
                    resource_delta: ResourceDelta::default(),
                    flow_label: FlowLabel::new("public", "public"),
                    decision_id: Some("dec-1".to_string()),
                },
            )
            .expect("recording hostcall should succeed");
        let record = recorder
            .get(record_id)
            .cloned()
            .expect("record should exist after successful recording");

        vec![HostcallTelemetryEnvelope {
            trace_id: "trace-1".to_string(),
            policy_id: "policy-a".to_string(),
            record,
        }]
    }

    fn sample_containment_receipts() -> Vec<ContainmentReceiptEnvelope> {
        let mut metadata = BTreeMap::new();
        metadata.insert("decision_id".to_string(), "dec-1".to_string());
        let mut receipt = ContainmentReceipt {
            receipt_id: "cr-1".to_string(),
            action: ContainmentAction::Sandbox,
            target_extension_id: "ext-a".to_string(),
            previous_state: ContainmentState::Running,
            new_state: ContainmentState::Sandboxed,
            timestamp_ns: 104,
            duration_ns: 0,
            success: true,
            cooperative: false,
            evidence_refs: vec!["ev-1".to_string()],
            epoch: SecurityEpoch::from_raw(7),
            content_hash: ContentHash::compute(b"placeholder"),
            metadata,
        };
        receipt.content_hash = ContentHash::compute(receipt.receipt_id.as_bytes());

        vec![ContainmentReceiptEnvelope {
            trace_id: "trace-1".to_string(),
            policy_id: "policy-a".to_string(),
            receipt,
        }]
    }

    fn sample_input() -> RuntimeDiagnosticsCliInput {
        RuntimeDiagnosticsCliInput {
            trace_id: "trace-runtime-cli".to_string(),
            decision_id: "decision-runtime-cli".to_string(),
            policy_id: "policy-runtime-cli".to_string(),
            runtime_state: sample_runtime_state(),
            evidence_entries: sample_evidence_entries(),
            hostcall_records: sample_hostcall_envelopes(),
            containment_receipts: sample_containment_receipts(),
            replay_artifacts: vec![ReplayArtifactRecord {
                trace_id: "trace-1".to_string(),
                extension_id: "ext-a".to_string(),
                timestamp_ns: 105,
                artifact_id: "replay-1".to_string(),
                replay_pointer: "artifacts/replay/trace-1.json".to_string(),
            }],
        }
    }

    #[test]
    fn diagnostics_snapshot_is_deterministic_and_sorted() {
        let state = sample_runtime_state();
        let left = collect_runtime_diagnostics(&state, "trace", "decision", "policy");
        let right = collect_runtime_diagnostics(&state, "trace", "decision", "policy");

        assert_eq!(left, right);
        assert_eq!(left.loaded_extensions[0].extension_id, "ext-a");
        assert_eq!(left.loaded_extensions[1].extension_id, "ext-b");
        assert_eq!(left.active_policies, vec!["policy-a", "policy-z"]);
        assert_eq!(left.scheduler_lanes[0].lane, "cancel");
        assert_eq!(left.scheduler_lanes[1].lane, "ready");
        assert!(left.logs.iter().all(|event| {
            !event.trace_id.is_empty()
                && !event.decision_id.is_empty()
                && !event.policy_id.is_empty()
                && !event.component.is_empty()
                && !event.event.is_empty()
                && !event.outcome.is_empty()
        }));
    }

    #[test]
    fn evidence_export_filters_narrow_results() {
        let input = sample_input();
        let filter = EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            trace_id: Some("trace-1".to_string()),
            start_timestamp_ns: Some(103),
            end_timestamp_ns: Some(104),
            severity: Some(EvidenceSeverity::Warning),
            decision_type: None,
        };

        let output = export_evidence_bundle(&input, filter);
        assert_eq!(output.summary.total_records, 2);
        assert!(output.records.iter().all(|record| {
            record.trace_id == "trace-1"
                && record.extension_id.as_deref() == Some("ext-a")
                && (103..=104).contains(&record.timestamp_ns)
                && record.severity == EvidenceSeverity::Warning
        }));
    }

    #[test]
    fn evidence_export_is_deterministic_for_same_query() {
        let input = sample_input();
        let filter = EvidenceExportFilter::default();
        let first = export_evidence_bundle(&input, filter.clone());
        let second = export_evidence_bundle(&input, filter);
        assert_eq!(first, second);
    }

    #[test]
    fn evidence_export_empty_result_is_valid() {
        let input = sample_input();
        let output = export_evidence_bundle(
            &input,
            EvidenceExportFilter {
                extension_id: Some("missing-extension".to_string()),
                ..EvidenceExportFilter::default()
            },
        );

        assert_eq!(output.summary.total_records, 0);
        assert!(output.records.is_empty());
        assert_eq!(
            render_evidence_summary(&output),
            "No evidence entries found for the specified filters."
        );
    }

    #[test]
    fn severity_and_decision_type_parsers_accept_known_values() {
        assert_eq!(
            parse_evidence_severity("critical"),
            Some(EvidenceSeverity::Critical)
        );
        assert_eq!(
            parse_decision_type("policy_update"),
            Some(DecisionType::PolicyUpdate)
        );
        assert_eq!(parse_evidence_severity("unknown"), None);
        assert_eq!(parse_decision_type("unknown"), None);
    }

    #[test]
    fn export_includes_required_kinds() {
        let input = sample_input();
        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());

        let kinds = output
            .records
            .iter()
            .map(|record| record.kind)
            .collect::<BTreeSet<_>>();

        assert!(kinds.contains(&EvidenceRecordKind::DecisionReceipt));
        assert!(kinds.contains(&EvidenceRecordKind::PolicyChange));
        assert!(kinds.contains(&EvidenceRecordKind::HostcallTelemetry));
        assert!(kinds.contains(&EvidenceRecordKind::ContainmentAction));
        assert!(kinds.contains(&EvidenceRecordKind::ReplayArtifact));
    }

    #[test]
    fn integration_like_export_over_ledger_data_remains_stable() {
        let mut ledger = InMemoryLedger::new();
        for entry in sample_evidence_entries() {
            crate::evidence_ledger::EvidenceEmitter::emit(&mut ledger, entry)
                .expect("ledger emit should succeed");
        }

        let mut input = sample_input();
        input.evidence_entries = ledger.entries().to_vec();

        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
        assert!(output.summary.total_records >= 5);
        assert!(
            output
                .logs
                .iter()
                .any(|event| event.event == "evidence_export")
        );
    }

    // -- serde roundtrips -----------------------------------------------------

    #[test]
    fn evidence_severity_serde_roundtrip() {
        for sev in &[
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ] {
            let json = serde_json::to_string(sev).unwrap();
            let back: EvidenceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    #[test]
    fn evidence_record_kind_serde_roundtrip() {
        for kind in &[
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ] {
            let json = serde_json::to_string(kind).unwrap();
            let back: EvidenceRecordKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn structured_log_event_serde_roundtrip() {
        let event = StructuredLogEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "test".to_string(),
            event: "snap".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("E001".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn evidence_export_filter_serde_roundtrip() {
        let filter = EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            trace_id: Some("t1".to_string()),
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            severity: Some(EvidenceSeverity::Warning),
            decision_type: Some(DecisionType::Revocation),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let back: EvidenceExportFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter, back);
    }

    #[test]
    fn gc_pressure_sample_serde_roundtrip() {
        let sample = GcPressureSample {
            extension_id: "ext-1".to_string(),
            used_bytes: 500,
            budget_bytes: 1000,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: GcPressureSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn scheduler_lane_sample_serde_roundtrip() {
        let sample = SchedulerLaneSample {
            lane: "fast".to_string(),
            queue_depth: 5,
            max_depth: 50,
            tasks_submitted: 100,
            tasks_scheduled: 90,
            tasks_completed: 80,
            tasks_timed_out: 2,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: SchedulerLaneSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn replay_artifact_record_serde_roundtrip() {
        let record = ReplayArtifactRecord {
            trace_id: "t1".to_string(),
            extension_id: "ext-1".to_string(),
            timestamp_ns: 42,
            artifact_id: "a1".to_string(),
            replay_pointer: "path/to/artifact".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ReplayArtifactRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // -- Display tests --------------------------------------------------------

    #[test]
    fn evidence_severity_display() {
        assert_eq!(EvidenceSeverity::Info.to_string(), "info");
        assert_eq!(EvidenceSeverity::Warning.to_string(), "warning");
        assert_eq!(EvidenceSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn evidence_record_kind_display() {
        assert_eq!(
            EvidenceRecordKind::DecisionReceipt.to_string(),
            "decision_receipt"
        );
        assert_eq!(
            EvidenceRecordKind::HostcallTelemetry.to_string(),
            "hostcall_telemetry"
        );
        assert_eq!(
            EvidenceRecordKind::ContainmentAction.to_string(),
            "containment_action"
        );
        assert_eq!(
            EvidenceRecordKind::PolicyChange.to_string(),
            "policy_change"
        );
        assert_eq!(
            EvidenceRecordKind::ReplayArtifact.to_string(),
            "replay_artifact"
        );
    }

    // -- parser edge cases ----------------------------------------------------

    #[test]
    fn parse_evidence_severity_case_insensitive() {
        assert_eq!(
            parse_evidence_severity("INFO"),
            Some(EvidenceSeverity::Info)
        );
        assert_eq!(
            parse_evidence_severity("  Warning  "),
            Some(EvidenceSeverity::Warning)
        );
        assert_eq!(
            parse_evidence_severity("CRITICAL"),
            Some(EvidenceSeverity::Critical)
        );
    }

    #[test]
    fn parse_decision_type_all_known_values() {
        let cases = [
            ("security_action", DecisionType::SecurityAction),
            ("policy_update", DecisionType::PolicyUpdate),
            ("epoch_transition", DecisionType::EpochTransition),
            ("revocation", DecisionType::Revocation),
            ("extension_lifecycle", DecisionType::ExtensionLifecycle),
            ("capability_decision", DecisionType::CapabilityDecision),
            ("contract_evaluation", DecisionType::ContractEvaluation),
            ("remote_authorization", DecisionType::RemoteAuthorization),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                parse_decision_type(input),
                Some(*expected),
                "failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn parse_decision_type_case_insensitive() {
        assert_eq!(
            parse_decision_type("SECURITY_ACTION"),
            Some(DecisionType::SecurityAction)
        );
        assert_eq!(
            parse_decision_type("  Policy_Update  "),
            Some(DecisionType::PolicyUpdate)
        );
    }

    // -- compute_pressure_millionths ------------------------------------------

    #[test]
    fn pressure_zero_budget_zero_used_is_zero() {
        assert_eq!(compute_pressure_millionths(0, 0), 0);
    }

    #[test]
    fn pressure_zero_budget_nonzero_used_is_million() {
        assert_eq!(compute_pressure_millionths(100, 0), 1_000_000);
    }

    #[test]
    fn pressure_exact_budget_is_million() {
        assert_eq!(compute_pressure_millionths(1000, 1000), 1_000_000);
    }

    #[test]
    fn pressure_half_budget_is_half_million() {
        assert_eq!(compute_pressure_millionths(500, 1000), 500_000);
    }

    #[test]
    fn pressure_over_budget_capped_at_million() {
        assert_eq!(compute_pressure_millionths(2000, 1000), 1_000_000);
    }

    // -- EvidenceExportFilter matching ----------------------------------------

    #[test]
    fn filter_default_matches_all() {
        let filter = EvidenceExportFilter::default();
        assert!(filter.matches_timestamp(0));
        assert!(filter.matches_timestamp(u64::MAX));
        assert!(filter.matches_extension(&None));
        assert!(filter.matches_extension(&Some("any".to_string())));
        assert!(filter.matches_trace("any"));
        assert!(filter.matches_severity(EvidenceSeverity::Info));
        assert!(filter.matches_decision_type(None));
    }

    #[test]
    fn filter_timestamp_range() {
        let filter = EvidenceExportFilter {
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            ..EvidenceExportFilter::default()
        };
        assert!(!filter.matches_timestamp(99));
        assert!(filter.matches_timestamp(100));
        assert!(filter.matches_timestamp(150));
        assert!(filter.matches_timestamp(200));
        assert!(!filter.matches_timestamp(201));
    }

    #[test]
    fn filter_extension_match() {
        let filter = EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            ..EvidenceExportFilter::default()
        };
        assert!(filter.matches_extension(&Some("ext-a".to_string())));
        assert!(!filter.matches_extension(&Some("ext-b".to_string())));
        assert!(!filter.matches_extension(&None));
    }

    #[test]
    fn filter_trace_match() {
        let filter = EvidenceExportFilter {
            trace_id: Some("t-1".to_string()),
            ..EvidenceExportFilter::default()
        };
        assert!(filter.matches_trace("t-1"));
        assert!(!filter.matches_trace("t-2"));
    }

    // -- diagnostics snapshot edge cases --------------------------------------

    #[test]
    fn diagnostics_empty_state() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert!(out.loaded_extensions.is_empty());
        assert!(out.active_policies.is_empty());
        assert!(out.gc_pressure.is_empty());
        assert!(out.scheduler_lanes.is_empty());
        assert_eq!(out.logs.len(), 1);
    }

    #[test]
    fn diagnostics_deduplicates_policies() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![
                "a".to_string(),
                "b".to_string(),
                "a".to_string(),
                "b".to_string(),
            ],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert_eq!(out.active_policies, vec!["a", "b"]);
    }

    #[test]
    fn diagnostics_filters_empty_policies() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec!["".to_string(), "  ".to_string(), "real".to_string()],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert_eq!(out.active_policies, vec!["real"]);
    }

    #[test]
    fn gc_pressure_over_budget_flag() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![
                GcPressureSample {
                    extension_id: "over".to_string(),
                    used_bytes: 2000,
                    budget_bytes: 1000,
                },
                GcPressureSample {
                    extension_id: "under".to_string(),
                    used_bytes: 500,
                    budget_bytes: 1000,
                },
            ],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let over = out
            .gc_pressure
            .iter()
            .find(|g| g.extension_id == "over")
            .unwrap();
        let under = out
            .gc_pressure
            .iter()
            .find(|g| g.extension_id == "under")
            .unwrap();
        assert!(over.over_budget);
        assert!(!under.over_budget);
    }

    // -- render_diagnostics_summary -------------------------------------------

    #[test]
    fn render_diagnostics_summary_contains_epoch() {
        let state = sample_runtime_state();
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let rendered = render_diagnostics_summary(&out);
        assert!(rendered.contains("security_epoch: 7"));
    }

    #[test]
    fn render_diagnostics_summary_contains_extension_count() {
        let state = sample_runtime_state();
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let rendered = render_diagnostics_summary(&out);
        assert!(rendered.contains("loaded_extensions: 2"));
    }

    // -- render_evidence_summary ----------------------------------------------

    #[test]
    fn render_evidence_summary_nonempty_has_counts() {
        let input = sample_input();
        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
        let rendered = render_evidence_summary(&output);
        assert!(rendered.contains("total_records:"));
        assert!(rendered.contains("counts_by_kind:"));
        assert!(rendered.contains("counts_by_severity:"));
    }

    // -- severity functions ---------------------------------------------------

    #[test]
    fn severity_from_containment_covers_all_actions() {
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Allow),
            EvidenceSeverity::Info
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Challenge),
            EvidenceSeverity::Warning
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Sandbox),
            EvidenceSeverity::Warning
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Suspend),
            EvidenceSeverity::Critical
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Terminate),
            EvidenceSeverity::Critical
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Quarantine),
            EvidenceSeverity::Critical
        );
    }

    #[test]
    fn severity_from_hostcall_result() {
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Success),
            EvidenceSeverity::Info
        );
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Denied {
                reason: "nope".to_string()
            }),
            EvidenceSeverity::Warning
        );
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Error { code: 500 }),
            EvidenceSeverity::Critical
        );
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Timeout),
            EvidenceSeverity::Critical
        );
    }

    // -- EvidenceExportSummary serde ------------------------------------------

    #[test]
    fn evidence_export_summary_serde_roundtrip() {
        let mut counts_by_kind = BTreeMap::new();
        counts_by_kind.insert("decision_receipt".to_string(), 3);
        let mut counts_by_severity = BTreeMap::new();
        counts_by_severity.insert("info".to_string(), 2);
        let summary = EvidenceExportSummary {
            total_records: 5,
            counts_by_kind,
            counts_by_severity,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: EvidenceExportSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -- severity ordering ----------------------------------------------------

    #[test]
    fn evidence_severity_ordering() {
        assert!(EvidenceSeverity::Info < EvidenceSeverity::Warning);
        assert!(EvidenceSeverity::Warning < EvidenceSeverity::Critical);
    }

    // -- evidence record kind ordering ----------------------------------------

    #[test]
    fn evidence_record_kind_ordering() {
        assert!(EvidenceRecordKind::DecisionReceipt < EvidenceRecordKind::ReplayArtifact);
    }
}
