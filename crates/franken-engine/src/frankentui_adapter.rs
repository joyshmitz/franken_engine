use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const FRANKENTUI_ADAPTER_SCHEMA_VERSION: u32 = 1;
const UNKNOWN_LABEL: &str = "unknown";

/// Boundary payloads from engine runtime state to `/dp/frankentui` presentation.
/// This module intentionally carries structured data only; policy and runtime
/// decision logic must remain outside the TUI layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrankentuiViewPayload {
    IncidentReplay(IncidentReplayView),
    PolicyExplanation(PolicyExplanationCardView),
    ControlDashboard(ControlDashboardView),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStream {
    IncidentReplay,
    PolicyExplanation,
    ControlDashboard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    Snapshot,
    Delta,
    Heartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterEnvelope {
    pub schema_version: u32,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub generated_at_unix_ms: u64,
    pub stream: AdapterStream,
    pub update_kind: UpdateKind,
    pub payload: FrankentuiViewPayload,
}

impl AdapterEnvelope {
    pub fn new(
        trace_id: impl Into<String>,
        generated_at_unix_ms: u64,
        stream: AdapterStream,
        update_kind: UpdateKind,
        payload: FrankentuiViewPayload,
    ) -> Self {
        Self {
            schema_version: FRANKENTUI_ADAPTER_SCHEMA_VERSION,
            trace_id: normalize_non_empty(trace_id.into()),
            decision_id: None,
            policy_id: None,
            generated_at_unix_ms,
            stream,
            update_kind,
            payload,
        }
    }

    pub fn with_decision_context(
        mut self,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        self.decision_id = Some(normalize_non_empty(decision_id.into()));
        self.policy_id = Some(normalize_non_empty(policy_id.into()));
        self
    }

    pub fn encode_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayView {
    pub trace_id: String,
    pub scenario_name: String,
    pub deterministic: bool,
    pub replay_status: ReplayStatus,
    pub events: Vec<ReplayEventView>,
    pub artifact_handles: Vec<String>,
}

impl IncidentReplayView {
    pub fn snapshot(
        trace_id: impl Into<String>,
        scenario_name: impl Into<String>,
        events: Vec<ReplayEventView>,
    ) -> Self {
        Self {
            trace_id: normalize_non_empty(trace_id.into()),
            scenario_name: normalize_non_empty(scenario_name.into()),
            deterministic: true,
            replay_status: if events.is_empty() {
                ReplayStatus::NoEvents
            } else {
                ReplayStatus::Complete
            },
            events,
            artifact_handles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    Running,
    Complete,
    Failed,
    NoEvents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEventView {
    pub sequence: u64,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_unix_ms: u64,
}

impl ReplayEventView {
    pub fn new(
        sequence: u64,
        component: impl Into<String>,
        event: impl Into<String>,
        outcome: impl Into<String>,
        timestamp_unix_ms: u64,
    ) -> Self {
        Self {
            sequence,
            component: normalize_non_empty(component.into()),
            event: normalize_non_empty(event.into()),
            outcome: normalize_non_empty(outcome.into()),
            error_code: None,
            timestamp_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExplanationCardView {
    pub decision_id: String,
    pub policy_id: String,
    pub selected_action: String,
    pub confidence_millionths: i64,
    pub expected_loss_millionths: i64,
    pub action_candidates: Vec<ActionCandidateView>,
    pub key_drivers: Vec<DriverView>,
}

impl PolicyExplanationCardView {
    pub fn from_partial(input: PolicyExplanationPartial) -> Self {
        Self {
            decision_id: normalize_non_empty(input.decision_id),
            policy_id: normalize_non_empty(input.policy_id),
            selected_action: normalize_non_empty(input.selected_action),
            confidence_millionths: input.confidence_millionths.unwrap_or_default(),
            expected_loss_millionths: input.expected_loss_millionths.unwrap_or_default(),
            action_candidates: input.action_candidates,
            key_drivers: input.key_drivers,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyExplanationPartial {
    pub decision_id: String,
    pub policy_id: String,
    pub selected_action: String,
    pub confidence_millionths: Option<i64>,
    pub expected_loss_millionths: Option<i64>,
    #[serde(default)]
    pub action_candidates: Vec<ActionCandidateView>,
    #[serde(default)]
    pub key_drivers: Vec<DriverView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCandidateView {
    pub action: String,
    pub expected_loss_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverView {
    pub name: String,
    pub contribution_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub runtime_mode: String,
    pub metrics: Vec<DashboardMetricView>,
    pub extension_rows: Vec<ExtensionStatusRow>,
    pub incident_counts: BTreeMap<String, u64>,
}

impl ControlDashboardView {
    pub fn from_partial(input: ControlDashboardPartial) -> Self {
        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.unwrap_or_default(),
            runtime_mode: normalize_non_empty(input.runtime_mode),
            metrics: input.metrics,
            extension_rows: input.extension_rows,
            incident_counts: input.incident_counts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlDashboardPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub runtime_mode: String,
    #[serde(default)]
    pub metrics: Vec<DashboardMetricView>,
    #[serde(default)]
    pub extension_rows: Vec<ExtensionStatusRow>,
    #[serde(default)]
    pub incident_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardMetricView {
    pub metric: String,
    pub value: i64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionStatusRow {
    pub extension_id: String,
    pub state: String,
    pub trust_level: String,
}

fn normalize_non_empty(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        UNKNOWN_LABEL.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_snapshot_marks_empty_event_set() {
        let replay = IncidentReplayView::snapshot("trace-1", "incident-alpha", vec![]);
        assert_eq!(replay.replay_status, ReplayStatus::NoEvents);
        assert_eq!(replay.trace_id, "trace-1");
    }

    #[test]
    fn policy_explanation_partial_defaults_missing_fields() {
        let partial = PolicyExplanationPartial {
            decision_id: "  ".to_string(),
            policy_id: "".to_string(),
            selected_action: "   ".to_string(),
            confidence_millionths: None,
            expected_loss_millionths: None,
            action_candidates: vec![],
            key_drivers: vec![],
        };

        let card = PolicyExplanationCardView::from_partial(partial);

        assert_eq!(card.decision_id, "unknown");
        assert_eq!(card.policy_id, "unknown");
        assert_eq!(card.selected_action, "unknown");
        assert_eq!(card.confidence_millionths, 0);
        assert_eq!(card.expected_loss_millionths, 0);
    }

    #[test]
    fn control_dashboard_partial_defaults_missing_fields() {
        let dashboard = ControlDashboardView::from_partial(ControlDashboardPartial::default());
        assert_eq!(dashboard.cluster, "unknown");
        assert_eq!(dashboard.zone, "unknown");
        assert_eq!(dashboard.runtime_mode, "unknown");
        assert_eq!(dashboard.security_epoch, 0);
    }

    #[test]
    fn envelope_json_round_trip_is_stable() {
        let payload = FrankentuiViewPayload::ControlDashboard(ControlDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: 7,
            runtime_mode: "secure".to_string(),
            metrics: vec![DashboardMetricView {
                metric: "containment_latency_p95_ms".to_string(),
                value: 42,
                unit: "ms".to_string(),
            }],
            extension_rows: vec![ExtensionStatusRow {
                extension_id: "weather-ext".to_string(),
                state: "running".to_string(),
                trust_level: "trusted".to_string(),
            }],
            incident_counts: BTreeMap::new(),
        });

        let envelope = AdapterEnvelope::new(
            "trace-abc",
            1_700_000_000_000,
            AdapterStream::ControlDashboard,
            UpdateKind::Snapshot,
            payload,
        )
        .with_decision_context("decision-1", "policy-1");

        let encoded = envelope.encode_json().expect("encoding should succeed");
        let decoded: AdapterEnvelope =
            serde_json::from_slice(&encoded).expect("decoding should succeed");

        assert_eq!(decoded, envelope);
    }
}
