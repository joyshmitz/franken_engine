use std::collections::{BTreeMap, BTreeSet};

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
    ControlPlaneInvariantsDashboard(ControlPlaneInvariantsDashboardView),
    FlowDecisionDashboard(FlowDecisionDashboardView),
    ReplacementProgressDashboard(ReplacementProgressDashboardView),
    ProofSpecializationLineageDashboard(ProofSpecializationLineageDashboardView),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStream {
    IncidentReplay,
    PolicyExplanation,
    ControlDashboard,
    ControlPlaneInvariantsDashboard,
    FlowDecisionDashboard,
    ReplacementProgressDashboard,
    ProofSpecializationLineageDashboard,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DashboardSeverity {
    #[default]
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcomeKind {
    Allow,
    Deny,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationState {
    Open,
    Fulfilled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationKind {
    Unload,
    Quarantine,
    Suspend,
    Terminate,
    Revocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayHealthStatus {
    Pass,
    Fail,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    #[default]
    Recovering,
    Recovered,
    Waived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCompatibilityStatus {
    #[default]
    Unknown,
    Compatible,
    NeedsMigration,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStreamEntryView {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action_type: String,
    pub decision_outcome: DecisionOutcomeKind,
    pub expected_loss_millionths: i64,
    pub extension_id: String,
    pub region_id: String,
    pub severity: DashboardSeverity,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecisionOutcomesPanelView {
    pub allow_count: u64,
    pub deny_count: u64,
    pub fallback_count: u64,
    pub average_expected_loss_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationStatusRowView {
    pub obligation_id: String,
    pub extension_id: String,
    pub region_id: String,
    pub state: ObligationState,
    pub severity: DashboardSeverity,
    pub due_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObligationStatusPanelView {
    pub open_count: u64,
    pub fulfilled_count: u64,
    pub failed_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionLifecycleRowView {
    pub region_id: String,
    pub is_active: bool,
    pub active_extensions: u64,
    pub created_at_unix_ms: u64,
    pub closed_at_unix_ms: Option<u64>,
    pub quiescent_close_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegionLifecyclePanelView {
    pub active_region_count: u64,
    pub region_creations_in_window: u64,
    pub region_destructions_in_window: u64,
    pub average_quiescent_close_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationEventView {
    pub extension_id: String,
    pub region_id: String,
    pub cancellation_kind: CancellationKind,
    pub severity: DashboardSeverity,
    pub detail: String,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayHealthPanelView {
    pub last_run_status: ReplayHealthStatus,
    pub divergence_count: u64,
    pub last_replay_timestamp_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkTrendPointView {
    pub timestamp_unix_ms: u64,
    pub throughput_tps: u64,
    pub latency_p95_ms: u64,
    pub memory_peak_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BenchmarkTrendsPanelView {
    pub points: Vec<BenchmarkTrendPointView>,
    pub throughput_floor_tps: u64,
    pub latency_p95_ceiling_ms: u64,
    pub memory_peak_ceiling_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeActivationView {
    pub activation_id: String,
    pub activation_type: String,
    pub extension_id: String,
    pub region_id: String,
    pub severity: DashboardSeverity,
    pub recovery_status: RecoveryStatus,
    pub activated_at_unix_ms: u64,
    pub recovered_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SchemaVersionPanelView {
    pub evidence_schema_version: u32,
    pub last_migration_unix_ms: Option<u64>,
    pub compatibility_status: SchemaCompatibilityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardAlertMetric {
    ObligationFailureRateMillionths,
    ReplayDivergenceCount,
    SafeModeActivationCount,
    CancellationEventCount,
    FallbackActivationCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdComparator {
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
    Equal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardAlertRule {
    pub rule_id: String,
    pub description: String,
    pub metric: DashboardAlertMetric,
    pub comparator: ThresholdComparator,
    pub threshold: i64,
    pub severity: DashboardSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggeredAlertView {
    pub rule_id: String,
    pub description: String,
    pub metric: DashboardAlertMetric,
    pub observed_value: i64,
    pub threshold: i64,
    pub severity: DashboardSeverity,
    pub triggered_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardRefreshPolicy {
    pub evidence_stream_refresh_secs: u64,
    pub aggregate_refresh_secs: u64,
}

impl Default for DashboardRefreshPolicy {
    fn default() -> Self {
        Self {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 60,
        }
    }
}

impl DashboardRefreshPolicy {
    fn normalized(self) -> Self {
        let evidence_stream_refresh_secs = if self.evidence_stream_refresh_secs == 0 {
            5
        } else {
            self.evidence_stream_refresh_secs.min(5)
        };
        let aggregate_refresh_secs = if self.aggregate_refresh_secs == 0 {
            60
        } else {
            self.aggregate_refresh_secs.min(60)
        };
        Self {
            evidence_stream_refresh_secs,
            aggregate_refresh_secs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneInvariantsDashboardView {
    pub cluster: String,
    pub zone: String,
    pub runtime_mode: String,
    pub generated_at_unix_ms: u64,
    pub refresh_policy: DashboardRefreshPolicy,
    pub evidence_stream_last_updated_unix_ms: u64,
    pub aggregates_last_updated_unix_ms: u64,
    pub evidence_stream: Vec<EvidenceStreamEntryView>,
    pub decision_outcomes: DecisionOutcomesPanelView,
    pub obligation_status: ObligationStatusPanelView,
    pub obligation_rows: Vec<ObligationStatusRowView>,
    pub region_lifecycle: RegionLifecyclePanelView,
    pub region_rows: Vec<RegionLifecycleRowView>,
    pub cancellation_events: Vec<CancellationEventView>,
    pub replay_health: ReplayHealthPanelView,
    pub benchmark_trends: BenchmarkTrendsPanelView,
    pub safe_mode_activations: Vec<SafeModeActivationView>,
    pub schema_version: SchemaVersionPanelView,
    pub alert_rules: Vec<DashboardAlertRule>,
}

impl ControlPlaneInvariantsDashboardView {
    pub fn from_partial(input: ControlPlaneInvariantsPartial) -> Self {
        let mut evidence_stream = input.evidence_stream;
        evidence_stream.sort_by(|left, right| {
            left.timestamp_unix_ms
                .cmp(&right.timestamp_unix_ms)
                .then(left.trace_id.cmp(&right.trace_id))
                .then(left.decision_id.cmp(&right.decision_id))
                .then(left.policy_id.cmp(&right.policy_id))
        });
        for entry in &mut evidence_stream {
            entry.trace_id = normalize_non_empty(std::mem::take(&mut entry.trace_id));
            entry.decision_id = normalize_non_empty(std::mem::take(&mut entry.decision_id));
            entry.policy_id = normalize_non_empty(std::mem::take(&mut entry.policy_id));
            entry.action_type = normalize_non_empty(std::mem::take(&mut entry.action_type));
            entry.extension_id = normalize_non_empty(std::mem::take(&mut entry.extension_id));
            entry.region_id = normalize_non_empty(std::mem::take(&mut entry.region_id));
            entry.component = normalize_non_empty(std::mem::take(&mut entry.component));
            entry.event = normalize_non_empty(std::mem::take(&mut entry.event));
            entry.outcome = normalize_non_empty(std::mem::take(&mut entry.outcome));
            entry.error_code = normalize_optional_non_empty(entry.error_code.take());
        }

        let mut obligation_rows = input.obligation_rows;
        obligation_rows.sort_by(|left, right| {
            left.obligation_id
                .cmp(&right.obligation_id)
                .then(left.updated_at_unix_ms.cmp(&right.updated_at_unix_ms))
        });
        for row in &mut obligation_rows {
            row.obligation_id = normalize_non_empty(std::mem::take(&mut row.obligation_id));
            row.extension_id = normalize_non_empty(std::mem::take(&mut row.extension_id));
            row.region_id = normalize_non_empty(std::mem::take(&mut row.region_id));
            row.detail = normalize_non_empty(std::mem::take(&mut row.detail));
        }

        let mut region_rows = input.region_rows;
        region_rows.sort_by(|left, right| left.region_id.cmp(&right.region_id));
        for row in &mut region_rows {
            row.region_id = normalize_non_empty(std::mem::take(&mut row.region_id));
        }

        let mut cancellation_events = input.cancellation_events;
        cancellation_events.sort_by(|left, right| {
            left.timestamp_unix_ms
                .cmp(&right.timestamp_unix_ms)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.region_id.cmp(&right.region_id))
        });
        for event in &mut cancellation_events {
            event.extension_id = normalize_non_empty(std::mem::take(&mut event.extension_id));
            event.region_id = normalize_non_empty(std::mem::take(&mut event.region_id));
            event.detail = normalize_non_empty(std::mem::take(&mut event.detail));
        }

        let mut benchmark_points = input.benchmark_points;
        benchmark_points
            .sort_by(|left, right| left.timestamp_unix_ms.cmp(&right.timestamp_unix_ms));

        let mut safe_mode_activations = input.safe_mode_activations;
        safe_mode_activations.sort_by(|left, right| {
            left.activated_at_unix_ms
                .cmp(&right.activated_at_unix_ms)
                .then(left.activation_id.cmp(&right.activation_id))
        });
        for activation in &mut safe_mode_activations {
            activation.activation_id =
                normalize_non_empty(std::mem::take(&mut activation.activation_id));
            activation.activation_type =
                normalize_non_empty(std::mem::take(&mut activation.activation_type));
            activation.extension_id =
                normalize_non_empty(std::mem::take(&mut activation.extension_id));
            activation.region_id = normalize_non_empty(std::mem::take(&mut activation.region_id));
        }

        let mut alert_rules = input.alert_rules;
        alert_rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        for rule in &mut alert_rules {
            rule.rule_id = normalize_non_empty(std::mem::take(&mut rule.rule_id));
            rule.description = normalize_non_empty(std::mem::take(&mut rule.description));
        }

        let refresh_policy = input.refresh_policy.unwrap_or_default().normalized();
        let generated_at_unix_ms = input.generated_at_unix_ms.unwrap_or_default();
        let evidence_stream_last_updated_unix_ms = input
            .evidence_stream_last_updated_unix_ms
            .or_else(|| evidence_stream.last().map(|entry| entry.timestamp_unix_ms))
            .unwrap_or(generated_at_unix_ms);
        let aggregates_last_updated_unix_ms = input
            .aggregates_last_updated_unix_ms
            .unwrap_or(generated_at_unix_ms);

        let decision_outcomes = input
            .decision_outcomes
            .unwrap_or_else(|| summarize_decision_outcomes(&evidence_stream));
        let obligation_status = input
            .obligation_status
            .unwrap_or_else(|| summarize_obligation_status(&obligation_rows));
        let region_lifecycle = input
            .region_lifecycle
            .unwrap_or_else(|| summarize_region_lifecycle(&region_rows));
        let replay_health = input.replay_health.unwrap_or_default();
        let schema_version = input.schema_version.unwrap_or_default();
        let benchmark_trends = BenchmarkTrendsPanelView {
            points: benchmark_points,
            throughput_floor_tps: input.throughput_floor_tps.unwrap_or_default(),
            latency_p95_ceiling_ms: input.latency_p95_ceiling_ms.unwrap_or_default(),
            memory_peak_ceiling_mb: input.memory_peak_ceiling_mb.unwrap_or_default(),
        };

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            runtime_mode: normalize_non_empty(input.runtime_mode),
            generated_at_unix_ms,
            refresh_policy,
            evidence_stream_last_updated_unix_ms,
            aggregates_last_updated_unix_ms,
            evidence_stream,
            decision_outcomes,
            obligation_status,
            obligation_rows,
            region_lifecycle,
            region_rows,
            cancellation_events,
            replay_health,
            benchmark_trends,
            safe_mode_activations,
            schema_version,
            alert_rules,
        }
    }

    pub fn filtered(&self, filter: &ControlPlaneDashboardFilter) -> Self {
        let evidence_stream = self
            .evidence_stream
            .iter()
            .filter(|entry| evidence_entry_matches_filter(entry, filter))
            .cloned()
            .collect::<Vec<_>>();
        let obligation_rows = self
            .obligation_rows
            .iter()
            .filter(|row| obligation_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let region_rows = self
            .region_rows
            .iter()
            .filter(|row| region_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let cancellation_events = self
            .cancellation_events
            .iter()
            .filter(|event| cancellation_event_matches_filter(event, filter))
            .cloned()
            .collect::<Vec<_>>();
        let benchmark_points = self
            .benchmark_trends
            .points
            .iter()
            .filter(|point| timestamp_matches_range(point.timestamp_unix_ms, filter))
            .cloned()
            .collect::<Vec<_>>();
        let safe_mode_activations = self
            .safe_mode_activations
            .iter()
            .filter(|activation| safe_mode_activation_matches_filter(activation, filter))
            .cloned()
            .collect::<Vec<_>>();

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            runtime_mode: self.runtime_mode.clone(),
            generated_at_unix_ms: self.generated_at_unix_ms,
            refresh_policy: self.refresh_policy.clone(),
            evidence_stream_last_updated_unix_ms: self.evidence_stream_last_updated_unix_ms,
            aggregates_last_updated_unix_ms: self.aggregates_last_updated_unix_ms,
            decision_outcomes: summarize_decision_outcomes(&evidence_stream),
            obligation_status: summarize_obligation_status(&obligation_rows),
            region_lifecycle: summarize_region_lifecycle(&region_rows),
            replay_health: self.replay_health.clone(),
            benchmark_trends: BenchmarkTrendsPanelView {
                points: benchmark_points,
                throughput_floor_tps: self.benchmark_trends.throughput_floor_tps,
                latency_p95_ceiling_ms: self.benchmark_trends.latency_p95_ceiling_ms,
                memory_peak_ceiling_mb: self.benchmark_trends.memory_peak_ceiling_mb,
            },
            schema_version: self.schema_version.clone(),
            alert_rules: self.alert_rules.clone(),
            evidence_stream,
            obligation_rows,
            region_rows,
            cancellation_events,
            safe_mode_activations,
        }
    }

    pub fn evaluate_alerts(&self, rules: &[DashboardAlertRule]) -> Vec<TriggeredAlertView> {
        let mut triggered = rules
            .iter()
            .filter_map(|rule| {
                let observed = dashboard_metric_value(self, rule.metric);
                threshold_matches(rule.comparator, observed, rule.threshold).then(|| {
                    TriggeredAlertView {
                        rule_id: rule.rule_id.clone(),
                        description: rule.description.clone(),
                        metric: rule.metric,
                        observed_value: observed,
                        threshold: rule.threshold,
                        severity: rule.severity,
                        triggered_at_unix_ms: self.generated_at_unix_ms,
                    }
                })
            })
            .collect::<Vec<_>>();
        triggered.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        triggered
    }

    pub fn triggered_alerts(&self) -> Vec<TriggeredAlertView> {
        self.evaluate_alerts(&self.alert_rules)
    }

    pub fn meets_refresh_sla(&self) -> bool {
        let evidence_lag_ms = self
            .generated_at_unix_ms
            .saturating_sub(self.evidence_stream_last_updated_unix_ms);
        let aggregate_lag_ms = self
            .generated_at_unix_ms
            .saturating_sub(self.aggregates_last_updated_unix_ms);
        let evidence_budget_ms = self
            .refresh_policy
            .evidence_stream_refresh_secs
            .saturating_mul(1_000);
        let aggregate_budget_ms = self
            .refresh_policy
            .aggregate_refresh_secs
            .saturating_mul(1_000);
        evidence_lag_ms <= evidence_budget_ms && aggregate_lag_ms <= aggregate_budget_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlPlaneInvariantsPartial {
    pub cluster: String,
    pub zone: String,
    pub runtime_mode: String,
    pub generated_at_unix_ms: Option<u64>,
    pub refresh_policy: Option<DashboardRefreshPolicy>,
    pub evidence_stream_last_updated_unix_ms: Option<u64>,
    pub aggregates_last_updated_unix_ms: Option<u64>,
    #[serde(default)]
    pub evidence_stream: Vec<EvidenceStreamEntryView>,
    pub decision_outcomes: Option<DecisionOutcomesPanelView>,
    #[serde(default)]
    pub obligation_rows: Vec<ObligationStatusRowView>,
    pub obligation_status: Option<ObligationStatusPanelView>,
    #[serde(default)]
    pub region_rows: Vec<RegionLifecycleRowView>,
    pub region_lifecycle: Option<RegionLifecyclePanelView>,
    #[serde(default)]
    pub cancellation_events: Vec<CancellationEventView>,
    pub replay_health: Option<ReplayHealthPanelView>,
    #[serde(default)]
    pub benchmark_points: Vec<BenchmarkTrendPointView>,
    pub throughput_floor_tps: Option<u64>,
    pub latency_p95_ceiling_ms: Option<u64>,
    pub memory_peak_ceiling_mb: Option<u64>,
    #[serde(default)]
    pub safe_mode_activations: Vec<SafeModeActivationView>,
    pub schema_version: Option<SchemaVersionPanelView>,
    #[serde(default)]
    pub alert_rules: Vec<DashboardAlertRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlPlaneDashboardFilter {
    pub extension_id: Option<String>,
    pub region_id: Option<String>,
    pub severity: Option<DashboardSeverity>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FlowSensitivityLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationOutcome {
    Approved,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementStatus {
    Full,
    Partial,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelMapNodeView {
    pub label_id: String,
    pub sensitivity: FlowSensitivityLevel,
    pub description: String,
    pub extension_overlays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelMapEdgeView {
    pub source_label: String,
    pub sink_clearance: String,
    pub route_policy_id: Option<String>,
    pub route_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LabelMapView {
    pub nodes: Vec<LabelMapNodeView>,
    pub edges: Vec<LabelMapEdgeView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedFlowView {
    pub flow_id: String,
    pub extension_id: String,
    pub source_label: String,
    pub sink_clearance: String,
    pub sensitivity: FlowSensitivityLevel,
    pub blocked_reason: String,
    pub attempted_exfiltration: bool,
    pub code_path_ref: String,
    pub extension_context_ref: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub error_code: Option<String>,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationDecisionView {
    pub decision_id: String,
    pub extension_id: String,
    pub source_label: String,
    pub sink_clearance: String,
    pub sensitivity: FlowSensitivityLevel,
    pub outcome: DeclassificationOutcome,
    pub policy_id: String,
    pub loss_assessment_summary: String,
    pub rationale: String,
    pub receipt_ref: String,
    pub replay_ref: String,
    pub decided_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowProofCoverageView {
    pub proof_id: String,
    pub source_label: String,
    pub sink_clearance: String,
    pub covered: bool,
    pub proof_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementProofView {
    pub extension_id: String,
    pub status: ConfinementStatus,
    pub covered_flow_count: u64,
    pub uncovered_flow_count: u64,
    pub proof_rows: Vec<FlowProofCoverageView>,
    pub uncovered_flow_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDecisionAlertView {
    pub alert_id: String,
    pub extension_id: String,
    pub severity: DashboardSeverity,
    pub reason: String,
    pub blocked_flow_count: u64,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDecisionDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub label_map: LabelMapView,
    pub blocked_flows: Vec<BlockedFlowView>,
    pub declassification_history: Vec<DeclassificationDecisionView>,
    pub confinement_proofs: Vec<ConfinementProofView>,
    pub alert_indicators: Vec<FlowDecisionAlertView>,
}

impl FlowDecisionDashboardView {
    pub fn from_partial(input: FlowDecisionPartial) -> Self {
        let mut label_map = input.label_map;
        label_map
            .nodes
            .sort_by(|left, right| left.label_id.cmp(&right.label_id));
        label_map.edges.sort_by(|left, right| {
            left.source_label
                .cmp(&right.source_label)
                .then(left.sink_clearance.cmp(&right.sink_clearance))
                .then(left.route_policy_id.cmp(&right.route_policy_id))
        });
        for node in &mut label_map.nodes {
            node.label_id = normalize_non_empty(std::mem::take(&mut node.label_id));
            node.description = normalize_non_empty(std::mem::take(&mut node.description));
            node.extension_overlays.sort();
            for extension in &mut node.extension_overlays {
                *extension = normalize_non_empty(std::mem::take(extension));
            }
        }
        for edge in &mut label_map.edges {
            edge.source_label = normalize_non_empty(std::mem::take(&mut edge.source_label));
            edge.sink_clearance = normalize_non_empty(std::mem::take(&mut edge.sink_clearance));
            edge.route_policy_id = normalize_optional_non_empty(edge.route_policy_id.take());
        }

        let mut blocked_flows = input.blocked_flows;
        blocked_flows.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.flow_id.cmp(&right.flow_id))
        });
        for flow in &mut blocked_flows {
            flow.flow_id = normalize_non_empty(std::mem::take(&mut flow.flow_id));
            flow.extension_id = normalize_non_empty(std::mem::take(&mut flow.extension_id));
            flow.source_label = normalize_non_empty(std::mem::take(&mut flow.source_label));
            flow.sink_clearance = normalize_non_empty(std::mem::take(&mut flow.sink_clearance));
            flow.blocked_reason = normalize_non_empty(std::mem::take(&mut flow.blocked_reason));
            flow.code_path_ref = normalize_non_empty(std::mem::take(&mut flow.code_path_ref));
            flow.extension_context_ref =
                normalize_non_empty(std::mem::take(&mut flow.extension_context_ref));
            flow.trace_id = normalize_non_empty(std::mem::take(&mut flow.trace_id));
            flow.decision_id = normalize_non_empty(std::mem::take(&mut flow.decision_id));
            flow.policy_id = normalize_non_empty(std::mem::take(&mut flow.policy_id));
            flow.error_code = normalize_optional_non_empty(flow.error_code.take());
        }

        let mut declassification_history = input.declassification_history;
        declassification_history.sort_by(|left, right| {
            left.decided_at_unix_ms
                .cmp(&right.decided_at_unix_ms)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.decision_id.cmp(&right.decision_id))
        });
        for decision in &mut declassification_history {
            decision.decision_id = normalize_non_empty(std::mem::take(&mut decision.decision_id));
            decision.extension_id = normalize_non_empty(std::mem::take(&mut decision.extension_id));
            decision.source_label = normalize_non_empty(std::mem::take(&mut decision.source_label));
            decision.sink_clearance =
                normalize_non_empty(std::mem::take(&mut decision.sink_clearance));
            decision.policy_id = normalize_non_empty(std::mem::take(&mut decision.policy_id));
            decision.loss_assessment_summary =
                normalize_non_empty(std::mem::take(&mut decision.loss_assessment_summary));
            decision.rationale = normalize_non_empty(std::mem::take(&mut decision.rationale));
            decision.receipt_ref = normalize_non_empty(std::mem::take(&mut decision.receipt_ref));
            decision.replay_ref = normalize_non_empty(std::mem::take(&mut decision.replay_ref));
        }

        let mut confinement_proofs = input.confinement_proofs;
        confinement_proofs.sort_by(|left, right| left.extension_id.cmp(&right.extension_id));
        for proof in &mut confinement_proofs {
            proof.extension_id = normalize_non_empty(std::mem::take(&mut proof.extension_id));
            proof.proof_rows.sort_by(|left, right| {
                left.source_label
                    .cmp(&right.source_label)
                    .then(left.sink_clearance.cmp(&right.sink_clearance))
                    .then(left.proof_id.cmp(&right.proof_id))
            });
            for row in &mut proof.proof_rows {
                row.proof_id = normalize_non_empty(std::mem::take(&mut row.proof_id));
                row.source_label = normalize_non_empty(std::mem::take(&mut row.source_label));
                row.sink_clearance = normalize_non_empty(std::mem::take(&mut row.sink_clearance));
                row.proof_ref = normalize_non_empty(std::mem::take(&mut row.proof_ref));
            }
            proof.uncovered_flow_refs.sort();
            for uncovered in &mut proof.uncovered_flow_refs {
                *uncovered = normalize_non_empty(std::mem::take(uncovered));
            }
        }

        let generated_at_unix_ms = input.generated_at_unix_ms.unwrap_or_default();
        let alert_threshold = input.blocked_flow_alert_threshold.unwrap_or(5);
        let mut alert_indicators = if input.alert_indicators.is_empty() {
            compute_flow_alert_indicators(
                &blocked_flows,
                &confinement_proofs,
                generated_at_unix_ms,
                alert_threshold,
            )
        } else {
            input.alert_indicators
        };
        alert_indicators.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
        for alert in &mut alert_indicators {
            alert.alert_id = normalize_non_empty(std::mem::take(&mut alert.alert_id));
            alert.extension_id = normalize_non_empty(std::mem::take(&mut alert.extension_id));
            alert.reason = normalize_non_empty(std::mem::take(&mut alert.reason));
        }

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.unwrap_or_default(),
            generated_at_unix_ms,
            label_map,
            blocked_flows,
            declassification_history,
            confinement_proofs,
            alert_indicators,
        }
    }

    pub fn filtered(&self, filter: &FlowDecisionDashboardFilter) -> Self {
        let blocked_flows = self
            .blocked_flows
            .iter()
            .filter(|flow| blocked_flow_matches_filter(flow, filter))
            .cloned()
            .collect::<Vec<_>>();
        let declassification_history = self
            .declassification_history
            .iter()
            .filter(|decision| declassification_matches_filter(decision, filter))
            .cloned()
            .collect::<Vec<_>>();
        let confinement_proofs = self
            .confinement_proofs
            .iter()
            .filter(|proof| confinement_proof_matches_filter(proof, filter))
            .cloned()
            .collect::<Vec<_>>();
        let relevant_extensions = blocked_flows
            .iter()
            .map(|flow| flow.extension_id.clone())
            .chain(
                declassification_history
                    .iter()
                    .map(|decision| decision.extension_id.clone()),
            )
            .collect::<BTreeSet<_>>();
        let alert_indicators = self
            .alert_indicators
            .iter()
            .filter(|alert| relevant_extensions.contains(&alert.extension_id))
            .cloned()
            .collect::<Vec<_>>();
        let label_map = self.filtered_label_map(filter, &relevant_extensions);

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            label_map,
            blocked_flows,
            declassification_history,
            confinement_proofs,
            alert_indicators,
        }
    }

    fn filtered_label_map(
        &self,
        filter: &FlowDecisionDashboardFilter,
        relevant_extensions: &BTreeSet<String>,
    ) -> LabelMapView {
        let mut nodes = self
            .label_map
            .nodes
            .iter()
            .filter(|node| {
                filter
                    .sensitivity
                    .is_none_or(|sensitivity| node.sensitivity == sensitivity)
                    && (relevant_extensions.is_empty()
                        || node
                            .extension_overlays
                            .iter()
                            .any(|extension| relevant_extensions.contains(extension)))
            })
            .cloned()
            .collect::<Vec<_>>();
        let node_labels = nodes
            .iter()
            .map(|node| node.label_id.clone())
            .collect::<BTreeSet<_>>();
        let edges = self
            .label_map
            .edges
            .iter()
            .filter(|edge| {
                node_labels.contains(&edge.source_label)
                    && (filter
                        .sink_clearance
                        .as_deref()
                        .is_none_or(|sink| edge.sink_clearance.eq_ignore_ascii_case(sink)))
            })
            .cloned()
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.label_id.cmp(&right.label_id));
        LabelMapView { nodes, edges }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowDecisionPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    pub label_map: LabelMapView,
    #[serde(default)]
    pub blocked_flows: Vec<BlockedFlowView>,
    #[serde(default)]
    pub declassification_history: Vec<DeclassificationDecisionView>,
    #[serde(default)]
    pub confinement_proofs: Vec<ConfinementProofView>,
    #[serde(default)]
    pub alert_indicators: Vec<FlowDecisionAlertView>,
    pub blocked_flow_alert_threshold: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowDecisionDashboardFilter {
    pub extension_id: Option<String>,
    pub source_label: Option<String>,
    pub sink_clearance: Option<String>,
    pub sensitivity: Option<FlowSensitivityLevel>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementRiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Investigating,
    Resolved,
    Waived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotStatusOverviewRow {
    pub slot_id: String,
    pub slot_kind: String,
    pub implementation_kind: String,
    pub promotion_status: String,
    pub risk_level: ReplacementRiskLevel,
    pub last_transition_unix_ms: u64,
    pub health: String,
    pub lineage_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageTrendPoint {
    pub timestamp_unix_ms: u64,
    pub native_coverage_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCoverageMeter {
    pub native_slots: usize,
    pub delegate_slots: usize,
    pub native_coverage_millionths: u64,
    pub trend: Vec<CoverageTrendPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedPromotionView {
    pub slot_id: String,
    pub gate_failure_code: String,
    pub failure_detail: String,
    pub recommended_remediation: String,
    pub lineage_ref: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEventView {
    pub slot_id: String,
    pub receipt_id: String,
    pub reason: String,
    pub status: RollbackStatus,
    pub occurred_at_unix_ms: u64,
    pub lineage_ref: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementOpportunityInput {
    pub slot_id: String,
    pub slot_kind: String,
    pub performance_uplift_millionths: u64,
    pub invocation_frequency_per_minute: u64,
    pub risk_reduction_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementOpportunityView {
    pub slot_id: String,
    pub slot_kind: String,
    pub expected_value_score_millionths: i64,
    pub performance_uplift_millionths: u64,
    pub invocation_frequency_per_minute: u64,
    pub risk_reduction_millionths: u64,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementProgressDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub slot_status_overview: Vec<SlotStatusOverviewRow>,
    pub native_coverage: NativeCoverageMeter,
    pub blocked_promotions: Vec<BlockedPromotionView>,
    pub rollback_events: Vec<RollbackEventView>,
    pub next_best_replacements: Vec<ReplacementOpportunityView>,
}

impl ReplacementProgressDashboardView {
    pub fn from_partial(input: ReplacementProgressPartial) -> Self {
        let mut slot_status_overview = input.slot_status_overview;
        slot_status_overview.sort_by(|left, right| {
            left.slot_id
                .cmp(&right.slot_id)
                .then(left.slot_kind.cmp(&right.slot_kind))
        });

        for row in &mut slot_status_overview {
            row.slot_id = normalize_non_empty(std::mem::take(&mut row.slot_id));
            row.slot_kind = normalize_non_empty(std::mem::take(&mut row.slot_kind));
            row.implementation_kind =
                normalize_non_empty(std::mem::take(&mut row.implementation_kind));
            row.promotion_status = normalize_non_empty(std::mem::take(&mut row.promotion_status));
            row.health = normalize_non_empty(std::mem::take(&mut row.health));
            row.lineage_ref = normalize_non_empty(std::mem::take(&mut row.lineage_ref));
        }

        let mut native_coverage_history = input.native_coverage_history;
        native_coverage_history.sort_by(|left, right| {
            left.timestamp_unix_ms.cmp(&right.timestamp_unix_ms).then(
                left.native_coverage_millionths
                    .cmp(&right.native_coverage_millionths),
            )
        });
        for point in &mut native_coverage_history {
            point.native_coverage_millionths =
                canonicalize_coverage_millionths(point.native_coverage_millionths);
        }

        let native_coverage = match input.native_coverage {
            Some(mut meter) => {
                meter.native_coverage_millionths =
                    canonicalize_coverage_millionths(meter.native_coverage_millionths);
                meter.trend.sort_by(|left, right| {
                    left.timestamp_unix_ms.cmp(&right.timestamp_unix_ms).then(
                        left.native_coverage_millionths
                            .cmp(&right.native_coverage_millionths),
                    )
                });
                for point in &mut meter.trend {
                    point.native_coverage_millionths =
                        canonicalize_coverage_millionths(point.native_coverage_millionths);
                }
                meter
            }
            None => build_native_coverage_meter(&slot_status_overview, native_coverage_history),
        };

        let mut blocked_promotions = input.blocked_promotions;
        blocked_promotions.sort_by(|left, right| {
            left.slot_id
                .cmp(&right.slot_id)
                .then(left.gate_failure_code.cmp(&right.gate_failure_code))
        });
        for blocked in &mut blocked_promotions {
            blocked.slot_id = normalize_non_empty(std::mem::take(&mut blocked.slot_id));
            blocked.gate_failure_code =
                normalize_non_empty(std::mem::take(&mut blocked.gate_failure_code));
            blocked.failure_detail =
                normalize_non_empty(std::mem::take(&mut blocked.failure_detail));
            blocked.recommended_remediation =
                normalize_non_empty(std::mem::take(&mut blocked.recommended_remediation));
            blocked.lineage_ref = normalize_non_empty(std::mem::take(&mut blocked.lineage_ref));
            blocked.evidence_ref = normalize_non_empty(std::mem::take(&mut blocked.evidence_ref));
        }

        let mut rollback_events = input.rollback_events;
        rollback_events.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.slot_id.cmp(&right.slot_id))
                .then(left.receipt_id.cmp(&right.receipt_id))
        });
        for rollback in &mut rollback_events {
            rollback.slot_id = normalize_non_empty(std::mem::take(&mut rollback.slot_id));
            rollback.receipt_id = normalize_non_empty(std::mem::take(&mut rollback.receipt_id));
            rollback.reason = normalize_non_empty(std::mem::take(&mut rollback.reason));
            rollback.lineage_ref = normalize_non_empty(std::mem::take(&mut rollback.lineage_ref));
            rollback.evidence_ref = normalize_non_empty(std::mem::take(&mut rollback.evidence_ref));
        }

        let mut next_best_replacements = if input.next_best_replacements.is_empty() {
            rank_replacement_opportunities(input.replacement_inputs)
        } else {
            input.next_best_replacements
        };
        next_best_replacements.sort_by(|left, right| {
            right
                .expected_value_score_millionths
                .cmp(&left.expected_value_score_millionths)
                .then(left.slot_id.cmp(&right.slot_id))
        });
        for replacement in &mut next_best_replacements {
            replacement.slot_id = normalize_non_empty(std::mem::take(&mut replacement.slot_id));
            replacement.slot_kind = normalize_non_empty(std::mem::take(&mut replacement.slot_kind));
            replacement.rationale = normalize_non_empty(std::mem::take(&mut replacement.rationale));
        }

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.unwrap_or_default(),
            generated_at_unix_ms: input.generated_at_unix_ms.unwrap_or_default(),
            slot_status_overview,
            native_coverage,
            blocked_promotions,
            rollback_events,
            next_best_replacements,
        }
    }

    pub fn filtered(&self, filter: &ReplacementDashboardFilter) -> Self {
        let slot_status_overview = self
            .slot_status_overview
            .iter()
            .filter(|row| slot_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let slot_ids = slot_status_overview
            .iter()
            .map(|row| row.slot_id.clone())
            .collect::<BTreeSet<_>>();

        let blocked_promotions = self
            .blocked_promotions
            .iter()
            .filter(|entry| slot_ids.contains(&entry.slot_id))
            .cloned()
            .collect::<Vec<_>>();
        let rollback_events = self
            .rollback_events
            .iter()
            .filter(|entry| slot_ids.contains(&entry.slot_id))
            .cloned()
            .collect::<Vec<_>>();
        let next_best_replacements = self
            .next_best_replacements
            .iter()
            .filter(|entry| slot_ids.contains(&entry.slot_id))
            .cloned()
            .collect::<Vec<_>>();
        let native_coverage =
            build_native_coverage_meter(&slot_status_overview, self.native_coverage.trend.clone());

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            slot_status_overview,
            native_coverage,
            blocked_promotions,
            rollback_events,
            next_best_replacements,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplacementProgressPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub slot_status_overview: Vec<SlotStatusOverviewRow>,
    #[serde(default)]
    pub native_coverage_history: Vec<CoverageTrendPoint>,
    pub native_coverage: Option<NativeCoverageMeter>,
    #[serde(default)]
    pub blocked_promotions: Vec<BlockedPromotionView>,
    #[serde(default)]
    pub rollback_events: Vec<RollbackEventView>,
    #[serde(default)]
    pub replacement_inputs: Vec<ReplacementOpportunityInput>,
    #[serde(default)]
    pub next_best_replacements: Vec<ReplacementOpportunityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplacementDashboardFilter {
    pub slot_kind: Option<String>,
    pub risk_level: Option<ReplacementRiskLevel>,
    pub promotion_status: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofInventoryKind {
    CapabilityWitness,
    FlowProof,
    ReplayMotif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProofValidityStatus {
    #[default]
    Valid,
    ExpiringSoon,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSpecializationInvalidationReason {
    EpochChange,
    ProofExpired,
    ProofRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationFallbackReason {
    ProofUnavailable,
    ProofExpired,
    ProofRevoked,
    ValidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInventoryRowView {
    pub proof_id: String,
    pub proof_kind: ProofInventoryKind,
    pub validity_status: ProofValidityStatus,
    pub epoch_id: u64,
    pub linked_specialization_count: u64,
    pub enabled_specialization_ids: Vec<String>,
    pub proof_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSpecializationRowView {
    pub specialization_id: String,
    pub target_id: String,
    pub target_kind: String,
    pub optimization_class: String,
    pub latency_reduction_millionths: u64,
    pub throughput_increase_millionths: u64,
    pub proof_input_ids: Vec<String>,
    pub transformation_ref: String,
    pub receipt_ref: String,
    pub activated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationInvalidationRowView {
    pub invalidation_id: String,
    pub specialization_id: String,
    pub target_id: String,
    pub reason: ProofSpecializationInvalidationReason,
    pub reason_detail: String,
    pub proof_id: Option<String>,
    pub old_epoch_id: Option<u64>,
    pub new_epoch_id: Option<u64>,
    pub fallback_confirmed: bool,
    pub fallback_confirmation_ref: String,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationFallbackEventView {
    pub event_id: String,
    pub specialization_id: Option<String>,
    pub target_id: String,
    pub reason: SpecializationFallbackReason,
    pub reason_detail: String,
    pub unspecialized_path_ref: String,
    pub compilation_ref: String,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SpecializationPerformanceImpactView {
    pub active_specialization_count: u64,
    pub aggregate_latency_reduction_millionths: u64,
    pub aggregate_throughput_increase_millionths: u64,
    pub specialization_coverage_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSpecializationAlertView {
    pub alert_id: String,
    pub severity: DashboardSeverity,
    pub reason: String,
    pub affected_count: u64,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSpecializationLineageDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub proof_inventory: Vec<ProofInventoryRowView>,
    pub active_specializations: Vec<ActiveSpecializationRowView>,
    pub invalidation_feed: Vec<SpecializationInvalidationRowView>,
    pub fallback_events: Vec<SpecializationFallbackEventView>,
    pub performance_impact: SpecializationPerformanceImpactView,
    pub alert_indicators: Vec<ProofSpecializationAlertView>,
}

impl ProofSpecializationLineageDashboardView {
    pub fn from_partial(input: ProofSpecializationLineagePartial) -> Self {
        let mut proof_inventory = input.proof_inventory;
        proof_inventory.sort_by(|left, right| {
            left.proof_id
                .cmp(&right.proof_id)
                .then(left.epoch_id.cmp(&right.epoch_id))
                .then(left.proof_ref.cmp(&right.proof_ref))
        });
        for proof in &mut proof_inventory {
            proof.proof_id = normalize_non_empty(std::mem::take(&mut proof.proof_id));
            proof.proof_ref = normalize_non_empty(std::mem::take(&mut proof.proof_ref));
            for specialization_id in &mut proof.enabled_specialization_ids {
                *specialization_id = normalize_non_empty(std::mem::take(specialization_id));
            }
            proof.enabled_specialization_ids.sort();
        }

        let mut active_specializations = input.active_specializations;
        active_specializations.sort_by(|left, right| {
            left.target_id
                .cmp(&right.target_id)
                .then(left.specialization_id.cmp(&right.specialization_id))
        });
        for specialization in &mut active_specializations {
            specialization.specialization_id =
                normalize_non_empty(std::mem::take(&mut specialization.specialization_id));
            specialization.target_id =
                normalize_non_empty(std::mem::take(&mut specialization.target_id));
            specialization.target_kind =
                normalize_non_empty(std::mem::take(&mut specialization.target_kind));
            specialization.optimization_class =
                normalize_non_empty(std::mem::take(&mut specialization.optimization_class));
            specialization.transformation_ref =
                normalize_non_empty(std::mem::take(&mut specialization.transformation_ref));
            specialization.receipt_ref =
                normalize_non_empty(std::mem::take(&mut specialization.receipt_ref));
            for proof_id in &mut specialization.proof_input_ids {
                *proof_id = normalize_non_empty(std::mem::take(proof_id));
            }
            specialization.proof_input_ids.sort();
        }

        let mut invalidation_feed = input.invalidation_feed;
        invalidation_feed.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.target_id.cmp(&right.target_id))
                .then(left.invalidation_id.cmp(&right.invalidation_id))
        });
        for invalidation in &mut invalidation_feed {
            invalidation.invalidation_id =
                normalize_non_empty(std::mem::take(&mut invalidation.invalidation_id));
            invalidation.specialization_id =
                normalize_non_empty(std::mem::take(&mut invalidation.specialization_id));
            invalidation.target_id =
                normalize_non_empty(std::mem::take(&mut invalidation.target_id));
            invalidation.reason_detail =
                normalize_non_empty(std::mem::take(&mut invalidation.reason_detail));
            invalidation.proof_id = normalize_optional_non_empty(invalidation.proof_id.take());
            invalidation.fallback_confirmation_ref =
                normalize_non_empty(std::mem::take(&mut invalidation.fallback_confirmation_ref));
        }

        let mut fallback_events = input.fallback_events;
        fallback_events.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.target_id.cmp(&right.target_id))
                .then(left.event_id.cmp(&right.event_id))
        });
        for event in &mut fallback_events {
            event.event_id = normalize_non_empty(std::mem::take(&mut event.event_id));
            event.specialization_id = normalize_optional_non_empty(event.specialization_id.take());
            event.target_id = normalize_non_empty(std::mem::take(&mut event.target_id));
            event.reason_detail = normalize_non_empty(std::mem::take(&mut event.reason_detail));
            event.unspecialized_path_ref =
                normalize_non_empty(std::mem::take(&mut event.unspecialized_path_ref));
            event.compilation_ref = normalize_non_empty(std::mem::take(&mut event.compilation_ref));
        }

        let generated_at_unix_ms = input.generated_at_unix_ms.unwrap_or_default();
        let performance_impact = match input.performance_impact {
            Some(mut provided) => {
                provided.specialization_coverage_millionths =
                    canonicalize_coverage_millionths(provided.specialization_coverage_millionths);
                provided
            }
            None => {
                build_specialization_performance_impact(&active_specializations, &proof_inventory)
            }
        };

        let bulk_invalidation_alert_threshold =
            input.bulk_invalidation_alert_threshold.unwrap_or(10).max(1);
        let degraded_coverage_alert_threshold_millionths = canonicalize_coverage_millionths(
            input
                .degraded_coverage_alert_threshold_millionths
                .unwrap_or(750_000),
        );
        let mut alert_indicators = if input.alert_indicators.is_empty() {
            compute_proof_specialization_alerts(
                &invalidation_feed,
                performance_impact.specialization_coverage_millionths,
                generated_at_unix_ms,
                bulk_invalidation_alert_threshold,
                degraded_coverage_alert_threshold_millionths,
            )
        } else {
            input.alert_indicators
        };
        alert_indicators.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
        for alert in &mut alert_indicators {
            alert.alert_id = normalize_non_empty(std::mem::take(&mut alert.alert_id));
            alert.reason = normalize_non_empty(std::mem::take(&mut alert.reason));
        }

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.unwrap_or_default(),
            generated_at_unix_ms,
            proof_inventory,
            active_specializations,
            invalidation_feed,
            fallback_events,
            performance_impact,
            alert_indicators,
        }
    }

    pub fn filtered(&self, filter: &ProofSpecializationDashboardFilter) -> Self {
        let active_specializations = self
            .active_specializations
            .iter()
            .filter(|row| proof_specialization_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let filtered_specialization_ids = active_specializations
            .iter()
            .map(|row| row.specialization_id.clone())
            .collect::<BTreeSet<_>>();

        let invalidation_feed = self
            .invalidation_feed
            .iter()
            .filter(|row| proof_specialization_invalidation_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let fallback_events = self
            .fallback_events
            .iter()
            .filter(|row| proof_specialization_fallback_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let referenced_proof_ids = active_specializations
            .iter()
            .flat_map(|row| row.proof_input_ids.iter().cloned())
            .chain(
                invalidation_feed
                    .iter()
                    .filter_map(|row| row.proof_id.clone()),
            )
            .collect::<BTreeSet<_>>();

        let proof_inventory = self
            .proof_inventory
            .iter()
            .filter(|proof| {
                filter
                    .proof_id
                    .as_deref()
                    .is_none_or(|proof_id| proof.proof_id.eq_ignore_ascii_case(proof_id))
                    && (referenced_proof_ids.is_empty()
                        || referenced_proof_ids.contains(&proof.proof_id)
                        || proof
                            .enabled_specialization_ids
                            .iter()
                            .any(|id| filtered_specialization_ids.contains(id)))
            })
            .cloned()
            .collect::<Vec<_>>();

        let performance_impact =
            build_specialization_performance_impact(&active_specializations, &proof_inventory);
        let mut alert_indicators = compute_proof_specialization_alerts(
            &invalidation_feed,
            performance_impact.specialization_coverage_millionths,
            self.generated_at_unix_ms,
            10,
            750_000,
        );
        alert_indicators.retain(|alert| {
            self.alert_indicators
                .iter()
                .any(|existing| existing.alert_id == alert.alert_id)
                || alert.alert_id == "bulk-invalidation"
                || alert.alert_id == "specialization-coverage-degraded"
        });

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            proof_inventory,
            active_specializations,
            invalidation_feed,
            fallback_events,
            performance_impact,
            alert_indicators,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProofSpecializationLineagePartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub proof_inventory: Vec<ProofInventoryRowView>,
    #[serde(default)]
    pub active_specializations: Vec<ActiveSpecializationRowView>,
    #[serde(default)]
    pub invalidation_feed: Vec<SpecializationInvalidationRowView>,
    #[serde(default)]
    pub fallback_events: Vec<SpecializationFallbackEventView>,
    pub performance_impact: Option<SpecializationPerformanceImpactView>,
    #[serde(default)]
    pub alert_indicators: Vec<ProofSpecializationAlertView>,
    pub bulk_invalidation_alert_threshold: Option<u64>,
    pub degraded_coverage_alert_threshold_millionths: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProofSpecializationDashboardFilter {
    pub target_id: Option<String>,
    pub proof_id: Option<String>,
    pub optimization_class: Option<String>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
}

pub fn build_native_coverage_meter(
    slot_status_overview: &[SlotStatusOverviewRow],
    trend: Vec<CoverageTrendPoint>,
) -> NativeCoverageMeter {
    let native_slots = slot_status_overview
        .iter()
        .filter(|row| implementation_is_native(&row.implementation_kind))
        .count();
    let delegate_slots = slot_status_overview.len().saturating_sub(native_slots);
    let native_coverage_millionths = if slot_status_overview.is_empty() {
        0
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            ((native_slots as u128 * 1_000_000u128) / slot_status_overview.len() as u128) as u64
        }
    };

    NativeCoverageMeter {
        native_slots,
        delegate_slots,
        native_coverage_millionths,
        trend,
    }
}

pub fn rank_replacement_opportunities(
    inputs: Vec<ReplacementOpportunityInput>,
) -> Vec<ReplacementOpportunityView> {
    let mut ranked = inputs
        .into_iter()
        .map(|input| {
            let expected_value_score_millionths = compute_expected_value_score_millionths(&input);
            ReplacementOpportunityView {
                slot_id: normalize_non_empty(input.slot_id),
                slot_kind: normalize_non_empty(input.slot_kind),
                expected_value_score_millionths,
                performance_uplift_millionths: input.performance_uplift_millionths,
                invocation_frequency_per_minute: input.invocation_frequency_per_minute,
                risk_reduction_millionths: input.risk_reduction_millionths,
                rationale: format!(
                    "perf_uplift={} freq_per_min={} risk_reduction={}",
                    input.performance_uplift_millionths,
                    input.invocation_frequency_per_minute,
                    input.risk_reduction_millionths
                ),
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .expected_value_score_millionths
            .cmp(&left.expected_value_score_millionths)
            .then(left.slot_id.cmp(&right.slot_id))
    });
    ranked
}

pub fn build_specialization_performance_impact(
    active_specializations: &[ActiveSpecializationRowView],
    proof_inventory: &[ProofInventoryRowView],
) -> SpecializationPerformanceImpactView {
    let active_specialization_count = active_specializations.len() as u64;
    let aggregate_latency_reduction_millionths =
        active_specializations.iter().fold(0u64, |sum, row| {
            sum.saturating_add(row.latency_reduction_millionths)
        });
    let aggregate_throughput_increase_millionths =
        active_specializations.iter().fold(0u64, |sum, row| {
            sum.saturating_add(row.throughput_increase_millionths)
        });
    let linked_specialization_total = proof_inventory.iter().fold(0u64, |sum, row| {
        sum.saturating_add(row.linked_specialization_count)
    });
    let specialization_coverage_millionths = if linked_specialization_total == 0 {
        if active_specializations.is_empty() {
            1_000_000
        } else {
            0
        }
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            ((u128::from(active_specialization_count) * 1_000_000u128)
                / u128::from(linked_specialization_total)) as u64
        }
    };

    SpecializationPerformanceImpactView {
        active_specialization_count,
        aggregate_latency_reduction_millionths,
        aggregate_throughput_increase_millionths,
        specialization_coverage_millionths: canonicalize_coverage_millionths(
            specialization_coverage_millionths,
        ),
    }
}

fn compute_proof_specialization_alerts(
    invalidation_feed: &[SpecializationInvalidationRowView],
    specialization_coverage_millionths: u64,
    generated_at_unix_ms: u64,
    bulk_invalidation_alert_threshold: u64,
    degraded_coverage_alert_threshold_millionths: u64,
) -> Vec<ProofSpecializationAlertView> {
    let mut alerts = Vec::new();
    let invalidation_count = invalidation_feed.len() as u64;
    let bulk_threshold = bulk_invalidation_alert_threshold.max(1);
    if invalidation_count >= bulk_threshold {
        alerts.push(ProofSpecializationAlertView {
            alert_id: "bulk-invalidation".to_string(),
            severity: if invalidation_count >= bulk_threshold.saturating_mul(2) {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            },
            reason: format!(
                "invalidations={} exceeds threshold={}",
                invalidation_count, bulk_threshold
            ),
            affected_count: invalidation_count,
            generated_at_unix_ms,
        });
    }

    let degraded_threshold =
        canonicalize_coverage_millionths(degraded_coverage_alert_threshold_millionths);
    if specialization_coverage_millionths < degraded_threshold {
        alerts.push(ProofSpecializationAlertView {
            alert_id: "specialization-coverage-degraded".to_string(),
            severity: if specialization_coverage_millionths < degraded_threshold / 2 {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            },
            reason: format!(
                "specialization_coverage_millionths={} below threshold={}",
                specialization_coverage_millionths, degraded_threshold
            ),
            affected_count: degraded_threshold.saturating_sub(specialization_coverage_millionths),
            generated_at_unix_ms,
        });
    }

    alerts.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
    alerts
}

fn proof_specialization_row_matches_filter(
    row: &ActiveSpecializationRowView,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(target_id) = filter.target_id.as_deref()
        && !row.target_id.eq_ignore_ascii_case(target_id)
    {
        return false;
    }
    if let Some(optimization_class) = filter.optimization_class.as_deref()
        && !row
            .optimization_class
            .eq_ignore_ascii_case(optimization_class)
    {
        return false;
    }
    if let Some(proof_id) = filter.proof_id.as_deref()
        && !row
            .proof_input_ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(proof_id))
    {
        return false;
    }
    proof_specialization_timestamp_matches_range(row.activated_at_unix_ms, filter)
}

fn proof_specialization_invalidation_matches_filter(
    row: &SpecializationInvalidationRowView,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(target_id) = filter.target_id.as_deref()
        && !row.target_id.eq_ignore_ascii_case(target_id)
    {
        return false;
    }
    if let Some(proof_id) = filter.proof_id.as_deref()
        && !row
            .proof_id
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case(proof_id))
    {
        return false;
    }
    proof_specialization_timestamp_matches_range(row.occurred_at_unix_ms, filter)
}

fn proof_specialization_fallback_matches_filter(
    row: &SpecializationFallbackEventView,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(target_id) = filter.target_id.as_deref()
        && !row.target_id.eq_ignore_ascii_case(target_id)
    {
        return false;
    }
    proof_specialization_timestamp_matches_range(row.occurred_at_unix_ms, filter)
}

fn proof_specialization_timestamp_matches_range(
    timestamp_unix_ms: u64,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(start_unix_ms) = filter.start_unix_ms
        && timestamp_unix_ms < start_unix_ms
    {
        return false;
    }
    if let Some(end_unix_ms) = filter.end_unix_ms
        && timestamp_unix_ms > end_unix_ms
    {
        return false;
    }
    true
}

fn compute_flow_alert_indicators(
    blocked_flows: &[BlockedFlowView],
    confinement_proofs: &[ConfinementProofView],
    generated_at_unix_ms: u64,
    blocked_flow_alert_threshold: u64,
) -> Vec<FlowDecisionAlertView> {
    let mut alerts = Vec::new();
    let mut blocked_counts_by_extension = BTreeMap::<String, u64>::new();
    for flow in blocked_flows {
        let entry = blocked_counts_by_extension
            .entry(flow.extension_id.clone())
            .or_default();
        *entry = entry.saturating_add(1);
    }
    for (extension_id, blocked_flow_count) in blocked_counts_by_extension {
        if blocked_flow_count >= blocked_flow_alert_threshold {
            let severity = if blocked_flow_count >= blocked_flow_alert_threshold.saturating_mul(2) {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            };
            alerts.push(FlowDecisionAlertView {
                alert_id: format!("blocked-rate-{extension_id}"),
                extension_id: extension_id.clone(),
                severity,
                reason: format!(
                    "blocked_flow_count={} exceeds threshold={}",
                    blocked_flow_count, blocked_flow_alert_threshold
                ),
                blocked_flow_count,
                generated_at_unix_ms,
            });
        }
    }
    for proof in confinement_proofs {
        if proof.status != ConfinementStatus::Full {
            alerts.push(FlowDecisionAlertView {
                alert_id: format!("confinement-{}", proof.extension_id),
                extension_id: proof.extension_id.clone(),
                severity: if proof.status == ConfinementStatus::Degraded {
                    DashboardSeverity::Critical
                } else {
                    DashboardSeverity::Warning
                },
                reason: format!("confinement_status={:?}", proof.status),
                blocked_flow_count: proof.uncovered_flow_count,
                generated_at_unix_ms,
            });
        }
    }
    alerts.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
    alerts
}

fn blocked_flow_matches_filter(
    flow: &BlockedFlowView,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !flow.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(source_label) = filter.source_label.as_deref()
        && !flow.source_label.eq_ignore_ascii_case(source_label)
    {
        return false;
    }
    if let Some(sink_clearance) = filter.sink_clearance.as_deref()
        && !flow.sink_clearance.eq_ignore_ascii_case(sink_clearance)
    {
        return false;
    }
    if let Some(sensitivity) = filter.sensitivity
        && flow.sensitivity != sensitivity
    {
        return false;
    }
    flow_timestamp_matches_range(flow.occurred_at_unix_ms, filter)
}

fn declassification_matches_filter(
    decision: &DeclassificationDecisionView,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !decision.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(source_label) = filter.source_label.as_deref()
        && !decision.source_label.eq_ignore_ascii_case(source_label)
    {
        return false;
    }
    if let Some(sink_clearance) = filter.sink_clearance.as_deref()
        && !decision.sink_clearance.eq_ignore_ascii_case(sink_clearance)
    {
        return false;
    }
    if let Some(sensitivity) = filter.sensitivity
        && decision.sensitivity != sensitivity
    {
        return false;
    }
    flow_timestamp_matches_range(decision.decided_at_unix_ms, filter)
}

fn confinement_proof_matches_filter(
    proof: &ConfinementProofView,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !proof.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(source_label) = filter.source_label.as_deref()
        && !proof
            .proof_rows
            .iter()
            .any(|row| row.source_label.eq_ignore_ascii_case(source_label))
    {
        return false;
    }
    if let Some(sink_clearance) = filter.sink_clearance.as_deref()
        && !proof
            .proof_rows
            .iter()
            .any(|row| row.sink_clearance.eq_ignore_ascii_case(sink_clearance))
    {
        return false;
    }
    if let Some(sensitivity) = filter.sensitivity
        && sensitivity == FlowSensitivityLevel::Critical
        && proof.status == ConfinementStatus::Full
    {
        return false;
    }
    true
}

fn flow_timestamp_matches_range(
    timestamp_unix_ms: u64,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(start_unix_ms) = filter.start_unix_ms
        && timestamp_unix_ms < start_unix_ms
    {
        return false;
    }
    if let Some(end_unix_ms) = filter.end_unix_ms
        && timestamp_unix_ms > end_unix_ms
    {
        return false;
    }
    true
}

fn summarize_decision_outcomes(entries: &[EvidenceStreamEntryView]) -> DecisionOutcomesPanelView {
    let mut allow_count = 0u64;
    let mut deny_count = 0u64;
    let mut fallback_count = 0u64;
    let mut total_expected_loss = 0i128;

    for entry in entries {
        match entry.decision_outcome {
            DecisionOutcomeKind::Allow => allow_count = allow_count.saturating_add(1),
            DecisionOutcomeKind::Deny => deny_count = deny_count.saturating_add(1),
            DecisionOutcomeKind::Fallback => fallback_count = fallback_count.saturating_add(1),
        }
        total_expected_loss =
            total_expected_loss.saturating_add(i128::from(entry.expected_loss_millionths));
    }

    let average_expected_loss_millionths = if entries.is_empty() {
        0
    } else {
        (total_expected_loss / i128::try_from(entries.len()).unwrap_or(1))
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    };

    DecisionOutcomesPanelView {
        allow_count,
        deny_count,
        fallback_count,
        average_expected_loss_millionths,
    }
}

fn summarize_obligation_status(rows: &[ObligationStatusRowView]) -> ObligationStatusPanelView {
    let mut open_count = 0u64;
    let mut fulfilled_count = 0u64;
    let mut failed_count = 0u64;
    for row in rows {
        match row.state {
            ObligationState::Open => open_count = open_count.saturating_add(1),
            ObligationState::Fulfilled => fulfilled_count = fulfilled_count.saturating_add(1),
            ObligationState::Failed => failed_count = failed_count.saturating_add(1),
        }
    }
    ObligationStatusPanelView {
        open_count,
        fulfilled_count,
        failed_count,
    }
}

fn summarize_region_lifecycle(rows: &[RegionLifecycleRowView]) -> RegionLifecyclePanelView {
    let active_region_count = rows.iter().filter(|row| row.is_active).count() as u64;
    let region_creations_in_window =
        rows.iter().filter(|row| row.created_at_unix_ms > 0).count() as u64;
    let region_destructions_in_window = rows
        .iter()
        .filter(|row| row.closed_at_unix_ms.is_some())
        .count() as u64;
    let close_times = rows
        .iter()
        .filter_map(|row| row.quiescent_close_time_ms)
        .collect::<Vec<_>>();
    let average_quiescent_close_time_ms = if close_times.is_empty() {
        0
    } else {
        close_times.iter().copied().sum::<u64>() / close_times.len() as u64
    };
    RegionLifecyclePanelView {
        active_region_count,
        region_creations_in_window,
        region_destructions_in_window,
        average_quiescent_close_time_ms,
    }
}

fn evidence_entry_matches_filter(
    entry: &EvidenceStreamEntryView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !entry.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !entry.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && entry.severity != severity
    {
        return false;
    }
    timestamp_matches_range(entry.timestamp_unix_ms, filter)
}

fn obligation_row_matches_filter(
    row: &ObligationStatusRowView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !row.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !row.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && row.severity != severity
    {
        return false;
    }
    timestamp_matches_range(row.updated_at_unix_ms, filter)
}

fn region_row_matches_filter(
    row: &RegionLifecycleRowView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(region_id) = filter.region_id.as_deref()
        && !row.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    timestamp_matches_range(row.created_at_unix_ms, filter)
}

fn cancellation_event_matches_filter(
    event: &CancellationEventView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !event.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !event.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && event.severity != severity
    {
        return false;
    }
    timestamp_matches_range(event.timestamp_unix_ms, filter)
}

fn safe_mode_activation_matches_filter(
    activation: &SafeModeActivationView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !activation.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !activation.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && activation.severity != severity
    {
        return false;
    }
    timestamp_matches_range(activation.activated_at_unix_ms, filter)
}

fn timestamp_matches_range(timestamp_unix_ms: u64, filter: &ControlPlaneDashboardFilter) -> bool {
    if let Some(start_unix_ms) = filter.start_unix_ms
        && timestamp_unix_ms < start_unix_ms
    {
        return false;
    }
    if let Some(end_unix_ms) = filter.end_unix_ms
        && timestamp_unix_ms > end_unix_ms
    {
        return false;
    }
    true
}

fn dashboard_metric_value(
    view: &ControlPlaneInvariantsDashboardView,
    metric: DashboardAlertMetric,
) -> i64 {
    match metric {
        DashboardAlertMetric::ObligationFailureRateMillionths => {
            let total = view
                .obligation_status
                .open_count
                .saturating_add(view.obligation_status.fulfilled_count)
                .saturating_add(view.obligation_status.failed_count);
            if total == 0 {
                0
            } else {
                #[allow(clippy::cast_possible_wrap)]
                {
                    ((u128::from(view.obligation_status.failed_count) * 1_000_000u128)
                        / u128::from(total)) as i64
                }
            }
        }
        DashboardAlertMetric::ReplayDivergenceCount => view.replay_health.divergence_count as i64,
        DashboardAlertMetric::SafeModeActivationCount => view.safe_mode_activations.len() as i64,
        DashboardAlertMetric::CancellationEventCount => view.cancellation_events.len() as i64,
        DashboardAlertMetric::FallbackActivationCount => {
            view.decision_outcomes.fallback_count as i64
        }
    }
}

fn threshold_matches(comparator: ThresholdComparator, observed: i64, threshold: i64) -> bool {
    match comparator {
        ThresholdComparator::GreaterThan => observed > threshold,
        ThresholdComparator::GreaterOrEqual => observed >= threshold,
        ThresholdComparator::LessThan => observed < threshold,
        ThresholdComparator::LessOrEqual => observed <= threshold,
        ThresholdComparator::Equal => observed == threshold,
    }
}

fn normalize_non_empty(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        UNKNOWN_LABEL.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_optional_non_empty(value: Option<String>) -> Option<String> {
    value.map(normalize_non_empty)
}

fn canonicalize_coverage_millionths(value: u64) -> u64 {
    value.min(1_000_000)
}

fn slot_row_matches_filter(
    row: &SlotStatusOverviewRow,
    filter: &ReplacementDashboardFilter,
) -> bool {
    if let Some(slot_kind) = filter.slot_kind.as_deref()
        && !row.slot_kind.eq_ignore_ascii_case(slot_kind)
    {
        return false;
    }
    if let Some(risk_level) = filter.risk_level
        && row.risk_level != risk_level
    {
        return false;
    }
    if let Some(promotion_status) = filter.promotion_status.as_deref()
        && !row.promotion_status.eq_ignore_ascii_case(promotion_status)
    {
        return false;
    }
    true
}

fn implementation_is_native(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("native")
}

fn compute_expected_value_score_millionths(input: &ReplacementOpportunityInput) -> i64 {
    let perf_component = i128::from(input.performance_uplift_millionths)
        .saturating_mul(i128::from(input.invocation_frequency_per_minute).saturating_add(1))
        .saturating_div(100);
    let risk_component = i128::from(input.risk_reduction_millionths).saturating_mul(3);
    perf_component
        .saturating_add(risk_component)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
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
    fn control_plane_invariants_dashboard_populates_required_panels() {
        let dashboard =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_000_500),
                evidence_stream: vec![
                    EvidenceStreamEntryView {
                        trace_id: "trace-a".to_string(),
                        decision_id: "decision-a".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "allow".to_string(),
                        decision_outcome: DecisionOutcomeKind::Allow,
                        expected_loss_millionths: 120_000,
                        extension_id: "ext-a".to_string(),
                        region_id: "region-1".to_string(),
                        severity: DashboardSeverity::Info,
                        component: "guardplane".to_string(),
                        event: "decision_evaluated".to_string(),
                        outcome: "allow".to_string(),
                        error_code: None,
                        timestamp_unix_ms: 1_700_000_000_300,
                    },
                    EvidenceStreamEntryView {
                        trace_id: "trace-b".to_string(),
                        decision_id: "decision-b".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "fallback".to_string(),
                        decision_outcome: DecisionOutcomeKind::Fallback,
                        expected_loss_millionths: 300_000,
                        extension_id: "ext-b".to_string(),
                        region_id: "region-2".to_string(),
                        severity: DashboardSeverity::Warning,
                        component: "guardplane".to_string(),
                        event: "safe_mode_activated".to_string(),
                        outcome: "fallback".to_string(),
                        error_code: Some("FE-SAFE-001".to_string()),
                        timestamp_unix_ms: 1_700_000_000_320,
                    },
                ],
                obligation_rows: vec![
                    ObligationStatusRowView {
                        obligation_id: "obl-1".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-1".to_string(),
                        state: ObligationState::Open,
                        severity: DashboardSeverity::Warning,
                        due_at_unix_ms: 1_700_000_001_000,
                        updated_at_unix_ms: 1_700_000_000_330,
                        detail: "awaiting replay verification".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-2".to_string(),
                        extension_id: "ext-b".to_string(),
                        region_id: "region-2".to_string(),
                        state: ObligationState::Failed,
                        severity: DashboardSeverity::Critical,
                        due_at_unix_ms: 1_700_000_001_100,
                        updated_at_unix_ms: 1_700_000_000_340,
                        detail: "checkpoint timeout".to_string(),
                    },
                ],
                region_rows: vec![
                    RegionLifecycleRowView {
                        region_id: "region-1".to_string(),
                        is_active: true,
                        active_extensions: 2,
                        created_at_unix_ms: 1_700_000_000_000,
                        closed_at_unix_ms: None,
                        quiescent_close_time_ms: None,
                    },
                    RegionLifecycleRowView {
                        region_id: "region-2".to_string(),
                        is_active: false,
                        active_extensions: 0,
                        created_at_unix_ms: 1_700_000_000_050,
                        closed_at_unix_ms: Some(1_700_000_000_300),
                        quiescent_close_time_ms: Some(220),
                    },
                ],
                cancellation_events: vec![CancellationEventView {
                    extension_id: "ext-b".to_string(),
                    region_id: "region-2".to_string(),
                    cancellation_kind: CancellationKind::Quarantine,
                    severity: DashboardSeverity::Critical,
                    detail: "forced quarantine".to_string(),
                    timestamp_unix_ms: 1_700_000_000_350,
                }],
                replay_health: Some(ReplayHealthPanelView {
                    last_run_status: ReplayHealthStatus::Pass,
                    divergence_count: 0,
                    last_replay_timestamp_unix_ms: Some(1_700_000_000_360),
                }),
                benchmark_points: vec![BenchmarkTrendPointView {
                    timestamp_unix_ms: 1_700_000_000_200,
                    throughput_tps: 2_100,
                    latency_p95_ms: 93,
                    memory_peak_mb: 640,
                }],
                throughput_floor_tps: Some(2_000),
                latency_p95_ceiling_ms: Some(100),
                memory_peak_ceiling_mb: Some(700),
                safe_mode_activations: vec![SafeModeActivationView {
                    activation_id: "sm-1".to_string(),
                    activation_type: "attestation_stale".to_string(),
                    extension_id: "ext-b".to_string(),
                    region_id: "region-2".to_string(),
                    severity: DashboardSeverity::Warning,
                    recovery_status: RecoveryStatus::Recovering,
                    activated_at_unix_ms: 1_700_000_000_320,
                    recovered_at_unix_ms: None,
                }],
                schema_version: Some(SchemaVersionPanelView {
                    evidence_schema_version: 4,
                    last_migration_unix_ms: Some(1_699_999_999_000),
                    compatibility_status: SchemaCompatibilityStatus::Compatible,
                }),
                refresh_policy: Some(DashboardRefreshPolicy {
                    evidence_stream_refresh_secs: 4,
                    aggregate_refresh_secs: 30,
                }),
                evidence_stream_last_updated_unix_ms: Some(1_700_000_000_498),
                aggregates_last_updated_unix_ms: Some(1_700_000_000_480),
                alert_rules: vec![DashboardAlertRule {
                    rule_id: "alert-obligation-failure".to_string(),
                    description: "obligation failure rate > 0".to_string(),
                    metric: DashboardAlertMetric::ObligationFailureRateMillionths,
                    comparator: ThresholdComparator::GreaterThan,
                    threshold: 0,
                    severity: DashboardSeverity::Critical,
                }],
                ..Default::default()
            });

        assert_eq!(dashboard.decision_outcomes.allow_count, 1);
        assert_eq!(dashboard.decision_outcomes.fallback_count, 1);
        assert_eq!(dashboard.obligation_status.open_count, 1);
        assert_eq!(dashboard.obligation_status.failed_count, 1);
        assert_eq!(dashboard.region_lifecycle.active_region_count, 1);
        assert_eq!(dashboard.cancellation_events.len(), 1);
        assert_eq!(
            dashboard.replay_health.last_run_status,
            ReplayHealthStatus::Pass
        );
        assert_eq!(dashboard.benchmark_trends.points.len(), 1);
        assert_eq!(dashboard.safe_mode_activations.len(), 1);
        assert_eq!(dashboard.schema_version.evidence_schema_version, 4);
        assert!(dashboard.meets_refresh_sla());
        assert_eq!(dashboard.triggered_alerts().len(), 1);
    }

    #[test]
    fn control_plane_invariants_filter_narrows_panels_consistently() {
        let dashboard =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-west-2".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_000_600),
                evidence_stream: vec![
                    EvidenceStreamEntryView {
                        trace_id: "trace-1".to_string(),
                        decision_id: "decision-1".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "deny".to_string(),
                        decision_outcome: DecisionOutcomeKind::Deny,
                        expected_loss_millionths: 500_000,
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        severity: DashboardSeverity::Critical,
                        component: "guardplane".to_string(),
                        event: "blocked".to_string(),
                        outcome: "deny".to_string(),
                        error_code: Some("FE-POL-001".to_string()),
                        timestamp_unix_ms: 1_700_000_000_550,
                    },
                    EvidenceStreamEntryView {
                        trace_id: "trace-2".to_string(),
                        decision_id: "decision-2".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "allow".to_string(),
                        decision_outcome: DecisionOutcomeKind::Allow,
                        expected_loss_millionths: 100_000,
                        extension_id: "ext-b".to_string(),
                        region_id: "region-b".to_string(),
                        severity: DashboardSeverity::Info,
                        component: "guardplane".to_string(),
                        event: "allowed".to_string(),
                        outcome: "allow".to_string(),
                        error_code: None,
                        timestamp_unix_ms: 1_700_000_000_560,
                    },
                ],
                obligation_rows: vec![
                    ObligationStatusRowView {
                        obligation_id: "obl-1".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Failed,
                        severity: DashboardSeverity::Critical,
                        due_at_unix_ms: 1_700_000_000_800,
                        updated_at_unix_ms: 1_700_000_000_555,
                        detail: "failed".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-2".to_string(),
                        extension_id: "ext-b".to_string(),
                        region_id: "region-b".to_string(),
                        state: ObligationState::Fulfilled,
                        severity: DashboardSeverity::Info,
                        due_at_unix_ms: 1_700_000_000_900,
                        updated_at_unix_ms: 1_700_000_000_565,
                        detail: "ok".to_string(),
                    },
                ],
                region_rows: vec![
                    RegionLifecycleRowView {
                        region_id: "region-a".to_string(),
                        is_active: true,
                        active_extensions: 1,
                        created_at_unix_ms: 1_700_000_000_100,
                        closed_at_unix_ms: None,
                        quiescent_close_time_ms: None,
                    },
                    RegionLifecycleRowView {
                        region_id: "region-b".to_string(),
                        is_active: true,
                        active_extensions: 1,
                        created_at_unix_ms: 1_700_000_000_200,
                        closed_at_unix_ms: None,
                        quiescent_close_time_ms: None,
                    },
                ],
                cancellation_events: vec![
                    CancellationEventView {
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        cancellation_kind: CancellationKind::Quarantine,
                        severity: DashboardSeverity::Critical,
                        detail: "quarantine".to_string(),
                        timestamp_unix_ms: 1_700_000_000_556,
                    },
                    CancellationEventView {
                        extension_id: "ext-b".to_string(),
                        region_id: "region-b".to_string(),
                        cancellation_kind: CancellationKind::Unload,
                        severity: DashboardSeverity::Info,
                        detail: "normal unload".to_string(),
                        timestamp_unix_ms: 1_700_000_000_566,
                    },
                ],
                ..Default::default()
            });

        let filtered = dashboard.filtered(&ControlPlaneDashboardFilter {
            extension_id: Some("ext-a".to_string()),
            region_id: Some("region-a".to_string()),
            severity: Some(DashboardSeverity::Critical),
            start_unix_ms: Some(1_700_000_000_540),
            end_unix_ms: Some(1_700_000_000_560),
        });

        assert_eq!(filtered.evidence_stream.len(), 1);
        assert_eq!(filtered.obligation_rows.len(), 1);
        assert_eq!(filtered.cancellation_events.len(), 1);
        assert_eq!(filtered.decision_outcomes.deny_count, 1);
        assert_eq!(filtered.obligation_status.failed_count, 1);
        assert_eq!(filtered.region_rows.len(), 1);
    }

    #[test]
    fn flow_decision_dashboard_builds_alerts_and_filters_views() {
        let dashboard = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
            cluster: "prod".to_string(),
            zone: "us-east-2".to_string(),
            security_epoch: Some(19),
            generated_at_unix_ms: Some(1_700_000_001_000),
            label_map: LabelMapView {
                nodes: vec![
                    LabelMapNodeView {
                        label_id: "pii".to_string(),
                        sensitivity: FlowSensitivityLevel::High,
                        description: "user pii".to_string(),
                        extension_overlays: vec!["ext-a".to_string()],
                    },
                    LabelMapNodeView {
                        label_id: "public".to_string(),
                        sensitivity: FlowSensitivityLevel::Low,
                        description: "public data".to_string(),
                        extension_overlays: vec!["ext-a".to_string(), "ext-b".to_string()],
                    },
                ],
                edges: vec![LabelMapEdgeView {
                    source_label: "pii".to_string(),
                    sink_clearance: "high".to_string(),
                    route_policy_id: Some("policy-flow-1".to_string()),
                    route_enabled: true,
                }],
            },
            blocked_flows: vec![
                BlockedFlowView {
                    flow_id: "flow-1".to_string(),
                    extension_id: "ext-a".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    sensitivity: FlowSensitivityLevel::Critical,
                    blocked_reason: "sink clearance mismatch".to_string(),
                    attempted_exfiltration: true,
                    code_path_ref: "src/ext_a/main.ts:42".to_string(),
                    extension_context_ref: "frankentui://extension/ext-a".to_string(),
                    trace_id: "trace-flow-1".to_string(),
                    decision_id: "decision-flow-1".to_string(),
                    policy_id: "policy-flow-1".to_string(),
                    error_code: Some("FE-IFC-BLOCK".to_string()),
                    occurred_at_unix_ms: 1_700_000_000_900,
                },
                BlockedFlowView {
                    flow_id: "flow-2".to_string(),
                    extension_id: "ext-a".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    sensitivity: FlowSensitivityLevel::Critical,
                    blocked_reason: "sink clearance mismatch".to_string(),
                    attempted_exfiltration: true,
                    code_path_ref: "src/ext_a/main.ts:55".to_string(),
                    extension_context_ref: "frankentui://extension/ext-a".to_string(),
                    trace_id: "trace-flow-2".to_string(),
                    decision_id: "decision-flow-2".to_string(),
                    policy_id: "policy-flow-1".to_string(),
                    error_code: Some("FE-IFC-BLOCK".to_string()),
                    occurred_at_unix_ms: 1_700_000_000_910,
                },
            ],
            declassification_history: vec![DeclassificationDecisionView {
                decision_id: "decl-1".to_string(),
                extension_id: "ext-a".to_string(),
                source_label: "pii".to_string(),
                sink_clearance: "external".to_string(),
                sensitivity: FlowSensitivityLevel::Critical,
                outcome: DeclassificationOutcome::Denied,
                policy_id: "policy-flow-1".to_string(),
                loss_assessment_summary: "expected loss too high".to_string(),
                rationale: "deny exfiltration route".to_string(),
                receipt_ref: "frankentui://declassification/decl-1".to_string(),
                replay_ref: "frankentui://replay/decl-1".to_string(),
                decided_at_unix_ms: 1_700_000_000_920,
            }],
            confinement_proofs: vec![ConfinementProofView {
                extension_id: "ext-a".to_string(),
                status: ConfinementStatus::Degraded,
                covered_flow_count: 10,
                uncovered_flow_count: 2,
                proof_rows: vec![FlowProofCoverageView {
                    proof_id: "proof-1".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    covered: false,
                    proof_ref: "frankentui://proof/proof-1".to_string(),
                }],
                uncovered_flow_refs: vec!["frankentui://flow/flow-1".to_string()],
            }],
            blocked_flow_alert_threshold: Some(2),
            ..Default::default()
        });

        assert_eq!(dashboard.alert_indicators.len(), 2);
        assert_eq!(dashboard.blocked_flows.len(), 2);
        assert_eq!(dashboard.declassification_history.len(), 1);
        assert_eq!(dashboard.confinement_proofs.len(), 1);

        let filtered = dashboard.filtered(&FlowDecisionDashboardFilter {
            extension_id: Some("ext-a".to_string()),
            source_label: Some("pii".to_string()),
            sink_clearance: Some("external".to_string()),
            sensitivity: Some(FlowSensitivityLevel::Critical),
            start_unix_ms: Some(1_700_000_000_905),
            end_unix_ms: Some(1_700_000_001_000),
        });

        assert_eq!(filtered.blocked_flows.len(), 1);
        assert_eq!(filtered.declassification_history.len(), 1);
        assert_eq!(filtered.confinement_proofs.len(), 1);
        assert_eq!(filtered.alert_indicators.len(), 2);
        assert_eq!(filtered.label_map.nodes.len(), 1);
    }

    #[test]
    fn proof_specialization_lineage_dashboard_builds_aggregates_and_filters() {
        let dashboard = ProofSpecializationLineageDashboardView::from_partial(
            ProofSpecializationLineagePartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                security_epoch: Some(31),
                generated_at_unix_ms: Some(1_700_000_002_000),
                proof_inventory: vec![
                    ProofInventoryRowView {
                        proof_id: " proof-cap-1 ".to_string(),
                        proof_kind: ProofInventoryKind::CapabilityWitness,
                        validity_status: ProofValidityStatus::Valid,
                        epoch_id: 31,
                        linked_specialization_count: 2,
                        enabled_specialization_ids: vec![
                            " spec-b ".to_string(),
                            "spec-a".to_string(),
                        ],
                        proof_ref: " frankentui://proof/proof-cap-1 ".to_string(),
                    },
                    ProofInventoryRowView {
                        proof_id: "proof-flow-2".to_string(),
                        proof_kind: ProofInventoryKind::FlowProof,
                        validity_status: ProofValidityStatus::ExpiringSoon,
                        epoch_id: 31,
                        linked_specialization_count: 2,
                        enabled_specialization_ids: vec![
                            "spec-c".to_string(),
                            "spec-b".to_string(),
                        ],
                        proof_ref: "frankentui://proof/proof-flow-2".to_string(),
                    },
                ],
                active_specializations: vec![
                    ActiveSpecializationRowView {
                        specialization_id: "spec-b".to_string(),
                        target_id: "ext-b".to_string(),
                        target_kind: "extension".to_string(),
                        optimization_class: "hostcall_dispatch_specialization".to_string(),
                        latency_reduction_millionths: 120_000,
                        throughput_increase_millionths: 200_000,
                        proof_input_ids: vec![
                            "proof-cap-1".to_string(),
                            "proof-flow-2".to_string(),
                        ],
                        transformation_ref: "frankentui://transform/spec-b".to_string(),
                        receipt_ref: "frankentui://receipt/spec-b".to_string(),
                        activated_at_unix_ms: 1_700_000_001_950,
                    },
                    ActiveSpecializationRowView {
                        specialization_id: "spec-a".to_string(),
                        target_id: "ext-a".to_string(),
                        target_kind: "extension".to_string(),
                        optimization_class: "ifc_check_elision".to_string(),
                        latency_reduction_millionths: 350_000,
                        throughput_increase_millionths: 480_000,
                        proof_input_ids: vec!["proof-cap-1".to_string()],
                        transformation_ref: "frankentui://transform/spec-a".to_string(),
                        receipt_ref: "frankentui://receipt/spec-a".to_string(),
                        activated_at_unix_ms: 1_700_000_001_940,
                    },
                ],
                invalidation_feed: vec![
                    SpecializationInvalidationRowView {
                        invalidation_id: "inv-1".to_string(),
                        specialization_id: "spec-a".to_string(),
                        target_id: "ext-a".to_string(),
                        reason: ProofSpecializationInvalidationReason::EpochChange,
                        reason_detail: "epoch advanced".to_string(),
                        proof_id: Some("proof-cap-1".to_string()),
                        old_epoch_id: Some(30),
                        new_epoch_id: Some(31),
                        fallback_confirmed: true,
                        fallback_confirmation_ref: "frankentui://fallback/spec-a".to_string(),
                        occurred_at_unix_ms: 1_700_000_001_960,
                    },
                    SpecializationInvalidationRowView {
                        invalidation_id: "inv-2".to_string(),
                        specialization_id: "spec-b".to_string(),
                        target_id: "ext-b".to_string(),
                        reason: ProofSpecializationInvalidationReason::ProofRevoked,
                        reason_detail: "revocation head advanced".to_string(),
                        proof_id: Some("proof-flow-2".to_string()),
                        old_epoch_id: None,
                        new_epoch_id: None,
                        fallback_confirmed: true,
                        fallback_confirmation_ref: "frankentui://fallback/spec-b".to_string(),
                        occurred_at_unix_ms: 1_700_000_001_970,
                    },
                ],
                fallback_events: vec![SpecializationFallbackEventView {
                    event_id: "fb-1".to_string(),
                    specialization_id: Some("spec-a".to_string()),
                    target_id: "ext-a".to_string(),
                    reason: SpecializationFallbackReason::ValidationFailed,
                    reason_detail: "equivalence proof failed".to_string(),
                    unspecialized_path_ref: "frankentui://path/ext-a/unspecialized".to_string(),
                    compilation_ref: "frankentui://compile/ext-a/42".to_string(),
                    occurred_at_unix_ms: 1_700_000_001_980,
                }],
                bulk_invalidation_alert_threshold: Some(2),
                degraded_coverage_alert_threshold_millionths: Some(900_000),
                ..Default::default()
            },
        );

        assert_eq!(dashboard.performance_impact.active_specialization_count, 2);
        assert_eq!(
            dashboard
                .performance_impact
                .aggregate_latency_reduction_millionths,
            470_000
        );
        assert_eq!(
            dashboard
                .performance_impact
                .aggregate_throughput_increase_millionths,
            680_000
        );
        assert_eq!(
            dashboard
                .performance_impact
                .specialization_coverage_millionths,
            500_000
        );
        assert_eq!(dashboard.alert_indicators.len(), 2);
        assert_eq!(dashboard.proof_inventory[0].proof_id, "proof-cap-1");
        assert_eq!(
            dashboard.proof_inventory[0].enabled_specialization_ids,
            vec!["spec-a".to_string(), "spec-b".to_string()]
        );

        let filtered = dashboard.filtered(&ProofSpecializationDashboardFilter {
            target_id: Some("ext-a".to_string()),
            proof_id: Some("proof-cap-1".to_string()),
            optimization_class: Some("ifc_check_elision".to_string()),
            start_unix_ms: Some(1_700_000_001_930),
            end_unix_ms: Some(1_700_000_002_000),
        });

        assert_eq!(filtered.active_specializations.len(), 1);
        assert_eq!(
            filtered.active_specializations[0].specialization_id,
            "spec-a"
        );
        assert_eq!(filtered.invalidation_feed.len(), 1);
        assert_eq!(filtered.fallback_events.len(), 1);
        assert_eq!(filtered.proof_inventory.len(), 1);
        assert_eq!(filtered.performance_impact.active_specialization_count, 1);
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

    #[test]
    fn replacement_progress_partial_ranks_opportunities_and_builds_coverage() {
        let view = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: Some(14),
            generated_at_unix_ms: Some(1_700_000_000_300),
            slot_status_overview: vec![
                SlotStatusOverviewRow {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    implementation_kind: "delegate".to_string(),
                    promotion_status: "promotion_candidate".to_string(),
                    risk_level: ReplacementRiskLevel::Medium,
                    last_transition_unix_ms: 1_700_000_000_100,
                    health: "attention".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                },
                SlotStatusOverviewRow {
                    slot_id: "module-loader".to_string(),
                    slot_kind: "module_loader".to_string(),
                    implementation_kind: "native".to_string(),
                    promotion_status: "promoted".to_string(),
                    risk_level: ReplacementRiskLevel::Low,
                    last_transition_unix_ms: 1_700_000_000_080,
                    health: "healthy".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/module-loader".to_string(),
                },
            ],
            replacement_inputs: vec![
                ReplacementOpportunityInput {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    performance_uplift_millionths: 420_000,
                    invocation_frequency_per_minute: 190,
                    risk_reduction_millionths: 300_000,
                },
                ReplacementOpportunityInput {
                    slot_id: "async-runtime".to_string(),
                    slot_kind: "async_runtime".to_string(),
                    performance_uplift_millionths: 900_000,
                    invocation_frequency_per_minute: 10,
                    risk_reduction_millionths: 120_000,
                },
            ],
            ..Default::default()
        });

        assert_eq!(view.native_coverage.native_slots, 1);
        assert_eq!(view.native_coverage.delegate_slots, 1);
        assert_eq!(view.native_coverage.native_coverage_millionths, 500_000);
        assert_eq!(view.next_best_replacements.len(), 2);
        assert_eq!(view.next_best_replacements[0].slot_id, "parser");
        assert_eq!(view.next_best_replacements[1].slot_id, "async-runtime");
    }

    #[test]
    fn replacement_progress_filter_keeps_associated_panels_in_sync() {
        let view = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
            cluster: "prod".to_string(),
            zone: "us-west-2".to_string(),
            slot_status_overview: vec![
                SlotStatusOverviewRow {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    implementation_kind: "delegate".to_string(),
                    promotion_status: "promotion_candidate".to_string(),
                    risk_level: ReplacementRiskLevel::High,
                    last_transition_unix_ms: 10,
                    health: "blocked".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                },
                SlotStatusOverviewRow {
                    slot_id: "gc".to_string(),
                    slot_kind: "garbage_collector".to_string(),
                    implementation_kind: "native".to_string(),
                    promotion_status: "promoted".to_string(),
                    risk_level: ReplacementRiskLevel::Low,
                    last_transition_unix_ms: 11,
                    health: "healthy".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
                },
            ],
            blocked_promotions: vec![
                BlockedPromotionView {
                    slot_id: "parser".to_string(),
                    gate_failure_code: "FE-GATE-001".to_string(),
                    failure_detail: "differential mismatch".to_string(),
                    recommended_remediation: "rerun divergence minimizer".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                    evidence_ref: "frankentui://evidence/parser".to_string(),
                },
                BlockedPromotionView {
                    slot_id: "gc".to_string(),
                    gate_failure_code: "FE-GATE-002".to_string(),
                    failure_detail: "none".to_string(),
                    recommended_remediation: "n/a".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
                    evidence_ref: "frankentui://evidence/gc".to_string(),
                },
            ],
            rollback_events: vec![
                RollbackEventView {
                    slot_id: "parser".to_string(),
                    receipt_id: "rcpt-parser".to_string(),
                    reason: "canary regression".to_string(),
                    status: RollbackStatus::Investigating,
                    occurred_at_unix_ms: 99,
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                    evidence_ref: "frankentui://evidence/parser".to_string(),
                },
                RollbackEventView {
                    slot_id: "gc".to_string(),
                    receipt_id: "rcpt-gc".to_string(),
                    reason: "none".to_string(),
                    status: RollbackStatus::Resolved,
                    occurred_at_unix_ms: 100,
                    lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
                    evidence_ref: "frankentui://evidence/gc".to_string(),
                },
            ],
            next_best_replacements: vec![
                ReplacementOpportunityView {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    expected_value_score_millionths: 10,
                    performance_uplift_millionths: 1,
                    invocation_frequency_per_minute: 1,
                    risk_reduction_millionths: 1,
                    rationale: "parser".to_string(),
                },
                ReplacementOpportunityView {
                    slot_id: "gc".to_string(),
                    slot_kind: "garbage_collector".to_string(),
                    expected_value_score_millionths: 9,
                    performance_uplift_millionths: 1,
                    invocation_frequency_per_minute: 1,
                    risk_reduction_millionths: 1,
                    rationale: "gc".to_string(),
                },
            ],
            ..Default::default()
        });

        let filtered = view.filtered(&ReplacementDashboardFilter {
            slot_kind: Some("parser".to_string()),
            risk_level: Some(ReplacementRiskLevel::High),
            promotion_status: Some("promotion_candidate".to_string()),
        });

        assert_eq!(filtered.slot_status_overview.len(), 1);
        assert_eq!(filtered.slot_status_overview[0].slot_id, "parser");
        assert_eq!(filtered.blocked_promotions.len(), 1);
        assert_eq!(filtered.rollback_events.len(), 1);
        assert_eq!(filtered.next_best_replacements.len(), 1);
        assert_eq!(filtered.native_coverage.native_slots, 0);
        assert_eq!(filtered.native_coverage.delegate_slots, 1);
    }
}
