//! Deterministic Replay, Failover, and Incident Artifact Pipeline (FRX-04.4)
//!
//! Captures minimal nondeterminism traces, replays compile/runtime decisions
//! bit-stably, provides deterministic failover to fallback paths, and generates
//! postmortem-ready incident artifact bundles.

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn replay_schema() -> SchemaId {
    SchemaId::from_definition(b"deterministic_replay-v1")
}

/// Fixed-point multiplier: 1_000_000 ≡ 1.0.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Nondeterminism trace
// ---------------------------------------------------------------------------

/// Source of nondeterminism that must be captured for replay.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NondeterminismSource {
    /// Random value used for lane selection.
    LaneSelectionRandom,
    /// Timer/clock reading.
    TimerRead,
    /// External API response.
    ExternalApiResponse,
    /// Thread scheduling decision.
    ThreadSchedule,
    /// Resource availability check.
    ResourceCheck,
    /// User interaction timing.
    UserInteractionTiming,
}

impl NondeterminismSource {
    pub const ALL: [NondeterminismSource; 6] = [
        NondeterminismSource::LaneSelectionRandom,
        NondeterminismSource::TimerRead,
        NondeterminismSource::ExternalApiResponse,
        NondeterminismSource::ThreadSchedule,
        NondeterminismSource::ResourceCheck,
        NondeterminismSource::UserInteractionTiming,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LaneSelectionRandom => "lane_selection_random",
            Self::TimerRead => "timer_read",
            Self::ExternalApiResponse => "external_api_response",
            Self::ThreadSchedule => "thread_schedule",
            Self::ResourceCheck => "resource_check",
            Self::UserInteractionTiming => "user_interaction_timing",
        }
    }
}

/// A single captured nondeterminism event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub sequence: u64,
    pub source: NondeterminismSource,
    /// The captured deterministic value (opaque bytes).
    pub value: Vec<u8>,
    /// Virtual timestamp (monotonic counter, not wall clock).
    pub virtual_ts: u64,
    /// Component that produced this event.
    pub component: String,
}

impl TraceEvent {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "trace-{}-{}-{}",
            self.sequence,
            self.source.as_str(),
            self.virtual_ts
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for trace event")
    }
}

/// Nondeterminism trace: a complete record of all nondeterministic decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NondeterminismTrace {
    pub session_id: String,
    pub events: Vec<TraceEvent>,
    pub next_sequence: u64,
    pub capture_started_vts: u64,
    pub capture_ended_vts: Option<u64>,
}

impl NondeterminismTrace {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            events: Vec::new(),
            next_sequence: 0,
            capture_started_vts: 0,
            capture_ended_vts: None,
        }
    }

    /// Record a nondeterminism event.
    pub fn capture(
        &mut self,
        source: NondeterminismSource,
        value: Vec<u8>,
        virtual_ts: u64,
        component: impl Into<String>,
    ) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.events.push(TraceEvent {
            sequence: seq,
            source,
            value,
            virtual_ts,
            component: component.into(),
        });
        seq
    }

    /// Finalise the trace.
    pub fn finalise(&mut self, end_vts: u64) {
        self.capture_ended_vts = Some(end_vts);
    }

    /// Total events captured.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Whether the trace is finalised.
    pub fn is_finalised(&self) -> bool {
        self.capture_ended_vts.is_some()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("trace-{}-events-{}", self.session_id, self.events.len());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for trace")
    }
}

// ---------------------------------------------------------------------------
// Replay engine
// ---------------------------------------------------------------------------

/// Replay mode: how strictly to follow the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplayMode {
    /// Exact bit-stable replay: divergence is an error.
    Strict,
    /// Best-effort replay: log divergences but continue.
    BestEffort,
    /// Validation mode: compare live decisions against trace.
    Validate,
}

/// A divergence detected during replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDivergence {
    pub sequence: u64,
    pub source: NondeterminismSource,
    pub expected_value: Vec<u8>,
    pub actual_value: Vec<u8>,
    pub virtual_ts: u64,
    pub severity: DivergenceSeverity,
}

/// How severe a replay divergence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceSeverity {
    /// Benign: does not affect correctness (e.g. timing jitter).
    Benign,
    /// Warning: may affect behaviour but not safety.
    Warning,
    /// Critical: affects correctness or safety.
    Critical,
}

/// Replay engine state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEngine {
    pub mode: ReplayMode,
    pub trace: NondeterminismTrace,
    pub cursor: usize,
    pub divergences: Vec<ReplayDivergence>,
    pub replayed_events: u64,
    pub virtual_ts: u64,
}

/// Errors from replay operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayError {
    /// Trace exhausted: no more events to replay.
    TraceExhausted { cursor: usize, total: usize },
    /// Critical divergence in strict mode.
    CriticalDivergence {
        sequence: u64,
        source: NondeterminismSource,
    },
    /// Source mismatch: expected one source, got another.
    SourceMismatch {
        sequence: u64,
        expected: NondeterminismSource,
        actual: NondeterminismSource,
    },
    /// Trace not finalised.
    TraceNotFinalised,
}

impl ReplayEngine {
    /// Create a replay engine from a captured trace.
    pub fn new(trace: NondeterminismTrace, mode: ReplayMode) -> Self {
        Self {
            mode,
            trace,
            cursor: 0,
            divergences: Vec::new(),
            replayed_events: 0,
            virtual_ts: 0,
        }
    }

    /// Replay the next event, providing the live value for comparison.
    pub fn replay_next(
        &mut self,
        source: NondeterminismSource,
        live_value: &[u8],
    ) -> Result<Vec<u8>, ReplayError> {
        if self.cursor >= self.trace.events.len() {
            return Err(ReplayError::TraceExhausted {
                cursor: self.cursor,
                total: self.trace.events.len(),
            });
        }

        let event = &self.trace.events[self.cursor];

        // Check source matches
        if event.source != source {
            return Err(ReplayError::SourceMismatch {
                sequence: event.sequence,
                expected: event.source.clone(),
                actual: source,
            });
        }

        // Compare values
        let traced_value = event.value.clone();
        if live_value != traced_value.as_slice() {
            let severity = classify_divergence(&source, &traced_value, live_value);
            let divergence = ReplayDivergence {
                sequence: event.sequence,
                source: source.clone(),
                expected_value: traced_value.clone(),
                actual_value: live_value.to_vec(),
                virtual_ts: event.virtual_ts,
                severity,
            };

            match self.mode {
                ReplayMode::Strict => {
                    if severity == DivergenceSeverity::Critical {
                        self.divergences.push(divergence);
                        return Err(ReplayError::CriticalDivergence {
                            sequence: event.sequence,
                            source,
                        });
                    }
                    self.divergences.push(divergence);
                }
                ReplayMode::BestEffort | ReplayMode::Validate => {
                    self.divergences.push(divergence);
                }
            }
        }

        self.virtual_ts = event.virtual_ts;
        self.cursor += 1;
        self.replayed_events += 1;

        // In replay mode, return the traced value (not live) for determinism
        match self.mode {
            ReplayMode::Strict | ReplayMode::BestEffort => Ok(traced_value),
            ReplayMode::Validate => Ok(live_value.to_vec()),
        }
    }

    /// Whether all trace events have been replayed.
    pub fn is_complete(&self) -> bool {
        self.cursor >= self.trace.events.len()
    }

    /// Remaining events to replay.
    pub fn remaining(&self) -> usize {
        self.trace.events.len().saturating_sub(self.cursor)
    }

    /// Total divergences detected.
    pub fn divergence_count(&self) -> usize {
        self.divergences.len()
    }

    /// Critical divergence count.
    pub fn critical_divergences(&self) -> usize {
        self.divergences
            .iter()
            .filter(|d| d.severity == DivergenceSeverity::Critical)
            .count()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("replay-{}-cursor-{}", self.trace.session_id, self.cursor);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for replay engine")
    }
}

/// Classify divergence severity based on source type and value difference.
fn classify_divergence(
    source: &NondeterminismSource,
    _expected: &[u8],
    _actual: &[u8],
) -> DivergenceSeverity {
    match source {
        NondeterminismSource::TimerRead | NondeterminismSource::UserInteractionTiming => {
            DivergenceSeverity::Benign
        }
        NondeterminismSource::ThreadSchedule => DivergenceSeverity::Warning,
        NondeterminismSource::LaneSelectionRandom
        | NondeterminismSource::ExternalApiResponse
        | NondeterminismSource::ResourceCheck => DivergenceSeverity::Critical,
    }
}

// ---------------------------------------------------------------------------
// Failover controller
// ---------------------------------------------------------------------------

/// Failover strategy when the primary execution path fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailoverStrategy {
    /// Switch to the baseline-safe lane immediately.
    ImmediateBaseline,
    /// Retry on the same lane once before failing over.
    RetryThenBaseline,
    /// Halt execution and report the failure.
    Halt,
}

/// Reason for failover.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FailoverReason {
    /// Lane exceeded its resource budget.
    BudgetExhausted {
        metric: String,
        value: u64,
        limit: u64,
    },
    /// Lane returned an error.
    LaneError { message: String },
    /// Lane entered safe mode.
    SafeModeTriggered,
    /// Timeout exceeded.
    Timeout { elapsed_us: u64, limit_us: u64 },
    /// Replay divergence during execution.
    ReplayDivergence { divergence_count: usize },
    /// Operator-initiated failover.
    Manual,
}

/// Record of a failover event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverRecord {
    pub sequence: u64,
    pub reason: FailoverReason,
    pub strategy: FailoverStrategy,
    pub from_component: String,
    pub to_component: String,
    pub virtual_ts: u64,
    pub success: bool,
}

impl FailoverRecord {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "failover-{}-{}-{}",
            self.sequence, self.from_component, self.virtual_ts
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for failover record")
    }
}

/// Failover controller: manages deterministic failover decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverController {
    pub default_strategy: FailoverStrategy,
    /// Per-component strategy overrides.
    pub strategy_overrides: BTreeMap<String, FailoverStrategy>,
    pub records: Vec<FailoverRecord>,
    pub next_sequence: u64,
    pub total_failovers: u64,
    pub successful_failovers: u64,
    /// Maximum failovers before halting.
    pub max_failovers: u64,
    pub halted: bool,
}

impl FailoverController {
    pub fn new(default_strategy: FailoverStrategy, max_failovers: u64) -> Self {
        Self {
            default_strategy,
            strategy_overrides: BTreeMap::new(),
            records: Vec::new(),
            next_sequence: 0,
            total_failovers: 0,
            successful_failovers: 0,
            max_failovers,
            halted: false,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(FailoverStrategy::RetryThenBaseline, 10)
    }

    /// Set a strategy override for a specific component.
    pub fn set_override(&mut self, component: impl Into<String>, strategy: FailoverStrategy) {
        self.strategy_overrides.insert(component.into(), strategy);
    }

    /// Get the failover strategy for a component.
    pub fn strategy_for(&self, component: &str) -> FailoverStrategy {
        self.strategy_overrides
            .get(component)
            .copied()
            .unwrap_or(self.default_strategy)
    }

    /// Record a failover event.
    pub fn record_failover(
        &mut self,
        reason: FailoverReason,
        from_component: impl Into<String>,
        to_component: impl Into<String>,
        virtual_ts: u64,
        success: bool,
    ) -> Result<FailoverRecord, FailoverError> {
        if self.halted {
            return Err(FailoverError::Halted);
        }
        if self.total_failovers >= self.max_failovers {
            self.halted = true;
            return Err(FailoverError::MaxFailoversExceeded {
                count: self.total_failovers,
                limit: self.max_failovers,
            });
        }

        let from = from_component.into();
        let strategy = self.strategy_for(&from);

        let record = FailoverRecord {
            sequence: self.next_sequence,
            reason,
            strategy,
            from_component: from,
            to_component: to_component.into(),
            virtual_ts,
            success,
        };

        self.next_sequence += 1;
        self.total_failovers += 1;
        if success {
            self.successful_failovers += 1;
        }
        self.records.push(record.clone());

        Ok(record)
    }

    /// Success rate in millionths.
    pub fn success_rate_millionths(&self) -> i64 {
        if self.total_failovers == 0 {
            return MILLION;
        }
        (self.successful_failovers as i64 * MILLION) / self.total_failovers as i64
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("failover-ctrl-seq-{}", self.next_sequence);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for failover controller")
    }
}

/// Errors from failover operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverError {
    /// Controller is halted due to too many failovers.
    Halted,
    /// Maximum failover count exceeded.
    MaxFailoversExceeded { count: u64, limit: u64 },
}

// ---------------------------------------------------------------------------
// Incident artifact bundle
// ---------------------------------------------------------------------------

/// Severity of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IncidentSeverity {
    /// Informational: no user impact.
    Info,
    /// Warning: degraded but functional.
    Warning,
    /// Error: user-visible impact.
    Error,
    /// Critical: requires immediate attention.
    Critical,
}

impl IncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// An artifact included in an incident bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentArtifact {
    pub name: String,
    pub kind: ArtifactKind,
    pub data: Vec<u8>,
    pub content_hash: String,
}

/// Kind of artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// Nondeterminism trace for replay.
    NondeterminismTrace,
    /// Decision log from the router.
    DecisionLog,
    /// Failover records.
    FailoverLog,
    /// Signal graph snapshot.
    SignalGraphSnapshot,
    /// DOM state snapshot.
    DomSnapshot,
    /// Performance metrics.
    PerformanceMetrics,
    /// Configuration at time of incident.
    Configuration,
    /// Replay divergence report.
    DivergenceReport,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NondeterminismTrace => "nondeterminism_trace",
            Self::DecisionLog => "decision_log",
            Self::FailoverLog => "failover_log",
            Self::SignalGraphSnapshot => "signal_graph_snapshot",
            Self::DomSnapshot => "dom_snapshot",
            Self::PerformanceMetrics => "performance_metrics",
            Self::Configuration => "configuration",
            Self::DivergenceReport => "divergence_report",
        }
    }
}

impl IncidentArtifact {
    pub fn new(name: impl Into<String>, kind: ArtifactKind, data: Vec<u8>) -> Self {
        let hash = compute_simple_hash(&data);
        Self {
            name: name.into(),
            kind,
            data,
            content_hash: hash,
        }
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("artifact-{}-{}", self.name, self.content_hash);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for artifact")
    }
}

/// Incident artifact bundle: everything needed for postmortem analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentBundle {
    pub incident_id: String,
    pub severity: IncidentSeverity,
    pub summary: String,
    pub trigger_component: String,
    pub virtual_ts: u64,
    pub artifacts: Vec<IncidentArtifact>,
    pub tags: Vec<String>,
    pub bundle_hash: String,
}

impl IncidentBundle {
    pub fn new(
        incident_id: impl Into<String>,
        severity: IncidentSeverity,
        summary: impl Into<String>,
        trigger_component: impl Into<String>,
        virtual_ts: u64,
    ) -> Self {
        Self {
            incident_id: incident_id.into(),
            severity,
            summary: summary.into(),
            trigger_component: trigger_component.into(),
            virtual_ts,
            artifacts: Vec::new(),
            tags: Vec::new(),
            bundle_hash: String::new(),
        }
    }

    /// Add an artifact to the bundle.
    pub fn add_artifact(&mut self, artifact: IncidentArtifact) {
        self.artifacts.push(artifact);
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    /// Finalise the bundle by computing its hash.
    pub fn finalise(&mut self) {
        let mut content = Vec::new();
        content.extend_from_slice(self.incident_id.as_bytes());
        content.extend_from_slice(self.severity.as_str().as_bytes());
        for artifact in &self.artifacts {
            content.extend_from_slice(artifact.content_hash.as_bytes());
        }
        self.bundle_hash = compute_simple_hash(&content);
    }

    /// Whether the bundle has been finalised.
    pub fn is_finalised(&self) -> bool {
        !self.bundle_hash.is_empty()
    }

    /// Artifact count.
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Total data size across all artifacts.
    pub fn total_data_size(&self) -> usize {
        self.artifacts.iter().map(|a| a.data.len()).sum()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("bundle-{}-{}", self.incident_id, self.severity.as_str());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "replay",
            &replay_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for bundle")
    }
}

// ---------------------------------------------------------------------------
// Incident bundle builder (convenience)
// ---------------------------------------------------------------------------

/// Builder for constructing incident bundles from replay/failover state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentBundleBuilder {
    incident_id: String,
    severity: IncidentSeverity,
    summary: String,
    trigger_component: String,
    virtual_ts: u64,
    include_trace: bool,
    include_decisions: bool,
    include_failovers: bool,
    include_divergences: bool,
}

impl IncidentBundleBuilder {
    pub fn new(
        incident_id: impl Into<String>,
        severity: IncidentSeverity,
        summary: impl Into<String>,
        trigger_component: impl Into<String>,
        virtual_ts: u64,
    ) -> Self {
        Self {
            incident_id: incident_id.into(),
            severity,
            summary: summary.into(),
            trigger_component: trigger_component.into(),
            virtual_ts,
            include_trace: true,
            include_decisions: true,
            include_failovers: true,
            include_divergences: true,
        }
    }

    pub fn with_trace(mut self, include: bool) -> Self {
        self.include_trace = include;
        self
    }

    pub fn with_decisions(mut self, include: bool) -> Self {
        self.include_decisions = include;
        self
    }

    pub fn with_failovers(mut self, include: bool) -> Self {
        self.include_failovers = include;
        self
    }

    pub fn with_divergences(mut self, include: bool) -> Self {
        self.include_divergences = include;
        self
    }

    /// Build the bundle from replay engine and failover controller state.
    pub fn build(
        &self,
        trace: Option<&NondeterminismTrace>,
        replay: Option<&ReplayEngine>,
        failover: Option<&FailoverController>,
    ) -> IncidentBundle {
        let mut bundle = IncidentBundle::new(
            &self.incident_id,
            self.severity,
            &self.summary,
            &self.trigger_component,
            self.virtual_ts,
        );

        if self.include_trace
            && let Some(t) = trace
        {
            let data = serde_json::to_vec(t).unwrap_or_default();
            bundle.add_artifact(IncidentArtifact::new(
                "nondeterminism_trace",
                ArtifactKind::NondeterminismTrace,
                data,
            ));
        }

        if self.include_failovers
            && let Some(fc) = failover
        {
            let data = serde_json::to_vec(&fc.records).unwrap_or_default();
            bundle.add_artifact(IncidentArtifact::new(
                "failover_log",
                ArtifactKind::FailoverLog,
                data,
            ));
        }

        if self.include_divergences
            && let Some(re) = replay
            && !re.divergences.is_empty()
        {
            let data = serde_json::to_vec(&re.divergences).unwrap_or_default();
            bundle.add_artifact(IncidentArtifact::new(
                "divergence_report",
                ArtifactKind::DivergenceReport,
                data,
            ));
        }

        bundle.add_tag("auto-generated");
        bundle.add_tag(self.severity.as_str());
        bundle.finalise();
        bundle
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Simple deterministic hash (FNV-1a) for content hashing.
fn compute_simple_hash(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- NondeterminismSource --

    #[test]
    fn source_as_str_all_variants() {
        for source in &NondeterminismSource::ALL {
            let s = source.as_str();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn source_serde_roundtrip() {
        for source in &NondeterminismSource::ALL {
            let json = serde_json::to_string(source).unwrap();
            let back: NondeterminismSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*source, back);
        }
    }

    // -- NondeterminismTrace --

    #[test]
    fn trace_new_empty() {
        let trace = NondeterminismTrace::new("session-1");
        assert_eq!(trace.event_count(), 0);
        assert!(!trace.is_finalised());
    }

    #[test]
    fn trace_capture_events() {
        let mut trace = NondeterminismTrace::new("session-1");
        let seq0 = trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        let seq1 = trace.capture(
            NondeterminismSource::TimerRead,
            vec![0, 0, 0, 1],
            200,
            "scheduler",
        );
        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(trace.event_count(), 2);
    }

    #[test]
    fn trace_finalise() {
        let mut trace = NondeterminismTrace::new("session-1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
        trace.finalise(200);
        assert!(trace.is_finalised());
        assert_eq!(trace.capture_ended_vts, Some(200));
    }

    #[test]
    fn trace_derive_id_stable() {
        let t1 = NondeterminismTrace::new("s1");
        let t2 = NondeterminismTrace::new("s1");
        assert_eq!(t1.derive_id(), t2.derive_id());
    }

    #[test]
    fn trace_serde_roundtrip() {
        let mut trace = NondeterminismTrace::new("session-1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        let json = serde_json::to_string(&trace).unwrap();
        let back: NondeterminismTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }

    // -- TraceEvent --

    #[test]
    fn trace_event_derive_id() {
        let event = TraceEvent {
            sequence: 0,
            source: NondeterminismSource::TimerRead,
            value: vec![1, 2, 3],
            virtual_ts: 100,
            component: "clock".to_string(),
        };
        let id1 = event.derive_id();
        let id2 = event.derive_id();
        assert_eq!(id1, id2);
    }

    // -- ReplayEngine --

    #[test]
    fn replay_empty_trace_exhausted() {
        let trace = NondeterminismTrace::new("s1");
        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::TimerRead, &[1]);
        assert!(matches!(result, Err(ReplayError::TraceExhausted { .. })));
    }

    #[test]
    fn replay_exact_match() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.finalise(200);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
            .unwrap();
        assert_eq!(result, vec![42]);
        assert!(engine.is_complete());
        assert_eq!(engine.divergence_count(), 0);
    }

    #[test]
    fn replay_source_mismatch() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::TimerRead, &[42]);
        assert!(matches!(result, Err(ReplayError::SourceMismatch { .. })));
    }

    #[test]
    fn replay_strict_critical_divergence() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        let result = engine.replay_next(NondeterminismSource::LaneSelectionRandom, &[99]);
        assert!(matches!(
            result,
            Err(ReplayError::CriticalDivergence { .. })
        ));
        assert_eq!(engine.critical_divergences(), 1);
    }

    #[test]
    fn replay_strict_benign_divergence_continues() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        // Timer divergence is benign
        let result = engine
            .replay_next(NondeterminismSource::TimerRead, &[2])
            .unwrap();
        // Returns traced value in strict mode
        assert_eq!(result, vec![1]);
        assert_eq!(engine.divergence_count(), 1);
        assert_eq!(engine.critical_divergences(), 0);
    }

    #[test]
    fn replay_best_effort_logs_divergences() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );

        let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);
        let result = engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
            .unwrap();
        // Returns traced value in best-effort mode
        assert_eq!(result, vec![42]);
        assert_eq!(engine.divergence_count(), 1);
    }

    #[test]
    fn replay_validate_uses_live_value() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );

        let mut engine = ReplayEngine::new(trace, ReplayMode::Validate);
        let result = engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
            .unwrap();
        // Validate mode returns live value
        assert_eq!(result, vec![99]);
        assert_eq!(engine.divergence_count(), 1);
    }

    #[test]
    fn replay_multi_event_sequence() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![10],
            100,
            "router",
        );
        trace.capture(NondeterminismSource::TimerRead, vec![20], 200, "clock");
        trace.capture(NondeterminismSource::ResourceCheck, vec![30], 300, "budget");
        trace.finalise(400);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        assert_eq!(engine.remaining(), 3);

        engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[10])
            .unwrap();
        assert_eq!(engine.remaining(), 2);

        engine
            .replay_next(NondeterminismSource::TimerRead, &[20])
            .unwrap();
        engine
            .replay_next(NondeterminismSource::ResourceCheck, &[30])
            .unwrap();

        assert!(engine.is_complete());
        assert_eq!(engine.replayed_events, 3);
    }

    #[test]
    fn replay_derive_id_stable() {
        let trace = NondeterminismTrace::new("s1");
        let e1 = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
        let e2 = ReplayEngine::new(trace, ReplayMode::Strict);
        assert_eq!(e1.derive_id(), e2.derive_id());
    }

    // -- FailoverController --

    #[test]
    fn failover_new() {
        let fc = FailoverController::with_defaults();
        assert_eq!(fc.total_failovers, 0);
        assert!(!fc.halted);
        assert_eq!(fc.default_strategy, FailoverStrategy::RetryThenBaseline);
    }

    #[test]
    fn failover_record() {
        let mut fc = FailoverController::with_defaults();
        let record = fc
            .record_failover(
                FailoverReason::SafeModeTriggered,
                "wasm-lane",
                "js-lane",
                100,
                true,
            )
            .unwrap();
        assert_eq!(record.sequence, 0);
        assert!(record.success);
        assert_eq!(fc.total_failovers, 1);
        assert_eq!(fc.successful_failovers, 1);
    }

    #[test]
    fn failover_strategy_override() {
        let mut fc = FailoverController::with_defaults();
        fc.set_override("critical-path", FailoverStrategy::Halt);
        assert_eq!(fc.strategy_for("critical-path"), FailoverStrategy::Halt);
        assert_eq!(
            fc.strategy_for("other"),
            FailoverStrategy::RetryThenBaseline
        );
    }

    #[test]
    fn failover_max_exceeded() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 2);
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        fc.record_failover(FailoverReason::Manual, "a", "b", 200, true)
            .unwrap();
        let err = fc
            .record_failover(FailoverReason::Manual, "a", "b", 300, true)
            .unwrap_err();
        assert!(matches!(err, FailoverError::MaxFailoversExceeded { .. }));
        assert!(fc.halted);
    }

    #[test]
    fn failover_halted_rejects() {
        let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 1);
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        // Exceed max
        let _ = fc.record_failover(FailoverReason::Manual, "a", "b", 200, true);
        // Now halted
        let err = fc
            .record_failover(FailoverReason::Manual, "a", "b", 300, true)
            .unwrap_err();
        assert_eq!(err, FailoverError::Halted);
    }

    #[test]
    fn failover_success_rate() {
        let mut fc = FailoverController::with_defaults();
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        fc.record_failover(FailoverReason::Manual, "a", "b", 200, false)
            .unwrap();
        assert_eq!(fc.success_rate_millionths(), 500_000); // 50%
    }

    #[test]
    fn failover_success_rate_no_failovers() {
        let fc = FailoverController::with_defaults();
        assert_eq!(fc.success_rate_millionths(), MILLION); // 100%
    }

    #[test]
    fn failover_derive_id_stable() {
        let f1 = FailoverController::with_defaults();
        let f2 = FailoverController::with_defaults();
        assert_eq!(f1.derive_id(), f2.derive_id());
    }

    #[test]
    fn failover_record_derive_id() {
        let record = FailoverRecord {
            sequence: 0,
            reason: FailoverReason::SafeModeTriggered,
            strategy: FailoverStrategy::ImmediateBaseline,
            from_component: "wasm".to_string(),
            to_component: "js".to_string(),
            virtual_ts: 100,
            success: true,
        };
        let id1 = record.derive_id();
        let id2 = record.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn failover_serde_roundtrip() {
        let mut fc = FailoverController::with_defaults();
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();
        let json = serde_json::to_string(&fc).unwrap();
        let back: FailoverController = serde_json::from_str(&json).unwrap();
        assert_eq!(fc, back);
    }

    // -- FailoverReason --

    #[test]
    fn failover_reason_variants_serde() {
        let reasons = vec![
            FailoverReason::BudgetExhausted {
                metric: "signals".to_string(),
                value: 100,
                limit: 50,
            },
            FailoverReason::LaneError {
                message: "boom".to_string(),
            },
            FailoverReason::SafeModeTriggered,
            FailoverReason::Timeout {
                elapsed_us: 20_000,
                limit_us: 16_000,
            },
            FailoverReason::ReplayDivergence {
                divergence_count: 3,
            },
            FailoverReason::Manual,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: FailoverReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    // -- IncidentBundle --

    #[test]
    fn incident_severity_as_str() {
        assert_eq!(IncidentSeverity::Info.as_str(), "info");
        assert_eq!(IncidentSeverity::Warning.as_str(), "warning");
        assert_eq!(IncidentSeverity::Error.as_str(), "error");
        assert_eq!(IncidentSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn incident_artifact_new() {
        let artifact =
            IncidentArtifact::new("test", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
        assert!(!artifact.content_hash.is_empty());
        assert_eq!(artifact.data, vec![1, 2, 3]);
    }

    #[test]
    fn incident_artifact_derive_id() {
        let artifact =
            IncidentArtifact::new("test", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
        let id1 = artifact.derive_id();
        let id2 = artifact.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn incident_bundle_new() {
        let bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Error,
            "Test incident",
            "router",
            1000,
        );
        assert_eq!(bundle.artifact_count(), 0);
        assert!(!bundle.is_finalised());
    }

    #[test]
    fn incident_bundle_add_artifacts() {
        let mut bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Error,
            "Test incident",
            "router",
            1000,
        );
        bundle.add_artifact(IncidentArtifact::new(
            "trace",
            ArtifactKind::NondeterminismTrace,
            vec![1, 2, 3],
        ));
        bundle.add_artifact(IncidentArtifact::new(
            "config",
            ArtifactKind::Configuration,
            vec![4, 5, 6],
        ));
        assert_eq!(bundle.artifact_count(), 2);
        assert_eq!(bundle.total_data_size(), 6);
    }

    #[test]
    fn incident_bundle_tags_dedup() {
        let mut bundle =
            IncidentBundle::new("INC-001", IncidentSeverity::Info, "Test", "comp", 100);
        bundle.add_tag("replay");
        bundle.add_tag("replay");
        bundle.add_tag("critical");
        assert_eq!(bundle.tags.len(), 2);
    }

    #[test]
    fn incident_bundle_finalise() {
        let mut bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Critical,
            "Major issue",
            "router",
            1000,
        );
        bundle.add_artifact(IncidentArtifact::new(
            "trace",
            ArtifactKind::NondeterminismTrace,
            vec![1, 2, 3],
        ));
        bundle.finalise();
        assert!(bundle.is_finalised());
        assert!(!bundle.bundle_hash.is_empty());
    }

    #[test]
    fn incident_bundle_derive_id() {
        let bundle = IncidentBundle::new("INC-001", IncidentSeverity::Error, "Test", "comp", 100);
        let id1 = bundle.derive_id();
        let id2 = bundle.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn incident_bundle_serde_roundtrip() {
        let mut bundle = IncidentBundle::new(
            "INC-001",
            IncidentSeverity::Warning,
            "Test incident",
            "router",
            1000,
        );
        bundle.add_artifact(IncidentArtifact::new(
            "trace",
            ArtifactKind::NondeterminismTrace,
            vec![1, 2, 3],
        ));
        bundle.finalise();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: IncidentBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    // -- IncidentBundleBuilder --

    #[test]
    fn builder_constructs_bundle() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let builder = IncidentBundleBuilder::new(
            "INC-001",
            IncidentSeverity::Error,
            "Test incident",
            "router",
            1000,
        );
        let bundle = builder.build(Some(&trace), None, None);
        assert!(bundle.is_finalised());
        assert_eq!(bundle.artifact_count(), 1); // trace only
        assert!(bundle.tags.contains(&"auto-generated".to_string()));
    }

    #[test]
    fn builder_with_all_sources() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let mut replay = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
        let _ = replay.replay_next(NondeterminismSource::TimerRead, &[2]);

        let mut failover = FailoverController::with_defaults();
        failover
            .record_failover(FailoverReason::Manual, "a", "b", 100, true)
            .unwrap();

        let builder = IncidentBundleBuilder::new(
            "INC-002",
            IncidentSeverity::Critical,
            "Full incident",
            "router",
            2000,
        );
        let bundle = builder.build(Some(&trace), Some(&replay), Some(&failover));
        assert!(bundle.is_finalised());
        // trace + failover_log + divergence_report = 3
        assert_eq!(bundle.artifact_count(), 3);
    }

    #[test]
    fn builder_exclude_options() {
        let mut trace = NondeterminismTrace::new("s1");
        trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");

        let builder =
            IncidentBundleBuilder::new("INC-003", IncidentSeverity::Info, "Minimal", "comp", 100)
                .with_trace(false)
                .with_decisions(false)
                .with_failovers(false)
                .with_divergences(false);

        let bundle = builder.build(Some(&trace), None, None);
        assert_eq!(bundle.artifact_count(), 0); // everything excluded
    }

    // -- compute_simple_hash --

    #[test]
    fn hash_deterministic() {
        let h1 = compute_simple_hash(b"hello world");
        let h2 = compute_simple_hash(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_differs_for_different_input() {
        let h1 = compute_simple_hash(b"hello");
        let h2 = compute_simple_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_format() {
        let h = compute_simple_hash(b"test");
        assert_eq!(h.len(), 16); // 16 hex chars for u64
    }

    // -- classify_divergence --

    #[test]
    fn classify_timer_is_benign() {
        let s = classify_divergence(&NondeterminismSource::TimerRead, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Benign);
    }

    #[test]
    fn classify_thread_is_warning() {
        let s = classify_divergence(&NondeterminismSource::ThreadSchedule, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Warning);
    }

    #[test]
    fn classify_lane_random_is_critical() {
        let s = classify_divergence(&NondeterminismSource::LaneSelectionRandom, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Critical);
    }

    // -- ArtifactKind --

    #[test]
    fn artifact_kind_as_str() {
        let kinds = [
            ArtifactKind::NondeterminismTrace,
            ArtifactKind::DecisionLog,
            ArtifactKind::FailoverLog,
            ArtifactKind::SignalGraphSnapshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::PerformanceMetrics,
            ArtifactKind::Configuration,
            ArtifactKind::DivergenceReport,
        ];
        for k in &kinds {
            assert!(!k.as_str().is_empty());
        }
    }

    #[test]
    fn artifact_kind_serde() {
        let kind = ArtifactKind::DivergenceReport;
        let json = serde_json::to_string(&kind).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }

    // -- E2E: Full capture-replay-failover-incident pipeline --

    #[test]
    fn e2e_capture_replay_incident() {
        // 1. Capture trace
        let mut trace = NondeterminismTrace::new("session-e2e");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.capture(
            NondeterminismSource::TimerRead,
            vec![0, 0, 3, 232],
            200,
            "clock",
        );
        trace.capture(NondeterminismSource::ResourceCheck, vec![1], 300, "budget");
        trace.finalise(400);

        // 2. Replay with some divergence
        let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
        engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
            .unwrap();
        engine
            .replay_next(NondeterminismSource::TimerRead, &[0, 0, 4, 0]) // timer divergence
            .unwrap();
        engine
            .replay_next(NondeterminismSource::ResourceCheck, &[1])
            .unwrap();
        assert!(engine.is_complete());
        assert_eq!(engine.divergence_count(), 1);
        assert_eq!(engine.critical_divergences(), 0); // timer is benign

        // 3. Record a failover
        let mut failover = FailoverController::with_defaults();
        failover
            .record_failover(
                FailoverReason::SafeModeTriggered,
                "wasm-lane",
                "js-lane",
                500,
                true,
            )
            .unwrap();

        // 4. Build incident bundle
        let builder = IncidentBundleBuilder::new(
            "INC-E2E-001",
            IncidentSeverity::Warning,
            "WASM lane degraded, failover to JS",
            "wasm-lane",
            500,
        );
        let bundle = builder.build(Some(&trace), Some(&engine), Some(&failover));

        assert!(bundle.is_finalised());
        assert_eq!(bundle.severity, IncidentSeverity::Warning);
        assert_eq!(bundle.artifact_count(), 3); // trace + failover + divergence
        assert!(bundle.tags.contains(&"auto-generated".to_string()));
        assert!(bundle.tags.contains(&"warning".to_string()));
        assert!(!bundle.bundle_hash.is_empty());
    }

    #[test]
    fn e2e_strict_replay_halts_on_critical() {
        let mut trace = NondeterminismTrace::new("session-strict");
        trace.capture(
            NondeterminismSource::LaneSelectionRandom,
            vec![42],
            100,
            "router",
        );
        trace.capture(
            NondeterminismSource::ExternalApiResponse,
            vec![1, 2, 3],
            200,
            "api",
        );
        trace.finalise(300);

        let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
        engine
            .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
            .unwrap();

        // Critical divergence on external API response
        let result = engine.replay_next(NondeterminismSource::ExternalApiResponse, &[4, 5, 6]);
        assert!(matches!(
            result,
            Err(ReplayError::CriticalDivergence { .. })
        ));
    }

    // -- DivergenceSeverity --

    #[test]
    fn divergence_severity_ordering() {
        assert!(DivergenceSeverity::Benign < DivergenceSeverity::Warning);
        assert!(DivergenceSeverity::Warning < DivergenceSeverity::Critical);
    }

    #[test]
    fn divergence_severity_serde() {
        for s in [
            DivergenceSeverity::Benign,
            DivergenceSeverity::Warning,
            DivergenceSeverity::Critical,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: DivergenceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn nondeterminism_source_as_str_all_unique() {
        let strs: std::collections::BTreeSet<&str> = NondeterminismSource::ALL
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(strs.len(), 6);
    }

    #[test]
    fn incident_severity_as_str_all_unique() {
        let strs: std::collections::BTreeSet<&str> = [
            IncidentSeverity::Info,
            IncidentSeverity::Warning,
            IncidentSeverity::Error,
            IncidentSeverity::Critical,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        assert_eq!(strs.len(), 4);
    }

    // ── Enrichment: replay error serde ──────────────────────────

    #[test]
    fn replay_error_serde_all_variants() {
        let errors = vec![
            ReplayError::TraceExhausted {
                cursor: 3,
                total: 10,
            },
            ReplayError::SourceMismatch {
                expected: NondeterminismSource::TimerRead,
                actual: NondeterminismSource::LaneSelectionRandom,
                sequence: 0,
            },
            ReplayError::CriticalDivergence {
                source: NondeterminismSource::ExternalApiResponse,
                sequence: 1,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ReplayError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // ── Enrichment: ReplayMode serde ────────────────────────────

    #[test]
    fn replay_mode_serde_roundtrip() {
        for mode in [
            ReplayMode::Strict,
            ReplayMode::BestEffort,
            ReplayMode::Validate,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: ReplayMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // ── Enrichment: FailoverError serde ─────────────────────────

    #[test]
    fn failover_error_serde_roundtrip() {
        let errors = vec![
            FailoverError::MaxFailoversExceeded {
                count: 11,
                limit: 10,
            },
            FailoverError::Halted,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: FailoverError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // ── Enrichment: FailoverStrategy serde ──────────────────────

    #[test]
    fn failover_strategy_serde_all_variants() {
        for strategy in [
            FailoverStrategy::RetryThenBaseline,
            FailoverStrategy::ImmediateBaseline,
            FailoverStrategy::Halt,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let back: FailoverStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, back);
        }
    }

    // ── Enrichment: IncidentBundle empty finalise ────────────────

    #[test]
    fn incident_bundle_finalise_empty_produces_hash() {
        let mut bundle =
            IncidentBundle::new("INC-EMPTY", IncidentSeverity::Info, "Empty", "comp", 0);
        bundle.finalise();
        assert!(bundle.is_finalised());
        assert!(!bundle.bundle_hash.is_empty());
    }

    // ── Enrichment: classify_divergence all sources ─────────────

    #[test]
    fn classify_divergence_user_interaction_is_benign() {
        let s = classify_divergence(&NondeterminismSource::UserInteractionTiming, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Benign);
    }

    #[test]
    fn classify_divergence_resource_check_is_critical() {
        let s = classify_divergence(&NondeterminismSource::ResourceCheck, &[1], &[2]);
        assert_eq!(s, DivergenceSeverity::Critical);
    }
}
