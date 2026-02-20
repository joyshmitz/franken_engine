//! Obligation leak response policy: lab=fatal, prod=diagnostic + scoped failover.
//!
//! In lab mode, any unresolved obligation leak is a hard abort with diagnostics.
//! In production, leaks trigger evidence emission and scoped region failover.
//! Policy is immutable after init to prevent evasion.
//!
//! Plan references: Section 10.11 item 7, 9G.3 (linear-obligation discipline),
//! Top-10 #3 (deterministic evidence graph + replay).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ObligationLeakPolicy — lab vs production behavior
// ---------------------------------------------------------------------------

/// Policy governing how obligation leaks are handled.
/// Set at startup and immutable thereafter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationLeakPolicy {
    /// Lab mode: obligation leak triggers panic/abort with full diagnostics.
    Lab,
    /// Production: obligation leak triggers evidence emission + scoped failover.
    Production,
}

impl fmt::Display for ObligationLeakPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lab => write!(f, "lab"),
            Self::Production => write!(f, "production"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeakDiagnostic — structured information about a leak
// ---------------------------------------------------------------------------

/// Full diagnostic payload for an obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakDiagnostic {
    pub obligation_id: u64,
    pub channel_id: String,
    pub creator_trace_id: String,
    pub obligation_age_ticks: u64,
    pub region_id: String,
    pub component: String,
}

impl fmt::Display for LeakDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "obligation leak: id={}, channel={}, trace={}, age={}, region={}, component={}",
            self.obligation_id,
            self.channel_id,
            self.creator_trace_id,
            self.obligation_age_ticks,
            self.region_id,
            self.component
        )
    }
}

// ---------------------------------------------------------------------------
// LeakSeverity — severity classification
// ---------------------------------------------------------------------------

/// Severity of the leak event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeakSeverity {
    Warning,
    Critical,
    Fatal,
}

impl fmt::Display for LeakSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

// ---------------------------------------------------------------------------
// FailoverAction — what production mode does on leak
// ---------------------------------------------------------------------------

/// Action taken in production mode on obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverAction {
    /// Region enters forced close (cancel -> drain -> finalize).
    ScopedRegionClose { region_id: String },
    /// Alert emitted without region close (for non-critical paths).
    AlertOnly,
}

impl fmt::Display for FailoverAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopedRegionClose { region_id } => {
                write!(f, "scoped_region_close:{region_id}")
            }
            Self::AlertOnly => write!(f, "alert_only"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeakEvent — structured evidence event
// ---------------------------------------------------------------------------

/// Structured evidence event for an obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakEvent {
    pub trace_id: String,
    pub obligation_id: u64,
    pub channel_id: String,
    pub region_id: String,
    pub component: String,
    pub leak_policy: ObligationLeakPolicy,
    pub failover_action: Option<FailoverAction>,
    pub severity: LeakSeverity,
}

// ---------------------------------------------------------------------------
// LeakMetrics — per-region/channel/component counters
// ---------------------------------------------------------------------------

/// Metrics tracking obligation leak counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakMetrics {
    /// Leaks per region_id.
    pub by_region: BTreeMap<String, u64>,
    /// Leaks per channel_id.
    pub by_channel: BTreeMap<String, u64>,
    /// Leaks per component.
    pub by_component: BTreeMap<String, u64>,
    /// Total leaks.
    pub total: u64,
}

impl LeakMetrics {
    /// Record a leak for the given dimensions.
    pub fn record(&mut self, region_id: &str, channel_id: &str, component: &str) {
        *self.by_region.entry(region_id.to_string()).or_insert(0) += 1;
        *self.by_channel.entry(channel_id.to_string()).or_insert(0) += 1;
        *self.by_component.entry(component.to_string()).or_insert(0) += 1;
        self.total += 1;
    }
}

// ---------------------------------------------------------------------------
// LeakResponse — result of handling a leak
// ---------------------------------------------------------------------------

/// Result of handling an obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakResponse {
    /// Lab mode: should abort (caller panics).
    Abort { diagnostic: LeakDiagnostic },
    /// Production mode: evidence emitted, optional failover.
    Handled {
        event: LeakEvent,
        failover: Option<FailoverAction>,
    },
}

// ---------------------------------------------------------------------------
// LeakHandler — the policy handler
// ---------------------------------------------------------------------------

/// Handles obligation leak events according to the configured policy.
#[derive(Debug)]
pub struct LeakHandler {
    policy: ObligationLeakPolicy,
    metrics: LeakMetrics,
    events: Vec<LeakEvent>,
}

impl LeakHandler {
    /// Create a new handler with immutable policy.
    pub fn new(policy: ObligationLeakPolicy) -> Self {
        Self {
            policy,
            metrics: LeakMetrics::default(),
            events: Vec::new(),
        }
    }

    /// Current policy.
    pub fn policy(&self) -> ObligationLeakPolicy {
        self.policy
    }

    /// Handle an obligation leak. Returns the response.
    pub fn handle_leak(&mut self, diagnostic: LeakDiagnostic) -> LeakResponse {
        self.metrics.record(
            &diagnostic.region_id,
            &diagnostic.channel_id,
            &diagnostic.component,
        );

        match self.policy {
            ObligationLeakPolicy::Lab => LeakResponse::Abort { diagnostic },
            ObligationLeakPolicy::Production => {
                let failover = FailoverAction::ScopedRegionClose {
                    region_id: diagnostic.region_id.clone(),
                };

                let event = LeakEvent {
                    trace_id: diagnostic.creator_trace_id.clone(),
                    obligation_id: diagnostic.obligation_id,
                    channel_id: diagnostic.channel_id,
                    region_id: diagnostic.region_id,
                    component: diagnostic.component,
                    leak_policy: self.policy,
                    failover_action: Some(failover.clone()),
                    severity: LeakSeverity::Critical,
                };

                self.events.push(event.clone());

                LeakResponse::Handled {
                    event,
                    failover: Some(failover),
                }
            }
        }
    }

    /// Current metrics.
    pub fn metrics(&self) -> &LeakMetrics {
        &self.metrics
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<LeakEvent> {
        std::mem::take(&mut self.events)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_diagnostic() -> LeakDiagnostic {
        LeakDiagnostic {
            obligation_id: 42,
            channel_id: "chan-1".to_string(),
            creator_trace_id: "trace-1".to_string(),
            obligation_age_ticks: 500,
            region_id: "region-1".to_string(),
            component: "policy_controller".to_string(),
        }
    }

    // -- Policy display --

    #[test]
    fn policy_display() {
        assert_eq!(ObligationLeakPolicy::Lab.to_string(), "lab");
        assert_eq!(ObligationLeakPolicy::Production.to_string(), "production");
    }

    // -- Lab mode --

    #[test]
    fn lab_mode_returns_abort() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let response = handler.handle_leak(test_diagnostic());
        assert!(matches!(response, LeakResponse::Abort { .. }));
    }

    #[test]
    fn lab_mode_abort_includes_diagnostic() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let diag = test_diagnostic();
        let response = handler.handle_leak(diag.clone());
        if let LeakResponse::Abort { diagnostic } = response {
            assert_eq!(diagnostic, diag);
        } else {
            panic!("expected Abort");
        }
    }

    // -- Production mode --

    #[test]
    fn production_mode_returns_handled() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let response = handler.handle_leak(test_diagnostic());
        assert!(matches!(response, LeakResponse::Handled { .. }));
    }

    #[test]
    fn production_mode_triggers_scoped_failover() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let response = handler.handle_leak(test_diagnostic());
        if let LeakResponse::Handled { failover, .. } = response {
            assert!(matches!(
                failover,
                Some(FailoverAction::ScopedRegionClose { .. })
            ));
        } else {
            panic!("expected Handled");
        }
    }

    #[test]
    fn production_mode_emits_event() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());

        let events = handler.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].obligation_id, 42);
        assert_eq!(events[0].severity, LeakSeverity::Critical);
        assert_eq!(events[0].leak_policy, ObligationLeakPolicy::Production);
    }

    #[test]
    fn production_event_carries_correct_fields() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());

        let events = handler.drain_events();
        let event = &events[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.channel_id, "chan-1");
        assert_eq!(event.region_id, "region-1");
        assert_eq!(event.component, "policy_controller");
    }

    // -- Metrics --

    #[test]
    fn metrics_increment_on_leak() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        handler.handle_leak(LeakDiagnostic {
            obligation_id: 43,
            channel_id: "chan-2".to_string(),
            creator_trace_id: "trace-2".to_string(),
            obligation_age_ticks: 100,
            region_id: "region-1".to_string(),
            component: "evidence_flusher".to_string(),
        });

        let metrics = handler.metrics();
        assert_eq!(metrics.total, 2);
        assert_eq!(metrics.by_region.get("region-1"), Some(&2));
        assert_eq!(metrics.by_channel.get("chan-1"), Some(&1));
        assert_eq!(metrics.by_channel.get("chan-2"), Some(&1));
        assert_eq!(metrics.by_component.get("policy_controller"), Some(&1));
        assert_eq!(metrics.by_component.get("evidence_flusher"), Some(&1));
    }

    #[test]
    fn lab_mode_also_records_metrics() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        handler.handle_leak(test_diagnostic());
        assert_eq!(handler.metrics().total, 1);
    }

    // -- LeakDiagnostic display --

    #[test]
    fn diagnostic_display() {
        let diag = test_diagnostic();
        let s = diag.to_string();
        assert!(s.contains("obligation leak"));
        assert!(s.contains("42"));
        assert!(s.contains("chan-1"));
        assert!(s.contains("region-1"));
    }

    // -- Severity ordering --

    #[test]
    fn severity_ordering() {
        assert!(LeakSeverity::Warning < LeakSeverity::Critical);
        assert!(LeakSeverity::Critical < LeakSeverity::Fatal);
    }

    #[test]
    fn severity_display() {
        assert_eq!(LeakSeverity::Warning.to_string(), "warning");
        assert_eq!(LeakSeverity::Critical.to_string(), "critical");
        assert_eq!(LeakSeverity::Fatal.to_string(), "fatal");
    }

    // -- FailoverAction display --

    #[test]
    fn failover_action_display() {
        assert_eq!(
            FailoverAction::ScopedRegionClose {
                region_id: "r-1".to_string()
            }
            .to_string(),
            "scoped_region_close:r-1"
        );
        assert_eq!(FailoverAction::AlertOnly.to_string(), "alert_only");
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<LeakEvent> {
            let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
            handler.handle_leak(test_diagnostic());
            handler.handle_leak(LeakDiagnostic {
                obligation_id: 99,
                channel_id: "chan-x".to_string(),
                creator_trace_id: "trace-x".to_string(),
                obligation_age_ticks: 200,
                region_id: "region-2".to_string(),
                component: "scheduler".to_string(),
            });
            handler.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- Serialization --

    #[test]
    fn leak_diagnostic_serialization_round_trip() {
        let diag = test_diagnostic();
        let json = serde_json::to_string(&diag).expect("serialize");
        let restored: LeakDiagnostic = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(diag, restored);
    }

    #[test]
    fn leak_event_serialization_round_trip() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 1,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: Some(FailoverAction::ScopedRegionClose {
                region_id: "r".to_string(),
            }),
            severity: LeakSeverity::Critical,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: LeakEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn leak_metrics_serialization_round_trip() {
        let mut metrics = LeakMetrics::default();
        metrics.record("r", "c", "comp");
        let json = serde_json::to_string(&metrics).expect("serialize");
        let restored: LeakMetrics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(metrics, restored);
    }
}
