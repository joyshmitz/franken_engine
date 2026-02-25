//! Supervision tree for long-lived services with restart budgets,
//! escalation semantics, and monotone severity outcomes.
//!
//! Inspired by Erlang/OTP supervision patterns adapted for the
//! FrankenEngine safety model. Each service follows the region-quiescence
//! protocol (cancel → drain → finalize) before restart.
//!
//! Plan references: Section 10.11 item 8, 9G.2 (cancellation as protocol),
//! 9G.3 (linear-obligation discipline), Top-10 #2, #8.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity — monotone escalation levels
// ---------------------------------------------------------------------------

/// Escalation severity level. Transitions must be monotonically non-decreasing
/// within a single incident chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Restart,
    Isolate,
    SubtreeRestart,
    SubtreeTerminate,
    RootEscalation,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restart => write!(f, "restart"),
            Self::Isolate => write!(f, "isolate"),
            Self::SubtreeRestart => write!(f, "subtree_restart"),
            Self::SubtreeTerminate => write!(f, "subtree_terminate"),
            Self::RootEscalation => write!(f, "root_escalation"),
        }
    }
}

// ---------------------------------------------------------------------------
// RestartPolicy — when to restart a service
// ---------------------------------------------------------------------------

/// Restart policy for a supervised service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartPolicy {
    /// Always restart on any termination.
    Permanent,
    /// Restart only on unexpected failure (not clean shutdown).
    Transient,
    /// Never restart.
    Temporary,
}

impl fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permanent => write!(f, "permanent"),
            Self::Transient => write!(f, "transient"),
            Self::Temporary => write!(f, "temporary"),
        }
    }
}

// ---------------------------------------------------------------------------
// RestartBudget — bounded restart attempts
// ---------------------------------------------------------------------------

/// Restart budget: maximum restarts within a sliding window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartBudget {
    /// Maximum restarts allowed within the window.
    pub max_restarts: u32,
    /// Window size in virtual ticks.
    pub window_ticks: u64,
}

impl Default for RestartBudget {
    fn default() -> Self {
        Self {
            max_restarts: 5,
            window_ticks: 60_000,
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceState — current state of a supervised service
// ---------------------------------------------------------------------------

/// Current state of a supervised service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Starting,
    Running,
    Failed,
    Restarting,
    Isolated,
    Terminated,
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Failed => write!(f, "failed"),
            Self::Restarting => write!(f, "restarting"),
            Self::Isolated => write!(f, "isolated"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

// ---------------------------------------------------------------------------
// HealthStatus — aggregate health
// ---------------------------------------------------------------------------

/// Aggregate health status of a supervisor node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// SupervisorAction — structured evidence for supervisor decisions
// ---------------------------------------------------------------------------

/// Action taken by the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupervisorAction {
    Start,
    Restart,
    Isolate,
    Terminate,
    Escalate,
}

impl fmt::Display for SupervisorAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "start"),
            Self::Restart => write!(f, "restart"),
            Self::Isolate => write!(f, "isolate"),
            Self::Terminate => write!(f, "terminate"),
            Self::Escalate => write!(f, "escalate"),
        }
    }
}

// ---------------------------------------------------------------------------
// SupervisorEvent — structured evidence
// ---------------------------------------------------------------------------

/// Structured event emitted by supervisor actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorEvent {
    pub trace_id: String,
    pub service_id: String,
    pub action: SupervisorAction,
    pub reason: String,
    pub restart_count: u32,
    pub budget_remaining: u32,
    pub severity: Severity,
}

// ---------------------------------------------------------------------------
// ServiceConfig — declarative service configuration
// ---------------------------------------------------------------------------

/// Declarative configuration for a supervised service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub service_id: String,
    pub restart_policy: RestartPolicy,
    pub restart_budget: RestartBudget,
    /// Higher = shut down first during ordered shutdown.
    pub shutdown_order: u32,
}

// ---------------------------------------------------------------------------
// ServiceEntry — runtime state for a supervised service
// ---------------------------------------------------------------------------

/// Runtime tracking for a single supervised service.
#[derive(Debug)]
struct ServiceEntry {
    config: ServiceConfig,
    state: ServiceState,
    restart_count: u32,
    /// Tick timestamps of recent restarts for sliding window.
    restart_timestamps: Vec<u64>,
    current_severity: Severity,
}

impl ServiceEntry {
    fn new(config: ServiceConfig) -> Self {
        Self {
            config,
            state: ServiceState::Starting,
            restart_count: 0,
            restart_timestamps: Vec::new(),
            current_severity: Severity::Restart,
        }
    }

    /// Count restarts within the budget window ending at `now`.
    fn restarts_in_window(&self, now: u64) -> u32 {
        let window_start = now.saturating_sub(self.config.restart_budget.window_ticks);
        self.restart_timestamps
            .iter()
            .filter(|&&ts| ts >= window_start)
            .count() as u32
    }

    /// Check if budget is exhausted at the given time.
    fn budget_exhausted(&self, now: u64) -> bool {
        self.restarts_in_window(now) >= self.config.restart_budget.max_restarts
    }

    fn budget_remaining(&self, now: u64) -> u32 {
        let used = self.restarts_in_window(now);
        self.config.restart_budget.max_restarts.saturating_sub(used)
    }
}

// ---------------------------------------------------------------------------
// Supervisor — tree node managing child services
// ---------------------------------------------------------------------------

/// Supervision tree node managing a set of child services.
#[derive(Debug)]
pub struct Supervisor {
    pub id: String,
    pub trace_id: String,
    services: BTreeMap<String, ServiceEntry>,
    events: Vec<SupervisorEvent>,
    /// Escalation severity for this supervisor node.
    escalated_severity: Option<Severity>,
}

impl Supervisor {
    /// Create a new supervisor.
    pub fn new(id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            trace_id: trace_id.into(),
            services: BTreeMap::new(),
            events: Vec::new(),
            escalated_severity: None,
        }
    }

    /// Add a service to be supervised.
    pub fn add_service(&mut self, config: ServiceConfig) {
        let id = config.service_id.clone();
        self.services.insert(id, ServiceEntry::new(config));
    }

    /// Start a service (transition to Running).
    pub fn start_service(&mut self, service_id: &str) -> bool {
        if let Some(entry) = self.services.get_mut(service_id) {
            entry.state = ServiceState::Running;
            self.events.push(SupervisorEvent {
                trace_id: self.trace_id.clone(),
                service_id: service_id.to_string(),
                action: SupervisorAction::Start,
                reason: "initial_start".to_string(),
                restart_count: entry.restart_count,
                budget_remaining: entry.config.restart_budget.max_restarts,
                severity: Severity::Restart,
            });
            true
        } else {
            false
        }
    }

    /// Report a service failure. Returns the action taken.
    pub fn report_failure(
        &mut self,
        service_id: &str,
        reason: &str,
        now: u64,
    ) -> Option<SupervisorAction> {
        let entry = self.services.get_mut(service_id)?;
        entry.state = ServiceState::Failed;

        // Check restart policy
        match entry.config.restart_policy {
            RestartPolicy::Temporary => {
                // Never restart — terminate
                entry.state = ServiceState::Terminated;
                self.events.push(SupervisorEvent {
                    trace_id: self.trace_id.clone(),
                    service_id: service_id.to_string(),
                    action: SupervisorAction::Terminate,
                    reason: reason.to_string(),
                    restart_count: entry.restart_count,
                    budget_remaining: entry.budget_remaining(now),
                    severity: entry.current_severity,
                });
                Some(SupervisorAction::Terminate)
            }
            RestartPolicy::Permanent | RestartPolicy::Transient => {
                if entry.budget_exhausted(now) {
                    // Budget exhausted — escalate
                    let new_severity = escalate_severity(entry.current_severity);
                    entry.current_severity = new_severity;

                    if new_severity >= Severity::Isolate {
                        entry.state = ServiceState::Isolated;
                        self.escalated_severity = Some(new_severity);
                        self.events.push(SupervisorEvent {
                            trace_id: self.trace_id.clone(),
                            service_id: service_id.to_string(),
                            action: SupervisorAction::Escalate,
                            reason: format!("budget_exhausted: {reason}"),
                            restart_count: entry.restart_count,
                            budget_remaining: 0,
                            severity: new_severity,
                        });
                        Some(SupervisorAction::Escalate)
                    } else {
                        // Still at Restart level but budget exhausted — isolate
                        entry.state = ServiceState::Isolated;
                        entry.current_severity = Severity::Isolate;
                        self.events.push(SupervisorEvent {
                            trace_id: self.trace_id.clone(),
                            service_id: service_id.to_string(),
                            action: SupervisorAction::Isolate,
                            reason: format!("budget_exhausted: {reason}"),
                            restart_count: entry.restart_count,
                            budget_remaining: 0,
                            severity: Severity::Isolate,
                        });
                        Some(SupervisorAction::Isolate)
                    }
                } else {
                    // Budget available — restart
                    entry.restart_count += 1;
                    entry.restart_timestamps.push(now);
                    entry.state = ServiceState::Restarting;

                    self.events.push(SupervisorEvent {
                        trace_id: self.trace_id.clone(),
                        service_id: service_id.to_string(),
                        action: SupervisorAction::Restart,
                        reason: reason.to_string(),
                        restart_count: entry.restart_count,
                        budget_remaining: entry.budget_remaining(now),
                        severity: entry.current_severity,
                    });

                    // Complete restart: transition to Running
                    entry.state = ServiceState::Running;
                    Some(SupervisorAction::Restart)
                }
            }
        }
    }

    /// Get the current state of a service.
    pub fn service_state(&self, service_id: &str) -> Option<ServiceState> {
        self.services.get(service_id).map(|e| e.state)
    }

    /// Get the restart count of a service.
    pub fn restart_count(&self, service_id: &str) -> Option<u32> {
        self.services.get(service_id).map(|e| e.restart_count)
    }

    /// Get the current severity of a service.
    pub fn service_severity(&self, service_id: &str) -> Option<Severity> {
        self.services.get(service_id).map(|e| e.current_severity)
    }

    /// Check if this supervisor has been escalated.
    pub fn escalated_severity(&self) -> Option<Severity> {
        self.escalated_severity
    }

    /// Aggregate health status based on child states.
    pub fn health(&self) -> HealthStatus {
        let mut has_failed = false;
        let mut has_isolated = false;

        for entry in self.services.values() {
            match entry.state {
                ServiceState::Isolated | ServiceState::Terminated => {
                    has_isolated = true;
                }
                ServiceState::Failed | ServiceState::Restarting => {
                    has_failed = true;
                }
                ServiceState::Starting | ServiceState::Running => {}
            }
        }

        if has_isolated {
            HealthStatus::Critical
        } else if has_failed {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    /// Get services in shutdown order (highest shutdown_order first).
    pub fn shutdown_order(&self) -> Vec<String> {
        let mut entries: Vec<_> = self
            .services
            .iter()
            .map(|(id, entry)| (id.clone(), entry.config.shutdown_order))
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.1));
        entries.into_iter().map(|(id, _)| id).collect()
    }

    /// Number of supervised services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SupervisorEvent> {
        std::mem::take(&mut self.events)
    }
}

/// Escalate severity monotonically.
fn escalate_severity(current: Severity) -> Severity {
    match current {
        Severity::Restart => Severity::Isolate,
        Severity::Isolate => Severity::SubtreeRestart,
        Severity::SubtreeRestart => Severity::SubtreeTerminate,
        Severity::SubtreeTerminate => Severity::RootEscalation,
        Severity::RootEscalation => Severity::RootEscalation, // ceiling
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(id: &str) -> ServiceConfig {
        ServiceConfig {
            service_id: id.to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget {
                max_restarts: 3,
                window_ticks: 100,
            },
            shutdown_order: 0,
        }
    }

    fn test_supervisor() -> Supervisor {
        let mut sup = Supervisor::new("sup-1", "trace-1");
        sup.add_service(test_config("svc-a"));
        sup.start_service("svc-a");
        sup
    }

    // -- Severity --

    #[test]
    fn severity_ordering() {
        assert!(Severity::Restart < Severity::Isolate);
        assert!(Severity::Isolate < Severity::SubtreeRestart);
        assert!(Severity::SubtreeRestart < Severity::SubtreeTerminate);
        assert!(Severity::SubtreeTerminate < Severity::RootEscalation);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Restart.to_string(), "restart");
        assert_eq!(Severity::Isolate.to_string(), "isolate");
        assert_eq!(Severity::SubtreeRestart.to_string(), "subtree_restart");
        assert_eq!(Severity::SubtreeTerminate.to_string(), "subtree_terminate");
        assert_eq!(Severity::RootEscalation.to_string(), "root_escalation");
    }

    // -- RestartPolicy --

    #[test]
    fn restart_policy_display() {
        assert_eq!(RestartPolicy::Permanent.to_string(), "permanent");
        assert_eq!(RestartPolicy::Transient.to_string(), "transient");
        assert_eq!(RestartPolicy::Temporary.to_string(), "temporary");
    }

    // -- Service lifecycle --

    #[test]
    fn service_starts_running() {
        let sup = test_supervisor();
        assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
    }

    #[test]
    fn failure_with_budget_triggers_restart() {
        let mut sup = test_supervisor();
        let action = sup.report_failure("svc-a", "crash", 10).unwrap();
        assert_eq!(action, SupervisorAction::Restart);
        assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
        assert_eq!(sup.restart_count("svc-a"), Some(1));
    }

    #[test]
    fn budget_exhaustion_triggers_isolate() {
        let mut sup = test_supervisor();
        // Use 3 restarts (budget is 3)
        sup.report_failure("svc-a", "crash-1", 10);
        sup.report_failure("svc-a", "crash-2", 20);
        sup.report_failure("svc-a", "crash-3", 30);

        // 4th failure — budget exhausted, escalates
        let action = sup.report_failure("svc-a", "crash-4", 40).unwrap();
        assert_eq!(action, SupervisorAction::Escalate);
        assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Isolated));
    }

    #[test]
    fn temporary_service_never_restarts() {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(ServiceConfig {
            service_id: "tmp-svc".to_string(),
            restart_policy: RestartPolicy::Temporary,
            restart_budget: RestartBudget::default(),
            shutdown_order: 0,
        });
        sup.start_service("tmp-svc");

        let action = sup.report_failure("tmp-svc", "crash", 10).unwrap();
        assert_eq!(action, SupervisorAction::Terminate);
        assert_eq!(sup.service_state("tmp-svc"), Some(ServiceState::Terminated));
    }

    // -- Monotone severity --

    #[test]
    fn severity_escalates_monotonically() {
        assert_eq!(escalate_severity(Severity::Restart), Severity::Isolate);
        assert_eq!(
            escalate_severity(Severity::Isolate),
            Severity::SubtreeRestart
        );
        assert_eq!(
            escalate_severity(Severity::SubtreeRestart),
            Severity::SubtreeTerminate
        );
        assert_eq!(
            escalate_severity(Severity::SubtreeTerminate),
            Severity::RootEscalation
        );
        assert_eq!(
            escalate_severity(Severity::RootEscalation),
            Severity::RootEscalation
        );
    }

    #[test]
    fn repeated_escalation_increases_severity() {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(ServiceConfig {
            service_id: "svc".to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget {
                max_restarts: 1,
                window_ticks: 100,
            },
            shutdown_order: 0,
        });
        sup.start_service("svc");

        // First failure: restart (within budget)
        sup.report_failure("svc", "crash", 10);
        assert_eq!(sup.service_severity("svc"), Some(Severity::Restart));

        // Second failure: budget exhausted -> escalate to Isolate
        sup.report_failure("svc", "crash", 20);
        assert!(sup.service_severity("svc").unwrap() >= Severity::Isolate);
    }

    // -- Sliding window budget --

    #[test]
    fn budget_resets_after_window_expires() {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(ServiceConfig {
            service_id: "svc".to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget {
                max_restarts: 2,
                window_ticks: 100,
            },
            shutdown_order: 0,
        });
        sup.start_service("svc");

        // Two restarts within window
        sup.report_failure("svc", "crash", 10);
        sup.report_failure("svc", "crash", 20);

        // Next failure at t=200 (outside window of 100) — budget refreshed
        let action = sup.report_failure("svc", "crash", 200).unwrap();
        assert_eq!(action, SupervisorAction::Restart);
    }

    // -- Health reporting --

    #[test]
    fn healthy_when_all_running() {
        let sup = test_supervisor();
        assert_eq!(sup.health(), HealthStatus::Healthy);
    }

    #[test]
    fn critical_when_service_isolated() {
        let mut sup = test_supervisor();
        // Exhaust budget
        sup.report_failure("svc-a", "crash", 10);
        sup.report_failure("svc-a", "crash", 20);
        sup.report_failure("svc-a", "crash", 30);
        sup.report_failure("svc-a", "crash", 40);

        assert_eq!(sup.health(), HealthStatus::Critical);
    }

    // -- Shutdown ordering --

    #[test]
    fn shutdown_order_respects_priority() {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(ServiceConfig {
            service_id: "low".to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget::default(),
            shutdown_order: 1,
        });
        sup.add_service(ServiceConfig {
            service_id: "high".to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget::default(),
            shutdown_order: 10,
        });
        sup.add_service(ServiceConfig {
            service_id: "mid".to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget::default(),
            shutdown_order: 5,
        });

        let order = sup.shutdown_order();
        assert_eq!(order, vec!["high", "mid", "low"]);
    }

    // -- Events --

    #[test]
    fn events_emitted_on_start_and_failure() {
        let mut sup = test_supervisor();
        sup.report_failure("svc-a", "crash", 10);

        let events = sup.drain_events();
        assert!(events.len() >= 2); // start + restart
        assert_eq!(events[0].action, SupervisorAction::Start);
        assert_eq!(events[1].action, SupervisorAction::Restart);
    }

    #[test]
    fn event_carries_correct_fields() {
        let mut sup = test_supervisor();
        sup.report_failure("svc-a", "test_crash", 10);

        let events = sup.drain_events();
        let restart_event = events
            .iter()
            .find(|e| e.action == SupervisorAction::Restart)
            .unwrap();
        assert_eq!(restart_event.trace_id, "trace-1");
        assert_eq!(restart_event.service_id, "svc-a");
        assert_eq!(restart_event.reason, "test_crash");
        assert_eq!(restart_event.restart_count, 1);
        assert_eq!(restart_event.severity, Severity::Restart);
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<SupervisorEvent> {
            let mut sup = Supervisor::new("sup", "t");
            sup.add_service(ServiceConfig {
                service_id: "svc".to_string(),
                restart_policy: RestartPolicy::Permanent,
                restart_budget: RestartBudget {
                    max_restarts: 2,
                    window_ticks: 100,
                },
                shutdown_order: 0,
            });
            sup.start_service("svc");
            sup.report_failure("svc", "crash-1", 10);
            sup.report_failure("svc", "crash-2", 20);
            sup.report_failure("svc", "crash-3", 30);
            sup.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- Nonexistent service --

    #[test]
    fn operations_on_nonexistent_service_return_none() {
        let mut sup = Supervisor::new("sup", "t");
        assert!(!sup.start_service("ghost"));
        assert!(sup.report_failure("ghost", "crash", 10).is_none());
        assert!(sup.service_state("ghost").is_none());
        assert!(sup.restart_count("ghost").is_none());
    }

    // -- Serialization --

    #[test]
    fn severity_serialization_round_trip() {
        let severities = vec![
            Severity::Restart,
            Severity::Isolate,
            Severity::SubtreeRestart,
            Severity::SubtreeTerminate,
            Severity::RootEscalation,
        ];
        for s in &severities {
            let json = serde_json::to_string(s).expect("serialize");
            let restored: Severity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*s, restored);
        }
    }

    #[test]
    fn service_config_serialization_round_trip() {
        let config = test_config("svc-1");
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ServiceConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn supervisor_event_serialization_round_trip() {
        let event = SupervisorEvent {
            trace_id: "t".to_string(),
            service_id: "svc".to_string(),
            action: SupervisorAction::Restart,
            reason: "crash".to_string(),
            restart_count: 1,
            budget_remaining: 2,
            severity: Severity::Restart,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: SupervisorEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Multiple services --

    // -- Enrichment: serde roundtrips, Display, defaults --

    #[test]
    fn restart_policy_serde_roundtrip_all_variants() {
        let variants = [
            RestartPolicy::Permanent,
            RestartPolicy::Transient,
            RestartPolicy::Temporary,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: RestartPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn service_state_serde_roundtrip_all_variants() {
        let variants = [
            ServiceState::Starting,
            ServiceState::Running,
            ServiceState::Failed,
            ServiceState::Restarting,
            ServiceState::Isolated,
            ServiceState::Terminated,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: ServiceState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn service_state_display_all_variants() {
        let display_strs: Vec<String> = [
            ServiceState::Starting,
            ServiceState::Running,
            ServiceState::Failed,
            ServiceState::Restarting,
            ServiceState::Isolated,
            ServiceState::Terminated,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(display_strs.len(), 6);
        // All distinct
        let set: std::collections::BTreeSet<_> = display_strs.iter().collect();
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn health_status_serde_roundtrip_all_variants() {
        let variants = [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Critical,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: HealthStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn health_status_display_all_variants() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Critical.to_string(), "critical");
    }

    #[test]
    fn health_status_ordering() {
        assert!(HealthStatus::Healthy < HealthStatus::Degraded);
        assert!(HealthStatus::Degraded < HealthStatus::Critical);
    }

    #[test]
    fn supervisor_action_serde_roundtrip_all_variants() {
        let variants = [
            SupervisorAction::Start,
            SupervisorAction::Restart,
            SupervisorAction::Isolate,
            SupervisorAction::Terminate,
            SupervisorAction::Escalate,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: SupervisorAction = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn supervisor_action_display_all_variants() {
        let display_strs: Vec<String> = [
            SupervisorAction::Start,
            SupervisorAction::Restart,
            SupervisorAction::Isolate,
            SupervisorAction::Terminate,
            SupervisorAction::Escalate,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(display_strs.len(), 5);
        let set: std::collections::BTreeSet<_> = display_strs.iter().collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn restart_budget_default_values() {
        let d = RestartBudget::default();
        assert!(d.max_restarts > 0, "default budget should allow restarts");
        assert!(d.window_ticks > 0, "default window should be nonzero");
    }

    #[test]
    fn restart_budget_serde_roundtrip() {
        let b = RestartBudget {
            max_restarts: 5,
            window_ticks: 200,
        };
        let json = serde_json::to_string(&b).expect("serialize");
        let restored: RestartBudget = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(b, restored);
    }

    #[test]
    fn drain_events_on_fresh_supervisor_is_empty() {
        let mut sup = Supervisor::new("sup", "t");
        assert!(sup.drain_events().is_empty());
    }

    #[test]
    fn service_count_tracks_additions() {
        let mut sup = Supervisor::new("sup", "t");
        assert_eq!(sup.service_count(), 0);
        sup.add_service(test_config("a"));
        assert_eq!(sup.service_count(), 1);
        sup.add_service(test_config("b"));
        assert_eq!(sup.service_count(), 2);
    }

    // -- Multiple services --

    #[test]
    fn multiple_services_independent_budgets() {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(test_config("svc-a"));
        sup.add_service(test_config("svc-b"));
        sup.start_service("svc-a");
        sup.start_service("svc-b");

        // Exhaust svc-a budget
        sup.report_failure("svc-a", "crash", 10);
        sup.report_failure("svc-a", "crash", 20);
        sup.report_failure("svc-a", "crash", 30);
        sup.report_failure("svc-a", "crash", 40);

        // svc-b should still have full budget
        let action = sup.report_failure("svc-b", "crash", 50).unwrap();
        assert_eq!(action, SupervisorAction::Restart);
        assert_eq!(sup.service_state("svc-b"), Some(ServiceState::Running));
        assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Isolated));
    }
}
