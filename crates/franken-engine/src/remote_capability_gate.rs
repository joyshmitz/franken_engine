//! Remote operation capability gate — no implicit network side effects.
//!
//! All remote operations (HTTP, gRPC, DNS, distributed state mutations,
//! lease renewal, cross-process IPC) must pass through `RemoteOperationGate`
//! which verifies the caller holds `RemoteCaps` before dispatching.
//!
//! Rejection emits a typed `RemoteCapabilityDenied` error and a structured
//! evidence event. Permitted operations also emit audit events.
//!
//! Plan references: Section 10.11 item 20, 9G.7 (remote-effects contract).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// RemoteOperationType — classification of remote operations
// ---------------------------------------------------------------------------

/// Classification of remote operations subject to capability gating.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RemoteOperationType {
    /// Outbound HTTP/HTTPS request.
    HttpRequest,
    /// gRPC call.
    GrpcCall,
    /// DNS resolution (potential covert channel).
    DnsResolution,
    /// Distributed state mutation (anti-entropy sync, revocation propagation).
    DistributedStateMutation,
    /// Lease renewal or liveness check.
    LeaseRenewal,
    /// Cross-process IPC to a remote endpoint.
    RemoteIpc,
}

impl fmt::Display for RemoteOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpRequest => write!(f, "http_request"),
            Self::GrpcCall => write!(f, "grpc_call"),
            Self::DnsResolution => write!(f, "dns_resolution"),
            Self::DistributedStateMutation => write!(f, "distributed_state_mutation"),
            Self::LeaseRenewal => write!(f, "lease_renewal"),
            Self::RemoteIpc => write!(f, "remote_ipc"),
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteCapabilityDenied — denial error
// ---------------------------------------------------------------------------

/// Error when a remote operation is attempted without `RemoteCaps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCapabilityDenied {
    /// The operation that was attempted.
    pub operation: RemoteOperationType,
    /// The component that attempted the operation.
    pub component: String,
    /// The capability profile held by the caller.
    pub held_profile: ProfileKind,
    /// Specific capabilities that were required.
    pub required_capabilities: Vec<RuntimeCapability>,
    /// Trace identifier for the denied request.
    pub trace_id: String,
}

impl fmt::Display for RemoteCapabilityDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "remote capability denied: {} requires RemoteCaps but held profile {} does not grant it (component: {}, trace: {})",
            self.operation, self.held_profile, self.component, self.trace_id
        )
    }
}

impl std::error::Error for RemoteCapabilityDenied {}

// ---------------------------------------------------------------------------
// RemoteGateEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for remote operation gate decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteGateEvent {
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Component that requested the operation.
    pub component: String,
    /// Type of remote operation.
    pub operation_type: String,
    /// Sanitized remote endpoint (no credentials, IPs may be masked).
    pub remote_endpoint: String,
    /// Security epoch at time of decision.
    pub epoch_id: u64,
    /// Virtual timestamp.
    pub timestamp_ticks: u64,
    /// Outcome: "permitted" or "denied".
    pub outcome: String,
    /// Held profile kind.
    pub held_profile: String,
}

// ---------------------------------------------------------------------------
// RemoteOperationGate
// ---------------------------------------------------------------------------

/// Gate that enforces `RemoteCaps` before any remote operation.
///
/// All network-touching code must route through this gate. Attempts
/// without the required capability are rejected and logged.
#[derive(Debug)]
pub struct RemoteOperationGate {
    /// Current security epoch (remote ops must hold an epoch guard).
    current_epoch: SecurityEpoch,
    /// Accumulated audit events.
    events: Vec<RemoteGateEvent>,
    /// Counters by operation type.
    permitted_counts: BTreeMap<String, u64>,
    denied_counts: BTreeMap<String, u64>,
}

impl RemoteOperationGate {
    /// Create a new gate bound to the given security epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: epoch,
            events: Vec::new(),
            permitted_counts: BTreeMap::new(),
            denied_counts: BTreeMap::new(),
        }
    }

    /// Current epoch this gate is bound to.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Check whether a remote operation is permitted under the given profile.
    ///
    /// Returns `Ok(())` if the profile grants all required remote capabilities,
    /// or `Err(RemoteCapabilityDenied)` otherwise.
    pub fn check(
        &mut self,
        profile: &CapabilityProfile,
        operation: RemoteOperationType,
        component: &str,
        remote_endpoint: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> Result<(), RemoteCapabilityDenied> {
        let required = required_capabilities(&operation);
        let all_granted = required.iter().all(|cap| profile.has(*cap));

        let op_str = operation.to_string();
        let sanitized_endpoint = sanitize_endpoint(remote_endpoint);

        if all_granted {
            *self.permitted_counts.entry(op_str.clone()).or_insert(0) += 1;
            self.events.push(RemoteGateEvent {
                trace_id: trace_id.to_string(),
                component: component.to_string(),
                operation_type: op_str,
                remote_endpoint: sanitized_endpoint,
                epoch_id: self.current_epoch.as_u64(),
                timestamp_ticks,
                outcome: "permitted".to_string(),
                held_profile: profile.kind.to_string(),
            });
            Ok(())
        } else {
            *self.denied_counts.entry(op_str.clone()).or_insert(0) += 1;
            self.events.push(RemoteGateEvent {
                trace_id: trace_id.to_string(),
                component: component.to_string(),
                operation_type: op_str,
                remote_endpoint: sanitized_endpoint,
                epoch_id: self.current_epoch.as_u64(),
                timestamp_ticks,
                outcome: "denied".to_string(),
                held_profile: profile.kind.to_string(),
            });
            Err(RemoteCapabilityDenied {
                operation,
                component: component.to_string(),
                held_profile: profile.kind,
                required_capabilities: required,
                trace_id: trace_id.to_string(),
            })
        }
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<RemoteGateEvent> {
        std::mem::take(&mut self.events)
    }

    /// Total number of permitted operations.
    pub fn total_permitted(&self) -> u64 {
        self.permitted_counts.values().sum()
    }

    /// Total number of denied operations.
    pub fn total_denied(&self) -> u64 {
        self.denied_counts.values().sum()
    }

    /// Per-operation-type permitted counts.
    pub fn permitted_counts(&self) -> &BTreeMap<String, u64> {
        &self.permitted_counts
    }

    /// Per-operation-type denied counts.
    pub fn denied_counts(&self) -> &BTreeMap<String, u64> {
        &self.denied_counts
    }
}

// ---------------------------------------------------------------------------
// RemoteTransport — trait for network operations
// ---------------------------------------------------------------------------

/// Trait for remote transport operations. All network-touching code must
/// implement this trait and pass through a `RemoteOperationGate`.
///
/// Implementations must not perform any network I/O outside of this trait's
/// methods.
pub trait RemoteTransport {
    /// Execute a remote operation, returning the response as bytes.
    ///
    /// The gate check must be performed before calling this method.
    fn execute(
        &mut self,
        operation: &RemoteOperationType,
        endpoint: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, RemoteTransportError>;
}

/// Error from remote transport execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteTransportError {
    /// Connection refused or unreachable.
    ConnectionFailed { endpoint: String, reason: String },
    /// Remote endpoint returned an error.
    RemoteError { status: u32, message: String },
    /// Operation timed out.
    Timeout { endpoint: String, duration_ms: u64 },
    /// Capability gate denied the operation.
    CapabilityDenied(RemoteCapabilityDenied),
}

impl fmt::Display for RemoteTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed { endpoint, reason } => {
                write!(f, "connection failed to {endpoint}: {reason}")
            }
            Self::RemoteError { status, message } => {
                write!(f, "remote error {status}: {message}")
            }
            Self::Timeout {
                endpoint,
                duration_ms,
            } => write!(f, "timeout after {duration_ms}ms to {endpoint}"),
            Self::CapabilityDenied(denied) => write!(f, "{denied}"),
        }
    }
}

impl std::error::Error for RemoteTransportError {}

// ---------------------------------------------------------------------------
// MockRemoteTransport — test double
// ---------------------------------------------------------------------------

/// Mock transport that records operations without actual network I/O.
#[derive(Debug, Default)]
pub struct MockRemoteTransport {
    /// Recorded operations.
    pub recorded: Vec<RecordedOperation>,
    /// Canned response to return for all operations.
    pub response: Vec<u8>,
    /// If set, all operations will fail with this error.
    pub fail_with: Option<RemoteTransportError>,
}

/// A recorded operation from the mock transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedOperation {
    pub operation: RemoteOperationType,
    pub endpoint: String,
    pub payload: Vec<u8>,
}

impl RemoteTransport for MockRemoteTransport {
    fn execute(
        &mut self,
        operation: &RemoteOperationType,
        endpoint: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, RemoteTransportError> {
        self.recorded.push(RecordedOperation {
            operation: operation.clone(),
            endpoint: endpoint.to_string(),
            payload: payload.to_vec(),
        });

        if let Some(ref err) = self.fail_with {
            return Err(err.clone());
        }

        Ok(self.response.clone())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine which capabilities are required for a given operation type.
fn required_capabilities(operation: &RemoteOperationType) -> Vec<RuntimeCapability> {
    match operation {
        RemoteOperationType::HttpRequest | RemoteOperationType::GrpcCall => {
            vec![RuntimeCapability::NetworkEgress]
        }
        RemoteOperationType::DnsResolution => {
            vec![RuntimeCapability::NetworkEgress]
        }
        RemoteOperationType::DistributedStateMutation => {
            vec![RuntimeCapability::NetworkEgress]
        }
        RemoteOperationType::LeaseRenewal => {
            vec![
                RuntimeCapability::NetworkEgress,
                RuntimeCapability::LeaseManagement,
            ]
        }
        RemoteOperationType::RemoteIpc => {
            vec![RuntimeCapability::NetworkEgress]
        }
    }
}

/// Sanitize a remote endpoint for logging (remove credentials, mask IPs).
fn sanitize_endpoint(endpoint: &str) -> String {
    // Strip userinfo from URLs (scheme://user:pass@host -> scheme://***@host).
    if let Some(scheme_end) = endpoint.find("://") {
        let after_scheme = &endpoint[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            let host_part = &after_scheme[at_pos..];
            return format!("{}://***{host_part}", &endpoint[..scheme_end]);
        }
    }
    endpoint.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityProfile;

    fn remote_profile() -> CapabilityProfile {
        CapabilityProfile::remote()
    }

    fn compute_only_profile() -> CapabilityProfile {
        CapabilityProfile::compute_only()
    }

    fn engine_core_profile() -> CapabilityProfile {
        CapabilityProfile::engine_core()
    }

    fn full_profile() -> CapabilityProfile {
        CapabilityProfile::full()
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // -- Gate permits with RemoteCaps --

    #[test]
    fn remote_profile_permits_http() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &remote_profile(),
                RemoteOperationType::HttpRequest,
                "sync",
                "https://example.com/api",
                "trace-1",
                100
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_profile_permits_grpc() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &remote_profile(),
                RemoteOperationType::GrpcCall,
                "rpc",
                "grpc://node:50051",
                "trace-2",
                200
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_profile_permits_dns() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &remote_profile(),
                RemoteOperationType::DnsResolution,
                "resolver",
                "dns://8.8.8.8",
                "trace-3",
                300
            )
            .is_ok()
        );
    }

    #[test]
    fn full_profile_permits_all_remote_ops() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let ops = vec![
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        for op in ops {
            assert!(
                gate.check(&full_profile(), op.clone(), "test", "endpoint", "t", 0)
                    .is_ok(),
                "full profile should permit {op}"
            );
        }
    }

    // -- Gate denies without RemoteCaps --

    #[test]
    fn compute_only_denies_http() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let err = gate
            .check(
                &compute_only_profile(),
                RemoteOperationType::HttpRequest,
                "compute",
                "https://evil.com",
                "trace-x",
                100,
            )
            .unwrap_err();
        assert_eq!(err.operation, RemoteOperationType::HttpRequest);
        assert_eq!(err.held_profile, ProfileKind::ComputeOnly);
    }

    #[test]
    fn engine_core_denies_grpc() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let err = gate
            .check(
                &engine_core_profile(),
                RemoteOperationType::GrpcCall,
                "engine",
                "grpc://host",
                "trace-y",
                200,
            )
            .unwrap_err();
        assert_eq!(err.operation, RemoteOperationType::GrpcCall);
        assert_eq!(err.held_profile, ProfileKind::EngineCore);
    }

    #[test]
    fn compute_only_denies_dns() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &compute_only_profile(),
                RemoteOperationType::DnsResolution,
                "resolver",
                "dns://8.8.8.8",
                "trace-z",
                300
            )
            .is_err()
        );
    }

    #[test]
    fn compute_only_denies_all_remote_ops() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let ops = vec![
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        for op in ops {
            assert!(
                gate.check(
                    &compute_only_profile(),
                    op.clone(),
                    "test",
                    "endpoint",
                    "t",
                    0
                )
                .is_err(),
                "compute-only should deny {op}"
            );
        }
    }

    // -- Audit events --

    #[test]
    fn permitted_emits_event() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "sync",
            "https://example.com",
            "trace-1",
            100,
        )
        .unwrap();

        let events = gate.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "permitted");
        assert_eq!(events[0].operation_type, "http_request");
        assert_eq!(events[0].trace_id, "trace-1");
    }

    #[test]
    fn denied_emits_event() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::HttpRequest,
            "compute",
            "https://evil.com",
            "trace-x",
            200,
        );

        let events = gate.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "denied");
        assert_eq!(events[0].held_profile, "ComputeOnlyCaps");
    }

    #[test]
    fn drain_events_clears() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t",
            0,
        )
        .unwrap();
        let e1 = gate.drain_events();
        assert_eq!(e1.len(), 1);
        let e2 = gate.drain_events();
        assert!(e2.is_empty());
    }

    // -- Counters --

    #[test]
    fn counters_track_permits_and_denials() {
        let mut gate = RemoteOperationGate::new(test_epoch());

        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t1",
            0,
        )
        .unwrap();
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t2",
            0,
        )
        .unwrap();
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::GrpcCall,
            "c",
            "e",
            "t3",
            0,
        );

        assert_eq!(gate.total_permitted(), 2);
        assert_eq!(gate.total_denied(), 1);
        assert_eq!(gate.permitted_counts().get("http_request"), Some(&2));
        assert_eq!(gate.denied_counts().get("grpc_call"), Some(&1));
    }

    // -- Endpoint sanitization --

    #[test]
    fn sanitize_strips_credentials() {
        assert_eq!(
            sanitize_endpoint("https://user:password@example.com/path"),
            "https://***@example.com/path"
        );
    }

    #[test]
    fn sanitize_preserves_clean_url() {
        assert_eq!(
            sanitize_endpoint("https://example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn sanitize_preserves_non_url() {
        assert_eq!(sanitize_endpoint("some-endpoint"), "some-endpoint");
    }

    // -- Mock transport --

    #[test]
    fn mock_transport_records_operations() {
        let mut transport = MockRemoteTransport {
            response: b"ok".to_vec(),
            ..Default::default()
        };

        let result = transport
            .execute(
                &RemoteOperationType::HttpRequest,
                "https://example.com",
                b"payload",
            )
            .unwrap();

        assert_eq!(result, b"ok");
        assert_eq!(transport.recorded.len(), 1);
        assert_eq!(
            transport.recorded[0].operation,
            RemoteOperationType::HttpRequest
        );
        assert_eq!(transport.recorded[0].endpoint, "https://example.com");
    }

    #[test]
    fn mock_transport_can_fail() {
        let mut transport = MockRemoteTransport {
            fail_with: Some(RemoteTransportError::Timeout {
                endpoint: "x".to_string(),
                duration_ms: 5000,
            }),
            ..Default::default()
        };

        let err = transport
            .execute(&RemoteOperationType::HttpRequest, "x", b"")
            .unwrap_err();
        assert!(matches!(err, RemoteTransportError::Timeout { .. }));
    }

    // -- Required capabilities --

    #[test]
    fn lease_renewal_requires_two_capabilities() {
        let caps = required_capabilities(&RemoteOperationType::LeaseRenewal);
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&RuntimeCapability::NetworkEgress));
        assert!(caps.contains(&RuntimeCapability::LeaseManagement));
    }

    #[test]
    fn http_requires_network_egress() {
        let caps = required_capabilities(&RemoteOperationType::HttpRequest);
        assert_eq!(caps, vec![RuntimeCapability::NetworkEgress]);
    }

    // -- Serialization --

    #[test]
    fn denied_error_serialization_round_trip() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-1".to_string(),
        };
        let json = serde_json::to_string(&denied).expect("serialize");
        let restored: RemoteCapabilityDenied = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(denied, restored);
    }

    #[test]
    fn gate_event_serialization_round_trip() {
        let event = RemoteGateEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            operation_type: "http_request".to_string(),
            remote_endpoint: "e".to_string(),
            epoch_id: 1,
            timestamp_ticks: 100,
            outcome: "permitted".to_string(),
            held_profile: "RemoteCaps".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: RemoteGateEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn transport_error_serialization_round_trip() {
        let errors = vec![
            RemoteTransportError::ConnectionFailed {
                endpoint: "x".to_string(),
                reason: "refused".to_string(),
            },
            RemoteTransportError::Timeout {
                endpoint: "y".to_string(),
                duration_ms: 5000,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: RemoteTransportError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn denied_error_display() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "sync".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-1".to_string(),
        };
        let msg = denied.to_string();
        assert!(msg.contains("http_request"));
        assert!(msg.contains("ComputeOnlyCaps"));
        assert!(msg.contains("sync"));
    }

    // -- Enrichment: serde, std::error --

    #[test]
    fn remote_operation_type_serde_all_variants() {
        let all = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        for op in &all {
            let json = serde_json::to_string(op).expect("serialize");
            let restored: RemoteOperationType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*op, restored);
        }
    }

    #[test]
    fn remote_transport_error_implements_std_error() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t-1".to_string(),
        };
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(RemoteTransportError::ConnectionFailed {
                endpoint: "http://localhost".into(),
                reason: "refused".into(),
            }),
            Box::new(RemoteTransportError::RemoteError {
                status: 500,
                message: "internal".into(),
            }),
            Box::new(RemoteTransportError::Timeout {
                endpoint: "http://localhost".into(),
                duration_ms: 5000,
            }),
            Box::new(RemoteTransportError::CapabilityDenied(denied)),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    #[test]
    fn operation_type_display() {
        assert_eq!(RemoteOperationType::HttpRequest.to_string(), "http_request");
        assert_eq!(
            RemoteOperationType::DistributedStateMutation.to_string(),
            "distributed_state_mutation"
        );
    }

    // -- Enrichment: gate starts empty --

    #[test]
    fn gate_starts_empty() {
        let gate = RemoteOperationGate::new(test_epoch());
        assert_eq!(gate.total_permitted(), 0);
        assert_eq!(gate.total_denied(), 0);
        assert!(gate.permitted_counts().is_empty());
        assert!(gate.denied_counts().is_empty());
    }

    #[test]
    fn gate_epoch_accessor() {
        let epoch = SecurityEpoch::from_raw(42);
        let gate = RemoteOperationGate::new(epoch);
        assert_eq!(gate.epoch(), epoch);
    }

    // -- Enrichment: transport error display all variants --

    #[test]
    fn transport_error_display_all_variants() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t".to_string(),
        };
        let errors: Vec<RemoteTransportError> = vec![
            RemoteTransportError::ConnectionFailed {
                endpoint: "http://host".to_string(),
                reason: "refused".to_string(),
            },
            RemoteTransportError::RemoteError {
                status: 503,
                message: "service unavailable".to_string(),
            },
            RemoteTransportError::Timeout {
                endpoint: "http://host".to_string(),
                duration_ms: 3000,
            },
            RemoteTransportError::CapabilityDenied(denied),
        ];
        assert_eq!(
            errors.len(),
            4,
            "must cover all RemoteTransportError variants"
        );
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
        assert!(errors[0].to_string().contains("refused"));
        assert!(errors[1].to_string().contains("503"));
        assert!(errors[2].to_string().contains("3000"));
        assert!(errors[3].to_string().contains("http_request"));
    }

    // -- Enrichment: denied error is std::error --

    #[test]
    fn remote_capability_denied_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(RemoteCapabilityDenied {
            operation: RemoteOperationType::GrpcCall,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: mock transport default --

    #[test]
    fn mock_remote_transport_default_empty() {
        let transport = MockRemoteTransport::default();
        assert!(transport.recorded.is_empty());
        assert!(transport.response.is_empty());
        assert!(transport.fail_with.is_none());
    }

    // -- Enrichment: operation type ordering --

    #[test]
    fn operation_type_ordering_deterministic() {
        let mut ops = [
            RemoteOperationType::RemoteIpc,
            RemoteOperationType::HttpRequest,
            RemoteOperationType::DnsResolution,
        ];
        ops.sort();
        // HttpRequest < DnsResolution < RemoteIpc (derived Ord)
        assert_eq!(ops[0], RemoteOperationType::HttpRequest);
    }

    // -- Enrichment: display all operation types --

    #[test]
    fn operation_type_display_all_variants() {
        let all = [
            (RemoteOperationType::HttpRequest, "http_request"),
            (RemoteOperationType::GrpcCall, "grpc_call"),
            (RemoteOperationType::DnsResolution, "dns_resolution"),
            (
                RemoteOperationType::DistributedStateMutation,
                "distributed_state_mutation",
            ),
            (RemoteOperationType::LeaseRenewal, "lease_renewal"),
            (RemoteOperationType::RemoteIpc, "remote_ipc"),
        ];
        for (op, expected) in all {
            assert_eq!(op.to_string(), expected);
        }
    }

    // -- Enrichment: remote error serde --

    #[test]
    fn remote_error_serde_roundtrip() {
        let err = RemoteTransportError::RemoteError {
            status: 500,
            message: "internal server error".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: RemoteTransportError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- Enrichment: sanitize no credentials --

    #[test]
    fn sanitize_no_at_sign_in_url() {
        assert_eq!(
            sanitize_endpoint("https://example.com:8080/path"),
            "https://example.com:8080/path"
        );
    }

    // -- Enrichment: counters per-type tracking --

    #[test]
    fn counters_track_multiple_operation_types() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t1",
            0,
        )
        .unwrap();
        gate.check(
            &remote_profile(),
            RemoteOperationType::GrpcCall,
            "s",
            "e",
            "t2",
            0,
        )
        .unwrap();
        gate.check(
            &remote_profile(),
            RemoteOperationType::DnsResolution,
            "s",
            "e",
            "t3",
            0,
        )
        .unwrap();

        assert_eq!(gate.total_permitted(), 3);
        assert_eq!(gate.permitted_counts().len(), 3);
        assert_eq!(gate.permitted_counts().get("http_request"), Some(&1));
        assert_eq!(gate.permitted_counts().get("grpc_call"), Some(&1));
        assert_eq!(gate.permitted_counts().get("dns_resolution"), Some(&1));
    }
}
