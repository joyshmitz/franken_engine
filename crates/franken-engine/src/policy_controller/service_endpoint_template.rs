//! Service endpoint integration template aligned to `fastapi_rust` conventions.
//!
//! This module defines framework-agnostic request/response envelopes for
//! service surfaces that FrankenEngine exposes to operators and automation:
//! - health
//! - control actions
//! - evidence export
//! - replay control
//!
//! The goal is to keep endpoint contracts deterministic and easy to bind to a
//! concrete transport layer while preserving stable structured-log fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const SCOPE_HEALTH_READ: &str = "engine.health.read";
pub const SCOPE_CONTROL_WRITE: &str = "engine.control.write";
pub const SCOPE_EVIDENCE_READ: &str = "engine.evidence.read";
pub const SCOPE_REPLAY_READ: &str = "engine.replay.read";
pub const SCOPE_REPLAY_WRITE: &str = "engine.replay.write";

/// Shared request context populated by transport adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub trace_id: String,
    pub request_id: String,
    pub component: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
}

/// Authentication principal and granted scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub subject: String,
    pub scopes: Vec<String>,
}

impl AuthContext {
    pub fn has_scope(&self, required_scope: &str) -> bool {
        self.scopes.iter().any(|scope| scope == required_scope)
    }
}

/// Canonical structured log event for endpoint execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Canonical error envelope aligned with service API contract expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error_code: String,
    pub message: String,
    pub trace_id: String,
    pub component: String,
    pub details: BTreeMap<String, String>,
}

/// Canonical endpoint response envelope for transport adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointResponse<T> {
    pub status: String,
    pub endpoint: String,
    pub trace_id: String,
    pub request_id: String,
    pub data: Option<T>,
    pub error: Option<ErrorEnvelope>,
    pub log: StructuredLogEvent,
}

/// Framework-agnostic failure returned from backend providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointFailure {
    pub error_code: String,
    pub message: String,
    pub details: BTreeMap<String, String>,
}

impl EndpointFailure {
    pub fn new(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_code: error_code.into(),
            message: message.into(),
            details: BTreeMap::new(),
        }
    }
}

/// Health endpoint payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatusResponse {
    pub runtime_status: String,
    pub loaded_extensions: Vec<String>,
    pub security_epoch: u64,
    pub gc_pressure_basis_points: u16,
}

/// Control endpoint action verbs routed through decision contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlAction {
    Start,
    Stop,
    Suspend,
    Quarantine,
}

/// Control action request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlActionRequest {
    pub extension_id: String,
    pub action: ControlAction,
    pub reason: String,
}

/// Control action response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlActionResponse {
    pub extension_id: String,
    pub action: ControlAction,
    pub accepted: bool,
    pub decision_id: String,
}

/// Evidence export request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportRequest {
    pub since_epoch_seconds: u64,
    pub until_epoch_seconds: Option<u64>,
    pub page_size: u16,
    pub cursor: Option<String>,
}

/// Evidence record payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub artifact_ref: String,
}

/// Evidence export response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportResponse {
    pub records: Vec<EvidenceRecord>,
    pub next_cursor: Option<String>,
}

/// Replay endpoint action verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayCommand {
    Start,
    Stop,
    Status,
}

/// Replay control request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayControlRequest {
    pub command: ReplayCommand,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
}

/// Replay control response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayControlResponse {
    pub session_id: String,
    pub state: String,
    pub trace_id: Option<String>,
    pub note: String,
}

pub trait RuntimeHealthProvider {
    fn read_health(&self) -> HealthStatusResponse;
}

pub trait DecisionContractExecutor {
    fn execute_control_action(
        &mut self,
        request: &ControlActionRequest,
        context: &RequestContext,
    ) -> Result<ControlActionResponse, EndpointFailure>;
}

pub trait EvidenceExportProvider {
    fn export_evidence(
        &self,
        request: &EvidenceExportRequest,
        context: &RequestContext,
    ) -> Result<EvidenceExportResponse, EndpointFailure>;
}

pub trait ReplayController {
    fn control_replay(
        &mut self,
        request: &ReplayControlRequest,
        context: &RequestContext,
    ) -> Result<ReplayControlResponse, EndpointFailure>;
}

/// Thin endpoint template that transport adapters can wrap.
#[derive(Debug)]
pub struct ServiceEndpointTemplate<H, D, E, R> {
    health_provider: H,
    decision_executor: D,
    evidence_provider: E,
    replay_controller: R,
}

impl<H, D, E, R> ServiceEndpointTemplate<H, D, E, R>
where
    H: RuntimeHealthProvider,
    D: DecisionContractExecutor,
    E: EvidenceExportProvider,
    R: ReplayController,
{
    pub fn new(
        health_provider: H,
        decision_executor: D,
        evidence_provider: E,
        replay_controller: R,
    ) -> Self {
        Self {
            health_provider,
            decision_executor,
            evidence_provider,
            replay_controller,
        }
    }

    pub fn health_endpoint(
        &self,
        auth: &AuthContext,
        context: &RequestContext,
    ) -> EndpointResponse<HealthStatusResponse> {
        if !auth.has_scope(SCOPE_HEALTH_READ) {
            return unauthorized("health", context, SCOPE_HEALTH_READ);
        }

        ok_response(
            "health",
            "health.read",
            context,
            self.health_provider.read_health(),
        )
    }

    pub fn control_action_endpoint(
        &mut self,
        auth: &AuthContext,
        context: &RequestContext,
        request: &ControlActionRequest,
    ) -> EndpointResponse<ControlActionResponse> {
        if !auth.has_scope(SCOPE_CONTROL_WRITE) {
            return unauthorized("control_action", context, SCOPE_CONTROL_WRITE);
        }
        if let Some(error) = validate_control_action_request(request, context) {
            return error;
        }

        match self
            .decision_executor
            .execute_control_action(request, context)
        {
            Ok(response) => ok_response("control_action", "control.execute", context, response),
            Err(failure) => upstream_failure("control_action", context, failure),
        }
    }

    pub fn evidence_export_endpoint(
        &self,
        auth: &AuthContext,
        context: &RequestContext,
        request: &EvidenceExportRequest,
    ) -> EndpointResponse<EvidenceExportResponse> {
        if !auth.has_scope(SCOPE_EVIDENCE_READ) {
            return unauthorized("evidence_export", context, SCOPE_EVIDENCE_READ);
        }
        if let Some(error) = validate_evidence_export_request(request, context) {
            return error;
        }

        match self.evidence_provider.export_evidence(request, context) {
            Ok(response) => ok_response("evidence_export", "evidence.export", context, response),
            Err(failure) => upstream_failure("evidence_export", context, failure),
        }
    }

    pub fn replay_control_endpoint(
        &mut self,
        auth: &AuthContext,
        context: &RequestContext,
        request: &ReplayControlRequest,
    ) -> EndpointResponse<ReplayControlResponse> {
        let required_scope = match request.command {
            ReplayCommand::Status => SCOPE_REPLAY_READ,
            ReplayCommand::Start | ReplayCommand::Stop => SCOPE_REPLAY_WRITE,
        };
        if !auth.has_scope(required_scope) {
            return unauthorized("replay_control", context, required_scope);
        }
        if let Some(error) = validate_replay_control_request(request, context) {
            return error;
        }

        match self.replay_controller.control_replay(request, context) {
            Ok(response) => ok_response("replay_control", "replay.control", context, response),
            Err(failure) => upstream_failure("replay_control", context, failure),
        }
    }
}

fn validate_control_action_request(
    request: &ControlActionRequest,
    context: &RequestContext,
) -> Option<EndpointResponse<ControlActionResponse>> {
    if request.extension_id.trim().is_empty() {
        return Some(invalid_request(
            "control_action",
            context,
            "extension_id",
            "must not be empty",
        ));
    }
    if request.reason.trim().is_empty() {
        return Some(invalid_request(
            "control_action",
            context,
            "reason",
            "must not be empty",
        ));
    }
    if request.reason.chars().count() > 256 {
        return Some(invalid_request(
            "control_action",
            context,
            "reason",
            "must be <= 256 characters",
        ));
    }
    None
}

fn validate_evidence_export_request(
    request: &EvidenceExportRequest,
    context: &RequestContext,
) -> Option<EndpointResponse<EvidenceExportResponse>> {
    if request.page_size == 0 || request.page_size > 1_000 {
        return Some(invalid_request(
            "evidence_export",
            context,
            "page_size",
            "must be within 1..=1000",
        ));
    }
    if let Some(until) = request.until_epoch_seconds
        && until < request.since_epoch_seconds
    {
        return Some(invalid_request(
            "evidence_export",
            context,
            "until_epoch_seconds",
            "must be >= since_epoch_seconds",
        ));
    }
    None
}

fn validate_replay_control_request(
    request: &ReplayControlRequest,
    context: &RequestContext,
) -> Option<EndpointResponse<ReplayControlResponse>> {
    match request.command {
        ReplayCommand::Start => {
            if request
                .trace_id
                .as_ref()
                .is_none_or(|trace| trace.trim().is_empty())
            {
                return Some(invalid_request(
                    "replay_control",
                    context,
                    "trace_id",
                    "must be present for start command",
                ));
            }
        }
        ReplayCommand::Stop | ReplayCommand::Status => {
            if request
                .session_id
                .as_ref()
                .is_none_or(|session| session.trim().is_empty())
            {
                return Some(invalid_request(
                    "replay_control",
                    context,
                    "session_id",
                    "must be present for stop/status command",
                ));
            }
        }
    }
    None
}

fn ok_response<T>(
    endpoint: &str,
    event: &str,
    context: &RequestContext,
    data: T,
) -> EndpointResponse<T> {
    EndpointResponse {
        status: "ok".to_string(),
        endpoint: endpoint.to_string(),
        trace_id: context.trace_id.clone(),
        request_id: context.request_id.clone(),
        data: Some(data),
        error: None,
        log: StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.component.clone(),
            event: event.to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        },
    }
}

fn unauthorized<T>(
    endpoint: &str,
    context: &RequestContext,
    required_scope: &str,
) -> EndpointResponse<T> {
    let mut details = BTreeMap::new();
    details.insert("required_scope".to_string(), required_scope.to_string());
    error_response(
        endpoint,
        "authz.denied",
        context,
        "unauthorized",
        "missing required scope",
        details,
    )
}

fn invalid_request<T>(
    endpoint: &str,
    context: &RequestContext,
    field: &str,
    reason: &str,
) -> EndpointResponse<T> {
    let mut details = BTreeMap::new();
    details.insert("field".to_string(), field.to_string());
    details.insert("reason".to_string(), reason.to_string());
    error_response(
        endpoint,
        "request.invalid",
        context,
        "invalid_request",
        "request validation failed",
        details,
    )
}

fn upstream_failure<T>(
    endpoint: &str,
    context: &RequestContext,
    failure: EndpointFailure,
) -> EndpointResponse<T> {
    error_response(
        endpoint,
        "backend.failure",
        context,
        &failure.error_code,
        &failure.message,
        failure.details,
    )
}

fn error_response<T>(
    endpoint: &str,
    event: &str,
    context: &RequestContext,
    error_code: &str,
    message: &str,
    details: BTreeMap<String, String>,
) -> EndpointResponse<T> {
    EndpointResponse {
        status: "error".to_string(),
        endpoint: endpoint.to_string(),
        trace_id: context.trace_id.clone(),
        request_id: context.request_id.clone(),
        data: None,
        error: Some(ErrorEnvelope {
            error_code: error_code.to_string(),
            message: message.to_string(),
            trace_id: context.trace_id.clone(),
            component: context.component.clone(),
            details,
        }),
        log: StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.component.clone(),
            event: event.to_string(),
            outcome: "error".to_string(),
            error_code: Some(error_code.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    fn context() -> RequestContext {
        RequestContext {
            trace_id: "trace-01".to_string(),
            request_id: "req-01".to_string(),
            component: "service.api".to_string(),
            decision_id: Some("decision-01".to_string()),
            policy_id: Some("policy-01".to_string()),
        }
    }

    fn auth_with_scopes(scopes: &[&str]) -> AuthContext {
        AuthContext {
            subject: "operator@example".to_string(),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
    }

    #[derive(Debug, Clone)]
    struct MockHealthProvider {
        snapshot: HealthStatusResponse,
    }

    impl RuntimeHealthProvider for MockHealthProvider {
        fn read_health(&self) -> HealthStatusResponse {
            self.snapshot.clone()
        }
    }

    #[derive(Debug, Clone)]
    struct MockDecisionExecutor {
        calls: Rc<Cell<u32>>,
    }

    impl DecisionContractExecutor for MockDecisionExecutor {
        fn execute_control_action(
            &mut self,
            request: &ControlActionRequest,
            _context: &RequestContext,
        ) -> Result<ControlActionResponse, EndpointFailure> {
            self.calls.set(self.calls.get() + 1);
            Ok(ControlActionResponse {
                extension_id: request.extension_id.clone(),
                action: request.action,
                accepted: true,
                decision_id: "decision-contract-7".to_string(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct MockEvidenceProvider;

    impl EvidenceExportProvider for MockEvidenceProvider {
        fn export_evidence(
            &self,
            request: &EvidenceExportRequest,
            _context: &RequestContext,
        ) -> Result<EvidenceExportResponse, EndpointFailure> {
            Ok(EvidenceExportResponse {
                records: vec![EvidenceRecord {
                    trace_id: "trace-01".to_string(),
                    decision_id: "decision-01".to_string(),
                    policy_id: "policy-01".to_string(),
                    component: "policy_controller".to_string(),
                    event: "decision.publish".to_string(),
                    outcome: "allow".to_string(),
                    artifact_ref: format!("evidence://cursor/{}", request.page_size),
                }],
                next_cursor: request.cursor.clone(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct MockReplayController;

    impl ReplayController for MockReplayController {
        fn control_replay(
            &mut self,
            request: &ReplayControlRequest,
            _context: &RequestContext,
        ) -> Result<ReplayControlResponse, EndpointFailure> {
            let (session_id, state, note) = match request.command {
                ReplayCommand::Start => (
                    "session-01".to_string(),
                    "running".to_string(),
                    "replay session started".to_string(),
                ),
                ReplayCommand::Stop => (
                    request
                        .session_id
                        .clone()
                        .unwrap_or_else(|| "session-unknown".to_string()),
                    "stopped".to_string(),
                    "replay session stopped".to_string(),
                ),
                ReplayCommand::Status => (
                    request
                        .session_id
                        .clone()
                        .unwrap_or_else(|| "session-unknown".to_string()),
                    "running".to_string(),
                    "replay session status".to_string(),
                ),
            };
            Ok(ReplayControlResponse {
                session_id,
                state,
                trace_id: request.trace_id.clone(),
                note,
            })
        }
    }

    fn template(
        call_counter: Rc<Cell<u32>>,
    ) -> ServiceEndpointTemplate<
        MockHealthProvider,
        MockDecisionExecutor,
        MockEvidenceProvider,
        MockReplayController,
    > {
        ServiceEndpointTemplate::new(
            MockHealthProvider {
                snapshot: HealthStatusResponse {
                    runtime_status: "healthy".to_string(),
                    loaded_extensions: vec!["ext-a".to_string(), "ext-b".to_string()],
                    security_epoch: 42,
                    gc_pressure_basis_points: 180,
                },
            },
            MockDecisionExecutor {
                calls: call_counter,
            },
            MockEvidenceProvider,
            MockReplayController,
        )
    }

    #[test]
    fn health_endpoint_response_schema_is_stable() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());

        assert_eq!(response.status, "ok");
        assert_eq!(response.endpoint, "health");
        let data = response.data.expect("health payload");
        assert_eq!(data.runtime_status, "healthy");
        assert_eq!(data.security_epoch, 42);
        assert_eq!(response.log.event, "health.read");
        assert_eq!(response.log.outcome, "ok");
    }

    #[test]
    fn health_endpoint_reflects_provider_state() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());
        let payload = response.data.expect("payload");
        assert_eq!(payload.loaded_extensions, vec!["ext-a", "ext-b"]);
        assert_eq!(payload.gc_pressure_basis_points, 180);
    }

    #[test]
    fn control_action_requires_valid_request() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: " ".to_string(),
                action: ControlAction::Suspend,
                reason: "maintenance".to_string(),
            },
        );

        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "invalid_request");
        assert_eq!(error.details["field"], "extension_id");
        assert_eq!(response.log.error_code.as_deref(), Some("invalid_request"));
    }

    #[test]
    fn control_action_routes_through_decision_contract() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(Rc::clone(&calls));
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Quarantine,
                reason: "risk threshold crossed".to_string(),
            },
        );

        assert_eq!(response.status, "ok");
        let payload = response.data.expect("control payload");
        assert_eq!(payload.decision_id, "decision-contract-7");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn evidence_export_validation_returns_structured_error() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 50,
                until_epoch_seconds: Some(49),
                page_size: 100,
                cursor: None,
            },
        );

        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "invalid_request");
        assert_eq!(error.details["field"], "until_epoch_seconds");
    }

    #[test]
    fn evidence_export_success_schema() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 1,
                until_epoch_seconds: Some(10),
                page_size: 25,
                cursor: Some("cursor-a".to_string()),
            },
        );

        assert_eq!(response.status, "ok");
        let payload = response.data.expect("evidence payload");
        assert_eq!(payload.records.len(), 1);
        assert_eq!(payload.records[0].artifact_ref, "evidence://cursor/25");
        assert_eq!(payload.next_cursor.as_deref(), Some("cursor-a"));
    }

    #[test]
    fn replay_control_uses_scope_by_command() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);

        let denied = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Status,
                trace_id: None,
                session_id: Some("session-42".to_string()),
            },
        );
        assert_eq!(denied.status, "error");
        assert_eq!(denied.error.expect("error").error_code, "unauthorized");

        let allowed = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_READ]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Status,
                trace_id: None,
                session_id: Some("session-42".to_string()),
            },
        );
        assert_eq!(allowed.status, "ok");
        assert_eq!(
            allowed.data.expect("replay payload").session_id,
            "session-42"
        );
    }

    #[test]
    fn response_is_serializable_for_dashboard_consumers() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());

        let json = serde_json::to_value(response).expect("serialize response");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["endpoint"], "health");
        assert!(json["trace_id"].is_string());
        assert!(json["log"]["event"].is_string());
    }
}
