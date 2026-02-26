//! FRX-20.4 deterministic unit/e2e test logging schema + correlation policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TEST_LOGGING_CONTRACT_SCHEMA_VERSION: &str = "frx.test-logging-schema.contract.v1";
pub const TEST_LOG_EVENT_SCHEMA_VERSION: &str = "frx.test-log-event.v1";
pub const TEST_LOGGING_FAILURE_CODE: &str = "FE-FRX-20-4-LOG-SCHEMA-0001";
pub const TEST_LOGGING_COMPONENT: &str = "frx_test_logging_schema";

const REQUIRED_FIELDS: [&str; 13] = [
    "scenario_id",
    "fixture_id",
    "trace_id",
    "decision_id",
    "policy_id",
    "lane",
    "component",
    "event",
    "outcome",
    "error_code",
    "seed",
    "timing_us",
    "timestamp_unix_ms",
];

const REQUIRED_CORRELATION_IDS: [&str; 5] = [
    "scenario_id",
    "trace_id",
    "decision_id",
    "policy_id",
    "seed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestLane {
    Compiler,
    Runtime,
    Router,
    Governance,
    E2e,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureTaxonomy {
    DeterminismDrift,
    InvariantViolation,
    Timeout,
    ResourceBudget,
    SchemaDrift,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSensitivity {
    Public,
    Internal,
    Sensitive,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionAction {
    Redact,
    Hash,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRule {
    pub field_path: String,
    pub sensitivity: DataSensitivity,
    pub action: RedactionAction,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub retention_days: u16,
    pub require_redaction_for_sensitive: bool,
    pub permit_raw_seed_storage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLoggingSchemaSpec {
    pub schema_version: String,
    pub event_schema_version: String,
    pub required_fields: Vec<String>,
    pub required_correlation_ids: Vec<String>,
    pub correlation_key_fields: Vec<String>,
    pub retention_policy: RetentionPolicy,
    pub redaction_rules: Vec<RedactionRule>,
}

impl Default for TestLoggingSchemaSpec {
    fn default() -> Self {
        Self {
            schema_version: TEST_LOGGING_CONTRACT_SCHEMA_VERSION.to_string(),
            event_schema_version: TEST_LOG_EVENT_SCHEMA_VERSION.to_string(),
            required_fields: REQUIRED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            required_correlation_ids: REQUIRED_CORRELATION_IDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            correlation_key_fields: REQUIRED_CORRELATION_IDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            retention_policy: RetentionPolicy {
                retention_days: 30,
                require_redaction_for_sensitive: true,
                permit_raw_seed_storage: false,
            },
            redaction_rules: vec![
                RedactionRule {
                    field_path: "payload.user_email".to_string(),
                    sensitivity: DataSensitivity::Sensitive,
                    action: RedactionAction::Hash,
                    rationale: "stable pseudonymization for debugging".to_string(),
                },
                RedactionRule {
                    field_path: "payload.auth_token".to_string(),
                    sensitivity: DataSensitivity::Secret,
                    action: RedactionAction::Drop,
                    rationale: "secret tokens must never be retained".to_string(),
                },
                RedactionRule {
                    field_path: "payload.ip_address".to_string(),
                    sensitivity: DataSensitivity::Sensitive,
                    action: RedactionAction::Redact,
                    rationale: "retain event utility without raw source identity".to_string(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestLogEvent {
    pub schema_version: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub lane: TestLane,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub seed: u64,
    pub timing_us: u64,
    pub timestamp_unix_ms: u64,
    pub failure_taxonomy: Option<FailureTaxonomy>,
}

impl TestLogEvent {
    pub fn correlation_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.scenario_id, self.trace_id, self.decision_id, self.policy_id, self.seed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationErrorCode {
    MissingRequiredField,
    SchemaVersionMismatch,
    CorrelationMismatch,
    RedactionPolicyViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFailure {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: ValidationErrorCode,
    pub message: String,
}

impl ValidationFailure {
    fn missing_field(field: &str) -> Self {
        Self {
            component: TEST_LOGGING_COMPONENT.to_string(),
            event: "validate_event".to_string(),
            outcome: "fail".to_string(),
            error_code: ValidationErrorCode::MissingRequiredField,
            message: format!("missing required field `{field}`"),
        }
    }

    fn schema_mismatch(found: &str) -> Self {
        Self {
            component: TEST_LOGGING_COMPONENT.to_string(),
            event: "validate_event".to_string(),
            outcome: "fail".to_string(),
            error_code: ValidationErrorCode::SchemaVersionMismatch,
            message: format!(
                "schema_version mismatch: expected `{}` found `{found}`",
                TEST_LOG_EVENT_SCHEMA_VERSION
            ),
        }
    }

    fn correlation_mismatch(field: &str, expected: &str, found: &str) -> Self {
        Self {
            component: TEST_LOGGING_COMPONENT.to_string(),
            event: "validate_correlation".to_string(),
            outcome: "fail".to_string(),
            error_code: ValidationErrorCode::CorrelationMismatch,
            message: format!(
                "correlation mismatch for `{field}`: expected `{expected}` found `{found}`"
            ),
        }
    }

    fn redaction_violation(path: &str) -> Self {
        Self {
            component: TEST_LOGGING_COMPONENT.to_string(),
            event: "validate_redaction".to_string(),
            outcome: "fail".to_string(),
            error_code: ValidationErrorCode::RedactionPolicyViolation,
            message: format!("sensitive field `{path}` is present without redaction"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub valid: bool,
    pub failures: Vec<ValidationFailure>,
}

pub fn validate_event(event: &TestLogEvent) -> Vec<ValidationFailure> {
    let mut failures = Vec::new();

    if event.schema_version != TEST_LOG_EVENT_SCHEMA_VERSION {
        failures.push(ValidationFailure::schema_mismatch(&event.schema_version));
    }

    for (field, value) in [
        ("scenario_id", event.scenario_id.as_str()),
        ("fixture_id", event.fixture_id.as_str()),
        ("trace_id", event.trace_id.as_str()),
        ("decision_id", event.decision_id.as_str()),
        ("policy_id", event.policy_id.as_str()),
        ("component", event.component.as_str()),
        ("event", event.event.as_str()),
        ("outcome", event.outcome.as_str()),
        ("error_code", event.error_code.as_str()),
    ] {
        if value.trim().is_empty() {
            failures.push(ValidationFailure::missing_field(field));
        }
    }

    if event.timing_us == 0 {
        failures.push(ValidationFailure::missing_field("timing_us"));
    }
    if event.timestamp_unix_ms == 0 {
        failures.push(ValidationFailure::missing_field("timestamp_unix_ms"));
    }

    failures
}

pub fn validate_correlation(events: &[TestLogEvent]) -> Vec<ValidationFailure> {
    if events.is_empty() {
        return vec![ValidationFailure::missing_field("events")];
    }

    let first = &events[0];
    let expected_correlation_key = first.correlation_key();
    let expected_trace_id = first.trace_id.as_str();
    let expected_decision_id = first.decision_id.as_str();
    let expected_policy_id = first.policy_id.as_str();
    let expected_seed = first.seed.to_string();
    let expected_scenario_id = first.scenario_id.as_str();

    let mut failures = Vec::new();
    for event in &events[1..] {
        if event.correlation_key() == expected_correlation_key {
            continue;
        }
        if event.scenario_id != expected_scenario_id {
            failures.push(ValidationFailure::correlation_mismatch(
                "scenario_id",
                expected_scenario_id,
                &event.scenario_id,
            ));
        }
        if event.trace_id != expected_trace_id {
            failures.push(ValidationFailure::correlation_mismatch(
                "trace_id",
                expected_trace_id,
                &event.trace_id,
            ));
        }
        if event.decision_id != expected_decision_id {
            failures.push(ValidationFailure::correlation_mismatch(
                "decision_id",
                expected_decision_id,
                &event.decision_id,
            ));
        }
        if event.policy_id != expected_policy_id {
            failures.push(ValidationFailure::correlation_mismatch(
                "policy_id",
                expected_policy_id,
                &event.policy_id,
            ));
        }
        if event.seed.to_string() != expected_seed {
            failures.push(ValidationFailure::correlation_mismatch(
                "seed",
                &expected_seed,
                &event.seed.to_string(),
            ));
        }
    }

    failures
}

pub fn apply_redaction(
    record: &BTreeMap<String, String>,
    spec: &TestLoggingSchemaSpec,
) -> BTreeMap<String, String> {
    let mut redacted = record.clone();
    for rule in &spec.redaction_rules {
        if let Some(value) = redacted.get(&rule.field_path).cloned() {
            let replacement = match rule.action {
                RedactionAction::Redact => "[REDACTED]".to_string(),
                RedactionAction::Hash => {
                    let mut hasher = Sha256::new();
                    hasher.update(value.as_bytes());
                    format!("sha256:{}", hex::encode(hasher.finalize()))
                }
                RedactionAction::Drop => String::new(),
            };
            redacted.insert(rule.field_path.clone(), replacement);
        }
    }
    redacted
}

pub fn validate_redaction(
    record: &BTreeMap<String, String>,
    spec: &TestLoggingSchemaSpec,
) -> Vec<ValidationFailure> {
    let mut failures = Vec::new();

    for rule in &spec.redaction_rules {
        let Some(value) = record.get(&rule.field_path) else {
            continue;
        };

        let violation = match rule.action {
            RedactionAction::Redact => value != "[REDACTED]",
            RedactionAction::Hash => !value.starts_with("sha256:"),
            RedactionAction::Drop => !value.is_empty(),
        };

        if violation {
            failures.push(ValidationFailure::redaction_violation(&rule.field_path));
        }
    }

    failures
}

pub fn validate_events(events: &[TestLogEvent]) -> ValidationReport {
    let mut failures = Vec::new();

    for event in events {
        failures.extend(validate_event(event));
    }
    failures.extend(validate_correlation(events));

    let (trace_id, decision_id, policy_id) = if let Some(first) = events.first() {
        (
            first.trace_id.clone(),
            first.decision_id.clone(),
            first.policy_id.clone(),
        )
    } else {
        (
            "trace-missing".to_string(),
            "decision-missing".to_string(),
            "policy-missing".to_string(),
        )
    };

    ValidationReport {
        schema_version: "frx.test-log-validation-report.v1".to_string(),
        trace_id,
        decision_id,
        policy_id,
        component: TEST_LOGGING_COMPONENT.to_string(),
        event: "validate_events".to_string(),
        outcome: if failures.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if failures.is_empty() {
            "none".to_string()
        } else {
            TEST_LOGGING_FAILURE_CODE.to_string()
        },
        valid: failures.is_empty(),
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_event() -> TestLogEvent {
        TestLogEvent {
            schema_version: TEST_LOG_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: "scenario-1".to_string(),
            fixture_id: "fixture-1".to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            lane: TestLane::Runtime,
            component: "runtime_kernel".to_string(),
            event: "unit_test_completed".to_string(),
            outcome: "pass".to_string(),
            error_code: "none".to_string(),
            seed: 42,
            timing_us: 77,
            timestamp_unix_ms: 1_740_000_000_000,
            failure_taxonomy: None,
        }
    }

    #[test]
    fn default_spec_is_deterministic_and_versioned() {
        let spec_a = TestLoggingSchemaSpec::default();
        let spec_b = TestLoggingSchemaSpec::default();
        assert_eq!(spec_a, spec_b);
        assert_eq!(spec_a.schema_version, TEST_LOGGING_CONTRACT_SCHEMA_VERSION);
        assert_eq!(spec_a.event_schema_version, TEST_LOG_EVENT_SCHEMA_VERSION);
        assert_eq!(spec_a.required_fields.len(), REQUIRED_FIELDS.len());
        assert_eq!(
            spec_a.required_correlation_ids.len(),
            REQUIRED_CORRELATION_IDS.len()
        );
    }

    #[test]
    fn validate_event_fails_closed_on_missing_fields() {
        let mut event = baseline_event();
        event.fixture_id.clear();
        event.timing_us = 0;
        let failures = validate_event(&event);
        assert!(failures
            .iter()
            .any(|failure| failure.message.contains("fixture_id")));
        assert!(failures
            .iter()
            .any(|failure| failure.message.contains("timing_us")));
    }

    #[test]
    fn validate_correlation_detects_cross_lane_mismatch() {
        let event_a = baseline_event();
        let mut event_b = baseline_event();
        event_b.lane = TestLane::Compiler;
        event_b.trace_id = "trace-mismatch".to_string();

        let failures = validate_correlation(&[event_a, event_b]);
        assert!(failures
            .iter()
            .any(|failure| failure.message.contains("trace_id")));
    }

    #[test]
    fn apply_redaction_enforces_rule_actions() {
        let mut record = BTreeMap::new();
        record.insert(
            "payload.user_email".to_string(),
            "alice@example.com".to_string(),
        );
        record.insert("payload.auth_token".to_string(), "secret-token".to_string());
        record.insert("payload.ip_address".to_string(), "10.0.0.1".to_string());

        let spec = TestLoggingSchemaSpec::default();
        let redacted = apply_redaction(&record, &spec);

        let email = redacted
            .get("payload.user_email")
            .expect("email key must exist");
        assert!(email.starts_with("sha256:"));
        assert_eq!(
            redacted.get("payload.auth_token").map(String::as_str),
            Some("")
        );
        assert_eq!(
            redacted.get("payload.ip_address").map(String::as_str),
            Some("[REDACTED]")
        );

        let failures = validate_redaction(&redacted, &spec);
        assert!(failures.is_empty(), "redacted output should validate");
    }
}
