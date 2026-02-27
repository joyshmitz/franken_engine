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
        assert!(
            failures
                .iter()
                .any(|failure| failure.message.contains("fixture_id"))
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.message.contains("timing_us"))
        );
    }

    #[test]
    fn validate_correlation_detects_cross_lane_mismatch() {
        let event_a = baseline_event();
        let mut event_b = baseline_event();
        event_b.lane = TestLane::Compiler;
        event_b.trace_id = "trace-mismatch".to_string();

        let failures = validate_correlation(&[event_a, event_b]);
        assert!(
            failures
                .iter()
                .any(|failure| failure.message.contains("trace_id"))
        );
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

    // -- Enrichment: enum serde roundtrips --

    #[test]
    fn test_lane_serde_roundtrip() {
        for lane in [
            TestLane::Compiler,
            TestLane::Runtime,
            TestLane::Router,
            TestLane::Governance,
            TestLane::E2e,
        ] {
            let json = serde_json::to_string(&lane).unwrap();
            let back: TestLane = serde_json::from_str(&json).unwrap();
            assert_eq!(lane, back);
        }
    }

    #[test]
    fn test_lane_ordering() {
        assert!(TestLane::Compiler < TestLane::Runtime);
        assert!(TestLane::Runtime < TestLane::Router);
        assert!(TestLane::Router < TestLane::Governance);
        assert!(TestLane::Governance < TestLane::E2e);
    }

    #[test]
    fn failure_taxonomy_serde_roundtrip() {
        for tax in [
            FailureTaxonomy::DeterminismDrift,
            FailureTaxonomy::InvariantViolation,
            FailureTaxonomy::Timeout,
            FailureTaxonomy::ResourceBudget,
            FailureTaxonomy::SchemaDrift,
            FailureTaxonomy::Unknown,
        ] {
            let json = serde_json::to_string(&tax).unwrap();
            let back: FailureTaxonomy = serde_json::from_str(&json).unwrap();
            assert_eq!(tax, back);
        }
    }

    #[test]
    fn data_sensitivity_serde_roundtrip() {
        for sensitivity in [
            DataSensitivity::Public,
            DataSensitivity::Internal,
            DataSensitivity::Sensitive,
            DataSensitivity::Secret,
        ] {
            let json = serde_json::to_string(&sensitivity).unwrap();
            let back: DataSensitivity = serde_json::from_str(&json).unwrap();
            assert_eq!(sensitivity, back);
        }
    }

    #[test]
    fn redaction_action_serde_roundtrip() {
        for action in [
            RedactionAction::Redact,
            RedactionAction::Hash,
            RedactionAction::Drop,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: RedactionAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn validation_error_code_serde_roundtrip() {
        for code in [
            ValidationErrorCode::MissingRequiredField,
            ValidationErrorCode::SchemaVersionMismatch,
            ValidationErrorCode::CorrelationMismatch,
            ValidationErrorCode::RedactionPolicyViolation,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: ValidationErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
        }
    }

    // -- Enrichment: struct serde --

    #[test]
    fn redaction_rule_serde_roundtrip() {
        let rule = RedactionRule {
            field_path: "payload.secret".to_string(),
            sensitivity: DataSensitivity::Secret,
            action: RedactionAction::Drop,
            rationale: "must never be retained".to_string(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: RedactionRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn retention_policy_serde_roundtrip() {
        let policy = RetentionPolicy {
            retention_days: 90,
            require_redaction_for_sensitive: true,
            permit_raw_seed_storage: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn test_log_event_serde_roundtrip() {
        let event = baseline_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: TestLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_log_event_with_failure_taxonomy_serde() {
        let mut event = baseline_event();
        event.failure_taxonomy = Some(FailureTaxonomy::DeterminismDrift);
        let json = serde_json::to_string(&event).unwrap();
        let back: TestLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(
            back.failure_taxonomy,
            Some(FailureTaxonomy::DeterminismDrift)
        );
    }

    #[test]
    fn test_logging_schema_spec_serde_roundtrip() {
        let spec = TestLoggingSchemaSpec::default();
        let json = serde_json::to_string(&spec).unwrap();
        let back: TestLoggingSchemaSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn validation_failure_serde_roundtrip() {
        let failure = ValidationFailure::missing_field("trace_id");
        let json = serde_json::to_string(&failure).unwrap();
        let back: ValidationFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(failure, back);
    }

    #[test]
    fn validation_report_serde_roundtrip() {
        let report = validate_events(&[baseline_event()]);
        let json = serde_json::to_string(&report).unwrap();
        let back: ValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -- Enrichment: correlation_key --

    #[test]
    fn correlation_key_deterministic() {
        let a = baseline_event();
        let b = baseline_event();
        assert_eq!(a.correlation_key(), b.correlation_key());
    }

    #[test]
    fn correlation_key_differs_by_scenario() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.scenario_id = "scenario-2".to_string();
        assert_ne!(a.correlation_key(), b.correlation_key());
    }

    #[test]
    fn correlation_key_differs_by_seed() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.seed = 99;
        assert_ne!(a.correlation_key(), b.correlation_key());
    }

    // -- Enrichment: validate_event edge cases --

    #[test]
    fn validate_event_passes_on_valid_event() {
        let event = baseline_event();
        let failures = validate_event(&event);
        assert!(failures.is_empty());
    }

    #[test]
    fn validate_event_detects_schema_version_mismatch() {
        let mut event = baseline_event();
        event.schema_version = "wrong-version".to_string();
        let failures = validate_event(&event);
        assert!(
            failures
                .iter()
                .any(|f| f.error_code == ValidationErrorCode::SchemaVersionMismatch)
        );
    }

    #[test]
    fn validate_event_detects_whitespace_only_fields() {
        let mut event = baseline_event();
        event.component = "   ".to_string();
        let failures = validate_event(&event);
        assert!(failures.iter().any(|f| f.message.contains("component")));
    }

    #[test]
    fn validate_event_detects_zero_timestamp() {
        let mut event = baseline_event();
        event.timestamp_unix_ms = 0;
        let failures = validate_event(&event);
        assert!(
            failures
                .iter()
                .any(|f| f.message.contains("timestamp_unix_ms"))
        );
    }

    #[test]
    fn validate_event_multiple_missing_fields() {
        let mut event = baseline_event();
        event.scenario_id.clear();
        event.trace_id.clear();
        event.decision_id.clear();
        event.timing_us = 0;
        let failures = validate_event(&event);
        assert!(failures.len() >= 4);
    }

    // -- Enrichment: validate_correlation edge cases --

    #[test]
    fn validate_correlation_empty_events() {
        let failures = validate_correlation(&[]);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].message.contains("events"));
    }

    #[test]
    fn validate_correlation_single_event_passes() {
        let failures = validate_correlation(&[baseline_event()]);
        assert!(failures.is_empty());
    }

    #[test]
    fn validate_correlation_matching_events_pass() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.lane = TestLane::Compiler; // different lane but same correlation
        let failures = validate_correlation(&[a, b]);
        assert!(failures.is_empty());
    }

    #[test]
    fn validate_correlation_detects_scenario_mismatch() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.scenario_id = "scenario-other".to_string();
        let failures = validate_correlation(&[a, b]);
        assert!(failures.iter().any(|f| f.message.contains("scenario_id")));
    }

    #[test]
    fn validate_correlation_detects_decision_id_mismatch() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.decision_id = "decision-other".to_string();
        let failures = validate_correlation(&[a, b]);
        assert!(failures.iter().any(|f| f.message.contains("decision_id")));
    }

    #[test]
    fn validate_correlation_detects_policy_id_mismatch() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.policy_id = "policy-other".to_string();
        let failures = validate_correlation(&[a, b]);
        assert!(failures.iter().any(|f| f.message.contains("policy_id")));
    }

    #[test]
    fn validate_correlation_detects_seed_mismatch() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.seed = 999;
        let failures = validate_correlation(&[a, b]);
        assert!(failures.iter().any(|f| f.message.contains("seed")));
    }

    // -- Enrichment: redaction edge cases --

    #[test]
    fn apply_redaction_no_matching_fields() {
        let record = BTreeMap::from([("unrelated_field".to_string(), "value".to_string())]);
        let spec = TestLoggingSchemaSpec::default();
        let redacted = apply_redaction(&record, &spec);
        assert_eq!(
            redacted.get("unrelated_field").map(String::as_str),
            Some("value")
        );
    }

    #[test]
    fn apply_redaction_hash_is_deterministic() {
        let mut record = BTreeMap::new();
        record.insert(
            "payload.user_email".to_string(),
            "alice@example.com".to_string(),
        );
        let spec = TestLoggingSchemaSpec::default();
        let r1 = apply_redaction(&record, &spec);
        let r2 = apply_redaction(&record, &spec);
        assert_eq!(r1, r2);
    }

    #[test]
    fn validate_redaction_detects_unredacted_sensitive_field() {
        let record = BTreeMap::from([
            (
                "payload.user_email".to_string(),
                "raw@email.com".to_string(),
            ),
            ("payload.auth_token".to_string(), "still-secret".to_string()),
            ("payload.ip_address".to_string(), "10.0.0.1".to_string()),
        ]);
        let spec = TestLoggingSchemaSpec::default();
        let failures = validate_redaction(&record, &spec);
        assert_eq!(failures.len(), 3);
        assert!(
            failures
                .iter()
                .all(|f| f.error_code == ValidationErrorCode::RedactionPolicyViolation)
        );
    }

    #[test]
    fn validate_redaction_passes_on_properly_redacted() {
        let record = BTreeMap::from([
            (
                "payload.user_email".to_string(),
                "sha256:abc123".to_string(),
            ),
            ("payload.auth_token".to_string(), String::new()),
            ("payload.ip_address".to_string(), "[REDACTED]".to_string()),
        ]);
        let spec = TestLoggingSchemaSpec::default();
        let failures = validate_redaction(&record, &spec);
        assert!(failures.is_empty());
    }

    #[test]
    fn validate_redaction_absent_fields_not_violations() {
        let record = BTreeMap::new();
        let spec = TestLoggingSchemaSpec::default();
        let failures = validate_redaction(&record, &spec);
        assert!(failures.is_empty());
    }

    // -- Enrichment: validate_events integration --

    #[test]
    fn validate_events_valid_batch() {
        let events = vec![baseline_event(), baseline_event()];
        let report = validate_events(&events);
        assert!(report.valid);
        assert_eq!(report.outcome, "pass");
        assert_eq!(report.error_code, "none");
        assert!(report.failures.is_empty());
    }

    #[test]
    fn validate_events_empty_batch() {
        let report = validate_events(&[]);
        assert!(!report.valid);
        assert_eq!(report.outcome, "fail");
        assert_eq!(report.error_code, TEST_LOGGING_FAILURE_CODE);
        assert_eq!(report.trace_id, "trace-missing");
    }

    #[test]
    fn validate_events_aggregates_event_and_correlation_failures() {
        let mut bad_event = baseline_event();
        bad_event.fixture_id.clear();
        let mut mismatched = baseline_event();
        mismatched.trace_id = "trace-other".to_string();
        let report = validate_events(&[bad_event, mismatched]);
        assert!(!report.valid);
        assert!(report.failures.len() >= 2);
    }

    // -- Enrichment: constants --

    #[test]
    fn required_fields_count() {
        assert_eq!(REQUIRED_FIELDS.len(), 13);
    }

    #[test]
    fn required_correlation_ids_count() {
        assert_eq!(REQUIRED_CORRELATION_IDS.len(), 5);
    }

    #[test]
    fn correlation_ids_are_subset_of_required_fields() {
        for id in &REQUIRED_CORRELATION_IDS {
            assert!(
                REQUIRED_FIELDS.contains(id),
                "correlation id `{id}` should be in required fields"
            );
        }
    }

    #[test]
    fn default_spec_redaction_rules_count() {
        let spec = TestLoggingSchemaSpec::default();
        assert_eq!(spec.redaction_rules.len(), 3);
    }

    #[test]
    fn default_spec_retention_days() {
        let spec = TestLoggingSchemaSpec::default();
        assert_eq!(spec.retention_policy.retention_days, 30);
        assert!(spec.retention_policy.require_redaction_for_sensitive);
        assert!(!spec.retention_policy.permit_raw_seed_storage);
    }

    // -- Enrichment: ValidationFailure constructors --

    #[test]
    fn validation_failure_missing_field_format() {
        let failure = ValidationFailure::missing_field("trace_id");
        assert_eq!(
            failure.error_code,
            ValidationErrorCode::MissingRequiredField
        );
        assert!(failure.message.contains("trace_id"));
        assert_eq!(failure.component, TEST_LOGGING_COMPONENT);
        assert_eq!(failure.outcome, "fail");
    }

    #[test]
    fn validation_failure_schema_mismatch_format() {
        let failure = ValidationFailure::schema_mismatch("wrong-v2");
        assert_eq!(
            failure.error_code,
            ValidationErrorCode::SchemaVersionMismatch
        );
        assert!(failure.message.contains("wrong-v2"));
    }

    #[test]
    fn validation_failure_correlation_mismatch_format() {
        let failure = ValidationFailure::correlation_mismatch("trace_id", "expected-1", "found-2");
        assert_eq!(failure.error_code, ValidationErrorCode::CorrelationMismatch);
        assert!(failure.message.contains("expected-1"));
        assert!(failure.message.contains("found-2"));
    }

    #[test]
    fn validation_failure_redaction_violation_format() {
        let failure = ValidationFailure::redaction_violation("payload.secret");
        assert_eq!(
            failure.error_code,
            ValidationErrorCode::RedactionPolicyViolation
        );
        assert!(failure.message.contains("payload.secret"));
    }

    // -- Enrichment: each lane in events --

    #[test]
    fn validate_event_passes_for_each_lane() {
        for lane in [
            TestLane::Compiler,
            TestLane::Runtime,
            TestLane::Router,
            TestLane::Governance,
            TestLane::E2e,
        ] {
            let mut event = baseline_event();
            event.lane = lane;
            let failures = validate_event(&event);
            assert!(
                failures.is_empty(),
                "event with lane {lane:?} should pass validation"
            );
        }
    }

    #[test]
    fn validate_event_each_failure_taxonomy() {
        for tax in [
            Some(FailureTaxonomy::DeterminismDrift),
            Some(FailureTaxonomy::InvariantViolation),
            Some(FailureTaxonomy::Timeout),
            Some(FailureTaxonomy::ResourceBudget),
            Some(FailureTaxonomy::SchemaDrift),
            Some(FailureTaxonomy::Unknown),
            None,
        ] {
            let mut event = baseline_event();
            event.failure_taxonomy = tax;
            let failures = validate_event(&event);
            assert!(
                failures.is_empty(),
                "event with taxonomy {tax:?} should pass"
            );
        }
    }

    // -- Enrichment: clone equality --

    #[test]
    fn clone_eq_redaction_rule() {
        let rule = RedactionRule {
            field_path: "payload.token".to_string(),
            sensitivity: DataSensitivity::Secret,
            action: RedactionAction::Drop,
            rationale: "never retain".to_string(),
        };
        let cloned = rule.clone();
        assert_eq!(rule, cloned);
    }

    #[test]
    fn clone_eq_retention_policy() {
        let policy = RetentionPolicy {
            retention_days: 7,
            require_redaction_for_sensitive: false,
            permit_raw_seed_storage: true,
        };
        let cloned = policy.clone();
        assert_eq!(policy, cloned);
    }

    #[test]
    fn clone_eq_validation_report() {
        let report = validate_events(&[baseline_event()]);
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn clone_eq_test_logging_schema_spec() {
        let spec = TestLoggingSchemaSpec::default();
        let cloned = spec.clone();
        assert_eq!(spec, cloned);
    }

    #[test]
    fn clone_eq_validation_failure() {
        let failure = ValidationFailure::redaction_violation("payload.ip");
        let cloned = failure.clone();
        assert_eq!(failure, cloned);
    }

    // -- Enrichment: JSON field presence --

    #[test]
    fn json_field_presence_test_log_event() {
        let event = baseline_event();
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"scenario_id\""));
        assert!(json.contains("\"fixture_id\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"lane\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"timing_us\""));
        assert!(json.contains("\"timestamp_unix_ms\""));
    }

    #[test]
    fn json_field_presence_validation_report() {
        let report = validate_events(&[baseline_event()]);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"valid\""));
        assert!(json.contains("\"failures\""));
        assert!(json.contains("\"error_code\""));
    }

    #[test]
    fn json_field_presence_redaction_rule() {
        let rule = RedactionRule {
            field_path: "p.x".to_string(),
            sensitivity: DataSensitivity::Internal,
            action: RedactionAction::Redact,
            rationale: "reason".to_string(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"field_path\""));
        assert!(json.contains("\"sensitivity\""));
        assert!(json.contains("\"action\""));
        assert!(json.contains("\"rationale\""));
    }

    // -- Enrichment: boundary conditions --

    #[test]
    fn validate_event_max_seed_and_timing_accepted() {
        let mut event = baseline_event();
        event.seed = u64::MAX;
        event.timing_us = u64::MAX;
        event.timestamp_unix_ms = u64::MAX;
        let failures = validate_event(&event);
        assert!(failures.is_empty(), "max u64 values should be accepted");
    }

    #[test]
    fn correlation_key_includes_all_five_fields() {
        let event = baseline_event();
        let key = event.correlation_key();
        assert!(key.contains(&event.scenario_id));
        assert!(key.contains(&event.trace_id));
        assert!(key.contains(&event.decision_id));
        assert!(key.contains(&event.policy_id));
        assert!(key.contains(&event.seed.to_string()));
        // Exactly 4 pipe separators for 5 fields
        assert_eq!(key.matches('|').count(), 4);
    }

    #[test]
    fn validate_correlation_three_events_second_and_third_mismatch() {
        let a = baseline_event();
        let mut b = baseline_event();
        b.trace_id = "trace-b".to_string();
        let mut c = baseline_event();
        c.policy_id = "policy-c".to_string();
        let failures = validate_correlation(&[a, b, c]);
        assert!(failures.iter().any(|f| f.message.contains("trace_id")));
        assert!(failures.iter().any(|f| f.message.contains("policy_id")));
        assert!(failures.len() >= 2);
    }

    #[test]
    fn retention_policy_zero_days_roundtrip() {
        let policy = RetentionPolicy {
            retention_days: 0,
            require_redaction_for_sensitive: false,
            permit_raw_seed_storage: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
        assert_eq!(back.retention_days, 0);
    }
}
