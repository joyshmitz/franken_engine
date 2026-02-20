//! Cross-repo contract tests validating schema/API compatibility for
//! integration boundaries between FrankenEngine and sibling repos.
//!
//! Every declared integration boundary (`frankentui`, `frankensqlite`,
//! `fastapi_rust`/service endpoints) must have at least one contract test
//! proving that serialized representations are stable, error codes are
//! machine-readable, and API envelopes satisfy schema invariants.
//!
//! Plan reference: Section 10.14 item 12 (`bd-rr94`).
//! Cross-refs: 10.15 (advanced cross-repo conformance lab),
//! Section 13 (cross-repo conformance lab pass is release gate).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::frankentui_adapter::FRANKENTUI_ADAPTER_SCHEMA_VERSION;
use crate::storage_adapter::STORAGE_SCHEMA_VERSION;

// ---------------------------------------------------------------------------
// Regression classification
// ---------------------------------------------------------------------------

/// Classification of a contract violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RegressionClass {
    /// Serialized shape changed — wire-incompatible.
    Breaking,
    /// Observable behavior changed (ordering, defaults, error messages).
    Behavioral,
    /// Structured log or telemetry field changed.
    Observability,
    /// Performance SLO regression (latency, throughput, memory).
    Performance,
}

impl fmt::Display for RegressionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Breaking => f.write_str("BREAKING"),
            Self::Behavioral => f.write_str("BEHAVIORAL"),
            Self::Observability => f.write_str("OBSERVABILITY"),
            Self::Performance => f.write_str("PERFORMANCE"),
        }
    }
}

/// A single contract violation detected during verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractViolation {
    pub boundary: String,
    pub contract_name: String,
    pub regression_class: RegressionClass,
    pub detail: String,
}

impl fmt::Display for ContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}/{}: {}",
            self.regression_class, self.boundary, self.contract_name, self.detail
        )
    }
}

// ---------------------------------------------------------------------------
// Schema contract: field presence + type assertions on serialized JSON
// ---------------------------------------------------------------------------

/// Declares expected top-level fields for a serialized type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaContract {
    pub boundary: String,
    pub type_name: String,
    pub required_fields: BTreeSet<String>,
    pub field_types: BTreeMap<String, FieldType>,
}

/// Expected JSON value type for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FieldType {
    String,
    Number,
    Bool,
    Array,
    Object,
    Null,
}

impl FieldType {
    fn matches(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Bool => value.is_boolean(),
            Self::Array => value.is_array(),
            Self::Object => value.is_object(),
            Self::Null => value.is_null(),
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => f.write_str("string"),
            Self::Number => f.write_str("number"),
            Self::Bool => f.write_str("bool"),
            Self::Array => f.write_str("array"),
            Self::Object => f.write_str("object"),
            Self::Null => f.write_str("null"),
        }
    }
}

impl SchemaContract {
    /// Verify a serialized JSON value against this contract.
    pub fn verify(&self, json: &Value) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        let obj = match json.as_object() {
            Some(obj) => obj,
            None => {
                violations.push(ContractViolation {
                    boundary: self.boundary.clone(),
                    contract_name: self.type_name.clone(),
                    regression_class: RegressionClass::Breaking,
                    detail: "expected JSON object at top level".to_string(),
                });
                return violations;
            }
        };

        for field in &self.required_fields {
            if !obj.contains_key(field.as_str()) {
                violations.push(ContractViolation {
                    boundary: self.boundary.clone(),
                    contract_name: self.type_name.clone(),
                    regression_class: RegressionClass::Breaking,
                    detail: format!("missing required field `{field}`"),
                });
            }
        }

        for (field, expected_type) in &self.field_types {
            if let Some(value) = obj.get(field.as_str())
                && !value.is_null()
                && !expected_type.matches(value)
            {
                violations.push(ContractViolation {
                    boundary: self.boundary.clone(),
                    contract_name: self.type_name.clone(),
                    regression_class: RegressionClass::Breaking,
                    detail: format!(
                        "field `{field}` expected type {expected_type}, got {}",
                        json_type_name(value)
                    ),
                });
            }
        }

        violations
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// Structured log contract
// ---------------------------------------------------------------------------

/// Canonical log field keys required by Section 10.14 contracts.
pub const REQUIRED_LOG_FIELDS: &[&str] = &["trace_id", "component", "event", "outcome"];

/// Optional but recommended structured log fields.
pub const OPTIONAL_LOG_FIELDS: &[&str] = &["decision_id", "policy_id", "error_code"];

/// Verify that a structured log event JSON contains all required fields.
pub fn verify_structured_log(json: &Value, boundary: &str) -> Vec<ContractViolation> {
    let mut violations = Vec::new();
    let obj = match json.as_object() {
        Some(obj) => obj,
        None => {
            violations.push(ContractViolation {
                boundary: boundary.to_string(),
                contract_name: "structured_log".to_string(),
                regression_class: RegressionClass::Observability,
                detail: "log event must be a JSON object".to_string(),
            });
            return violations;
        }
    };

    for field in REQUIRED_LOG_FIELDS {
        if !obj.contains_key(*field) {
            violations.push(ContractViolation {
                boundary: boundary.to_string(),
                contract_name: "structured_log".to_string(),
                regression_class: RegressionClass::Observability,
                detail: format!("missing required log field `{field}`"),
            });
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Error code contract
// ---------------------------------------------------------------------------

/// Verify an error code matches the stable prefix format.
pub fn verify_error_code_format(code: &str, expected_prefix: &str) -> bool {
    code.starts_with(expected_prefix)
}

// ---------------------------------------------------------------------------
// Boundary contract builders
// ---------------------------------------------------------------------------

/// Build the schema contract for `AdapterEnvelope` (frankentui boundary).
pub fn frankentui_envelope_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in [
        "schema_version",
        "trace_id",
        "generated_at_unix_ms",
        "stream",
        "update_kind",
        "payload",
    ] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("schema_version".to_string(), FieldType::Number);
    types.insert("trace_id".to_string(), FieldType::String);
    types.insert("generated_at_unix_ms".to_string(), FieldType::Number);
    types.insert("stream".to_string(), FieldType::String);
    types.insert("update_kind".to_string(), FieldType::String);
    types.insert("payload".to_string(), FieldType::Object);

    SchemaContract {
        boundary: "frankentui".to_string(),
        type_name: "AdapterEnvelope".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `StoreRecord` (frankensqlite boundary).
pub fn frankensqlite_store_record_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in ["store", "key", "value", "metadata", "revision"] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("store".to_string(), FieldType::String);
    types.insert("key".to_string(), FieldType::String);
    types.insert("value".to_string(), FieldType::Array);
    types.insert("metadata".to_string(), FieldType::Object);
    types.insert("revision".to_string(), FieldType::Number);

    SchemaContract {
        boundary: "frankensqlite".to_string(),
        type_name: "StoreRecord".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `EndpointResponse` (fastapi_rust boundary).
pub fn fastapi_endpoint_response_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in ["status", "endpoint", "trace_id", "request_id", "log"] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("status".to_string(), FieldType::String);
    types.insert("endpoint".to_string(), FieldType::String);
    types.insert("trace_id".to_string(), FieldType::String);
    types.insert("request_id".to_string(), FieldType::String);
    types.insert("log".to_string(), FieldType::Object);

    SchemaContract {
        boundary: "fastapi_rust".to_string(),
        type_name: "EndpointResponse".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `StorageEvent` (frankensqlite telemetry).
pub fn frankensqlite_storage_event_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
    ] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("trace_id".to_string(), FieldType::String);
    types.insert("decision_id".to_string(), FieldType::String);
    types.insert("policy_id".to_string(), FieldType::String);
    types.insert("component".to_string(), FieldType::String);
    types.insert("event".to_string(), FieldType::String);
    types.insert("outcome".to_string(), FieldType::String);

    SchemaContract {
        boundary: "frankensqlite".to_string(),
        type_name: "StorageEvent".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `MigrationReceipt` (frankensqlite boundary).
pub fn frankensqlite_migration_receipt_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in [
        "backend",
        "from_version",
        "to_version",
        "stores_touched",
        "records_touched",
        "state_hash_before",
        "state_hash_after",
    ] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("backend".to_string(), FieldType::String);
    types.insert("from_version".to_string(), FieldType::Number);
    types.insert("to_version".to_string(), FieldType::Number);
    types.insert("stores_touched".to_string(), FieldType::Array);
    types.insert("records_touched".to_string(), FieldType::Number);
    types.insert("state_hash_before".to_string(), FieldType::String);
    types.insert("state_hash_after".to_string(), FieldType::String);

    SchemaContract {
        boundary: "frankensqlite".to_string(),
        type_name: "MigrationReceipt".to_string(),
        required_fields: required,
        field_types: types,
    }
}

// ---------------------------------------------------------------------------
// Deterministic verification helpers
// ---------------------------------------------------------------------------

/// Verify that two independent serializations of the same value produce
/// identical bytes (deterministic serde round-trip).
pub fn verify_deterministic_serde<T>(value: &T) -> Result<(), String>
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug,
{
    let bytes_a = serde_json::to_vec(value).map_err(|err| format!("serialize A: {err}"))?;
    let bytes_b = serde_json::to_vec(value).map_err(|err| format!("serialize B: {err}"))?;
    if bytes_a != bytes_b {
        return Err("non-deterministic: two serializations differ".to_string());
    }

    let decoded: T =
        serde_json::from_slice(&bytes_a).map_err(|err| format!("deserialize: {err}"))?;
    if decoded != *value {
        return Err("round-trip produced different value".to_string());
    }

    let bytes_c = serde_json::to_vec(&decoded).map_err(|err| format!("serialize C: {err}"))?;
    if bytes_a != bytes_c {
        return Err("round-trip serialization not stable".to_string());
    }

    Ok(())
}

/// Verify that a contract-covered type serializes to a schema-compliant JSON.
pub fn verify_schema_compliance<T: Serialize>(
    value: &T,
    contract: &SchemaContract,
) -> Vec<ContractViolation> {
    match serde_json::to_value(value) {
        Ok(json) => contract.verify(&json),
        Err(err) => vec![ContractViolation {
            boundary: contract.boundary.clone(),
            contract_name: contract.type_name.clone(),
            regression_class: RegressionClass::Breaking,
            detail: format!("serialization failed: {err}"),
        }],
    }
}

// ---------------------------------------------------------------------------
// Version compatibility registry
// ---------------------------------------------------------------------------

/// Known version pairs for cross-repo compatibility tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionCompatibilityEntry {
    pub boundary: String,
    pub current_version: u32,
    pub minimum_compatible_version: u32,
}

/// Build the version compatibility registry for all boundaries.
pub fn version_compatibility_registry() -> Vec<VersionCompatibilityEntry> {
    vec![
        VersionCompatibilityEntry {
            boundary: "frankentui".to_string(),
            current_version: FRANKENTUI_ADAPTER_SCHEMA_VERSION,
            minimum_compatible_version: 1,
        },
        VersionCompatibilityEntry {
            boundary: "frankensqlite".to_string(),
            current_version: STORAGE_SCHEMA_VERSION,
            minimum_compatible_version: 1,
        },
        VersionCompatibilityEntry {
            boundary: "fastapi_rust".to_string(),
            current_version: 1,
            minimum_compatible_version: 1,
        },
    ]
}

// ---------------------------------------------------------------------------
// Integration point inventory
// ---------------------------------------------------------------------------

/// All declared integration points across sibling repo boundaries.
pub fn integration_point_inventory() -> BTreeMap<String, Vec<String>> {
    let mut inventory = BTreeMap::new();

    inventory.insert(
        "frankentui".to_string(),
        vec![
            "AdapterEnvelope".to_string(),
            "FrankentuiViewPayload".to_string(),
            "IncidentReplayView".to_string(),
            "PolicyExplanationCardView".to_string(),
            "ControlDashboardView".to_string(),
        ],
    );

    inventory.insert(
        "frankensqlite".to_string(),
        vec![
            "StoreRecord".to_string(),
            "StoreQuery".to_string(),
            "BatchPutEntry".to_string(),
            "MigrationReceipt".to_string(),
            "StorageEvent".to_string(),
            "FrankensqliteBackend".to_string(),
        ],
    );

    inventory.insert(
        "fastapi_rust".to_string(),
        vec![
            "EndpointResponse".to_string(),
            "ErrorEnvelope".to_string(),
            "HealthStatusResponse".to_string(),
            "ControlActionRequest".to_string(),
            "ControlActionResponse".to_string(),
            "EvidenceExportRequest".to_string(),
            "EvidenceExportResponse".to_string(),
            "ReplayControlRequest".to_string(),
            "ReplayControlResponse".to_string(),
        ],
    );

    inventory
}

// ---------------------------------------------------------------------------
// Contract suite runner
// ---------------------------------------------------------------------------

/// Result of running the full contract verification suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSuiteResult {
    pub total_contracts: usize,
    pub passed: usize,
    pub failed: usize,
    pub violations: Vec<ContractViolation>,
    pub boundaries_covered: BTreeSet<String>,
}

impl ContractSuiteResult {
    pub fn is_passing(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for ContractSuiteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "contracts={} passed={} failed={} boundaries={}",
            self.total_contracts,
            self.passed,
            self.failed,
            self.boundaries_covered.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::frankentui_adapter::{
        AdapterEnvelope, AdapterStream, ControlDashboardView, DashboardMetricView,
        ExtensionStatusRow, FrankentuiViewPayload, IncidentReplayView, PolicyExplanationCardView,
        PolicyExplanationPartial, ReplayEventView, ReplayStatus, UpdateKind,
    };
    use crate::policy_controller::service_endpoint_template::{
        AuthContext, ControlAction, EndpointResponse, ErrorEnvelope, HealthStatusResponse,
        ReplayCommand, RequestContext, SCOPE_CONTROL_WRITE, SCOPE_EVIDENCE_READ, SCOPE_HEALTH_READ,
        SCOPE_REPLAY_READ, SCOPE_REPLAY_WRITE, StructuredLogEvent,
    };
    use crate::storage_adapter::{
        EventContext, InMemoryStorageAdapter, MigrationReceipt, StorageAdapter, StorageError,
        StorageEvent, StoreKind, StoreQuery, StoreRecord,
    };

    // ── frankentui boundary ────────────────────────────────────────────

    fn sample_envelope() -> AdapterEnvelope {
        let replay = IncidentReplayView::snapshot(
            "trace-contract-1",
            "contract-scenario",
            vec![ReplayEventView::new(
                1,
                "engine",
                "startup",
                "ok",
                1_700_000_000_000,
            )],
        );
        AdapterEnvelope::new(
            "trace-contract-1",
            1_700_000_000_000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        )
    }

    #[test]
    fn frankentui_envelope_schema_compliance() {
        let contract = frankentui_envelope_contract();
        let envelope = sample_envelope();
        let violations = verify_schema_compliance(&envelope, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankentui_envelope_deterministic_serde() {
        let envelope = sample_envelope();
        verify_deterministic_serde(&envelope).expect("must be deterministic");
    }

    #[test]
    fn frankentui_envelope_schema_version_matches_current() {
        let envelope = sample_envelope();
        assert_eq!(envelope.schema_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
    }

    #[test]
    fn frankentui_all_payload_variants_serialize() {
        let replay = FrankentuiViewPayload::IncidentReplay(IncidentReplayView::snapshot(
            "trace-1",
            "scenario-1",
            vec![],
        ));
        let policy = FrankentuiViewPayload::PolicyExplanation(
            PolicyExplanationCardView::from_partial(PolicyExplanationPartial {
                decision_id: "d-1".to_string(),
                policy_id: "p-1".to_string(),
                selected_action: "allow".to_string(),
                ..Default::default()
            }),
        );
        let dashboard = FrankentuiViewPayload::ControlDashboard(ControlDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 5,
            runtime_mode: "secure".to_string(),
            metrics: vec![DashboardMetricView {
                metric: "p95_ms".to_string(),
                value: 42,
                unit: "ms".to_string(),
            }],
            extension_rows: vec![ExtensionStatusRow {
                extension_id: "ext-a".to_string(),
                state: "running".to_string(),
                trust_level: "verified".to_string(),
            }],
            incident_counts: BTreeMap::new(),
        });

        for payload in [replay, policy, dashboard] {
            let envelope = AdapterEnvelope::new(
                "trace-variants",
                1_700_000_000_000,
                AdapterStream::ControlDashboard,
                UpdateKind::Snapshot,
                payload,
            );
            let json = serde_json::to_value(&envelope).expect("serialize");
            assert!(json["payload"].is_object(), "payload must be an object");
        }
    }

    #[test]
    fn frankentui_replay_status_enum_values_stable() {
        let statuses = [
            ReplayStatus::Running,
            ReplayStatus::Complete,
            ReplayStatus::Failed,
            ReplayStatus::NoEvents,
        ];
        let expected = ["running", "complete", "failed", "no_events"];
        for (status, expected_str) in statuses.iter().zip(expected.iter()) {
            let json = serde_json::to_value(status).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn frankentui_stream_enum_values_stable() {
        let streams = [
            AdapterStream::IncidentReplay,
            AdapterStream::PolicyExplanation,
            AdapterStream::ControlDashboard,
        ];
        let expected = ["incident_replay", "policy_explanation", "control_dashboard"];
        for (stream, expected_str) in streams.iter().zip(expected.iter()) {
            let json = serde_json::to_value(stream).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn frankentui_update_kind_enum_values_stable() {
        let kinds = [
            UpdateKind::Snapshot,
            UpdateKind::Delta,
            UpdateKind::Heartbeat,
        ];
        let expected = ["snapshot", "delta", "heartbeat"];
        for (kind, expected_str) in kinds.iter().zip(expected.iter()) {
            let json = serde_json::to_value(kind).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    // ── frankensqlite boundary ─────────────────────────────────────────

    fn sample_store_record() -> StoreRecord {
        let mut metadata = BTreeMap::new();
        metadata.insert("kind".to_string(), "benchmark".to_string());
        StoreRecord {
            store: StoreKind::BenchmarkLedger,
            key: "bench/latency".to_string(),
            value: vec![42, 0, 0, 0],
            metadata,
            revision: 1,
        }
    }

    #[test]
    fn frankensqlite_store_record_schema_compliance() {
        let contract = frankensqlite_store_record_contract();
        let record = sample_store_record();
        let violations = verify_schema_compliance(&record, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_store_record_deterministic_serde() {
        let record = sample_store_record();
        verify_deterministic_serde(&record).expect("must be deterministic");
    }

    #[test]
    fn frankensqlite_store_kind_integration_points_unique() {
        let kinds = [
            StoreKind::ReplayIndex,
            StoreKind::EvidenceIndex,
            StoreKind::BenchmarkLedger,
            StoreKind::PolicyCache,
            StoreKind::PlasWitness,
            StoreKind::ReplacementLineage,
            StoreKind::IfcProvenance,
            StoreKind::SpecializationIndex,
        ];

        let mut seen_names = BTreeSet::new();
        let mut seen_integration = BTreeSet::new();
        for kind in &kinds {
            assert!(
                seen_names.insert(kind.as_str()),
                "duplicate store name: {}",
                kind.as_str()
            );
            assert!(
                seen_integration.insert(kind.integration_point()),
                "duplicate integration point: {}",
                kind.integration_point()
            );
        }
    }

    #[test]
    fn frankensqlite_store_kind_serialization_stable() {
        let kinds = [
            (StoreKind::ReplayIndex, "ReplayIndex"),
            (StoreKind::EvidenceIndex, "EvidenceIndex"),
            (StoreKind::BenchmarkLedger, "BenchmarkLedger"),
            (StoreKind::PolicyCache, "PolicyCache"),
            (StoreKind::PlasWitness, "PlasWitness"),
            (StoreKind::ReplacementLineage, "ReplacementLineage"),
            (StoreKind::IfcProvenance, "IfcProvenance"),
            (StoreKind::SpecializationIndex, "SpecializationIndex"),
        ];
        for (kind, expected_json) in &kinds {
            let json = serde_json::to_value(kind).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_json);
        }
    }

    #[test]
    fn frankensqlite_migration_receipt_schema_compliance() {
        let contract = frankensqlite_migration_receipt_contract();
        let receipt = MigrationReceipt {
            backend: "in_memory".to_string(),
            from_version: 1,
            to_version: 2,
            stores_touched: vec![StoreKind::ReplayIndex],
            records_touched: 5,
            state_hash_before: "abc123".to_string(),
            state_hash_after: "def456".to_string(),
        };
        let violations = verify_schema_compliance(&receipt, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_storage_event_schema_compliance() {
        let contract = frankensqlite_storage_event_contract();
        let event = StorageEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let violations = verify_schema_compliance(&event, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_storage_event_structured_log_compliance() {
        let event = StorageEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_value(&event).expect("serialize");
        let violations = verify_structured_log(&json, "frankensqlite");
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_error_codes_have_stable_prefix() {
        let errors = [
            StorageError::InvalidContext {
                field: "trace_id".to_string(),
            },
            StorageError::InvalidKey {
                key: "bad".to_string(),
            },
            StorageError::InvalidQuery {
                detail: "bad".to_string(),
            },
            StorageError::NotFound {
                store: StoreKind::ReplayIndex,
                key: "missing".to_string(),
            },
            StorageError::SchemaVersionMismatch {
                expected: 1,
                actual: 2,
            },
            StorageError::MigrationFailed {
                from: 1,
                to: 0,
                reason: "downgrade".to_string(),
            },
            StorageError::IntegrityViolation {
                store: StoreKind::PolicyCache,
                detail: "corrupt".to_string(),
            },
            StorageError::BackendUnavailable {
                backend: "sqlite".to_string(),
                detail: "down".to_string(),
            },
            StorageError::WriteRejected {
                detail: "readonly".to_string(),
            },
        ];
        for err in &errors {
            assert!(
                verify_error_code_format(err.code(), "FE-STOR-"),
                "error code `{}` does not start with FE-STOR-",
                err.code()
            );
        }
    }

    #[test]
    fn frankensqlite_adapter_operations_emit_events() {
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = EventContext::new("trace-contract", "decision-contract", "policy-contract")
            .expect("ctx");

        adapter
            .put(
                StoreKind::ReplayIndex,
                "key-1".to_string(),
                vec![1],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
        adapter
            .get(StoreKind::ReplayIndex, "key-1", &ctx)
            .expect("get");

        let events = StorageAdapter::events(&adapter);
        assert!(events.len() >= 2, "expected at least 2 events");
        for event in events {
            assert_eq!(event.trace_id, "trace-contract");
            assert_eq!(event.component, "storage_adapter");
        }
    }

    #[test]
    fn frankensqlite_query_ordering_is_deterministic() {
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = EventContext::new("trace-order", "decision-order", "policy-order").expect("ctx");

        for key in ["z-key", "a-key", "m-key"] {
            adapter
                .put(
                    StoreKind::EvidenceIndex,
                    key.to_string(),
                    vec![1],
                    BTreeMap::new(),
                    &ctx,
                )
                .expect("put");
        }

        let first_query = adapter
            .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
            .expect("query 1");
        let second_query = adapter
            .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
            .expect("query 2");

        let keys_first: Vec<&str> = first_query.iter().map(|r| r.key.as_str()).collect();
        let keys_second: Vec<&str> = second_query.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys_first, keys_second,
            "query ordering must be deterministic"
        );
        assert_eq!(keys_first, vec!["a-key", "m-key", "z-key"]);
    }

    // ── fastapi_rust / service endpoint boundary ───────────────────────

    fn sample_health_response() -> EndpointResponse<HealthStatusResponse> {
        EndpointResponse {
            status: "ok".to_string(),
            endpoint: "health".to_string(),
            trace_id: "trace-contract".to_string(),
            request_id: "req-contract".to_string(),
            data: Some(HealthStatusResponse {
                runtime_status: "healthy".to_string(),
                loaded_extensions: vec!["ext-a".to_string()],
                security_epoch: 10,
                gc_pressure_basis_points: 50,
            }),
            error: None,
            log: StructuredLogEvent {
                trace_id: "trace-contract".to_string(),
                decision_id: Some("decision-contract".to_string()),
                policy_id: Some("policy-contract".to_string()),
                component: "service.api".to_string(),
                event: "health.read".to_string(),
                outcome: "ok".to_string(),
                error_code: None,
            },
        }
    }

    #[test]
    fn fastapi_endpoint_response_schema_compliance() {
        let contract = fastapi_endpoint_response_contract();
        let response = sample_health_response();
        let violations = verify_schema_compliance(&response, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn fastapi_endpoint_response_deterministic_serde() {
        let response = sample_health_response();
        verify_deterministic_serde(&response).expect("must be deterministic");
    }

    #[test]
    fn fastapi_endpoint_response_log_structured_compliance() {
        let response = sample_health_response();
        let json = serde_json::to_value(&response).expect("serialize");
        let log_json = &json["log"];
        let violations = verify_structured_log(log_json, "fastapi_rust");
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn fastapi_error_envelope_schema_stable() {
        let error = ErrorEnvelope {
            error_code: "unauthorized".to_string(),
            message: "missing required scope".to_string(),
            trace_id: "trace-1".to_string(),
            component: "service.api".to_string(),
            details: BTreeMap::new(),
        };
        let json = serde_json::to_value(&error).expect("serialize");
        let obj = json.as_object().expect("object");
        for field in ["error_code", "message", "trace_id", "component", "details"] {
            assert!(
                obj.contains_key(field),
                "missing field `{field}` in ErrorEnvelope"
            );
        }
    }

    #[test]
    fn fastapi_control_action_enum_values_stable() {
        let actions = [
            ControlAction::Start,
            ControlAction::Stop,
            ControlAction::Suspend,
            ControlAction::Quarantine,
        ];
        let expected = ["Start", "Stop", "Suspend", "Quarantine"];
        for (action, expected_str) in actions.iter().zip(expected.iter()) {
            let json = serde_json::to_value(action).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn fastapi_replay_command_enum_values_stable() {
        let commands = [
            ReplayCommand::Start,
            ReplayCommand::Stop,
            ReplayCommand::Status,
        ];
        let expected = ["Start", "Stop", "Status"];
        for (cmd, expected_str) in commands.iter().zip(expected.iter()) {
            let json = serde_json::to_value(cmd).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn fastapi_scope_constants_are_non_empty() {
        for scope in [
            SCOPE_HEALTH_READ,
            SCOPE_CONTROL_WRITE,
            SCOPE_EVIDENCE_READ,
            SCOPE_REPLAY_READ,
            SCOPE_REPLAY_WRITE,
        ] {
            assert!(!scope.is_empty(), "scope constant must not be empty");
            assert!(
                scope.starts_with("engine."),
                "scope `{scope}` must start with 'engine.'"
            );
        }
    }

    #[test]
    fn fastapi_request_context_serde_round_trip() {
        let ctx = RequestContext {
            trace_id: "trace-1".to_string(),
            request_id: "req-1".to_string(),
            component: "service.api".to_string(),
            decision_id: Some("d-1".to_string()),
            policy_id: None,
        };
        verify_deterministic_serde(&ctx).expect("must be deterministic");
    }

    #[test]
    fn fastapi_auth_context_serde_round_trip() {
        let auth = AuthContext {
            subject: "operator@example".to_string(),
            scopes: vec!["engine.health.read".to_string()],
        };
        verify_deterministic_serde(&auth).expect("must be deterministic");
    }

    // ── cross-boundary / meta tests ────────────────────────────────────

    #[test]
    fn version_compatibility_registry_covers_all_boundaries() {
        let registry = version_compatibility_registry();
        let boundaries: BTreeSet<String> = registry
            .iter()
            .map(|entry| entry.boundary.clone())
            .collect();
        assert!(boundaries.contains("frankentui"));
        assert!(boundaries.contains("frankensqlite"));
        assert!(boundaries.contains("fastapi_rust"));

        for entry in &registry {
            assert!(
                entry.current_version >= entry.minimum_compatible_version,
                "boundary {}: current {} < minimum {}",
                entry.boundary,
                entry.current_version,
                entry.minimum_compatible_version
            );
        }
    }

    #[test]
    fn integration_point_inventory_covers_all_boundaries() {
        let inventory = integration_point_inventory();
        assert!(inventory.contains_key("frankentui"));
        assert!(inventory.contains_key("frankensqlite"));
        assert!(inventory.contains_key("fastapi_rust"));

        for (boundary, types) in &inventory {
            assert!(
                !types.is_empty(),
                "boundary {boundary} must have at least one type"
            );
        }
    }

    #[test]
    fn schema_contract_detects_missing_field() {
        let contract = frankensqlite_store_record_contract();
        let mut json = serde_json::json!({
            "store": "ReplayIndex",
            "key": "k1",
            "value": [1],
            "metadata": {}
        });
        // missing "revision"
        let violations = contract.verify(&json);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].regression_class, RegressionClass::Breaking);
        assert!(violations[0].detail.contains("revision"));

        // add it back
        json["revision"] = serde_json::json!(1);
        let violations = contract.verify(&json);
        assert!(violations.is_empty());
    }

    #[test]
    fn schema_contract_detects_wrong_type() {
        let contract = frankensqlite_store_record_contract();
        let json = serde_json::json!({
            "store": "ReplayIndex",
            "key": "k1",
            "value": [1],
            "metadata": {},
            "revision": "not_a_number"
        });
        let violations = contract.verify(&json);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("revision"));
        assert!(violations[0].detail.contains("number"));
    }

    #[test]
    fn regression_class_ordering() {
        assert!(RegressionClass::Breaking < RegressionClass::Behavioral);
        assert!(RegressionClass::Behavioral < RegressionClass::Observability);
        assert!(RegressionClass::Observability < RegressionClass::Performance);
    }

    #[test]
    fn contract_violation_display() {
        let violation = ContractViolation {
            boundary: "frankentui".to_string(),
            contract_name: "AdapterEnvelope".to_string(),
            regression_class: RegressionClass::Breaking,
            detail: "missing field `payload`".to_string(),
        };
        let display = violation.to_string();
        assert!(display.contains("BREAKING"));
        assert!(display.contains("frankentui"));
        assert!(display.contains("AdapterEnvelope"));
        assert!(display.contains("missing field"));
    }

    #[test]
    fn contract_suite_result_serde_round_trip() {
        let result = ContractSuiteResult {
            total_contracts: 5,
            passed: 4,
            failed: 1,
            violations: vec![ContractViolation {
                boundary: "test".to_string(),
                contract_name: "TestType".to_string(),
                regression_class: RegressionClass::Behavioral,
                detail: "test violation".to_string(),
            }],
            boundaries_covered: {
                let mut set = BTreeSet::new();
                set.insert("frankentui".to_string());
                set
            },
        };
        verify_deterministic_serde(&result).expect("must be deterministic");
    }

    #[test]
    fn contract_suite_result_display() {
        let result = ContractSuiteResult {
            total_contracts: 10,
            passed: 8,
            failed: 2,
            violations: Vec::new(),
            boundaries_covered: BTreeSet::new(),
        };
        let display = result.to_string();
        assert!(display.contains("contracts=10"));
        assert!(display.contains("passed=8"));
        assert!(display.contains("failed=2"));
    }

    #[test]
    fn structured_log_verification_detects_missing_fields() {
        let incomplete = serde_json::json!({
            "trace_id": "t1",
            "component": "test"
            // missing "event" and "outcome"
        });
        let violations = verify_structured_log(&incomplete, "test");
        assert_eq!(violations.len(), 2);
        let fields: BTreeSet<String> = violations.iter().map(|v| v.detail.clone()).collect();
        assert!(fields.iter().any(|d| d.contains("event")));
        assert!(fields.iter().any(|d| d.contains("outcome")));
    }

    #[test]
    fn error_code_format_verification() {
        assert!(verify_error_code_format("FE-STOR-0001", "FE-STOR-"));
        assert!(verify_error_code_format("FE-STOR-0009", "FE-STOR-"));
        assert!(!verify_error_code_format("UNKNOWN-001", "FE-STOR-"));
    }

    // ── deterministic cross-boundary data exchange ─────────────────────

    #[test]
    fn cross_boundary_storage_then_tui_deterministic() {
        // Simulate: engine writes to storage, reads back, generates TUI view
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = EventContext::new("trace-xboundary", "decision-xb", "policy-xb").expect("ctx");

        adapter
            .put(
                StoreKind::EvidenceIndex,
                "decision/1".to_string(),
                b"evidence-payload".to_vec(),
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");

        let loaded = adapter
            .get(StoreKind::EvidenceIndex, "decision/1", &ctx)
            .expect("get")
            .expect("record exists");

        // Generate TUI view from loaded data
        let replay_event =
            ReplayEventView::new(1, "storage_adapter", "put", "ok", 1_700_000_000_000);
        let replay =
            IncidentReplayView::snapshot(&loaded.key, "evidence-replay", vec![replay_event]);
        let envelope = AdapterEnvelope::new(
            "trace-xboundary",
            1_700_000_000_000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        );

        // Both sides should be deterministic
        verify_deterministic_serde(&loaded).expect("storage record deterministic");
        verify_deterministic_serde(&envelope).expect("tui envelope deterministic");
    }

    #[test]
    fn cross_boundary_service_error_contract_matches_storage_error() {
        // Verify that service endpoint errors and storage errors both carry
        // structured fields suitable for the same telemetry pipeline.
        let storage_event = StorageEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "error".to_string(),
            error_code: Some("FE-STOR-0002".to_string()),
        };

        let service_log = StructuredLogEvent {
            trace_id: "trace-1".to_string(),
            decision_id: Some("d-1".to_string()),
            policy_id: Some("p-1".to_string()),
            component: "service.api".to_string(),
            event: "control.execute".to_string(),
            outcome: "error".to_string(),
            error_code: Some("unauthorized".to_string()),
        };

        // Both should pass structured log verification
        let storage_json = serde_json::to_value(&storage_event).expect("serialize");
        let service_json = serde_json::to_value(&service_log).expect("serialize");

        let v1 = verify_structured_log(&storage_json, "frankensqlite");
        let v2 = verify_structured_log(&service_json, "fastapi_rust");
        assert!(v1.is_empty(), "storage log violations: {v1:?}");
        assert!(v2.is_empty(), "service log violations: {v2:?}");
    }

    #[test]
    fn field_type_matches_correctly() {
        assert!(FieldType::String.matches(&serde_json::json!("hello")));
        assert!(!FieldType::String.matches(&serde_json::json!(42)));
        assert!(FieldType::Number.matches(&serde_json::json!(42)));
        assert!(FieldType::Bool.matches(&serde_json::json!(true)));
        assert!(FieldType::Array.matches(&serde_json::json!([1, 2])));
        assert!(FieldType::Object.matches(&serde_json::json!({"a": 1})));
        assert!(FieldType::Null.matches(&serde_json::json!(null)));
    }

    #[test]
    fn field_type_display() {
        assert_eq!(FieldType::String.to_string(), "string");
        assert_eq!(FieldType::Number.to_string(), "number");
        assert_eq!(FieldType::Bool.to_string(), "bool");
        assert_eq!(FieldType::Array.to_string(), "array");
        assert_eq!(FieldType::Object.to_string(), "object");
        assert_eq!(FieldType::Null.to_string(), "null");
    }

    #[test]
    fn regression_class_display() {
        assert_eq!(RegressionClass::Breaking.to_string(), "BREAKING");
        assert_eq!(RegressionClass::Behavioral.to_string(), "BEHAVIORAL");
        assert_eq!(RegressionClass::Observability.to_string(), "OBSERVABILITY");
        assert_eq!(RegressionClass::Performance.to_string(), "PERFORMANCE");
    }

    #[test]
    fn regression_class_serde_round_trip() {
        for class in [
            RegressionClass::Breaking,
            RegressionClass::Behavioral,
            RegressionClass::Observability,
            RegressionClass::Performance,
        ] {
            verify_deterministic_serde(&class).expect("must be deterministic");
        }
    }
}
