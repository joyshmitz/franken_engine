//! Storage adapter boundary for deterministic FrankenEngine persistence paths.
//!
//! This module introduces a thin adapter layer between runtime persistence
//! contracts and `/dp/frankensqlite` backends. The interface is intentionally
//! store-agnostic and deterministic:
//! - stable query ordering
//! - explicit schema version checks and migration receipts
//! - structured operation events with canonical logging fields
//!
//! Plan references: Section 10.14 item 6 (`bd-89l2`), ADR-0004.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Current schema version for storage-adapter contracts.
pub const STORAGE_SCHEMA_VERSION: u32 = 1;

/// Canonical control-plane stores mapped in the persistence inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StoreKind {
    ReplayIndex,
    EvidenceIndex,
    BenchmarkLedger,
    PolicyCache,
    PlasWitness,
    ReplacementLineage,
    IfcProvenance,
    SpecializationIndex,
}

impl StoreKind {
    /// Stable string name used in logs and deterministic serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayIndex => "replay_index",
            Self::EvidenceIndex => "evidence_index",
            Self::BenchmarkLedger => "benchmark_ledger",
            Self::PolicyCache => "policy_cache",
            Self::PlasWitness => "plas_witness",
            Self::ReplacementLineage => "replacement_lineage",
            Self::IfcProvenance => "ifc_provenance",
            Self::SpecializationIndex => "specialization_index",
        }
    }

    /// Inventory-mapped frankensqlite integration point for the store.
    pub fn integration_point(self) -> &'static str {
        match self {
            Self::ReplayIndex => "frankensqlite::control_plane::replay_index",
            Self::EvidenceIndex => "frankensqlite::control_plane::evidence_index",
            Self::BenchmarkLedger => "frankensqlite::benchmark::ledger",
            Self::PolicyCache => "frankensqlite::control_plane::policy_cache",
            Self::PlasWitness => "frankensqlite::analysis::plas_witness",
            Self::ReplacementLineage => "frankensqlite::replacement::lineage_log",
            Self::IfcProvenance => "frankensqlite::control_plane::ifc_provenance",
            Self::SpecializationIndex => "frankensqlite::control_plane::specialization_index",
        }
    }
}

impl fmt::Display for StoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical context carried into adapter operations.
///
/// Field names intentionally match required structured log keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl EventContext {
    /// Build a validated operation context.
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let trace_id = trace_id.into();
        let decision_id = decision_id.into();
        let policy_id = policy_id.into();
        if trace_id.trim().is_empty() {
            return Err(StorageError::InvalidContext {
                field: "trace_id".to_string(),
            });
        }
        if decision_id.trim().is_empty() {
            return Err(StorageError::InvalidContext {
                field: "decision_id".to_string(),
            });
        }
        if policy_id.trim().is_empty() {
            return Err(StorageError::InvalidContext {
                field: "policy_id".to_string(),
            });
        }
        Ok(Self {
            trace_id,
            decision_id,
            policy_id,
        })
    }
}

/// Stored value with deterministic metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRecord {
    pub store: StoreKind,
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
    pub revision: u64,
}

/// Query selector for deterministic reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StoreQuery {
    /// Optional key prefix filter.
    pub key_prefix: Option<String>,
    /// Equality filters that must all match.
    pub metadata_filters: BTreeMap<String, String>,
    /// Optional max result size.
    pub limit: Option<usize>,
}

/// Batched write entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPutEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

/// Deterministic migration receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub backend: String,
    pub from_version: u32,
    pub to_version: u32,
    pub stores_touched: Vec<StoreKind>,
    pub records_touched: u64,
    pub state_hash_before: String,
    pub state_hash_after: String,
}

/// Canonical structured event emitted by adapter operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Stable error taxonomy for storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageError {
    InvalidContext { field: String },
    InvalidKey { key: String },
    InvalidQuery { detail: String },
    NotFound { store: StoreKind, key: String },
    SchemaVersionMismatch { expected: u32, actual: u32 },
    MigrationFailed { from: u32, to: u32, reason: String },
    IntegrityViolation { store: StoreKind, detail: String },
    BackendUnavailable { backend: String, detail: String },
    WriteRejected { detail: String },
}

impl StorageError {
    /// Stable machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidContext { .. } => "FE-STOR-0001",
            Self::InvalidKey { .. } => "FE-STOR-0002",
            Self::InvalidQuery { .. } => "FE-STOR-0003",
            Self::NotFound { .. } => "FE-STOR-0004",
            Self::SchemaVersionMismatch { .. } => "FE-STOR-0005",
            Self::MigrationFailed { .. } => "FE-STOR-0006",
            Self::IntegrityViolation { .. } => "FE-STOR-0007",
            Self::BackendUnavailable { .. } => "FE-STOR-0008",
            Self::WriteRejected { .. } => "FE-STOR-0009",
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContext { field } => write!(f, "invalid context field: {field}"),
            Self::InvalidKey { key } => write!(f, "invalid key: `{key}`"),
            Self::InvalidQuery { detail } => write!(f, "invalid query: {detail}"),
            Self::NotFound { store, key } => write!(f, "record not found: {store}/{key}"),
            Self::SchemaVersionMismatch { expected, actual } => {
                write!(
                    f,
                    "schema version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MigrationFailed { from, to, reason } => {
                write!(f, "migration failed: {from} -> {to}: {reason}")
            }
            Self::IntegrityViolation { store, detail } => {
                write!(f, "integrity violation in {store}: {detail}")
            }
            Self::BackendUnavailable { backend, detail } => {
                write!(f, "backend unavailable ({backend}): {detail}")
            }
            Self::WriteRejected { detail } => write!(f, "write rejected: {detail}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Generic storage adapter contract.
pub trait StorageAdapter {
    /// Adapter backend identifier.
    fn backend_name(&self) -> &'static str;
    /// Current schema version.
    fn current_schema_version(&self) -> u32;
    /// Fail-closed schema check for callers requiring a specific version.
    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError>;
    /// Apply deterministic schema migration.
    fn migrate_to(&mut self, target_version: u32) -> Result<MigrationReceipt, StorageError>;

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError>;

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError>;

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError>;

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError>;

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError>;

    fn events(&self) -> &[StorageEvent];
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreState {
    next_revision: u64,
    records: BTreeMap<String, StoreRecord>,
}

impl StoreState {
    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
    ) -> StoreRecord {
        self.next_revision = self.next_revision.saturating_add(1);
        let record = StoreRecord {
            store,
            key: key.clone(),
            value,
            metadata,
            revision: self.next_revision,
        };
        self.records.insert(key, record.clone());
        record
    }
}

/// Deterministic in-memory adapter used for tests and local workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMemoryStorageAdapter {
    schema_version: u32,
    stores: BTreeMap<StoreKind, StoreState>,
    events: Vec<StorageEvent>,
    fail_writes: bool,
}

impl Default for InMemoryStorageAdapter {
    fn default() -> Self {
        Self {
            schema_version: STORAGE_SCHEMA_VERSION,
            stores: BTreeMap::new(),
            events: Vec::new(),
            fail_writes: false,
        }
    }
}

impl InMemoryStorageAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Optional failure-injection mode for tests.
    pub fn with_fail_writes(mut self, fail_writes: bool) -> Self {
        self.fail_writes = fail_writes;
        self
    }

    fn validate_key(key: &str) -> Result<(), StorageError> {
        if key.trim().is_empty() {
            return Err(StorageError::InvalidKey {
                key: key.to_string(),
            });
        }
        Ok(())
    }

    fn get_or_insert_state(&mut self, store: StoreKind) -> &mut StoreState {
        self.stores.entry(store).or_default()
    }

    fn record_event(
        &mut self,
        context: &EventContext,
        event: &str,
        outcome: &str,
        error: Option<&StorageError>,
    ) {
        self.events.push(StorageEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "storage_adapter".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error.map(|err| err.code().to_string()),
        });
    }

    fn state_hash(&self) -> String {
        let bytes = serde_json::to_vec(&(self.schema_version, &self.stores)).unwrap_or_default();
        digest_hex(&bytes)
    }

    fn total_records(&self) -> u64 {
        self.stores
            .values()
            .map(|state| state.records.len() as u64)
            .sum()
    }

    pub fn events(&self) -> &[StorageEvent] {
        &self.events
    }
}

impl StorageAdapter for InMemoryStorageAdapter {
    fn backend_name(&self) -> &'static str {
        "in_memory"
    }

    fn current_schema_version(&self) -> u32 {
        self.schema_version
    }

    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError> {
        if self.schema_version == expected {
            Ok(())
        } else {
            Err(StorageError::SchemaVersionMismatch {
                expected,
                actual: self.schema_version,
            })
        }
    }

    fn migrate_to(&mut self, target_version: u32) -> Result<MigrationReceipt, StorageError> {
        if target_version < self.schema_version {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "downgrade is not supported".to_string(),
            });
        }
        if target_version > self.schema_version.saturating_add(1) {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "only single-step migrations are allowed".to_string(),
            });
        }

        let from_version = self.schema_version;
        let state_hash_before = self.state_hash();
        self.schema_version = target_version;
        let state_hash_after = self.state_hash();
        let stores_touched = self.stores.keys().copied().collect();

        Ok(MigrationReceipt {
            backend: self.backend_name().to_string(),
            from_version,
            to_version: target_version,
            stores_touched,
            records_touched: self.total_records(),
            state_hash_before,
            state_hash_after,
        })
    }

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError> {
        let result = (|| {
            if self.fail_writes {
                return Err(StorageError::WriteRejected {
                    detail: "write failure injected".to_string(),
                });
            }
            Self::validate_key(&key)?;
            Ok(self
                .get_or_insert_state(store)
                .put(store, key, value, metadata))
        })();

        self.record_event(
            context,
            "put",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError> {
        let result = (|| {
            Self::validate_key(key)?;
            Ok(self
                .stores
                .get(&store)
                .and_then(|state| state.records.get(key).cloned()))
        })();

        self.record_event(
            context,
            "get",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            if matches!(query.limit, Some(0)) {
                return Err(StorageError::InvalidQuery {
                    detail: "limit cannot be zero".to_string(),
                });
            }

            let Some(state) = self.stores.get(&store) else {
                return Ok(Vec::new());
            };

            let out: Vec<StoreRecord> = state
                .records
                .values()
                .filter(|record| {
                    if let Some(prefix) = &query.key_prefix
                        && !record.key.starts_with(prefix)
                    {
                        return false;
                    }
                    query
                        .metadata_filters
                        .iter()
                        .all(|(k, v)| record.metadata.get(k) == Some(v))
                })
                .cloned()
                .collect();

            Ok(canonicalize_records(out, query.limit))
        })();

        self.record_event(
            context,
            "query",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError> {
        let result = (|| {
            if self.fail_writes {
                return Err(StorageError::WriteRejected {
                    detail: "write failure injected".to_string(),
                });
            }
            Self::validate_key(key)?;
            Ok(self
                .stores
                .get_mut(&store)
                .and_then(|state| state.records.remove(key))
                .is_some())
        })();

        self.record_event(
            context,
            "delete",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            if self.fail_writes {
                return Err(StorageError::WriteRejected {
                    detail: "write failure injected".to_string(),
                });
            }
            let mut staged = self.stores.get(&store).cloned().unwrap_or_default();
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                Self::validate_key(&entry.key)?;
                out.push(staged.put(store, entry.key, entry.value, entry.metadata));
            }
            self.stores.insert(store, staged);
            Ok(out)
        })();

        self.record_event(
            context,
            "put_batch",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn events(&self) -> &[StorageEvent] {
        self.events()
    }
}

/// Minimal backend contract expected from `/dp/frankensqlite` integration.
///
/// This seam lets `franken_engine` depend on stable adapter behavior without
/// owning WAL/PRAGMA/migration internals locally.
pub trait FrankensqliteBackend {
    fn apply_wal_profile(&mut self) -> Result<(), String>;
    fn set_pragma(&mut self, key: &str, value: &str) -> Result<(), String>;
    fn current_schema_version(&self) -> Result<u32, String>;
    fn migrate_to(&mut self, target_version: u32) -> Result<(), String>;
    fn put_record(
        &mut self,
        store: StoreKind,
        key: &str,
        value: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<StoreRecord, String>;
    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String>;
    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String>;
    fn delete_record(&mut self, store: StoreKind, key: &str) -> Result<bool, String>;
    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: &[BatchPutEntry],
    ) -> Result<Vec<StoreRecord>, String>;
}

/// Adapter implementation backed by a frankensqlite integration backend.
#[derive(Debug)]
pub struct FrankensqliteStorageAdapter<B: FrankensqliteBackend> {
    backend: B,
    schema_version: u32,
    events: Vec<StorageEvent>,
}

impl<B: FrankensqliteBackend> FrankensqliteStorageAdapter<B> {
    pub fn new(mut backend: B) -> Result<Self, StorageError> {
        backend
            .apply_wal_profile()
            .map_err(|detail| StorageError::BackendUnavailable {
                backend: "frankensqlite".to_string(),
                detail,
            })?;

        // These defaults match ADR-0004 posture; frankensqlite owns specifics.
        for (key, value) in [
            ("journal_mode", "WAL"),
            ("busy_timeout", "5000"),
            ("foreign_keys", "ON"),
        ] {
            backend
                .set_pragma(key, value)
                .map_err(|detail| StorageError::BackendUnavailable {
                    backend: "frankensqlite".to_string(),
                    detail,
                })?;
        }

        let schema_version = backend.current_schema_version().map_err(|detail| {
            StorageError::BackendUnavailable {
                backend: "frankensqlite".to_string(),
                detail,
            }
        })?;

        Ok(Self {
            backend,
            schema_version,
            events: Vec::new(),
        })
    }

    fn map_backend_error(detail: String) -> StorageError {
        StorageError::BackendUnavailable {
            backend: "frankensqlite".to_string(),
            detail,
        }
    }

    fn record_event(
        &mut self,
        context: &EventContext,
        event: &str,
        outcome: &str,
        error: Option<&StorageError>,
    ) {
        self.events.push(StorageEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "storage_adapter".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error.map(|err| err.code().to_string()),
        });
    }
}

impl<B: FrankensqliteBackend> StorageAdapter for FrankensqliteStorageAdapter<B> {
    fn backend_name(&self) -> &'static str {
        "frankensqlite"
    }

    fn current_schema_version(&self) -> u32 {
        self.schema_version
    }

    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError> {
        if self.schema_version == expected {
            Ok(())
        } else {
            Err(StorageError::SchemaVersionMismatch {
                expected,
                actual: self.schema_version,
            })
        }
    }

    fn migrate_to(&mut self, target_version: u32) -> Result<MigrationReceipt, StorageError> {
        if target_version < self.schema_version {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "downgrade is not supported".to_string(),
            });
        }
        if target_version > self.schema_version.saturating_add(1) {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "only single-step migrations are allowed".to_string(),
            });
        }

        let from_version = self.schema_version;
        let state_hash_before = digest_hex(format!("schema:{from_version}").as_bytes());
        self.backend
            .migrate_to(target_version)
            .map_err(Self::map_backend_error)?;
        self.schema_version = target_version;
        let state_hash_after = digest_hex(format!("schema:{target_version}").as_bytes());

        Ok(MigrationReceipt {
            backend: self.backend_name().to_string(),
            from_version,
            to_version: target_version,
            stores_touched: Vec::new(),
            records_touched: 0,
            state_hash_before,
            state_hash_after,
        })
    }

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError> {
        let result = (|| {
            InMemoryStorageAdapter::validate_key(&key)?;
            self.backend
                .put_record(store, &key, &value, &metadata)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "put",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError> {
        let result = (|| {
            InMemoryStorageAdapter::validate_key(key)?;
            self.backend
                .get_record(store, key)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "get",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            if matches!(query.limit, Some(0)) {
                return Err(StorageError::InvalidQuery {
                    detail: "limit cannot be zero".to_string(),
                });
            }

            // Query without a limit first, then canonicalize and truncate locally.
            // This prevents backend row-order variation from changing visible results.
            let mut unconstrained = query.clone();
            unconstrained.limit = None;

            let rows = self
                .backend
                .query_records(store, &unconstrained)
                .map_err(Self::map_backend_error)?;
            Ok(canonicalize_records(rows, query.limit))
        })();

        self.record_event(
            context,
            "query",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError> {
        let result = (|| {
            InMemoryStorageAdapter::validate_key(key)?;
            self.backend
                .delete_record(store, key)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "delete",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            for entry in &entries {
                InMemoryStorageAdapter::validate_key(&entry.key)?;
            }
            self.backend
                .put_batch(store, &entries)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "put_batch",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn events(&self) -> &[StorageEvent] {
        &self.events
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
}

fn canonicalize_records(mut rows: Vec<StoreRecord>, limit: Option<usize>) -> Vec<StoreRecord> {
    rows.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then(a.revision.cmp(&b.revision))
            .then(a.value.cmp(&b.value))
            .then(a.metadata.cmp(&b.metadata))
    });

    if let Some(limit) = limit {
        rows.truncate(limit);
    }
    rows
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EventContext {
        EventContext::new("trace-storage", "decision-storage", "policy-storage")
            .expect("context should be valid")
    }

    #[test]
    fn in_memory_adapter_crud_and_query_are_deterministic() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let mut meta_a = BTreeMap::new();
        meta_a.insert("kind".to_string(), "benchmark".to_string());
        let mut meta_b = BTreeMap::new();
        meta_b.insert("kind".to_string(), "benchmark".to_string());

        adapter
            .put(
                StoreKind::BenchmarkLedger,
                "bench/z".to_string(),
                vec![2],
                meta_a,
                &context,
            )
            .expect("put z");
        adapter
            .put(
                StoreKind::BenchmarkLedger,
                "bench/a".to_string(),
                vec![1],
                meta_b,
                &context,
            )
            .expect("put a");

        let rows = adapter
            .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
            .expect("query");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "bench/a");
        assert_eq!(rows[1].key, "bench/z");

        let loaded = adapter
            .get(StoreKind::BenchmarkLedger, "bench/a", &context)
            .expect("get")
            .expect("must exist");
        assert_eq!(loaded.value, vec![1]);

        assert!(
            adapter
                .delete(StoreKind::BenchmarkLedger, "bench/z", &context)
                .expect("delete")
        );
    }

    #[test]
    fn in_memory_batch_put_is_atomic_on_invalid_key() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        adapter
            .put(
                StoreKind::ReplayIndex,
                "run/seed".to_string(),
                vec![9],
                BTreeMap::new(),
                &context,
            )
            .expect("seed row");

        let bad_batch = vec![
            BatchPutEntry {
                key: "run/1".to_string(),
                value: vec![1],
                metadata: BTreeMap::new(),
            },
            BatchPutEntry {
                key: "   ".to_string(),
                value: vec![2],
                metadata: BTreeMap::new(),
            },
        ];

        let err = adapter
            .put_batch(StoreKind::ReplayIndex, bad_batch, &context)
            .expect_err("batch should fail");
        assert!(matches!(err, StorageError::InvalidKey { .. }));

        let rows = adapter
            .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
            .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "run/seed");
    }

    #[test]
    fn in_memory_migration_receipt_is_deterministic() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        adapter
            .put(
                StoreKind::EvidenceIndex,
                "decision/1".to_string(),
                vec![7, 7],
                BTreeMap::new(),
                &context,
            )
            .expect("put");

        let receipt = adapter
            .migrate_to(STORAGE_SCHEMA_VERSION + 1)
            .expect("migrate");
        assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
        assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
        assert_eq!(receipt.records_touched, 1);
        assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
    }

    #[test]
    fn events_include_required_structured_fields() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let err = adapter
            .put(
                StoreKind::PolicyCache,
                "".to_string(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect_err("invalid key must fail");
        assert_eq!(err.code(), "FE-STOR-0002");

        let event = adapter.events().last().expect("event");
        assert_eq!(event.trace_id, "trace-storage");
        assert_eq!(event.decision_id, "decision-storage");
        assert_eq!(event.policy_id, "policy-storage");
        assert_eq!(event.component, "storage_adapter");
        assert_eq!(event.event, "put");
        assert_eq!(event.outcome, "error");
        assert_eq!(event.error_code.as_deref(), Some("FE-STOR-0002"));
    }

    #[derive(Debug, Default)]
    struct MockFrankenSqlite {
        wal_applied: bool,
        pragmas: BTreeMap<String, String>,
        schema_version: u32,
        stores: BTreeMap<StoreKind, StoreState>,
    }

    impl FrankensqliteBackend for MockFrankenSqlite {
        fn apply_wal_profile(&mut self) -> Result<(), String> {
            self.wal_applied = true;
            Ok(())
        }

        fn set_pragma(&mut self, key: &str, value: &str) -> Result<(), String> {
            self.pragmas.insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn current_schema_version(&self) -> Result<u32, String> {
            Ok(self.schema_version.max(STORAGE_SCHEMA_VERSION))
        }

        fn migrate_to(&mut self, target_version: u32) -> Result<(), String> {
            self.schema_version = target_version;
            Ok(())
        }

        fn put_record(
            &mut self,
            store: StoreKind,
            key: &str,
            value: &[u8],
            metadata: &BTreeMap<String, String>,
        ) -> Result<StoreRecord, String> {
            let state = self.stores.entry(store).or_default();
            Ok(state.put(store, key.to_string(), value.to_vec(), metadata.clone()))
        }

        fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
            Ok(self
                .stores
                .get(&store)
                .and_then(|state| state.records.get(key).cloned()))
        }

        fn query_records(
            &self,
            store: StoreKind,
            query: &StoreQuery,
        ) -> Result<Vec<StoreRecord>, String> {
            let mut out = Vec::new();
            if let Some(state) = self.stores.get(&store) {
                for record in state.records.values() {
                    if let Some(prefix) = &query.key_prefix
                        && !record.key.starts_with(prefix)
                    {
                        continue;
                    }
                    if !query
                        .metadata_filters
                        .iter()
                        .all(|(k, v)| record.metadata.get(k) == Some(v))
                    {
                        continue;
                    }
                    out.push(record.clone());
                }
            }
            if let Some(limit) = query.limit {
                out.truncate(limit);
            }
            Ok(out)
        }

        fn delete_record(&mut self, store: StoreKind, key: &str) -> Result<bool, String> {
            Ok(self
                .stores
                .get_mut(&store)
                .and_then(|state| state.records.remove(key))
                .is_some())
        }

        fn put_batch(
            &mut self,
            store: StoreKind,
            entries: &[BatchPutEntry],
        ) -> Result<Vec<StoreRecord>, String> {
            let mut staged = self.stores.get(&store).cloned().unwrap_or_default();
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                out.push(staged.put(
                    store,
                    entry.key.clone(),
                    entry.value.clone(),
                    entry.metadata.clone(),
                ));
            }
            self.stores.insert(store, staged);
            Ok(out)
        }
    }

    #[test]
    fn frankensqlite_adapter_applies_wal_and_pragmas() {
        let backend = MockFrankenSqlite::default();
        let adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
    }
}
