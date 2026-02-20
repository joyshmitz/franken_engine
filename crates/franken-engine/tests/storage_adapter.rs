use std::collections::BTreeMap;

use frankenengine_engine::storage_adapter::{
    BatchPutEntry, EventContext, FrankensqliteBackend, FrankensqliteStorageAdapter,
    InMemoryStorageAdapter, STORAGE_SCHEMA_VERSION, StorageAdapter, StoreKind, StoreQuery,
    StoreRecord,
};

fn context() -> EventContext {
    EventContext::new("trace-it", "decision-it", "policy-it").expect("context")
}

#[test]
fn in_memory_adapter_supports_crud_batch_and_deterministic_queries() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "trace/2".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .expect("put trace/2");

    let mut metadata = BTreeMap::new();
    metadata.insert("zone".to_string(), "prod".to_string());
    let batch = vec![
        BatchPutEntry {
            key: "trace/1".to_string(),
            value: vec![1],
            metadata: metadata.clone(),
        },
        BatchPutEntry {
            key: "trace/3".to_string(),
            value: vec![3],
            metadata,
        },
    ];
    adapter
        .put_batch(StoreKind::ReplayIndex, batch, &context)
        .expect("batch put");

    let rows = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: Some("trace/".to_string()),
                metadata_filters: BTreeMap::new(),
                limit: None,
            },
            &context,
        )
        .expect("query");

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].key, "trace/1");
    assert_eq!(rows[1].key, "trace/2");
    assert_eq!(rows[2].key, "trace/3");

    let loaded = adapter
        .get(StoreKind::ReplayIndex, "trace/2", &context)
        .expect("get")
        .expect("value");
    assert_eq!(loaded.value, vec![2]);

    assert!(
        adapter
            .delete(StoreKind::ReplayIndex, "trace/2", &context)
            .expect("delete")
    );

    let post_delete = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .expect("query after delete");
    assert_eq!(post_delete.len(), 2);
}

#[test]
fn migration_and_version_checks_are_fail_closed() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    adapter
        .put(
            StoreKind::EvidenceIndex,
            "decision/one".to_string(),
            vec![1, 2, 3],
            BTreeMap::new(),
            &context,
        )
        .expect("seed");

    let receipt = adapter
        .migrate_to(STORAGE_SCHEMA_VERSION + 1)
        .expect("migrate");
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
    assert_eq!(receipt.records_touched, 1);

    let mismatch = adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION)
        .expect_err("should fail closed");
    assert_eq!(mismatch.code(), "FE-STOR-0005");
}

#[derive(Debug, Default)]
struct MockFrankensqlite {
    schema_version: u32,
    stores: BTreeMap<StoreKind, BTreeMap<String, StoreRecord>>,
}

impl FrankensqliteBackend for MockFrankensqlite {
    fn apply_wal_profile(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn set_pragma(&mut self, _key: &str, _value: &str) -> Result<(), String> {
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
        let records = self.stores.entry(store).or_default();
        let revision = records
            .get(key)
            .map_or(1, |existing| existing.revision.saturating_add(1));
        let record = StoreRecord {
            store,
            key: key.to_string(),
            value: value.to_vec(),
            metadata: metadata.clone(),
            revision,
        };
        records.insert(key.to_string(), record.clone());
        Ok(record)
    }

    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
        Ok(self
            .stores
            .get(&store)
            .and_then(|records| records.get(key).cloned()))
    }

    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String> {
        let mut out = Vec::new();
        if let Some(records) = self.stores.get(&store) {
            for record in records.values() {
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
            .and_then(|records| records.remove(key))
            .is_some())
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: &[BatchPutEntry],
    ) -> Result<Vec<StoreRecord>, String> {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            out.push(self.put_record(store, &entry.key, &entry.value, &entry.metadata)?);
        }
        Ok(out)
    }
}

#[test]
fn frankensqlite_adapter_works_with_backend_contract() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    let context = context();

    adapter
        .put(
            StoreKind::PolicyCache,
            "policy/default".to_string(),
            vec![7, 7, 7],
            BTreeMap::new(),
            &context,
        )
        .expect("put policy");

    let loaded = adapter
        .get(StoreKind::PolicyCache, "policy/default", &context)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![7, 7, 7]);

    let events = adapter.events();
    assert!(!events.is_empty());
    assert_eq!(events[0].trace_id, "trace-it");
    assert_eq!(events[0].decision_id, "decision-it");
    assert_eq!(events[0].policy_id, "policy-it");
}
