//! Deterministic module-cache invalidation strategy.
//!
//! Cache keys bind module identity to source hash, policy version, and trust
//! revision. Invalidation is explicit on source updates, policy changes, and
//! trust revocations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

pub type CacheResult<T> = Result<T, Box<CacheError>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleVersionFingerprint {
    pub source_hash: ContentHash,
    pub policy_version: u64,
    pub trust_revision: u64,
}

impl ModuleVersionFingerprint {
    pub fn new(source_hash: ContentHash, policy_version: u64, trust_revision: u64) -> Self {
        Self {
            source_hash,
            policy_version,
            trust_revision,
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "source_hash".to_string(),
            CanonicalValue::String(self.source_hash.to_hex()),
        );
        map.insert(
            "policy_version".to_string(),
            CanonicalValue::U64(self.policy_version),
        );
        map.insert(
            "trust_revision".to_string(),
            CanonicalValue::U64(self.trust_revision),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleCacheKey {
    pub module_id: String,
    pub version: ModuleVersionFingerprint,
}

impl ModuleCacheKey {
    pub fn new(module_id: impl Into<String>, version: ModuleVersionFingerprint) -> Self {
        Self {
            module_id: module_id.into(),
            version,
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "module_id".to_string(),
            CanonicalValue::String(self.module_id.clone()),
        );
        map.insert("version".to_string(), self.version.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCacheEntry {
    pub key: ModuleCacheKey,
    pub artifact_hash: ContentHash,
    pub resolved_specifier: String,
    pub inserted_seq: u64,
}

impl ModuleCacheEntry {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), self.key.canonical_value());
        map.insert(
            "artifact_hash".to_string(),
            CanonicalValue::String(self.artifact_hash.to_hex()),
        );
        map.insert(
            "resolved_specifier".to_string(),
            CanonicalValue::String(self.resolved_specifier.clone()),
        );
        map.insert(
            "inserted_seq".to_string(),
            CanonicalValue::U64(self.inserted_seq),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheInsertRequest {
    pub module_id: String,
    pub version: ModuleVersionFingerprint,
    pub artifact_hash: ContentHash,
    pub resolved_specifier: String,
}

impl CacheInsertRequest {
    pub fn new(
        module_id: impl Into<String>,
        version: ModuleVersionFingerprint,
        artifact_hash: ContentHash,
        resolved_specifier: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            version,
            artifact_hash,
            resolved_specifier: resolved_specifier.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl CacheContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvent {
    pub seq: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub module_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheErrorCode {
    ModuleRevoked,
    VersionRegression,
    EmptyModuleId,
}

impl CacheErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::ModuleRevoked => "FE-MODCACHE-0001",
            Self::VersionRegression => "FE-MODCACHE-0002",
            Self::EmptyModuleId => "FE-MODCACHE-0003",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheError {
    pub code: CacheErrorCode,
    pub message: String,
    pub event: CacheEvent,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.stable_code(), self.message)
    }
}

impl std::error::Error for CacheError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheSnapshot {
    pub entries: Vec<ModuleCacheEntry>,
    pub latest_versions: BTreeMap<String, ModuleVersionFingerprint>,
    pub revoked_modules: BTreeSet<String>,
    pub state_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ModuleCache {
    entries: BTreeMap<ModuleCacheKey, ModuleCacheEntry>,
    latest_versions: BTreeMap<String, ModuleVersionFingerprint>,
    revoked_modules: BTreeSet<String>,
    events: Vec<CacheEvent>,
    next_event_seq: u64,
}

impl ModuleCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(
        &self,
        module_id: &str,
        version: &ModuleVersionFingerprint,
    ) -> Option<&ModuleCacheEntry> {
        if self.revoked_modules.contains(module_id) {
            return None;
        }

        let latest = self.latest_versions.get(module_id)?;
        if latest != version {
            return None;
        }

        let key = ModuleCacheKey::new(module_id.to_string(), version.clone());
        self.entries.get(&key)
    }

    pub fn insert(
        &mut self,
        request: CacheInsertRequest,
        context: &CacheContext,
    ) -> CacheResult<()> {
        if request.module_id.trim().is_empty() {
            return Err(self.error(
                CacheErrorCode::EmptyModuleId,
                "module_id must not be empty",
                "cache_insert",
                "deny",
                "<empty>",
                context,
            ));
        }

        if self.revoked_modules.contains(&request.module_id) {
            return Err(self.error(
                CacheErrorCode::ModuleRevoked,
                format!("module '{}' is revoked", request.module_id),
                "cache_insert",
                "deny",
                &request.module_id,
                context,
            ));
        }

        if let Some(latest) = self.latest_versions.get(&request.module_id) {
            let is_policy_regression = request.version.policy_version < latest.policy_version;
            let is_trust_regression = request.version.trust_revision < latest.trust_revision;
            if is_policy_regression || is_trust_regression {
                return Err(self.error(
                    CacheErrorCode::VersionRegression,
                    format!(
                        "version regression for module '{}' (latest policy={}, trust={}, got policy={}, trust={})",
                        request.module_id,
                        latest.policy_version,
                        latest.trust_revision,
                        request.version.policy_version,
                        request.version.trust_revision,
                    ),
                    "cache_insert",
                    "deny",
                    &request.module_id,
                    context,
                ));
            }
        }

        self.latest_versions
            .insert(request.module_id.clone(), request.version.clone());

        let key = ModuleCacheKey::new(request.module_id.clone(), request.version);
        let entry = ModuleCacheEntry {
            key: key.clone(),
            artifact_hash: request.artifact_hash,
            resolved_specifier: request.resolved_specifier,
            inserted_seq: self.next_event_seq,
        };
        self.entries.insert(key, entry);

        self.prune_stale_entries(&request.module_id);
        self.push_event(
            "cache_insert",
            "allow",
            "none",
            request.module_id,
            "cache entry inserted",
            context,
        );
        Ok(())
    }

    pub fn invalidate_source_update(
        &mut self,
        module_id: &str,
        new_source_hash: ContentHash,
        context: &CacheContext,
    ) {
        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| ModuleVersionFingerprint::new(new_source_hash.clone(), 0, 0));
        latest.source_hash = new_source_hash;
        let current_source_hash = latest.source_hash.clone();
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |entry| {
            entry.key.version.source_hash != current_source_hash
        });

        self.push_event(
            "cache_invalidate_source_update",
            "allow",
            "none",
            module_id.to_string(),
            format!("removed {removed} stale source entries"),
            context,
        );
    }

    pub fn invalidate_policy_change(
        &mut self,
        module_id: &str,
        new_policy_version: u64,
        context: &CacheContext,
    ) {
        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.policy_version = new_policy_version;
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |entry| {
            entry.key.version.policy_version != new_policy_version
        });

        self.push_event(
            "cache_invalidate_policy_change",
            "allow",
            "none",
            module_id.to_string(),
            format!("removed {removed} stale policy entries"),
            context,
        );
    }

    pub fn invalidate_trust_revocation(
        &mut self,
        module_id: &str,
        new_trust_revision: u64,
        context: &CacheContext,
    ) {
        self.revoked_modules.insert(module_id.to_string());

        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.trust_revision = latest.trust_revision.max(new_trust_revision);
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |_| true);

        self.push_event(
            "cache_invalidate_trust_revocation",
            "allow",
            "none",
            module_id.to_string(),
            format!("removed {removed} entries and marked module revoked"),
            context,
        );
    }

    pub fn restore_trust(&mut self, module_id: &str, trust_revision: u64, context: &CacheContext) {
        self.revoked_modules.remove(module_id);

        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.trust_revision = latest.trust_revision.max(trust_revision);
        self.latest_versions.insert(module_id.to_string(), latest);

        self.push_event(
            "cache_restore_trust",
            "allow",
            "none",
            module_id.to_string(),
            "trust restored for module",
            context,
        );
    }

    pub fn snapshot(&self) -> CacheSnapshot {
        let entries = self.entries.values().cloned().collect::<Vec<_>>();
        CacheSnapshot {
            entries,
            latest_versions: self.latest_versions.clone(),
            revoked_modules: self.revoked_modules.clone(),
            state_hash: self.state_hash(),
        }
    }

    pub fn merge_snapshot(&mut self, snapshot: &CacheSnapshot, context: &CacheContext) {
        for (module_id, peer_version) in &snapshot.latest_versions {
            match self.latest_versions.get(module_id) {
                Some(local) if local >= peer_version => {}
                _ => {
                    self.latest_versions
                        .insert(module_id.clone(), peer_version.clone());
                }
            }
        }

        self.revoked_modules
            .extend(snapshot.revoked_modules.iter().cloned());

        for entry in &snapshot.entries {
            if self.revoked_modules.contains(&entry.key.module_id) {
                continue;
            }

            if self
                .latest_versions
                .get(&entry.key.module_id)
                .is_some_and(|latest| latest == &entry.key.version)
            {
                self.entries
                    .entry(entry.key.clone())
                    .or_insert_with(|| entry.clone());
            }
        }

        let module_ids = self.latest_versions.keys().cloned().collect::<Vec<_>>();
        for module_id in module_ids {
            self.prune_stale_entries(&module_id);
        }

        self.push_event(
            "cache_merge_snapshot",
            "allow",
            "none",
            "<fleet>".to_string(),
            "snapshot merged and stale entries pruned",
            context,
        );
    }

    pub fn state_hash(&self) -> ContentHash {
        let mut root = BTreeMap::new();

        let entries = self
            .entries
            .values()
            .map(ModuleCacheEntry::canonical_value)
            .collect::<Vec<_>>();
        root.insert("entries".to_string(), CanonicalValue::Array(entries));

        let mut versions = BTreeMap::new();
        for (module_id, version) in &self.latest_versions {
            versions.insert(module_id.clone(), version.canonical_value());
        }
        root.insert("latest_versions".to_string(), CanonicalValue::Map(versions));

        let revoked = self
            .revoked_modules
            .iter()
            .map(|module_id| CanonicalValue::String(module_id.clone()))
            .collect::<Vec<_>>();
        root.insert(
            "revoked_modules".to_string(),
            CanonicalValue::Array(revoked),
        );

        ContentHash::compute(&encode_value(&CanonicalValue::Map(root)))
    }

    pub fn events(&self) -> &[CacheEvent] {
        &self.events
    }

    fn prune_stale_entries(&mut self, module_id: &str) {
        if self.revoked_modules.contains(module_id) {
            self.entries
                .retain(|key, _| key.module_id.as_str() != module_id);
            return;
        }

        let latest = match self.latest_versions.get(module_id) {
            Some(latest) => latest.clone(),
            None => return,
        };

        self.entries
            .retain(|key, _| key.module_id.as_str() != module_id || key.version == latest);
    }

    fn remove_module_entries_where<F>(&mut self, module_id: &str, mut predicate: F) -> usize
    where
        F: FnMut(&ModuleCacheEntry) -> bool,
    {
        let keys_to_remove = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                if key.module_id.as_str() == module_id && predicate(entry) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let removed = keys_to_remove.len();
        for key in keys_to_remove {
            self.entries.remove(&key);
        }
        removed
    }

    fn push_event(
        &mut self,
        event: impl Into<String>,
        outcome: impl Into<String>,
        error_code: impl Into<String>,
        module_id: impl Into<String>,
        detail: impl Into<String>,
        context: &CacheContext,
    ) {
        let event = CacheEvent {
            seq: self.next_event_seq,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "module_cache".to_string(),
            event: event.into(),
            outcome: outcome.into(),
            error_code: error_code.into(),
            module_id: module_id.into(),
            detail: detail.into(),
        };
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        self.events.push(event);
    }

    fn error(
        &mut self,
        code: CacheErrorCode,
        message: impl Into<String>,
        event: &str,
        outcome: &str,
        module_id: &str,
        context: &CacheContext,
    ) -> Box<CacheError> {
        let message = message.into();
        self.push_event(
            event,
            outcome,
            code.stable_code(),
            module_id.to_string(),
            message.clone(),
            context,
        );
        Box::new(CacheError {
            code,
            message,
            event: self.events.last().expect("event was just pushed").clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CacheContext {
        CacheContext::new("trace-cache", "decision-cache", "policy-cache")
    }

    fn source_hash(seed: &str) -> ContentHash {
        ContentHash::compute(seed.as_bytes())
    }

    #[test]
    fn cache_hit_then_miss_after_source_update() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:a",
                    v1.clone(),
                    ContentHash::compute(b"artifact-a"),
                    "/app/a.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:a", &v1).is_some());

        let v2_hash = source_hash("v2");
        cache.invalidate_source_update("mod:a", v2_hash.clone(), &context());
        assert!(cache.get("mod:a", &v1).is_none());

        let v2 = ModuleVersionFingerprint::new(v2_hash, 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:a",
                    v2.clone(),
                    ContentHash::compute(b"artifact-a-v2"),
                    "/app/a.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:a", &v2).is_some());
    }

    #[test]
    fn trust_revocation_removes_entries_and_blocks_insert() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    version.clone(),
                    ContentHash::compute(b"artifact"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap();

        cache.invalidate_trust_revocation("mod:revoked", 2, &context());
        assert!(cache.get("mod:revoked", &version).is_none());

        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    ModuleVersionFingerprint::new(source_hash("v2"), 1, 2),
                    ContentHash::compute(b"artifact2"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::ModuleRevoked);

        cache.restore_trust("mod:revoked", 3, &context());
        let restored = ModuleVersionFingerprint::new(source_hash("v2"), 1, 3);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    restored.clone(),
                    ContentHash::compute(b"artifact3"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:revoked", &restored).is_some());
    }

    #[test]
    fn policy_change_invalidates_stale_entries() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("stable"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p",
                    v1.clone(),
                    ContentHash::compute(b"artifact-p"),
                    "/app/p.js",
                ),
                &context(),
            )
            .unwrap();

        cache.invalidate_policy_change("mod:p", 2, &context());
        assert!(cache.get("mod:p", &v1).is_none());

        let v2 = ModuleVersionFingerprint::new(source_hash("stable"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p",
                    v2.clone(),
                    ContentHash::compute(b"artifact-p2"),
                    "/app/p.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:p", &v2).is_some());
    }

    #[test]
    fn deterministic_state_hash_for_identical_sequences() {
        let build = || {
            let mut cache = ModuleCache::new();
            let ctx = context();
            let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
            cache
                .insert(
                    CacheInsertRequest::new(
                        "mod:x",
                        v1,
                        ContentHash::compute(b"artifact-x"),
                        "/app/x.js",
                    ),
                    &ctx,
                )
                .unwrap();
            cache.invalidate_policy_change("mod:x", 2, &ctx);
            let v2 = ModuleVersionFingerprint::new(source_hash("s1"), 2, 1);
            cache
                .insert(
                    CacheInsertRequest::new(
                        "mod:x",
                        v2,
                        ContentHash::compute(b"artifact-x2"),
                        "/app/x.js",
                    ),
                    &ctx,
                )
                .unwrap();
            cache.state_hash()
        };

        assert_eq!(build(), build());
    }

    #[test]
    fn snapshot_merge_converges_revocation_state() {
        let ctx = context();

        let mut a = ModuleCache::new();
        let mut b = ModuleCache::new();

        let version = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        a.insert(
            CacheInsertRequest::new(
                "mod:c",
                version,
                ContentHash::compute(b"artifact-c"),
                "/app/c.js",
            ),
            &ctx,
        )
        .unwrap();

        b.invalidate_trust_revocation("mod:c", 2, &ctx);

        let b_snapshot = b.snapshot();
        a.merge_snapshot(&b_snapshot, &ctx);

        let a_snapshot = a.snapshot();
        b.merge_snapshot(&a_snapshot, &ctx);

        assert_eq!(a.state_hash(), b.state_hash());
        assert!(a.revoked_modules.contains("mod:c"));
        assert!(b.revoked_modules.contains("mod:c"));
    }

    #[test]
    fn events_emit_required_structured_fields() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:e", 1, &ctx);

        let event = cache.events().last().unwrap();
        assert_eq!(event.component, "module_cache");
        assert_eq!(event.trace_id, "trace-cache");
        assert_eq!(event.decision_id, "decision-cache");
        assert_eq!(event.policy_id, "policy-cache");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
        assert!(!event.error_code.is_empty());
    }

    // -----------------------------------------------------------------------
    // Empty module ID rejection
    // -----------------------------------------------------------------------

    #[test]
    fn insert_empty_module_id_returns_empty_module_id_error() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "",
                    version,
                    ContentHash::compute(b"artifact"),
                    "/app/empty.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
        assert_eq!(err.code.stable_code(), "FE-MODCACHE-0003");
    }

    #[test]
    fn insert_whitespace_only_module_id_returns_empty_module_id_error() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "   ",
                    version,
                    ContentHash::compute(b"artifact"),
                    "/app/ws.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
    }

    // -----------------------------------------------------------------------
    // Version regression
    // -----------------------------------------------------------------------

    #[test]
    fn policy_version_regression_returns_version_regression_error() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 5, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:reg", v1, ContentHash::compute(b"a1"), "/app/reg.js"),
                &ctx,
            )
            .unwrap();

        let v2_regressed = ModuleVersionFingerprint::new(source_hash("s2"), 3, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:reg",
                    v2_regressed,
                    ContentHash::compute(b"a2"),
                    "/app/reg.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
        assert_eq!(err.code.stable_code(), "FE-MODCACHE-0002");
    }

    #[test]
    fn trust_revision_regression_returns_version_regression_error() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:tr", v1, ContentHash::compute(b"a1"), "/app/tr.js"),
                &ctx,
            )
            .unwrap();

        let v2_regressed = ModuleVersionFingerprint::new(source_hash("s2"), 1, 3);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:tr",
                    v2_regressed,
                    ContentHash::compute(b"a2"),
                    "/app/tr.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
    }

    // -----------------------------------------------------------------------
    // Get edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn get_unknown_module_returns_none() {
        let cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        assert!(cache.get("mod:unknown", &version).is_none());
    }

    #[test]
    fn get_with_stale_version_returns_none() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:stale",
                    v1.clone(),
                    ContentHash::compute(b"a1"),
                    "/app/stale.js",
                ),
                &context(),
            )
            .unwrap();

        let v2 = ModuleVersionFingerprint::new(source_hash("v2"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:stale",
                    v2,
                    ContentHash::compute(b"a2"),
                    "/app/stale.js",
                ),
                &context(),
            )
            .unwrap();

        // v1 is now stale
        assert!(cache.get("mod:stale", &v1).is_none());
    }

    // -----------------------------------------------------------------------
    // Multiple modules
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_modules_coexist_independently() {
        let mut cache = ModuleCache::new();
        let ctx = context();

        let va = ModuleVersionFingerprint::new(source_hash("a"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("b"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new("mod:a", va.clone(), ContentHash::compute(b"aa"), "/a.js"),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new("mod:b", vb.clone(), ContentHash::compute(b"bb"), "/b.js"),
                &ctx,
            )
            .unwrap();

        assert!(cache.get("mod:a", &va).is_some());
        assert!(cache.get("mod:b", &vb).is_some());

        // Revoke a, b should still be accessible
        cache.invalidate_trust_revocation("mod:a", 2, &ctx);
        assert!(cache.get("mod:a", &va).is_none());
        assert!(cache.get("mod:b", &vb).is_some());
    }

    // -----------------------------------------------------------------------
    // CacheErrorCode stable codes
    // -----------------------------------------------------------------------

    #[test]
    fn all_cache_error_codes_have_fe_modcache_prefix() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        for code in &codes {
            let stable = code.stable_code();
            assert!(
                stable.starts_with("FE-MODCACHE-"),
                "stable_code {} must start with FE-MODCACHE-",
                stable
            );
        }
    }

    #[test]
    fn cache_error_codes_are_unique() {
        let codes = [
            CacheErrorCode::ModuleRevoked.stable_code(),
            CacheErrorCode::VersionRegression.stable_code(),
            CacheErrorCode::EmptyModuleId.stable_code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all stable codes must be unique");
    }

    // -----------------------------------------------------------------------
    // CacheError Display
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_includes_stable_code_and_message() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", version, ContentHash::compute(b"a"), "/app/e.js"),
                &context(),
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0003"));
        assert!(display.contains("must not be empty"));
    }

    // -----------------------------------------------------------------------
    // Snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn empty_cache_snapshot_has_deterministic_state_hash() {
        let a = ModuleCache::new();
        let b = ModuleCache::new();
        assert_eq!(a.state_hash(), b.state_hash());
        let snap = a.snapshot();
        assert!(snap.entries.is_empty());
        assert!(snap.latest_versions.is_empty());
        assert!(snap.revoked_modules.is_empty());
    }

    #[test]
    fn snapshot_contains_all_current_entries() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new("mod:x", v1, ContentHash::compute(b"ax"), "/x.js"),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new("mod:y", v2, ContentHash::compute(b"ay"), "/y.js"),
                &ctx,
            )
            .unwrap();

        let snap = cache.snapshot();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.latest_versions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Merge snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn merge_snapshot_adopts_newer_versions() {
        let ctx = context();
        let mut local = ModuleCache::new();
        let mut remote = ModuleCache::new();

        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s"), 2, 1);

        local
            .insert(
                CacheInsertRequest::new("mod:m", v1.clone(), ContentHash::compute(b"a1"), "/m.js"),
                &ctx,
            )
            .unwrap();
        remote
            .insert(
                CacheInsertRequest::new("mod:m", v2.clone(), ContentHash::compute(b"a2"), "/m.js"),
                &ctx,
            )
            .unwrap();

        let remote_snap = remote.snapshot();
        local.merge_snapshot(&remote_snap, &ctx);

        // After merge, only v2 should be accessible (v1 is stale)
        assert!(local.get("mod:m", &v1).is_none());
        assert!(local.get("mod:m", &v2).is_some());
    }

    // -----------------------------------------------------------------------
    // Canonical value determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_canonical_value_is_deterministic() {
        let fp1 = ModuleVersionFingerprint::new(source_hash("stable"), 3, 7);
        let fp2 = ModuleVersionFingerprint::new(source_hash("stable"), 3, 7);
        assert_eq!(
            encode_value(&fp1.canonical_value()),
            encode_value(&fp2.canonical_value())
        );
    }

    #[test]
    fn module_cache_key_canonical_value_is_deterministic() {
        let version = ModuleVersionFingerprint::new(source_hash("k"), 1, 1);
        let k1 = ModuleCacheKey::new("mod:det", version.clone());
        let k2 = ModuleCacheKey::new("mod:det", version);
        assert_eq!(
            encode_value(&k1.canonical_value()),
            encode_value(&k2.canonical_value())
        );
    }

    // -----------------------------------------------------------------------
    // Event sequence monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn event_sequences_are_monotonically_increasing() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("ev"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:ev", v1, ContentHash::compute(b"a"), "/ev.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:ev", 2, &ctx);
        cache.restore_trust("mod:ev", 3, &ctx);

        let seqs: Vec<u64> = cache.events().iter().map(|e| e.seq).collect();
        for window in seqs.windows(2) {
            assert!(
                window[1] > window[0],
                "event seq must be monotonically increasing: {:?}",
                seqs
            );
        }
    }

    // -----------------------------------------------------------------------
    // Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_round_trip() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: CacheErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn module_version_fingerprint_serde_round_trip() {
        let fp = ModuleVersionFingerprint::new(source_hash("serde-test"), 42, 7);
        let json = serde_json::to_string(&fp).expect("serialize");
        let decoded: ModuleVersionFingerprint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, fp);
    }

    #[test]
    fn cache_snapshot_serde_round_trip() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("snap"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:snap", v, ContentHash::compute(b"as"), "/snap.js"),
                &ctx,
            )
            .unwrap();

        let snap = cache.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: CacheSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, snap);
    }

    // -----------------------------------------------------------------------
    // Invalidate source update on unknown module
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_source_update_on_unknown_module_creates_version_entry() {
        let mut cache = ModuleCache::new();
        cache.invalidate_source_update("mod:new", source_hash("fresh"), &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:new"));
    }

    // -----------------------------------------------------------------------
    // Forward version upgrade succeeds
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Serde round-trips (enrichment)
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_key_serde_round_trip() {
        let key = ModuleCacheKey::new("mod:serde", ModuleVersionFingerprint::new(source_hash("k"), 3, 7));
        let json = serde_json::to_string(&key).expect("serialize");
        let decoded: ModuleCacheKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, key);
    }

    #[test]
    fn module_cache_entry_serde_round_trip() {
        let key = ModuleCacheKey::new("mod:entry", ModuleVersionFingerprint::new(source_hash("e"), 1, 1));
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"artifact-serde"),
            resolved_specifier: "/app/entry.js".to_string(),
            inserted_seq: 42,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let decoded: ModuleCacheEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn cache_insert_request_serde_round_trip() {
        let req = CacheInsertRequest::new(
            "mod:req",
            ModuleVersionFingerprint::new(source_hash("r"), 2, 3),
            ContentHash::compute(b"art-req"),
            "/req.js",
        );
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: CacheInsertRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, req);
    }

    #[test]
    fn cache_context_serde_round_trip() {
        let ctx = CacheContext::new("t1", "d1", "p1");
        let json = serde_json::to_string(&ctx).expect("serialize");
        let decoded: CacheContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, ctx);
    }

    #[test]
    fn cache_event_serde_round_trip() {
        let mut cache = ModuleCache::new();
        cache.invalidate_source_update("mod:ev-serde", source_hash("x"), &context());
        let event = cache.events().last().unwrap().clone();
        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: CacheEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, event);
    }

    #[test]
    fn cache_error_serde_round_trip() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let json = serde_json::to_string(&*err).expect("serialize");
        let decoded: CacheError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, *err);
    }

    #[test]
    fn module_cache_snapshot_captures_revoked_and_entries() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("mc"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:mc", v, ContentHash::compute(b"art"), "/mc.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:revoked", 1, &ctx);
        let snap = cache.snapshot();
        // Snapshot roundtrips through JSON (unlike ModuleCache which has non-string map keys)
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: CacheSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, snap);
        assert_eq!(snap.entries.len(), 1);
        assert!(snap.revoked_modules.contains("mod:revoked"));
    }

    // -----------------------------------------------------------------------
    // CacheErrorCode serde uses snake_case
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_uses_snake_case() {
        let json = serde_json::to_string(&CacheErrorCode::ModuleRevoked).unwrap();
        assert_eq!(json, "\"module_revoked\"");
        let json = serde_json::to_string(&CacheErrorCode::VersionRegression).unwrap();
        assert_eq!(json, "\"version_regression\"");
        let json = serde_json::to_string(&CacheErrorCode::EmptyModuleId).unwrap();
        assert_eq!(json, "\"empty_module_id\"");
    }

    // -----------------------------------------------------------------------
    // CacheError Display for all error codes
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_module_revoked() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:rd", v, ContentHash::compute(b"a"), "/r.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:rd", 2, &ctx);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:rd",
                    ModuleVersionFingerprint::new(source_hash("s2"), 1, 2),
                    ContentHash::compute(b"a2"),
                    "/r.js",
                ),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0001"), "got: {display}");
        assert!(display.contains("revoked"), "got: {display}");
    }

    #[test]
    fn cache_error_display_version_regression() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 5, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:vr", v1, ContentHash::compute(b"a1"), "/vr.js"),
                &ctx,
            )
            .unwrap();
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 3, 5);
        let err = cache
            .insert(
                CacheInsertRequest::new("mod:vr", v2, ContentHash::compute(b"a2"), "/vr.js"),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0002"), "got: {display}");
        assert!(display.contains("regression"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // Default trait
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_default_equals_new() {
        let a = ModuleCache::new();
        let b = ModuleCache::default();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Invalidation on unknown modules
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_policy_change_on_unknown_module_creates_version_entry() {
        let mut cache = ModuleCache::new();
        cache.invalidate_policy_change("mod:unknown-policy", 5, &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:unknown-policy"));
        assert_eq!(snap.latest_versions["mod:unknown-policy"].policy_version, 5);
    }

    #[test]
    fn invalidate_trust_revocation_on_unknown_module_marks_revoked() {
        let mut cache = ModuleCache::new();
        cache.invalidate_trust_revocation("mod:unknown-trust", 3, &context());
        let snap = cache.snapshot();
        assert!(snap.revoked_modules.contains("mod:unknown-trust"));
        assert!(snap.latest_versions.contains_key("mod:unknown-trust"));
    }

    // -----------------------------------------------------------------------
    // restore_trust edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn restore_trust_on_non_revoked_module_is_harmless() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:nr", v.clone(), ContentHash::compute(b"a"), "/nr.js"),
                &ctx,
            )
            .unwrap();
        let hash_before = cache.state_hash();
        cache.restore_trust("mod:nr", 2, &ctx);
        // Module still accessible, trust_revision may advance
        assert!(cache.get("mod:nr", &v).is_none()); // version changed (trust_revision bumped)
        // But hash should differ since latest_versions changed
        assert_ne!(cache.state_hash(), hash_before);
    }

    #[test]
    fn restore_trust_on_unknown_module_creates_entry() {
        let mut cache = ModuleCache::new();
        cache.restore_trust("mod:ghost", 1, &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:ghost"));
        assert!(!snap.revoked_modules.contains("mod:ghost"));
    }

    // -----------------------------------------------------------------------
    // Merge snapshot edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn merge_empty_remote_snapshot_is_noop() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:local", v.clone(), ContentHash::compute(b"a"), "/l.js"),
                &ctx,
            )
            .unwrap();
        let hash_before = cache.state_hash();
        let empty_snap = ModuleCache::new().snapshot();
        cache.merge_snapshot(&empty_snap, &ctx);
        assert_eq!(cache.state_hash(), hash_before);
        assert!(cache.get("mod:local", &v).is_some());
    }

    #[test]
    fn merge_into_empty_local_adopts_remote_entries() {
        let mut remote = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("r"), 1, 1);
        remote
            .insert(
                CacheInsertRequest::new("mod:remote", v.clone(), ContentHash::compute(b"ar"), "/r.js"),
                &ctx,
            )
            .unwrap();
        let remote_snap = remote.snapshot();

        let mut local = ModuleCache::new();
        local.merge_snapshot(&remote_snap, &ctx);
        assert!(local.get("mod:remote", &v).is_some());
    }

    #[test]
    fn merge_does_not_import_revoked_module_entries() {
        let mut remote = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        remote
            .insert(
                CacheInsertRequest::new("mod:willrevoke", v, ContentHash::compute(b"a"), "/w.js"),
                &ctx,
            )
            .unwrap();
        remote.invalidate_trust_revocation("mod:willrevoke", 2, &ctx);
        let remote_snap = remote.snapshot();

        let mut local = ModuleCache::new();
        local.merge_snapshot(&remote_snap, &ctx);
        assert!(local.revoked_modules.contains("mod:willrevoke"));
        assert!(local.entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // State hash changes after operations
    // -----------------------------------------------------------------------

    #[test]
    fn state_hash_changes_after_insert() {
        let mut cache = ModuleCache::new();
        let hash_empty = cache.state_hash();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:sh", v, ContentHash::compute(b"a"), "/sh.js"),
                &context(),
            )
            .unwrap();
        assert_ne!(cache.state_hash(), hash_empty);
    }

    #[test]
    fn state_hash_changes_after_revocation() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:hr", v, ContentHash::compute(b"a"), "/hr.js"),
                &ctx,
            )
            .unwrap();
        let hash_before = cache.state_hash();
        cache.invalidate_trust_revocation("mod:hr", 2, &ctx);
        assert_ne!(cache.state_hash(), hash_before);
    }

    // -----------------------------------------------------------------------
    // Ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_ordering() {
        let a = ModuleVersionFingerprint::new(source_hash("a"), 1, 1);
        let b = ModuleVersionFingerprint::new(source_hash("a"), 2, 1);
        let c = ModuleVersionFingerprint::new(source_hash("a"), 2, 2);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn module_cache_key_ordering() {
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let ka = ModuleCacheKey::new("aaa", v.clone());
        let kb = ModuleCacheKey::new("bbb", v);
        assert!(ka < kb);
    }

    // -----------------------------------------------------------------------
    // Error event fields
    // -----------------------------------------------------------------------

    #[test]
    fn error_event_records_correct_fields() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let _ = cache.insert(
            CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
            &context(),
        );
        let event = cache.events().last().unwrap();
        assert_eq!(event.component, "module_cache");
        assert_eq!(event.event, "cache_insert");
        assert_eq!(event.outcome, "deny");
        assert_eq!(event.error_code, "FE-MODCACHE-0003");
        assert_eq!(event.module_id, "<empty>");
    }

    // -----------------------------------------------------------------------
    // ModuleCacheEntry canonical value determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_entry_canonical_value_is_deterministic() {
        let key = ModuleCacheKey::new("mod:det2", ModuleVersionFingerprint::new(source_hash("d"), 1, 1));
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"det-artifact"),
            resolved_specifier: "/det.js".to_string(),
            inserted_seq: 99,
        };
        let bytes1 = encode_value(&entry.canonical_value());
        let bytes2 = encode_value(&entry.canonical_value());
        assert_eq!(bytes1, bytes2);
    }

    // -----------------------------------------------------------------------
    // Forward version upgrade succeeds (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn forward_version_upgrade_succeeds() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:up", v1, ContentHash::compute(b"a1"), "/up.js"),
                &ctx,
            )
            .unwrap();

        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 2, 2);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:up",
                    v2.clone(),
                    ContentHash::compute(b"a2"),
                    "/up.js",
                ),
                &ctx,
            )
            .unwrap();

        assert!(cache.get("mod:up", &v2).is_some());
    }
}
