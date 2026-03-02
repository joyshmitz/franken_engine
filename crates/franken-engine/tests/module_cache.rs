use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheErrorCode, CacheInsertRequest, ModuleCache, ModuleVersionFingerprint,
};
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleRequest,
    ModuleResolver, ModuleSyntax, ResolutionContext,
};

fn resolver_context() -> ResolutionContext {
    ResolutionContext::new("trace-resolve", "decision-resolve", "policy-resolve")
}

fn cache_context() -> CacheContext {
    CacheContext::new("trace-cache", "decision-cache", "policy-cache")
}

#[test]
fn revocation_invalidation_blocks_cached_execution_until_restore() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .unwrap();

    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let resolved = resolver
        .resolve(&request, &resolver_context(), &AllowAllPolicy)
        .unwrap();

    let module_id = resolved.module.record.id.clone();
    let source_hash = resolved.module.record.canonical_hash();

    let mut cache = ModuleCache::new();
    let v1 = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                module_id.clone(),
                v1.clone(),
                resolved.module.content_hash.clone(),
                resolved.module.canonical_specifier.clone(),
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get(&module_id, &v1).is_some());

    cache.invalidate_trust_revocation(&module_id, 2, &cache_context());
    assert!(cache.get(&module_id, &v1).is_none());

    let blocked = cache
        .insert(
            CacheInsertRequest::new(
                module_id.clone(),
                ModuleVersionFingerprint::new(source_hash.clone(), 1, 2),
                ContentHash::compute(b"artifact-blocked"),
                "/app/main.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(blocked.code, CacheErrorCode::ModuleRevoked);

    cache.restore_trust(&module_id, 3, &cache_context());

    let resolved_again = resolver
        .resolve(&request, &resolver_context(), &AllowAllPolicy)
        .unwrap();
    let v3 = ModuleVersionFingerprint::new(source_hash, 1, 3);
    cache
        .insert(
            CacheInsertRequest::new(
                module_id.clone(),
                v3.clone(),
                resolved_again.module.content_hash,
                resolved_again.module.canonical_specifier,
            ),
            &cache_context(),
        )
        .unwrap();

    assert!(cache.get(&module_id, &v3).is_some());
}

#[test]
fn snapshot_merge_propagates_policy_and_revocation_changes() {
    let mut a = ModuleCache::new();
    let mut b = ModuleCache::new();

    let module_id = "mod:shared";
    let source_hash = ContentHash::compute(b"source-shared");

    a.insert(
        CacheInsertRequest::new(
            module_id,
            ModuleVersionFingerprint::new(source_hash, 1, 1),
            ContentHash::compute(b"artifact-shared"),
            "/app/shared.js",
        ),
        &cache_context(),
    )
    .unwrap();

    b.invalidate_policy_change(module_id, 2, &cache_context());
    b.invalidate_trust_revocation(module_id, 3, &cache_context());

    let b_snapshot = b.snapshot();
    a.merge_snapshot(&b_snapshot, &cache_context());

    let a_snapshot = a.snapshot();
    b.merge_snapshot(&a_snapshot, &cache_context());

    assert_eq!(a.state_hash(), b.state_hash());
    assert!(
        a.snapshot().revoked_modules.contains(module_id)
            && b.snapshot().revoked_modules.contains(module_id)
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: cache lifecycle, error paths, serde
// ────────────────────────────────────────────────────────────

#[test]
fn empty_cache_get_returns_none() {
    let cache = ModuleCache::new();
    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"x"), 1, 1);
    assert!(cache.get("nonexistent-mod", &v).is_none());
}

#[test]
fn insert_and_get_round_trip() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"round-trip");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:rt",
                v.clone(),
                ContentHash::compute(b"artifact-rt"),
                "/app/rt.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    let entry = cache.get("mod:rt", &v).expect("should be cached");
    assert_eq!(entry.resolved_specifier, "/app/rt.mjs");
}

#[test]
fn invalidate_source_update_removes_entry() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"source-inv");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:inv",
                v.clone(),
                ContentHash::compute(b"artifact-inv"),
                "/app/inv.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:inv", &v).is_some());

    cache.invalidate_source_update(
        "mod:inv",
        ContentHash::compute(b"new-source"),
        &cache_context(),
    );
    assert!(cache.get("mod:inv", &v).is_none());
}

#[test]
fn invalidate_policy_change_removes_entry() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"source-pol");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:pol",
                v.clone(),
                ContentHash::compute(b"artifact-pol"),
                "/app/pol.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:pol", &v).is_some());

    cache.invalidate_policy_change("mod:pol", 2, &cache_context());
    assert!(cache.get("mod:pol", &v).is_none());
}

#[test]
fn state_hash_changes_on_insert() {
    let mut cache = ModuleCache::new();
    let h0 = cache.state_hash();

    let source_hash = ContentHash::compute(b"src-h1");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:h1",
                v,
                ContentHash::compute(b"artifact-h1"),
                "/app/h1.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    let h1 = cache.state_hash();

    assert_ne!(h0, h1);
}

#[test]
fn state_hash_is_deterministic() {
    let make_cache = || {
        let mut cache = ModuleCache::new();
        let source_hash = ContentHash::compute(b"deterministic");
        let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:det",
                    v,
                    ContentHash::compute(b"artifact-det"),
                    "/app/det.mjs",
                ),
                &cache_context(),
            )
            .unwrap();
        cache
    };

    assert_eq!(make_cache().state_hash(), make_cache().state_hash());
}

#[test]
fn events_are_recorded_on_insert() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"events");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:ev",
                v,
                ContentHash::compute(b"artifact-ev"),
                "/app/ev.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    assert!(!cache.events().is_empty());
    let event = cache.events().last().expect("event");
    assert_eq!(event.trace_id, "trace-cache");
}

#[test]
fn cache_error_code_stable_codes() {
    assert_eq!(
        CacheErrorCode::ModuleRevoked.stable_code(),
        "FE-MODCACHE-0001"
    );
    assert_eq!(
        CacheErrorCode::VersionRegression.stable_code(),
        "FE-MODCACHE-0002"
    );
}

#[test]
fn cache_serde_round_trip_via_snapshot() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"serde-snap");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:serde",
                v.clone(),
                ContentHash::compute(b"artifact-serde"),
                "/app/serde.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    let snapshot = cache.snapshot();
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let recovered: frankenengine_engine::module_cache::CacheSnapshot =
        serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(snapshot.entries.len(), recovered.entries.len());
}

#[test]
fn module_version_fingerprint_serde_round_trip() {
    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"fp"), 5, 3);
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: ModuleVersionFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, recovered);
}

#[test]
fn restore_trust_after_revocation_allows_new_inserts() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"trust-restore");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);

    cache
        .insert(
            CacheInsertRequest::new(
                "mod:trust",
                v.clone(),
                ContentHash::compute(b"art-trust"),
                "/app/trust.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // Revoke
    cache.invalidate_trust_revocation("mod:trust", 2, &cache_context());
    assert!(cache.get("mod:trust", &v).is_none());

    // Restore
    cache.restore_trust("mod:trust", 3, &cache_context());

    // New insert should succeed
    let v2 = ModuleVersionFingerprint::new(source_hash, 1, 3);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:trust",
                v2.clone(),
                ContentHash::compute(b"art-trust-2"),
                "/app/trust.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:trust", &v2).is_some());
}
