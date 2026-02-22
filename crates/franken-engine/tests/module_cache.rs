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
