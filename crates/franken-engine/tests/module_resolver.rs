use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle,
    ModuleDefinition, ModuleDependency, ModuleRequest, ModuleResolver, ModuleSyntax,
    ResolutionContext, ResolutionErrorCode,
};

fn context() -> ResolutionContext {
    ResolutionContext::new(
        "trace-integration",
        "decision-integration",
        "policy-integration",
    )
}

#[test]
fn chain_resolution_enforces_transitive_policy_checks() {
    let mut resolver = DeterministicModuleResolver::new("/app");

    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './util';")
                .with_dependency(ModuleDependency::new("./util", ImportStyle::Import)),
        )
        .unwrap();

    resolver
        .register_workspace_module(
            "/app/util.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './secret';")
                .with_dependency(ModuleDependency::new("./secret", ImportStyle::Import)),
        )
        .unwrap();

    resolver
        .register_workspace_module(
            "/app/secret.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const secret = 1;")
                .require_capability(RuntimeCapability::FsWrite),
        )
        .unwrap();

    let entry = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);

    let denied_policy = CapabilityPolicyHook::new(BTreeSet::new());
    let denied_error = resolver
        .resolve_chain(&entry, &context(), &denied_policy)
        .expect_err("expected missing capability to deny transitive dependency");
    assert_eq!(denied_error.code, ResolutionErrorCode::PolicyDenied);
    assert_eq!(
        denied_error.event.error_code,
        ResolutionErrorCode::PolicyDenied.stable_code()
    );

    let mut granted = BTreeSet::new();
    granted.insert(RuntimeCapability::FsWrite);
    let allowed_policy = CapabilityPolicyHook::new(granted);
    let outcomes = resolver
        .resolve_chain(&entry, &context(), &allowed_policy)
        .expect("transitive resolution should pass when capability is granted");

    let ids = outcomes
        .iter()
        .map(|outcome| outcome.module.record.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec!["/app/main.mjs", "/app/util.mjs", "/app/secret.mjs"]
    );
}

#[test]
fn cjs_and_esm_compatibility_resolution_order_is_deterministic() {
    let mut resolver = DeterministicModuleResolver::new("/repo");
    resolver
        .register_workspace_module(
            "/repo/pkg/index.js",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/repo/pkg/index.cjs",
            ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 'cjs';"),
        )
        .unwrap();

    let require_request = ModuleRequest::new("pkg", ImportStyle::Require);
    let require_outcome = resolver
        .resolve(&require_request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        require_outcome.module.canonical_specifier,
        "/repo/pkg/index.cjs"
    );

    let import_request = ModuleRequest::new("pkg", ImportStyle::Import);
    let import_outcome = resolver
        .resolve(&import_request, &context(), &AllowAllPolicy)
        .unwrap();
    assert_eq!(
        import_outcome.module.canonical_specifier,
        "/repo/pkg/index.js"
    );
}
