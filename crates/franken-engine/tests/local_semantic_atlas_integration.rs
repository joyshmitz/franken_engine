use std::collections::{BTreeMap, BTreeSet};
use std::{fs, path::PathBuf};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::EffectBoundary;
use frankenengine_engine::semantic_contract_baseline::{
    LOCAL_SEMANTIC_ATLAS_BEAD_ID, LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION, LocalSemanticAtlas,
    LocalSemanticAtlasInput, SemanticContractVersion,
};
use frankenengine_engine::static_analysis_graph::{
    CapabilityBoundary, ComponentDescriptor, ComponentId, EffectClassification,
    HookKind as GraphHookKind, HookSlot,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn make_component(component_id: &str) -> ComponentDescriptor {
    let mut direct_capabilities = BTreeSet::new();
    direct_capabilities.insert("dom.mutate".to_string());

    ComponentDescriptor {
        id: ComponentId::new(component_id),
        is_function_component: true,
        module_path: format!("src/{component_id}.tsx"),
        export_name: Some(component_id.to_string()),
        hook_slots: vec![HookSlot {
            slot_index: 0,
            kind: GraphHookKind::Effect,
            label: "useEffect(sync)".to_string(),
            dependency_count: Some(1),
            has_cleanup: true,
            source_offset: 0,
            dependency_hash: None,
        }],
        props: BTreeMap::new(),
        consumed_contexts: vec!["AuthContext".to_string()],
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary {
            direct_capabilities,
            transitive_capabilities: BTreeSet::new(),
            render_effect: EffectBoundary::Pure,
            hook_effects: vec![EffectClassification {
                boundary: EffectBoundary::WriteEffect,
                required_capabilities: {
                    let mut caps = BTreeSet::new();
                    caps.insert("dom.mutate".to_string());
                    caps
                },
                idempotent: true,
                commutative: false,
                estimated_cost_millionths: 10_000,
            }],
            is_boundary: true,
            boundary_tags: Vec::new(),
        },
        is_pure: false,
        content_hash: ContentHash::compute(component_id.as_bytes()),
        children: Vec::new(),
    }
}

#[test]
fn frx_local_semantic_atlas_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_LOCAL_SEMANTIC_ATLAS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Local Semantic Atlas v1",
        "## Scope",
        "## Local Atlas Entry Contract",
        "## Fixture and Trace Linkage",
        "## Blocking Quality Debt Policy",
        "## Deterministic Replay",
        "## Evidence Pack",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "local semantic atlas doc missing section: {section}"
        );
    }
}

#[test]
fn frx_local_semantic_atlas_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_local_semantic_atlas_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.local-semantic-atlas.contract.v1")
    );
    assert_eq!(
        value["generated_by"].as_str(),
        Some(LOCAL_SEMANTIC_ATLAS_BEAD_ID)
    );
    assert_eq!(
        value["primary_bead"].as_str(),
        Some(LOCAL_SEMANTIC_ATLAS_BEAD_ID)
    );
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-14.1"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_fixture_trace_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_local_assumptions"].as_bool(),
        Some(true)
    );
}

#[test]
fn local_semantic_atlas_public_api_surfaces_blocking_debt() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        7,
        vec![LocalSemanticAtlasInput {
            component: make_component("UserPanel"),
            fixture_refs: Vec::new(),
            trace_refs: Vec::new(),
            assumption_keys: Vec::new(),
        }],
    );

    assert_eq!(atlas.schema_version, LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION);
    assert_eq!(atlas.blocking_debt_count(), 3);
    assert!(!atlas.validate().is_valid);
}

#[test]
fn frx_local_semantic_atlas_readme_gate_instructions_present() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        readme.contains("## FRX Local Semantic Atlas Gate"),
        "README missing local semantic atlas gate heading"
    );
    assert!(
        readme.contains("./scripts/run_frx_local_semantic_atlas_suite.sh ci"),
        "README missing local semantic atlas gate command"
    );
    assert!(
        readme.contains("./scripts/e2e/frx_local_semantic_atlas_replay.sh"),
        "README missing local semantic atlas replay command"
    );
}
