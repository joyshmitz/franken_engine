#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ts_module_resolution::{
    DeterministicTsModuleResolver, TsModuleRequest, TsModuleResolutionConfig,
    TsModuleResolutionMode, TsPackageDefinition, TsPackageExportTarget, TsRequestStyle,
    TsResolutionContext, TsResolutionDriftClass, classify_resolution_drift,
    write_ts_resolution_artifacts,
};
use serde_json::Value;

const SCHEMA_VERSION: &str = "rgc.ts-module-resolution.parity.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_ts_module_resolution_parity_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn context() -> TsResolutionContext {
    TsResolutionContext::new("trace-tsres-1", "decision-tsres-1", "policy-tsres-1")
}

fn base_config() -> TsModuleResolutionConfig {
    TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: ".".to_string(),
        mode: TsModuleResolutionMode::NodeNext,
        ..TsModuleResolutionConfig::default()
    }
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic from unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frx_ts_resolution_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn parse_contract() -> Value {
    serde_json::from_str(CONTRACT_JSON).expect("contract json should parse")
}

fn json_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .expect("array field should exist")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("array entry should be string")
                .to_string()
        })
        .collect()
}

#[test]
fn rgc_202_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_TS_MODULE_RESOLUTION_PARITY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required in [
        "# RGC TS Module Resolution Parity V1",
        "## Purpose",
        "## Resolution Semantics",
        "## Drift Classification and Remediation",
        "## Artifact Contract",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(required),
            "missing required section in {}: {required}",
            path.display()
        );
    }
}

#[test]
fn rgc_202_contract_schema_and_required_fields_are_present() {
    let contract = parse_contract();

    assert_eq!(
        contract
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version should be present"),
        SCHEMA_VERSION
    );
    assert_eq!(
        contract
            .get("bead_id")
            .and_then(Value::as_str)
            .expect("bead_id should be present"),
        "bd-1lsy.3.2"
    );

    let resolution_policy = contract
        .get("resolution_policy")
        .expect("resolution_policy should exist");
    assert_eq!(
        resolution_policy
            .get("deterministic")
            .and_then(Value::as_bool)
            .expect("deterministic should exist"),
        true
    );
    assert_eq!(
        resolution_policy
            .get("paths_alias_support")
            .and_then(Value::as_bool)
            .expect("paths_alias_support should exist"),
        true
    );
    assert_eq!(
        resolution_policy
            .get("base_url_fallback")
            .and_then(Value::as_bool)
            .expect("base_url_fallback should exist"),
        true
    );

    let stable_fields: BTreeSet<String> = json_string_array(resolution_policy, "stable_trace_fields")
        .into_iter()
        .collect();
    for required in ["trace_id", "decision_id", "policy_id", "event", "error_code"] {
        assert!(stable_fields.contains(required), "missing trace field {required}");
    }

    let parity_scenarios = contract
        .get("parity_scenarios")
        .and_then(Value::as_array)
        .expect("parity_scenarios should be array");
    assert_eq!(parity_scenarios.len(), 3);
    for scenario in parity_scenarios {
        assert_eq!(
            scenario
                .get("required")
                .and_then(Value::as_bool)
                .expect("required should exist"),
            true
        );
        assert!(
            scenario
                .get("coverage")
                .and_then(Value::as_array)
                .map(|entries| !entries.is_empty())
                .unwrap_or(false),
            "scenario coverage must be non-empty"
        );
    }

    let artifact_contract = contract
        .get("artifact_contract")
        .expect("artifact_contract should exist");
    let required_paths: BTreeSet<String> = json_string_array(artifact_contract, "required_paths")
        .into_iter()
        .collect();
    for required in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "ts_resolution_trace.jsonl",
    ] {
        assert!(required_paths.contains(required), "missing artifact path {required}");
    }

    let drift_classes: BTreeSet<String> = contract
        .get("drift_classification")
        .and_then(Value::as_array)
        .expect("drift_classification should exist")
        .iter()
        .filter_map(|entry| entry.get("class").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    for required in [
        "no_drift",
        "candidate_order_mismatch",
        "missing_target",
        "extra_target",
        "full_mismatch",
    ] {
        assert!(drift_classes.contains(required), "missing drift class {required}");
    }

    let operator_verification = contract
        .get("operator_verification")
        .and_then(Value::as_array)
        .expect("operator_verification should be present");
    let verification_lines = operator_verification
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(verification_lines.contains("jq empty"));
    assert!(verification_lines.contains("cargo test -p frankenengine-engine --test ts_module_resolution_parity"));
}

#[test]
fn resolver_honors_paths_alias_and_extension_probe_order() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string(), ".js".to_string()];
    config.paths = BTreeMap::from([(
        "@core/*".to_string(),
        vec!["packages/core/src/*".to_string()],
    )]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/core/src/math.ts");
    resolver.register_file("/repo/packages/core/src/math.js");

    let request = TsModuleRequest::new("@core/math", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("alias-based import should resolve");

    assert_eq!(outcome.resolved_path, "/repo/packages/core/src/math.ts");

    let probes = outcome.probe_sequence();
    assert_eq!(probes[0], "/repo/packages/core/src/math");
    assert_eq!(probes[1], "/repo/packages/core/src/math.ts");

    assert!(
        outcome
            .traces
            .iter()
            .any(|event| event.event == "paths_alias_match"),
        "expected alias match trace event"
    );
}

#[test]
fn resolver_selects_package_export_condition_by_request_style() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string(), "default".to_string()];
    config.require_conditions = vec!["require".to_string(), "default".to_string()];
    config.import_extensions = vec![".mjs".to_string(), ".js".to_string()];
    config.require_extensions = vec![".cjs".to_string(), ".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/toolkit/esm/index.mjs");
    resolver.register_file("/repo/node_modules/toolkit/cjs/index.cjs");
    resolver.register_file("/repo/node_modules/toolkit/dist/index.js");

    let mut condition_targets = BTreeMap::new();
    condition_targets.insert("import".to_string(), "./esm/index".to_string());
    condition_targets.insert("require".to_string(), "./cjs/index".to_string());
    condition_targets.insert("default".to_string(), "./dist/index".to_string());

    let package = TsPackageDefinition::new("toolkit", "/repo/node_modules/toolkit").with_export(
        ".",
        TsPackageExportTarget {
            condition_targets,
            fallback_target: Some("./dist/index".to_string()),
        },
    );
    resolver.register_package(package);

    let import_outcome = resolver
        .resolve(
            &TsModuleRequest::new("toolkit", TsRequestStyle::Import),
            &context(),
        )
        .expect("import should resolve");
    assert_eq!(import_outcome.resolved_path, "/repo/node_modules/toolkit/esm/index.mjs");
    assert_eq!(import_outcome.selected_condition.as_deref(), Some("import"));

    let require_outcome = resolver
        .resolve(
            &TsModuleRequest::new("toolkit", TsRequestStyle::Require),
            &context(),
        )
        .expect("require should resolve");
    assert_eq!(require_outcome.resolved_path, "/repo/node_modules/toolkit/cjs/index.cjs");
    assert_eq!(require_outcome.selected_condition.as_deref(), Some("require"));
}

#[test]
fn resolver_paths_alias_has_priority_over_base_url_fallback() {
    let mut with_alias = base_config();
    with_alias.base_url = "src".to_string();
    with_alias.paths = BTreeMap::from([(
        "utils/*".to_string(),
        vec!["../packages/utils/*".to_string()],
    )]);
    with_alias.import_extensions = vec![".ts".to_string()];

    let mut alias_resolver = DeterministicTsModuleResolver::new(with_alias);
    alias_resolver.register_file("/repo/packages/utils/math.ts");
    alias_resolver.register_file("/repo/src/utils/math.ts");

    let request = TsModuleRequest::new("utils/math", TsRequestStyle::Import);
    let alias_outcome = alias_resolver
        .resolve(&request, &context())
        .expect("alias route should win over baseUrl fallback");
    assert_eq!(alias_outcome.resolved_path, "/repo/packages/utils/math.ts");

    let mut without_alias = base_config();
    without_alias.base_url = "src".to_string();
    without_alias.paths.clear();
    without_alias.import_extensions = vec![".ts".to_string()];

    let mut fallback_resolver = DeterministicTsModuleResolver::new(without_alias);
    fallback_resolver.register_file("/repo/src/utils/math.ts");

    let fallback_outcome = fallback_resolver
        .resolve(&request, &context())
        .expect("baseUrl fallback should resolve without alias");
    assert_eq!(fallback_outcome.resolved_path, "/repo/src/utils/math.ts");
}

#[test]
fn monorepo_resolution_trace_is_deterministic_across_runs() {
    let mut config = base_config();
    config.paths = BTreeMap::from([(
        "@app/*".to_string(),
        vec![
            "apps/web/src/*".to_string(),
            "packages/shared/src/*".to_string(),
        ],
    )]);
    config.import_extensions = vec![".ts".to_string(), "/index.ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/shared/src/runtime/index.ts");

    let request = TsModuleRequest::new("@app/runtime", TsRequestStyle::Import);
    let first = resolver
        .resolve(&request, &context())
        .expect("first resolve should pass");
    let second = resolver
        .resolve(&request, &context())
        .expect("second resolve should pass");

    assert_eq!(first.resolved_path, "/repo/packages/shared/src/runtime/index.ts");
    assert_eq!(first.resolved_path, second.resolved_path);
    assert_eq!(first.traces, second.traces);
}

#[test]
fn drift_classifier_and_artifact_emitter_cover_e2e_requirements() {
    let mut config = base_config();
    config.paths = BTreeMap::from([(
        "@core/*".to_string(),
        vec!["packages/core/src/*".to_string()],
    )]);
    config.import_extensions = vec![".ts".to_string(), "/index.ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/core/src/runtime/index.ts");

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@core/runtime", TsRequestStyle::Import),
            &context(),
        )
        .expect("runtime alias should resolve");

    let reference = vec![
        "/repo/packages/core/src/runtime.ts".to_string(),
        "/repo/packages/core/src/runtime/index.ts".to_string(),
    ];
    let observed = vec![
        "/repo/packages/core/src/runtime/index.ts".to_string(),
        "/repo/packages/core/src/runtime.ts".to_string(),
    ];
    let drift = classify_resolution_drift(&reference, &observed);
    assert_eq!(drift.class, TsResolutionDriftClass::CandidateOrderMismatch);
    assert_eq!(drift.drift_detected, true);
    assert!(!drift.remediation.trim().is_empty());

    let output_dir = unique_temp_dir("parity");
    fs::create_dir_all(&output_dir).expect("output dir should be created");

    let commands = vec![
        "rch exec -- cargo test -p frankenengine-engine --test ts_module_resolution_parity"
            .to_string(),
        "jq empty docs/rgc_ts_module_resolution_parity_v1.json".to_string(),
    ];

    let manifest = write_ts_resolution_artifacts(
        &output_dir,
        "monorepo-fallback-and-trace-determinism",
        "2026-02-28T06:00:00Z",
        &commands,
        &outcome.traces,
        &drift,
    )
    .expect("artifact writer should succeed");

    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(
        manifest.scenario_id,
        "monorepo-fallback-and-trace-determinism"
    );
    assert_eq!(manifest.trace_count, outcome.traces.len());

    let required_files = [
        &manifest.artifact_paths.run_manifest,
        &manifest.artifact_paths.events,
        &manifest.artifact_paths.commands,
        &manifest.artifact_paths.ts_resolution_trace,
        &manifest.artifact_paths.drift_report,
    ];
    for path in required_files {
        assert!(
            output_dir.join(path).exists(),
            "missing artifact {}",
            output_dir.join(path).display()
        );
    }

    let commands_text = fs::read_to_string(output_dir.join(&manifest.artifact_paths.commands))
        .expect("commands file should be readable");
    assert!(commands_text.contains("rch exec -- cargo test"));

    let event_line_count = fs::read_to_string(output_dir.join(&manifest.artifact_paths.events))
        .expect("events file should be readable")
        .lines()
        .count();
    assert_eq!(event_line_count, outcome.traces.len());

    let trace_line_count =
        fs::read_to_string(output_dir.join(&manifest.artifact_paths.ts_resolution_trace))
            .expect("trace file should be readable")
            .lines()
            .count();
    assert_eq!(trace_line_count, outcome.traces.len());

    let drift_json = fs::read_to_string(output_dir.join(&manifest.artifact_paths.drift_report))
        .expect("drift report should be readable");
    assert!(drift_json.contains("candidate_order_mismatch"));

    let _ = fs::remove_dir_all(&output_dir);
}
