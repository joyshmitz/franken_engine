//! Integration tests for the migration_kit module (bd-3bz4.2).
//!
//! Tests full migration workflows: package analysis → capability inference →
//! behavior validation → remediation → manifest generation.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::migration_kit::{
    BehaviorDivergence, BehaviorValidationReport, CapabilityInferenceResult, CompatibilityReport,
    DivergenceKind, DivergenceSeverity, LockstepTestResult, ManifestGenerationInput,
    MigrationConfig, MigrationEvent, MigrationKitError, SourceFile, SourceRuntime, analyze_package,
    compute_migration_readiness, emit_migration_event, generate_manifest, generate_remediation,
    infer_capabilities, validate_behavior,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// =========================================================================
// Helpers
// =========================================================================

fn node_config() -> MigrationConfig {
    MigrationConfig::default()
}

fn bun_config() -> MigrationConfig {
    MigrationConfig {
        source_runtime: SourceRuntime::Bun,
        ..MigrationConfig::default()
    }
}

fn passing_result(name: &str) -> LockstepTestResult {
    LockstepTestResult {
        test_name: name.to_string(),
        node_output: "ok".to_string(),
        franken_output: "ok".to_string(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 500,
        franken_duration_us: 600,
    }
}

fn failing_result(name: &str, node_out: &str, franken_out: &str) -> LockstepTestResult {
    LockstepTestResult {
        test_name: name.to_string(),
        node_output: node_out.to_string(),
        franken_output: franken_out.to_string(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 500,
        franken_duration_us: 600,
    }
}

fn exit_mismatch_result(name: &str) -> LockstepTestResult {
    LockstepTestResult {
        test_name: name.to_string(),
        node_output: "error".to_string(),
        franken_output: "error".to_string(),
        node_exit_code: 0,
        franken_exit_code: 1,
        node_duration_us: 500,
        franken_duration_us: 600,
    }
}

fn make_empty_compat() -> CompatibilityReport {
    CompatibilityReport {
        source_runtime: SourceRuntime::Node,
        total_apis_used: 0,
        fully_supported_count: 0,
        partially_supported_count: 0,
        unsupported_count: 0,
        deprecated_count: 0,
        polyfill_required_count: 0,
        compatibility_score_millionths: 1_000_000,
        api_entries: vec![],
        dependency_entries: vec![],
        report_content_hash: ContentHash::compute(b"empty"),
    }
}

fn make_empty_behavior() -> BehaviorValidationReport {
    BehaviorValidationReport {
        total_test_cases: 1,
        passing_count: 1,
        divergence_count: 0,
        parity_score_millionths: 1_000_000,
        divergences: vec![],
        report_content_hash: ContentHash::compute(b"empty"),
    }
}

fn make_empty_caps() -> CapabilityInferenceResult {
    CapabilityInferenceResult {
        inferred_capabilities: vec![],
        minimum_capability_set: BTreeSet::new(),
        recommended_capability_set: BTreeSet::new(),
        capability_hash: ContentHash::compute(b"empty"),
    }
}

// =========================================================================
// E2E: Full migration workflow
// =========================================================================

#[test]
fn test_full_migration_workflow_simple_package() {
    let pkg = r#"{
        "name": "simple-extension",
        "version": "1.0.0",
        "main": "index.js",
        "dependencies": {
            "lodash": "^4.17.21",
            "uuid": "^9.0.0"
        }
    }"#;

    let config = node_config();

    // Step 1: Analyze package
    let compat = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat.source_runtime, SourceRuntime::Node);
    assert!(compat.compatibility_score_millionths > 0);

    // Step 2: Infer capabilities
    let source_files = vec![SourceFile {
        path: "index.js".to_string(),
        content: r#"
            const _ = require('lodash');
            const { v4: uuidv4 } = require('uuid');
            const fs = require('fs');
            module.exports = { process: (data) => _.map(data, x => x + 1) };
        "#
        .to_string(),
    }];
    let caps = infer_capabilities(&source_files, &config).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));

    // Step 3: Validate behavior
    let test_results = vec![
        passing_result("test_map"),
        passing_result("test_uuid"),
        passing_result("test_fs_read"),
    ];
    let behavior = validate_behavior(&test_results, &config).unwrap();
    assert_eq!(behavior.passing_count, 3);
    assert_eq!(behavior.parity_score_millionths, 1_000_000);

    // Step 4: Generate remediation
    let remediation = generate_remediation(&compat, &behavior, &caps).unwrap();
    // No unsupported APIs or divergences → no steps
    // (lodash, uuid are compatible)

    // Step 5: Generate manifest
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "simple-extension".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();

    assert_eq!(manifest.source_package_name, "simple-extension");
    assert_eq!(manifest.franken_extension_name, "simple-extension");
    assert!(manifest.migration_readiness_score_millionths >= 900_000);
    assert!(manifest.required_capabilities.contains("cap:fs"));

    // Step 6: Emit event
    let event = MigrationEvent {
        trace_id: "e2e-001".to_string(),
        decision_id: "d-001".to_string(),
        component: "migration_kit".to_string(),
        event: "workflow_complete".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        details: BTreeMap::from([
            (
                "readiness".to_string(),
                manifest.migration_readiness_score_millionths.to_string(),
            ),
            (
                "remediation_count".to_string(),
                remediation.len().to_string(),
            ),
        ]),
    };
    let json = emit_migration_event(&event);
    assert!(json.contains("e2e-001"));
    assert!(json.contains("workflow_complete"));
}

#[test]
fn test_full_migration_workflow_complex_package() {
    let pkg = r#"{
        "name": "@myorg/server-extension",
        "version": "3.2.1",
        "main": "dist/index.js",
        "module": "dist/index.mjs",
        "dependencies": {
            "express": "^4.18.0",
            "axios": "^1.5.0",
            "lodash": "^4.17.21",
            "sharp": "^0.33.0",
            "zod": "^3.22.0",
            "pg": "^8.11.0",
            "redis": "^4.6.0"
        },
        "devDependencies": {
            "typescript": "^5.3.0",
            "jest": "^29.7.0"
        },
        "scripts": {
            "start": "node dist/index.js",
            "test": "jest"
        }
    }"#;

    let config = node_config();
    let compat = analyze_package(pkg, &config).unwrap();

    // Should detect incompatible deps
    let incompatible: Vec<_> = compat
        .dependency_entries
        .iter()
        .filter(|d| !d.compatible)
        .collect();
    assert!(incompatible.len() >= 4); // express, axios, sharp, pg, redis

    // Analyze source
    let files = vec![
        SourceFile {
            path: "src/server.ts".to_string(),
            content: r#"
                import express from 'express';
                import { createHash } from 'crypto';
                const http = require('http');
                const port = process.env.PORT || 3000;
            "#
            .to_string(),
        },
        SourceFile {
            path: "src/db.ts".to_string(),
            content: "import { Pool } from 'pg';\nimport { createClient } from 'redis';"
                .to_string(),
        },
    ];
    let caps = infer_capabilities(&files, &config).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:net"));
    assert!(caps.minimum_capability_set.contains("cap:crypto"));
    assert!(caps.minimum_capability_set.contains("cap:env"));

    // Behavior with divergences
    let results = vec![
        passing_result("unit-lodash"),
        passing_result("unit-zod"),
        failing_result("integration-express", "HTTP 200 OK", "connection refused"),
        failing_result("integration-pg", "rows: [{id: 1}]", "driver not available"),
        exit_mismatch_result("integration-redis"),
    ];
    let behavior = validate_behavior(&results, &config).unwrap();
    assert_eq!(behavior.passing_count, 2);
    assert_eq!(behavior.divergence_count, 3);
    assert!(behavior.parity_score_millionths < 500_000);

    // Generate remediation
    let remediation = generate_remediation(&compat, &behavior, &caps).unwrap();
    assert!(!remediation.is_empty());

    // Generate manifest
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "@myorg/server-extension".to_string(),
        source_version: "3.2.1".to_string(),
        entry_point: "dist/index.js".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(10),
    })
    .unwrap();

    assert_eq!(manifest.franken_extension_name, "myorg__server-extension");
    assert!(manifest.migration_readiness_score_millionths < 800_000);
}

// =========================================================================
// Bun runtime workflow
// =========================================================================

#[test]
fn test_bun_migration_workflow() {
    let pkg = r#"{
        "name": "bun-tool",
        "version": "0.1.0",
        "main": "index.ts",
        "dependencies": {
            "chalk": "^5.0.0",
            "commander": "^11.0.0"
        }
    }"#;

    let config = bun_config();
    let compat = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat.source_runtime, SourceRuntime::Bun);

    let files = vec![SourceFile {
        path: "index.ts".to_string(),
        content: "import chalk from 'chalk';\nconsole.log(chalk.green('hello'));".to_string(),
    }];
    let caps = infer_capabilities(&files, &config).unwrap();

    let results = vec![passing_result("cli-output"), passing_result("cli-help")];
    let behavior = validate_behavior(&results, &config).unwrap();
    assert_eq!(behavior.parity_score_millionths, 1_000_000);

    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Bun,
        source_package_name: "bun-tool".to_string(),
        source_version: "0.1.0".to_string(),
        entry_point: "index.ts".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();

    assert_eq!(manifest.source_runtime, SourceRuntime::Bun);
}

// =========================================================================
// Determinism tests
// =========================================================================

#[test]
fn test_full_workflow_deterministic() {
    let pkg = r#"{"name":"det-test","version":"1.0.0","dependencies":{"lodash":"^4.0.0","express":"^4.0.0"}}"#;
    let config = node_config();

    let compat1 = analyze_package(pkg, &config).unwrap();
    let compat2 = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat1.report_content_hash, compat2.report_content_hash);
    assert_eq!(
        compat1.compatibility_score_millionths,
        compat2.compatibility_score_millionths
    );

    let files = vec![SourceFile {
        path: "a.js".to_string(),
        content: "const fs = require('fs'); const http = require('http');".to_string(),
    }];
    let caps1 = infer_capabilities(&files, &config).unwrap();
    let caps2 = infer_capabilities(&files, &config).unwrap();
    assert_eq!(caps1.capability_hash, caps2.capability_hash);

    let results = vec![passing_result("t1"), failing_result("t2", "a", "b")];
    let beh1 = validate_behavior(&results, &config).unwrap();
    let beh2 = validate_behavior(&results, &config).unwrap();
    assert_eq!(beh1.report_content_hash, beh2.report_content_hash);
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn test_unicode_content_in_source_files() {
    let files = vec![SourceFile {
        path: "unicode.js".to_string(),
        content: "const fs = require('fs');\n// 日本語コメント\nconst x = '🎉';".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));
}

#[test]
fn test_empty_source_files() {
    let files: Vec<SourceFile> = vec![];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.is_empty());
    assert!(caps.inferred_capabilities.is_empty());
}

#[test]
fn test_large_number_of_test_results() {
    let results: Vec<LockstepTestResult> = (0..500)
        .map(|i| passing_result(&format!("test_{i}")))
        .collect();
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.passing_count, 500);
    assert_eq!(report.parity_score_millionths, 1_000_000);
}

#[test]
fn test_mixed_divergence_severities() {
    let results = vec![
        passing_result("pass"),
        failing_result("case-diff", "Hello", "hello"),
        failing_result("major-diff", "long output with lots of content", "x"),
        LockstepTestResult {
            test_name: "exit-diff".to_string(),
            node_output: "error".to_string(),
            franken_output: "different-error".to_string(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 100,
        },
    ];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.passing_count, 1);
    assert_eq!(report.divergence_count, 3);

    let severities: Vec<_> = report.divergences.iter().map(|d| d.severity).collect();
    // Should be sorted by severity
    for window in severities.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

// =========================================================================
// Error handling
// =========================================================================

#[test]
fn test_invalid_json_package() {
    let err = analyze_package("}{bad json", &node_config()).unwrap_err();
    assert!(matches!(err, MigrationKitError::InvalidPackageJson { .. }));
    assert_eq!(err.code(), "FE-MK-0006");
}

#[test]
fn test_empty_test_results() {
    let err = validate_behavior(&[], &node_config()).unwrap_err();
    assert!(matches!(
        err,
        MigrationKitError::BehaviorValidationFailed { .. }
    ));
}

#[test]
fn test_manifest_empty_name() {
    let err = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: String::new(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap_err();
    assert_eq!(err.code(), "FE-MK-0002");
}

// =========================================================================
// Readiness score
// =========================================================================

#[test]
fn test_readiness_score_boundaries() {
    // Perfect scores
    let compat = CompatibilityReport {
        source_runtime: SourceRuntime::Node,
        total_apis_used: 10,
        fully_supported_count: 10,
        partially_supported_count: 0,
        unsupported_count: 0,
        deprecated_count: 0,
        polyfill_required_count: 0,
        compatibility_score_millionths: 1_000_000,
        api_entries: vec![],
        dependency_entries: vec![],
        report_content_hash: ContentHash::compute(b"test"),
    };
    let behavior = BehaviorValidationReport {
        total_test_cases: 100,
        passing_count: 100,
        divergence_count: 0,
        parity_score_millionths: 1_000_000,
        divergences: vec![],
        report_content_hash: ContentHash::compute(b"test"),
    };
    assert_eq!(compute_migration_readiness(&compat, &behavior), 1_000_000);

    // Zero compatibility, perfect parity
    let compat_zero = CompatibilityReport {
        compatibility_score_millionths: 0,
        ..compat.clone()
    };
    assert_eq!(
        compute_migration_readiness(&compat_zero, &behavior),
        600_000
    );

    // Perfect compatibility, zero parity
    let behavior_zero = BehaviorValidationReport {
        parity_score_millionths: 0,
        ..behavior.clone()
    };
    assert_eq!(
        compute_migration_readiness(&compat, &behavior_zero),
        400_000
    );

    // Both zero
    assert_eq!(compute_migration_readiness(&compat_zero, &behavior_zero), 0);
}

// =========================================================================
// Package.json edge cases
// =========================================================================

#[test]
fn test_package_with_only_dev_dependencies() {
    let pkg = r#"{
        "name": "dev-only",
        "version": "1.0.0",
        "devDependencies": {
            "typescript": "^5.3.0",
            "vitest": "^1.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.dependency_entries.iter().all(|d| d.compatible));
}

#[test]
fn test_package_with_peer_dependencies() {
    let pkg = r#"{
        "name": "peer-pkg",
        "version": "1.0.0",
        "peerDependencies": {
            "react": "^18.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert_eq!(report.dependency_entries.len(), 1);
}

#[test]
fn test_package_with_all_compatible_deps() {
    let pkg = r#"{
        "name": "all-compat",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.0.0",
            "uuid": "^9.0.0",
            "chalk": "^5.0.0",
            "zod": "^3.22.0",
            "date-fns": "^3.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.dependency_entries.iter().all(|d| d.compatible));
    assert!(report.compatibility_score_millionths >= 900_000);
}

#[test]
fn test_package_with_all_incompatible_deps() {
    let pkg = r#"{
        "name": "all-incompat",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.0.0",
            "sharp": "^0.33.0",
            "sqlite3": "^5.0.0",
            "ws": "^8.0.0",
            "pg": "^8.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    let incompatible_count = report
        .dependency_entries
        .iter()
        .filter(|d| !d.compatible)
        .count();
    assert_eq!(incompatible_count, 5);
}

// =========================================================================
// Capability inference edge cases
// =========================================================================

#[test]
fn test_infer_esm_import_syntax() {
    let files = vec![SourceFile {
        path: "esm.mjs".to_string(),
        content: "import { readFile } from 'fs';\nimport { createServer } from 'http';".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));
    assert!(caps.minimum_capability_set.contains("cap:net"));
}

#[test]
fn test_infer_dynamic_import() {
    let files = vec![SourceFile {
        path: "dynamic.js".to_string(),
        content: "const mod = await import('./plugin.js');".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:import:dynamic"));
}

#[test]
fn test_infer_native_addon() {
    let files = vec![SourceFile {
        path: "binding.js".to_string(),
        content: "const binding = require('./build/Release/addon.node\");".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:native-addon"));
}

// =========================================================================
// Remediation quality
// =========================================================================

#[test]
fn test_remediation_sorted_by_priority() {
    let compat = analyze_package(
        r#"{"name":"x","version":"1.0.0","dependencies":{"express":"^4.0.0","sharp":"^0.33.0"}}"#,
        &node_config(),
    )
    .unwrap();
    let behavior = make_empty_behavior();
    let caps = make_empty_caps();

    let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
    // Should be sorted descending by priority
    for window in steps.windows(2) {
        assert!(window[0].priority_score_millionths >= window[1].priority_score_millionths);
    }
}

#[test]
fn test_remediation_has_behavior_fixes() {
    let compat = make_empty_compat();
    let schema_id =
        frankenengine_engine::engine_object_id::SchemaId::from_definition(b"BehaviorDivergence.v1");
    let div_id = frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::EvidenceRecord,
        "migration-kit",
        &schema_id,
        b"test-div",
    )
    .unwrap();

    let behavior = BehaviorValidationReport {
        total_test_cases: 2,
        passing_count: 1,
        divergence_count: 1,
        parity_score_millionths: 500_000,
        divergences: vec![BehaviorDivergence {
            divergence_id: div_id,
            kind: DivergenceKind::SemanticDifference,
            severity: DivergenceSeverity::Critical,
            test_case: "critical-test".to_string(),
            node_bun_result: "expected".to_string(),
            franken_result: "different".to_string(),
            explanation: "semantic mismatch".to_string(),
            remediation: "fix logic".to_string(),
        }],
        report_content_hash: ContentHash::compute(b"test"),
    };
    let caps = make_empty_caps();

    let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
    assert!(!steps.is_empty());
    assert!(steps.iter().any(|s| s.title.contains("critical-test")));
}

// =========================================================================
// Manifest content hashing
// =========================================================================

#[test]
fn test_manifest_content_hash_stable() {
    let compat = make_empty_compat();
    let behavior = make_empty_behavior();
    let caps = make_empty_caps();

    let m1 = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "hash-test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: compat.clone(),
        behavior: behavior.clone(),
        capabilities: caps.clone(),
        epoch: SecurityEpoch::from_raw(42),
    })
    .unwrap();

    let m2 = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "hash-test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(42),
    })
    .unwrap();

    assert_eq!(m1.manifest_content_hash, m2.manifest_content_hash);
    assert_eq!(m1.manifest_id, m2.manifest_id);
}

// =========================================================================
// Event emission
// =========================================================================

#[test]
fn test_event_roundtrip() {
    let event = MigrationEvent {
        trace_id: "tr-integration".to_string(),
        decision_id: "d-integration".to_string(),
        component: "migration_kit".to_string(),
        event: "test_event".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        details: BTreeMap::from([
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value2".to_string()),
        ]),
    };
    let json = emit_migration_event(&event);
    let parsed: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.trace_id, "tr-integration");
    assert_eq!(parsed.details.len(), 2);
}

// =========================================================================
// Serde roundtrip for complex types
// =========================================================================

#[test]
fn test_serde_roundtrip_manifest() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "serde-test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();

    let json = serde_json::to_string(&manifest).unwrap();
    let roundtripped: frankenengine_engine::migration_kit::MigrationManifest =
        serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.manifest_id, roundtripped.manifest_id);
    assert_eq!(
        manifest.source_package_name,
        roundtripped.source_package_name
    );
}

#[test]
fn test_serde_roundtrip_behavior_report() {
    let results = vec![passing_result("t1"), failing_result("t2", "a", "b")];
    let report = validate_behavior(&results, &node_config()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let roundtripped: BehaviorValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.passing_count, roundtripped.passing_count);
    assert_eq!(report.divergence_count, roundtripped.divergence_count);
}
