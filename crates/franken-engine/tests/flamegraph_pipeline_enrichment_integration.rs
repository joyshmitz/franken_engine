#![forbid(unsafe_code)]
//! Enrichment integration tests for `flamegraph_pipeline`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, validation edge cases, and query defaults
//! beyond the existing 35 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::flamegraph_pipeline::{
    FLAMEGRAPH_COMPONENT, FLAMEGRAPH_SCHEMA_VERSION, FLAMEGRAPH_STORAGE_INTEGRATION_POINT,
    FlamegraphDiffEntry, FlamegraphEvidenceLink, FlamegraphKind, FlamegraphMetadata,
    FlamegraphPipelineDecision, FlamegraphPipelineError, FlamegraphPipelineEvent, FlamegraphQuery,
    FoldedStackSample,
};

// ===========================================================================
// 1) FlamegraphKind — exact Display / as_str
// ===========================================================================

#[test]
fn flamegraph_kind_display_exact() {
    assert_eq!(
        FlamegraphKind::Cpu.to_string(),
        FlamegraphKind::Cpu.as_str()
    );
    assert_eq!(
        FlamegraphKind::Allocation.to_string(),
        FlamegraphKind::Allocation.as_str()
    );
    assert_eq!(
        FlamegraphKind::DiffCpu.to_string(),
        FlamegraphKind::DiffCpu.as_str()
    );
    assert_eq!(
        FlamegraphKind::DiffAllocation.to_string(),
        FlamegraphKind::DiffAllocation.as_str()
    );
}

#[test]
fn flamegraph_kind_as_str_all_distinct() {
    let strs = [
        FlamegraphKind::Cpu.as_str(),
        FlamegraphKind::Allocation.as_str(),
        FlamegraphKind::DiffCpu.as_str(),
        FlamegraphKind::DiffAllocation.as_str(),
    ];
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 2) FlamegraphPipelineError — stable codes + uniqueness
// ===========================================================================

#[test]
fn pipeline_error_stable_codes_all_distinct() {
    let errors: Vec<(&str, Box<dyn Fn() -> FlamegraphPipelineError>)> = vec![
        (
            "FE-FLAME-1001",
            Box::new(|| FlamegraphPipelineError::InvalidRequest {
                field: "f".into(),
                detail: "d".into(),
            }),
        ),
        (
            "FE-FLAME-1002",
            Box::new(|| FlamegraphPipelineError::InvalidTimestamp { value: "v".into() }),
        ),
        (
            "FE-FLAME-1003",
            Box::new(|| FlamegraphPipelineError::EmptyFoldedStack { field: "f".into() }),
        ),
        (
            "FE-FLAME-1004",
            Box::new(|| FlamegraphPipelineError::MismatchedDiffInput),
        ),
        (
            "FE-FLAME-1005",
            Box::new(|| FlamegraphPipelineError::InvalidSvg {
                kind: FlamegraphKind::Cpu,
            }),
        ),
        (
            "FE-FLAME-1006",
            Box::new(|| FlamegraphPipelineError::SerializationFailure { detail: "d".into() }),
        ),
    ];
    for (expected_code, factory) in &errors {
        let e = factory();
        assert_eq!(e.stable_code(), *expected_code, "code mismatch for {e}");
    }
}

#[test]
fn pipeline_error_display_all_unique() {
    let variants: Vec<String> = vec![
        FlamegraphPipelineError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        }
        .to_string(),
        FlamegraphPipelineError::InvalidTimestamp { value: "v".into() }.to_string(),
        FlamegraphPipelineError::InvalidFoldedStack {
            field: "f".into(),
            line_number: 1,
            detail: "d".into(),
        }
        .to_string(),
        FlamegraphPipelineError::EmptyFoldedStack { field: "f".into() }.to_string(),
        FlamegraphPipelineError::MismatchedDiffInput.to_string(),
        FlamegraphPipelineError::InvalidSvg {
            kind: FlamegraphKind::Cpu,
        }
        .to_string(),
        FlamegraphPipelineError::SerializationFailure { detail: "d".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn pipeline_error_is_std_error() {
    let e = FlamegraphPipelineError::MismatchedDiffInput;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn pipeline_error_requires_rollback_only_storage() {
    assert!(
        !FlamegraphPipelineError::InvalidRequest {
            field: "f".into(),
            detail: "d".into()
        }
        .requires_rollback()
    );
    assert!(!FlamegraphPipelineError::MismatchedDiffInput.requires_rollback());
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_flamegraph_kind() {
    let variants = [
        format!("{:?}", FlamegraphKind::Cpu),
        format!("{:?}", FlamegraphKind::Allocation),
        format!("{:?}", FlamegraphKind::DiffCpu),
        format!("{:?}", FlamegraphKind::DiffAllocation),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 4) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_flamegraph_kind_tags() {
    let kinds = [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ];
    let expected = [
        "\"cpu\"",
        "\"allocation\"",
        "\"diff_cpu\"",
        "\"diff_allocation\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "FlamegraphKind serde tag mismatch for {k:?}");
    }
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_folded_stack_sample() {
    let fss = FoldedStackSample {
        stack: "main;foo;bar".into(),
        sample_count: 42,
    };
    let v: serde_json::Value = serde_json::to_value(&fss).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["stack", "sample_count"] {
        assert!(
            obj.contains_key(key),
            "FoldedStackSample missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_diff_entry() {
    let fde = FlamegraphDiffEntry {
        stack: "main;foo".into(),
        baseline_samples: 10,
        candidate_samples: 15,
        delta_samples: 5,
    };
    let v: serde_json::Value = serde_json::to_value(&fde).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "stack",
        "baseline_samples",
        "candidate_samples",
        "delta_samples",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphDiffEntry missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_metadata() {
    let fm = FlamegraphMetadata {
        benchmark_run_id: "run1".into(),
        baseline_benchmark_run_id: None,
        workload_id: "wl1".into(),
        benchmark_profile: "profile1".into(),
        config_fingerprint: "fp1".into(),
        git_commit: "abc123".into(),
        generated_at_utc: "2026-02-27T00:00:00Z".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fm).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "benchmark_run_id",
        "baseline_benchmark_run_id",
        "workload_id",
        "benchmark_profile",
        "config_fingerprint",
        "git_commit",
        "generated_at_utc",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphMetadata missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_evidence_link() {
    let fel = FlamegraphEvidenceLink {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        optimization_decision_id: "o".into(),
        evidence_node_id: "n".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fel).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "benchmark_run_id",
        "optimization_decision_id",
        "evidence_node_id",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphEvidenceLink missing field: {key}"
        );
    }
}

#[test]
fn json_fields_flamegraph_pipeline_event() {
    let fpe = FlamegraphPipelineEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: FLAMEGRAPH_COMPONENT.into(),
        event: "test".into(),
        outcome: "pass".into(),
        error_code: None,
        artifact_id: None,
        flamegraph_kind: None,
    };
    let v: serde_json::Value = serde_json::to_value(&fpe).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "artifact_id",
        "flamegraph_kind",
    ] {
        assert!(
            obj.contains_key(key),
            "FlamegraphPipelineEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 6) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(FLAMEGRAPH_COMPONENT, "flamegraph_pipeline");
    assert_eq!(
        FLAMEGRAPH_SCHEMA_VERSION,
        "franken-engine.flamegraph-artifact.v1"
    );
    assert_eq!(
        FLAMEGRAPH_STORAGE_INTEGRATION_POINT,
        "frankensqlite::benchmark::ledger"
    );
}

// ===========================================================================
// 7) FlamegraphQuery — default
// ===========================================================================

#[test]
fn flamegraph_query_default() {
    let q = FlamegraphQuery::default();
    assert!(q.benchmark_run_id.is_none());
    assert!(q.workload_id.is_none());
    assert!(q.git_commit.is_none());
    assert!(q.kind.is_none());
    assert!(q.decision_id.is_none());
    assert!(q.trace_id.is_none());
    assert!(q.limit.is_none());
}

// ===========================================================================
// 8) FlamegraphKind ordering
// ===========================================================================

#[test]
fn flamegraph_kind_ordering_stable() {
    let mut kinds = vec![
        FlamegraphKind::DiffAllocation,
        FlamegraphKind::Cpu,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::Allocation,
    ];
    kinds.sort();
    assert_eq!(kinds[0], FlamegraphKind::Cpu);
}

// ===========================================================================
// 9) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_flamegraph_kind_all() {
    for k in [
        FlamegraphKind::Cpu,
        FlamegraphKind::Allocation,
        FlamegraphKind::DiffCpu,
        FlamegraphKind::DiffAllocation,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: FlamegraphKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_folded_stack_sample() {
    let fss = FoldedStackSample {
        stack: "a;b;c".into(),
        sample_count: 100,
    };
    let json = serde_json::to_string(&fss).unwrap();
    let rt: FoldedStackSample = serde_json::from_str(&json).unwrap();
    assert_eq!(fss, rt);
}

#[test]
fn serde_roundtrip_flamegraph_diff_entry() {
    let fde = FlamegraphDiffEntry {
        stack: "x;y".into(),
        baseline_samples: 5,
        candidate_samples: 10,
        delta_samples: 5,
    };
    let json = serde_json::to_string(&fde).unwrap();
    let rt: FlamegraphDiffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(fde, rt);
}

#[test]
fn serde_roundtrip_flamegraph_query() {
    let q = FlamegraphQuery {
        benchmark_run_id: Some("run1".into()),
        kind: Some(FlamegraphKind::Cpu),
        limit: Some(10),
        ..FlamegraphQuery::default()
    };
    let json = serde_json::to_string(&q).unwrap();
    let rt: FlamegraphQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, rt);
}

// ===========================================================================
// 10) FlamegraphPipelineDecision — is_success
// ===========================================================================

#[test]
fn pipeline_decision_is_success() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "pass".into(),
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    assert!(d.is_success());
}

#[test]
fn pipeline_decision_is_failure() {
    let d = FlamegraphPipelineDecision {
        pipeline_id: "p1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        outcome: "fail".into(),
        error_code: Some("FE-FLAME-1001".into()),
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.into(),
        artifacts: vec![],
        store_keys: vec![],
        events: vec![],
    };
    assert!(!d.is_success());
}
