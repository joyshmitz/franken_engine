#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::path::PathBuf;

use conformance_harness::{ConformanceRunner, ConformanceWaiverSet};
use serde_json::Value;

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/ifc_corpus/ifc_conformance_assets.json")
}

#[test]
fn ifc_manifest_contains_required_metadata_fields() {
    let manifest_bytes = std::fs::read_to_string(manifest_path()).expect("read manifest");
    let manifest: Value = serde_json::from_str(&manifest_bytes).expect("parse manifest json");
    let assets = manifest["assets"].as_array().expect("assets array");
    assert_eq!(
        assets.len(),
        3,
        "initial IFC corpus should include three category seeds"
    );

    for asset in assets {
        let category = asset["category"].as_str().expect("category string");
        assert!(
            matches!(category, "benign" | "exfil" | "declassify"),
            "unexpected IFC category: {category}"
        );
        assert!(
            asset["source_labels"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        assert!(
            asset["sink_clearances"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        assert!(asset["flow_path_type"].as_str().is_some());
        assert!(asset["expected_outcome"].as_str().is_some());
        assert!(asset["expected_evidence_type"].as_str().is_some());
    }
}

#[test]
fn ifc_manifest_executes_deterministically_in_conformance_runner() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::default();

    let first = runner
        .run(manifest_path(), &waivers)
        .expect("first ifc conformance run");
    let second = runner
        .run(manifest_path(), &waivers)
        .expect("second ifc conformance run");

    assert_eq!(first.summary.total_assets, 3);
    assert_eq!(first.summary.failed, 0);
    assert_eq!(first.summary.errored, 0);
    first.enforce_ci_gate().expect("ifc corpus gate pass");

    assert_eq!(
        first.logs, second.logs,
        "runner output should be deterministic"
    );
    assert_eq!(first.summary, second.summary);

    let semantic_domains: Vec<_> = first
        .logs
        .iter()
        .map(|log| log.semantic_domain.as_str())
        .collect();
    assert!(
        semantic_domains
            .iter()
            .any(|domain| domain.contains("ifc_corpus/benign"))
    );
    assert!(
        semantic_domains
            .iter()
            .any(|domain| domain.contains("ifc_corpus/exfil"))
    );
    assert!(
        semantic_domains
            .iter()
            .any(|domain| domain.contains("ifc_corpus/declassify"))
    );
}
