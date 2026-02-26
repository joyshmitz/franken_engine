#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserCrossArchReproMatrixFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_log_keys: Vec<String>,
    architecture_targets: Vec<String>,
    required_lanes: Vec<RequiredLane>,
    delta_classes: Vec<DeltaClass>,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RequiredLane {
    lane_id: String,
    manifest_schema_version: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DeltaClass {
    class_id: String,
    severity: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneRunSummary {
    lane_id: String,
    arch_profile: String,
    outcome: String,
    error_code: Option<String>,
    witness_digest: String,
    toolchain_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeltaExplanation {
    class_id: String,
    severity: String,
    reason: String,
}

fn load_fixture() -> ParserCrossArchReproMatrixFixture {
    let path = Path::new("tests/fixtures/parser_cross_arch_repro_matrix_v1.json");
    let bytes = fs::read(path).expect("read parser cross-arch reproducibility matrix fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser cross-arch reproducibility fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_CROSS_ARCH_REPRO_MATRIX.md");
    fs::read_to_string(path).expect("read parser cross-arch reproducibility contract doc")
}

fn explain_delta(
    x86_run: &LaneRunSummary,
    arm64_run: &LaneRunSummary,
    allow_missing: bool,
) -> DeltaExplanation {
    if allow_missing
        && (x86_run.witness_digest == "missing-input"
            || arm64_run.witness_digest == "missing-input")
    {
        return DeltaExplanation {
            class_id: "missing_input".to_string(),
            severity: "critical".to_string(),
            reason: "required manifest input missing for one or more architecture lanes"
                .to_string(),
        };
    }

    if x86_run.outcome != arm64_run.outcome || x86_run.error_code != arm64_run.error_code {
        return DeltaExplanation {
            class_id: "upstream_lane_regression".to_string(),
            severity: "critical".to_string(),
            reason: "outcome or error_code diverged across architectures".to_string(),
        };
    }

    if x86_run.witness_digest == arm64_run.witness_digest {
        return DeltaExplanation {
            class_id: "none".to_string(),
            severity: "info".to_string(),
            reason: "witness digests and outcomes match".to_string(),
        };
    }

    if x86_run.toolchain_fingerprint != arm64_run.toolchain_fingerprint {
        return DeltaExplanation {
            class_id: "toolchain_fingerprint_delta".to_string(),
            severity: "warning".to_string(),
            reason: "digest drift is explainable by toolchain fingerprint differences".to_string(),
        };
    }

    DeltaExplanation {
        class_id: "digest_delta_unexplained".to_string(),
        severity: "critical".to_string(),
        reason: "digest drift without toolchain fingerprint delta".to_string(),
    }
}

fn build_lane_delta_event(
    fixture: &ParserCrossArchReproMatrixFixture,
    lane_id: &str,
    delta: &DeltaExplanation,
) -> Value {
    let error_code = match delta.class_id.as_str() {
        "none" => Value::Null,
        "toolchain_fingerprint_delta" => Value::Null,
        "digest_delta_unexplained" => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0001".to_string()),
        "upstream_lane_regression" => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0002".to_string()),
        "missing_input" => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0003".to_string()),
        _ => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0099".to_string()),
    };

    json!({
        "schema_version": "franken-engine.parser-cross-arch-repro-matrix.event.v1",
        "trace_id": format!("trace-parser-cross-arch-repro-{lane_id}"),
        "decision_id": format!("decision-parser-cross-arch-repro-{lane_id}"),
        "policy_id": fixture.policy_id,
        "component": "parser_cross_arch_repro_matrix_gate",
        "event": "lane_delta_evaluated",
        "scenario_id": lane_id,
        "outcome": if delta.severity == "critical" { "fail" } else { "pass" },
        "error_code": error_code,
        "delta_class": delta.class_id,
        "delta_reason": delta.reason,
        "replay_command": fixture.replay_command
    })
}

fn assert_required_event_keys(event: &Value, required_keys: &[String]) {
    for key in required_keys {
        let value = event
            .get(key)
            .unwrap_or_else(|| panic!("missing required key in event: {key}"));
        if key == "error_code" {
            assert!(
                value.is_null() || value.as_str().is_some_and(|raw| !raw.is_empty()),
                "error_code must be null or non-empty string"
            );
            continue;
        }
        assert!(
            value.as_str().is_some_and(|raw| !raw.is_empty()),
            "key `{key}` must be non-empty string"
        );
    }
}

#[test]
fn parser_cross_arch_repro_matrix_contract_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "# Parser Cross-Architecture Reproducibility Matrix Contract",
        "## Scope",
        "## Contract Version",
        "## Matrix Dimensions",
        "## Drift Classification",
        "## Structured Logging Contract",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "cross-arch reproducibility contract doc missing section: {section}"
        );
    }
}

#[test]
fn parser_cross_arch_matrix_fixture_covers_required_architectures_and_lanes() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-cross-arch-repro-matrix.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.7.2");
    assert_eq!(
        fixture.policy_id,
        "policy-parser-cross-arch-repro-matrix-v1"
    );
    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh"
    );

    let expected_arches: BTreeSet<_> = [
        "x86_64-unknown-linux-gnu".to_string(),
        "aarch64-unknown-linux-gnu".to_string(),
    ]
    .into_iter()
    .collect();
    let actual_arches: BTreeSet<_> = fixture.architecture_targets.iter().cloned().collect();
    assert_eq!(actual_arches, expected_arches);

    let lane_ids: BTreeSet<_> = fixture
        .required_lanes
        .iter()
        .map(|lane| lane.lane_id.clone())
        .collect();
    let expected_lanes: BTreeSet<_> = [
        "parser_event_ast_equivalence".to_string(),
        "parser_parallel_interference".to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(lane_ids, expected_lanes);

    for lane in &fixture.required_lanes {
        assert!(
            lane.manifest_schema_version
                .starts_with("franken-engine.parser-"),
            "unexpected lane manifest schema version: {}",
            lane.manifest_schema_version
        );
        assert!(
            lane.replay_command.starts_with("./scripts/"),
            "lane replay command must be script entrypoint: {}",
            lane.replay_command
        );
    }
}

#[test]
fn parser_cross_arch_matrix_delta_classifier_assigns_expected_classes() {
    let fixture = load_fixture();
    let allowed_classes: BTreeSet<_> = fixture
        .delta_classes
        .iter()
        .map(|entry| entry.class_id.as_str())
        .collect();

    let x86_stable = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "x86_64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:stable".to_string(),
        toolchain_fingerprint: "fp-host".to_string(),
    };
    let arm64_stable = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:stable".to_string(),
        toolchain_fingerprint: "fp-host".to_string(),
    };
    let parity = explain_delta(&x86_stable, &arm64_stable, false);
    assert_eq!(parity.class_id, "none");
    assert!(allowed_classes.contains(parity.class_id.as_str()));

    let arm64_toolchain_delta = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:different".to_string(),
        toolchain_fingerprint: "fp-arm".to_string(),
    };
    let toolchain_delta = explain_delta(&x86_stable, &arm64_toolchain_delta, false);
    assert_eq!(toolchain_delta.class_id, "toolchain_fingerprint_delta");
    assert_eq!(toolchain_delta.severity, "warning");
    assert!(allowed_classes.contains(toolchain_delta.class_id.as_str()));

    let arm64_regression = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-PARSER-EVENT-AST-EQUIV-REPLAY-0001".to_string()),
        witness_digest: "sha256:different".to_string(),
        toolchain_fingerprint: "fp-arm".to_string(),
    };
    let regression = explain_delta(&x86_stable, &arm64_regression, false);
    assert_eq!(regression.class_id, "upstream_lane_regression");
    assert_eq!(regression.severity, "critical");
    assert!(allowed_classes.contains(regression.class_id.as_str()));

    let missing = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "unknown".to_string(),
        error_code: Some("FE-PARSER-CROSS-ARCH-MATRIX-0003".to_string()),
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "unknown".to_string(),
    };
    let missing_input = explain_delta(&x86_stable, &missing, true);
    assert_eq!(missing_input.class_id, "missing_input");
    assert_eq!(missing_input.severity, "critical");
    assert!(allowed_classes.contains(missing_input.class_id.as_str()));
}

#[test]
fn parser_cross_arch_matrix_structured_events_include_required_keys() {
    let fixture = load_fixture();

    let x86 = LaneRunSummary {
        lane_id: "parser_parallel_interference".to_string(),
        arch_profile: "x86_64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:lane-x86".to_string(),
        toolchain_fingerprint: "fp-shared".to_string(),
    };
    let arm64 = LaneRunSummary {
        lane_id: "parser_parallel_interference".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:lane-arm".to_string(),
        toolchain_fingerprint: "fp-arm".to_string(),
    };
    let delta = explain_delta(&x86, &arm64, false);

    let event_a = build_lane_delta_event(&fixture, &x86.lane_id, &delta);
    let event_b = build_lane_delta_event(&fixture, &x86.lane_id, &delta);
    assert_eq!(event_a, event_b, "event emission must be deterministic");

    assert_required_event_keys(&event_a, &fixture.required_log_keys);
    assert_eq!(
        event_a["replay_command"].as_str(),
        Some("./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh")
    );
    assert_eq!(
        event_a["delta_class"].as_str(),
        Some("toolchain_fingerprint_delta")
    );
}
