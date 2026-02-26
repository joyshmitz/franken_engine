#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

const MATRIX_SCHEMA_VERSION: &str = "franken-engine.frx-cross-version-compat-matrix.v1";
const MATRIX_JSON: &str =
    include_str!("../../../docs/frx_cross_version_compatibility_matrix_v1.json");
const REPLAY_COMMAND: &str = "./scripts/e2e/frx_cross_version_compatibility_matrix_replay.sh ci";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CompatibilityMatrix {
    schema_version: String,
    generated_at_utc: String,
    policy_id: String,
    dimensions: MatrixDimensions,
    cases: Vec<CompatibilityCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixDimensions {
    react_versions: Vec<String>,
    browsers: Vec<String>,
    api_families: Vec<String>,
    compatibility_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CompatibilityCase {
    case_id: String,
    api_family: String,
    surface: String,
    react18_status: String,
    react19_status: String,
    browser_constraints: Vec<String>,
    compatibility_route: String,
    deterministic_fallback_required: bool,
    risk_level: String,
    behavior_notes: String,
    test_selector_tags: Vec<String>,
    release_claim_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixLogEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    scenario_id: String,
    outcome: String,
    error_code: Option<String>,
    replay_command: String,
}

fn parse_matrix() -> CompatibilityMatrix {
    serde_json::from_str(MATRIX_JSON).expect("compatibility matrix json must parse")
}

fn projection_from_tags<'a>(
    cases: &'a [CompatibilityCase],
    selector: impl Fn(&'a CompatibilityCase) -> &'a [String],
) -> BTreeMap<String, Vec<String>> {
    let mut projection = BTreeMap::<String, Vec<String>>::new();
    for case in cases {
        for tag in selector(case) {
            projection
                .entry(tag.clone())
                .or_default()
                .push(case.case_id.clone());
        }
    }

    for ids in projection.values_mut() {
        ids.sort();
        ids.dedup();
    }

    projection
}

#[test]
fn cross_version_matrix_covers_declared_api_families() {
    let matrix = parse_matrix();

    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.policy_id, "policy-frx-cross-version-compat-v1");
    assert!(matrix.generated_at_utc.ends_with('Z'));

    let versions: BTreeSet<_> = matrix.dimensions.react_versions.iter().cloned().collect();
    assert!(versions.contains("18.3"));
    assert!(versions.contains("19.0"));

    let case_families: BTreeSet<_> = matrix
        .cases
        .iter()
        .map(|case| case.api_family.clone())
        .collect();
    let declared_families: BTreeSet<_> = matrix.dimensions.api_families.iter().cloned().collect();
    assert!(declared_families.is_subset(&case_families));

    let mut seen_case_ids = BTreeSet::new();
    for case in &matrix.cases {
        assert!(seen_case_ids.insert(case.case_id.clone()));
        assert!(!case.surface.is_empty());
        assert!(!case.react18_status.is_empty());
        assert!(!case.react19_status.is_empty());
        assert!(!case.browser_constraints.is_empty());
        assert!(!case.risk_level.is_empty());
        assert!(!case.behavior_notes.is_empty());
        assert!(!case.test_selector_tags.is_empty());
        assert!(!case.release_claim_tags.is_empty());
        assert!(
            matrix
                .dimensions
                .compatibility_routes
                .contains(&case.compatibility_route)
        );
        if case.deterministic_fallback_required {
            assert_ne!(case.compatibility_route, "compile_native");
        }
    }
}

#[test]
fn cross_version_matrix_drives_deterministic_test_selection_projection() {
    let matrix = parse_matrix();

    let projection_a = projection_from_tags(&matrix.cases, |case| &case.test_selector_tags);
    let projection_b = projection_from_tags(&matrix.cases, |case| &case.test_selector_tags);

    assert_eq!(projection_a, projection_b);
    assert!(projection_a.contains_key("frx02"));
    assert!(projection_a.contains_key("react18"));
    assert!(projection_a.contains_key("react19"));

    for case_ids in projection_a.values() {
        assert!(!case_ids.is_empty());
        let mut sorted = case_ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(*case_ids, sorted);
    }
}

#[test]
fn cross_version_matrix_drives_release_claim_projection_and_logs() {
    let matrix = parse_matrix();

    let release_projection = projection_from_tags(&matrix.cases, |case| &case.release_claim_tags);
    assert!(release_projection.contains_key("frx-semantic-parity"));
    assert!(release_projection.contains_key("frx-deterministic-fallback"));
    assert!(release_projection.contains_key("frx-browser-surface-coverage"));

    let events: Vec<MatrixLogEvent> = matrix
        .cases
        .iter()
        .take(3)
        .enumerate()
        .map(|(idx, case)| MatrixLogEvent {
            schema_version: "franken-engine.parser-log-event.v1".to_string(),
            trace_id: format!("trace-frx-cross-version-{}", case.case_id),
            decision_id: format!("decision-frx-cross-version-{idx}"),
            policy_id: matrix.policy_id.clone(),
            component: "frx_cross_version_compatibility_matrix".to_string(),
            event: "matrix_case_validated".to_string(),
            scenario_id: case.case_id.clone(),
            outcome: "pass".to_string(),
            error_code: None,
            replay_command: REPLAY_COMMAND.to_string(),
        })
        .collect();

    assert_eq!(events.len(), 3);
    for event in &events {
        assert_eq!(event.schema_version, "franken-engine.parser-log-event.v1");
        assert_eq!(event.policy_id, "policy-frx-cross-version-compat-v1");
        assert_eq!(event.component, "frx_cross_version_compatibility_matrix");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_code, None);
        assert_eq!(event.replay_command, REPLAY_COMMAND);
    }

    let jsonl = events
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .expect("events must serialize")
        .join("\n");
    assert!(jsonl.contains("matrix_case_validated"));
}
