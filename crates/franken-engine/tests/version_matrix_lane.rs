#[path = "../src/version_matrix_lane.rs"]
mod version_matrix_lane;

use version_matrix_lane::{
    BoundaryMatrixSpec, FailureScopeKind, MatrixCellResult, MatrixLaneKind, MatrixOutcome,
    PinnedVersionCombination, VersionMatrixError, VersionSource, classify_failure_scopes,
    derive_version_matrix, derive_version_slots, summarize_matrix_health,
};

fn sample_spec() -> BoundaryMatrixSpec {
    BoundaryMatrixSpec {
        boundary_surface: "frankensqlite/store_record".to_string(),
        local_repo: "franken_engine".to_string(),
        remote_repo: "frankensqlite".to_string(),
        local_versions: VersionSource {
            tags: vec!["v1.4.0".to_string(), "v1.3.9".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        remote_versions: VersionSource {
            tags: vec![
                "v2.3.0".to_string(),
                "v2.2.0".to_string(),
                "v2.4.0-rc1".to_string(),
            ],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        pinned_combinations: vec![PinnedVersionCombination {
            local_version: "1.4.0".to_string(),
            remote_version: "2.1.5".to_string(),
            reason: "known regression tracking".to_string(),
        }],
    }
}

#[test]
fn matrix_derives_n_previous_next_and_pinned_cells() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");

    let lanes: Vec<MatrixLaneKind> = plan.cells.iter().map(|cell| cell.lane_kind).collect();
    assert!(lanes.contains(&MatrixLaneKind::Current));
    assert!(lanes.contains(&MatrixLaneKind::Previous));
    assert!(lanes.contains(&MatrixLaneKind::Next));
    assert!(lanes.contains(&MatrixLaneKind::Pinned));

    let current = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Current)
        .expect("current lane");
    assert_eq!(current.local_version, "1.4.0");
    assert_eq!(current.remote_version, "2.3.0");

    let previous = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Previous)
        .expect("previous lane");
    assert_eq!(previous.remote_version, "2.2.0");

    let next = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Next)
        .expect("next lane");
    assert_eq!(next.remote_version, "2.4.0-rc1");

    let pinned = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Pinned)
        .expect("pinned lane");
    assert_eq!(pinned.local_version, "1.4.0");
    assert_eq!(pinned.remote_version, "2.1.5");
    assert!(pinned.pinned);
}

#[test]
fn next_version_falls_back_to_branch_convention_when_no_prerelease_tag_exists() {
    let slots = derive_version_slots(
        &VersionSource {
            tags: vec!["v3.1.4".to_string(), "v3.1.3".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "franken_node",
    )
    .expect("derive slots");

    assert_eq!(slots.current, "3.1.4");
    assert_eq!(slots.previous.as_deref(), Some("3.1.3"));
    assert_eq!(slots.next.as_deref(), Some("3.1.5-next"));
}

#[test]
fn missing_current_version_is_fail_closed() {
    let err = derive_version_slots(
        &VersionSource {
            tags: vec!["not-a-version".to_string()],
            branch_names: vec![],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "frankentui",
    )
    .expect_err("must fail when no current version can be derived");

    match err {
        VersionMatrixError::MissingCurrentVersion { repo } => {
            assert_eq!(repo, "frankentui");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn failure_scope_classification_marks_universal_vs_version_specific() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");

    let mut results = Vec::new();
    for cell in &plan.cells {
        results.push(MatrixCellResult {
            trace_id: format!("trace-{}", cell.cell_id),
            decision_id: format!("decision-{}", cell.cell_id),
            policy_id: "policy-version-matrix-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: MatrixOutcome::Pass,
            error_code: None,
            failure_fingerprint: None,
            failure_class: None,
        });
    }

    // Universal failure appears in all cells.
    for result in &mut results {
        result.outcome = MatrixOutcome::Fail;
        result.failure_fingerprint = Some("fp-universal".to_string());
        result.failure_class = Some("breaking".to_string());
    }

    // Add one version-specific failure in a single cell.
    let specific = MatrixCellResult {
        trace_id: "trace-specific".to_string(),
        decision_id: "decision-specific".to_string(),
        policy_id: "policy-version-matrix-v1".to_string(),
        cell_id: plan.cells[0].cell_id.clone(),
        boundary_surface: plan.cells[0].boundary_surface.clone(),
        lane_kind: plan.cells[0].lane_kind,
        outcome: MatrixOutcome::Fail,
        error_code: Some("FE-MATRIX-VERSION-SPECIFIC".to_string()),
        failure_fingerprint: Some("fp-version-specific".to_string()),
        failure_class: Some("behavioral".to_string()),
    };
    results.push(specific);

    let scopes = classify_failure_scopes(&plan, &results);

    let universal = scopes
        .iter()
        .find(|scope| scope.failure_fingerprint == "fp-universal")
        .expect("universal scope");
    assert_eq!(universal.scope, FailureScopeKind::Universal);

    let version_specific = scopes
        .iter()
        .find(|scope| scope.failure_fingerprint == "fp-version-specific")
        .expect("version-specific scope");
    assert_eq!(version_specific.scope, FailureScopeKind::VersionSpecific);
    assert_eq!(version_specific.failing_cells.len(), 1);
}

#[test]
fn matrix_health_summary_counts_cells_and_scope_types() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let mut results = Vec::new();

    for (idx, cell) in plan.cells.iter().enumerate() {
        results.push(MatrixCellResult {
            trace_id: format!("trace-{idx}"),
            decision_id: format!("decision-{idx}"),
            policy_id: "policy-version-matrix-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: if idx % 2 == 0 {
                MatrixOutcome::Pass
            } else {
                MatrixOutcome::Fail
            },
            error_code: if idx % 2 == 0 {
                None
            } else {
                Some("FE-MATRIX-FAIL".to_string())
            },
            failure_fingerprint: if idx % 2 == 0 {
                None
            } else {
                Some(format!("fp-{idx}"))
            },
            failure_class: if idx % 2 == 0 {
                None
            } else {
                Some("behavioral".to_string())
            },
        });
    }

    let summary = summarize_matrix_health(&plan, &results);
    assert_eq!(summary.total_cells, plan.cells.len());
    assert_eq!(
        summary.passed_cells + summary.failed_cells,
        summary.total_cells
    );
    assert_eq!(summary.version_specific_failures, summary.failed_cells);
}
