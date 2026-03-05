use std::{fs, path::PathBuf};

#[test]
fn fastapi_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## In-Scope Endpoint Classes",
        "## Out-of-Scope Interfaces",
        "## Required `fastapi_rust` Conventions and Components",
        "## Exception Process",
        "## Review Gate",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_endpoint_classes = [
        "Health checks",
        "Control actions (`start`/`stop`/`quarantine`)",
        "Evidence export APIs",
        "Replay control APIs",
        "Benchmark result APIs",
    ];
    for endpoint_class in required_endpoint_classes {
        assert!(
            adr.contains(endpoint_class),
            "ADR must define in-scope endpoint class `{endpoint_class}`"
        );
    }
}

#[test]
fn fastapi_adr_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn fastapi_adr_references_exception_process() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Exception Process"));
    assert!(content.contains("Review Gate"));
}

#[test]
fn fastapi_adr_references_out_of_scope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Out-of-Scope"));
}

#[test]
fn fastapi_adr_mentions_health_checks_endpoint_class() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Health checks"));
}

#[test]
fn fastapi_adr_mentions_required_conventions() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Required `fastapi_rust` Conventions"));
}

#[test]
fn fastapi_adr_mentions_replay_and_benchmark_apis() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Replay control APIs"));
    assert!(content.contains("Benchmark result APIs"));
}

#[test]
fn fastapi_adr_status_is_accepted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Status: Accepted"));
}

#[test]
fn fastapi_adr_defines_error_response_envelope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Error response envelope"));
}

#[test]
fn fastapi_adr_has_context_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Context"));
}

#[test]
fn fastapi_adr_has_decision_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn fastapi_adr_references_related_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Related beads"));
}

#[test]
fn fastapi_adr_mentions_auth_middleware() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Authentication/authorization middleware"));
}

#[test]
fn fastapi_adr_has_non_goals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Non-Goals"));
}

#[test]
fn fastapi_adr_has_consequences_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn fastapi_adr_has_compliance_signals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Compliance Signals"));
}

#[test]
fn fastapi_adr_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(line_count > 10, "ADR should have >10 lines, got {line_count}");
}

#[test]
fn fastapi_adr_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn fastapi_adr_mentions_control_actions() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Control actions"));
}
