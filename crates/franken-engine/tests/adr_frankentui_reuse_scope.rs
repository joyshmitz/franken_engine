use std::{fs, path::PathBuf};

#[test]
fn frankentui_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## Decision",
        "## Scope",
        "## Rationale",
        "## Exception Process",
        "## Advanced TUI Boundary Definition",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_scope_items = [
        "Operator dashboards",
        "Incident/replay viewers",
        "Policy explanation cards and control panels",
        "Simple CLI output",
        "/dp/frankentui",
    ];
    for item in required_scope_items {
        assert!(
            adr.contains(item),
            "ADR must include required scope/boundary item `{item}`"
        );
    }
}

#[test]
fn frankentui_adr_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn frankentui_adr_references_advanced_tui_boundary() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Advanced TUI Boundary"));
}

#[test]
fn frankentui_adr_references_operator_dashboards() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Operator dashboards"));
}

#[test]
fn frankentui_adr_mentions_incident_replay_viewers() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Incident/replay viewers"));
}

#[test]
fn frankentui_adr_mentions_exception_process() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Exception Process"));
}

#[test]
fn frankentui_adr_mentions_simple_cli_output_boundary() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Simple CLI output"));
}

#[test]
fn frankentui_adr_status_is_accepted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Status: Accepted"));
}

#[test]
fn frankentui_adr_references_repo_split_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("REPO_SPLIT_CONTRACT.md"));
}

#[test]
fn frankentui_adr_has_rationale_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Rationale"));
}

#[test]
fn frankentui_adr_has_decision_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn frankentui_adr_references_related_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Related beads"));
}

#[test]
fn frankentui_adr_mentions_policy_explanation_cards() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Policy explanation cards"));
}

#[test]
fn frankentui_adr_has_consequences_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn frankentui_adr_has_compliance_signals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Compliance Signals"));
}

#[test]
fn frankentui_adr_has_scope_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Scope"));
}

#[test]
fn frankentui_adr_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(line_count > 10, "ADR should have >10 lines, got {line_count}");
}

#[test]
fn frankentui_adr_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn frankentui_adr_mentions_context_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Context"));
}
