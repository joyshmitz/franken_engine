use std::{fs, path::PathBuf};

#[test]
fn frankensqlite_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## Decision",
        "## Scope",
        "## Rationale",
        "## Exception Process",
        "## Persistence Boundary Definition",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_scope_items = [
        "replay index",
        "evidence index",
        "benchmark ledger",
        "policy cache",
        "witness stores",
        "lineage logs",
        "WAL/PRAGMA",
        "schema migration",
        "/dp/frankensqlite",
    ];
    for item in required_scope_items {
        assert!(
            adr.contains(item),
            "ADR must include required scope/boundary item `{item}`"
        );
    }
}

#[test]
fn frankensqlite_adr_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn frankensqlite_adr_references_companion_decision() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Companion Decision"));
}

#[test]
fn frankensqlite_adr_references_wal() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("WAL"));
}

#[test]
fn frankensqlite_adr_mentions_schema_migration() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("schema migration"));
}

#[test]
fn frankensqlite_adr_has_persistence_boundary_definition() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Persistence Boundary Definition"));
}

#[test]
fn frankensqlite_adr_has_rationale_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Rationale"));
}

#[test]
fn frankensqlite_adr_status_is_accepted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Status: Accepted"));
}

#[test]
fn frankensqlite_adr_mentions_canonical_substrate() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("canonical substrate"));
}

#[test]
fn frankensqlite_adr_has_context_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Context"));
}

#[test]
fn frankensqlite_adr_has_decision_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn frankensqlite_adr_references_related_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Related beads"));
}

#[test]
fn frankensqlite_adr_mentions_lineage_logs() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("lineage logs"));
}

#[test]
fn frankensqlite_adr_has_consequences_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn frankensqlite_adr_has_compliance_signals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Compliance Signals"));
}

#[test]
fn frankensqlite_adr_has_migration_policy_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Migration Policy"));
}

#[test]
fn frankensqlite_adr_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(line_count > 10, "ADR should have >10 lines, got {line_count}");
}

#[test]
fn frankensqlite_adr_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn frankensqlite_adr_mentions_evidence_index() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("evidence index"));
}
