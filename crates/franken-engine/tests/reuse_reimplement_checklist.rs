use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn pr_template_requires_reuse_vs_reimplement_justification() {
    let template_path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let template = fs::read_to_string(&template_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", template_path.display()));

    let required_clauses = [
        "Does this PR introduce new TUI/SQLite/service infrastructure?",
        "reuse vs reimplement",
        "Decision (reuse/reimplement)",
        "ADR-0003",
        "ADR-0004",
        "ADR-0002",
        "Exception artifact link",
        "Justification link",
    ];

    for clause in required_clauses {
        assert!(
            template.contains(clause),
            "PR template must include required clause: {clause}"
        );
    }
}

#[test]
fn release_checklist_requires_traceable_reimplement_decisions() {
    let checklist_path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let checklist = fs::read_to_string(&checklist_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", checklist_path.display()));

    let required_clauses = [
        "## Reuse Vs Reimplement Decisions",
        "Decision (reuse/reimplement)",
        "ADR-0003",
        "ADR-0004",
        "ADR-0002",
        "Exception artifact link",
        "Justification link",
        "Release gate fails if any reimplement decision lacks exception or justification evidence.",
    ];

    for clause in required_clauses {
        assert!(
            checklist.contains(clause),
            "Release checklist must include required clause: {clause}"
        );
    }
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- doc content ----------

#[test]
fn pr_template_is_nonempty() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(!content.is_empty());
}

#[test]
fn release_checklist_is_nonempty() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(!content.is_empty());
}

#[test]
fn pr_template_references_adr_documents() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("ADR-0002"));
    assert!(content.contains("ADR-0003"));
    assert!(content.contains("ADR-0004"));
}

#[test]
fn release_checklist_references_adr_documents() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("ADR-0002"));
    assert!(content.contains("ADR-0003"));
    assert!(content.contains("ADR-0004"));
}

#[test]
fn pr_template_mentions_exception_and_justification() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("Exception"), "PR template must mention Exception");
    assert!(content.contains("Justification"), "PR template must mention Justification");
}

#[test]
fn release_checklist_has_reuse_vs_reimplement_heading() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Reuse Vs Reimplement Decisions"));
}

#[test]
fn release_checklist_mentions_gate_failure_policy() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(
        content.contains("Release gate fails"),
        "release checklist must describe gate failure policy"
    );
}

#[test]
fn pr_template_mentions_tui_sqlite_service_infrastructure() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("TUI/SQLite/service infrastructure"));
}

#[test]
fn release_checklist_mentions_decision_reuse_reimplement() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("Decision (reuse/reimplement)"));
}

#[test]
fn pr_template_mentions_justification_link() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("Justification link"));
}

#[test]
fn release_checklist_mentions_exception_artifact_link() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("Exception artifact link"));
}

#[test]
fn pr_template_mentions_decision_reuse_reimplement() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("Decision (reuse/reimplement)"));
}

#[test]
fn release_checklist_mentions_justification_link() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("Justification link"));
}

#[test]
fn release_checklist_has_sign_off_section() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Sign-Off"));
}

#[test]
fn release_checklist_has_core_validation_gate() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Core Validation Gate"));
}

#[test]
fn release_checklist_has_machine_readable_gate() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Machine-Readable Gate"));
}

#[test]
fn pr_template_has_more_than_10_lines() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    let line_count = content.lines().count();
    assert!(line_count > 10, "PR template should have >10 lines, got {line_count}");
}

#[test]
fn release_checklist_has_more_than_10_lines() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let line_count = content.lines().count();
    assert!(line_count > 10, "release checklist should have >10 lines, got {line_count}");
}

#[test]
fn release_checklist_deterministic_double_read() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}
