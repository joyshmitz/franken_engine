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
