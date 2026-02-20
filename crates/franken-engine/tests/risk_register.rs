use std::{collections::BTreeSet, fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_risk_register() -> String {
    let path = repo_root().join("docs/RISK_REGISTER.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn parse_table_by_heading(doc: &str, heading: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let lines: Vec<&str> = doc.lines().collect();
    let heading_idx = lines
        .iter()
        .position(|line| line.trim() == heading)
        .unwrap_or_else(|| panic!("missing heading: {heading}"));

    let mut i = heading_idx + 1;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }

    assert!(
        i + 1 < lines.len(),
        "table for heading `{heading}` is incomplete"
    );

    let header_line = lines[i].trim();
    let separator_line = lines[i + 1].trim();
    assert!(
        header_line.starts_with('|') && separator_line.starts_with('|'),
        "heading `{heading}` must be followed by a markdown table"
    );
    let header = parse_table_row(header_line);

    let mut rows = Vec::new();
    i += 2;
    while i < lines.len() {
        let line = lines[i].trim();
        if !line.starts_with('|') {
            break;
        }
        rows.push(parse_table_row(line));
        i += 1;
    }

    (header, rows)
}

fn is_iso_date(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let (y, m, d) = (parts[0], parts[1], parts[2]);
    y.len() == 4
        && m.len() == 2
        && d.len() == 2
        && y.chars().all(|c| c.is_ascii_digit())
        && m.chars().all(|c| c.is_ascii_digit())
        && d.chars().all(|c| c.is_ascii_digit())
}

#[test]
fn risk_register_contains_required_sections() {
    let register = read_risk_register();

    let required_sections = [
        "# FrankenEngine Program Risk Register",
        "## Risk Schema",
        "## Active Risks",
        "## Review Cadence",
        "## Phase Gate Review Log",
        "## Update Procedure",
    ];

    for section in required_sections {
        assert!(
            register.contains(section),
            "risk register must contain section: {section}"
        );
    }
}

#[test]
fn active_risk_table_has_required_schema_and_values() {
    let register = read_risk_register();
    let (header, rows) = parse_table_by_heading(&register, "## Active Risks");

    let expected_header = vec![
        "Risk ID".to_string(),
        "Title".to_string(),
        "Severity".to_string(),
        "Likelihood".to_string(),
        "Impact Summary".to_string(),
        "Countermeasure Beads".to_string(),
        "Owner".to_string(),
        "Monitor".to_string(),
        "Review Cadence".to_string(),
        "Status".to_string(),
        "Last Reviewed".to_string(),
        "Evidence".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert!(!rows.is_empty(), "active risk table must not be empty");

    let valid_severity: BTreeSet<&str> = ["Critical", "High", "Medium", "Low"]
        .iter()
        .copied()
        .collect();
    let valid_likelihood: BTreeSet<&str> = ["High", "Medium", "Low"].iter().copied().collect();
    let valid_status: BTreeSet<&str> = ["Open", "Mitigating", "Accepted", "Closed"]
        .iter()
        .copied()
        .collect();
    let mut seen_ids = BTreeSet::new();

    for row in rows {
        assert_eq!(
            row.len(),
            12,
            "every active risk row must have exactly 12 columns"
        );

        let risk_id = &row[0];
        assert!(
            risk_id.starts_with("R-")
                && risk_id.len() == 5
                && risk_id[2..].chars().all(|c| c.is_ascii_digit()),
            "risk id must match R-### format: {risk_id}"
        );
        assert!(
            seen_ids.insert(risk_id.clone()),
            "risk ids must be unique; duplicate: {risk_id}"
        );
        assert!(!row[1].is_empty(), "title is required for {risk_id}");
        assert!(
            valid_severity.contains(row[2].as_str()),
            "invalid severity for {risk_id}: {}",
            row[2]
        );
        assert!(
            valid_likelihood.contains(row[3].as_str()),
            "invalid likelihood for {risk_id}: {}",
            row[3]
        );
        assert!(
            !row[4].is_empty(),
            "impact summary is required for {risk_id}"
        );
        assert!(
            row[5].contains("bd-"),
            "countermeasure beads must reference bead ids for {risk_id}"
        );
        assert!(!row[6].is_empty(), "owner is required for {risk_id}");
        assert!(!row[7].is_empty(), "monitor is required for {risk_id}");
        assert!(
            !row[8].is_empty(),
            "review cadence is required for {risk_id}"
        );
        assert!(
            valid_status.contains(row[9].as_str()),
            "invalid status for {risk_id}: {}",
            row[9]
        );
        assert!(
            is_iso_date(&row[10]),
            "last reviewed must be YYYY-MM-DD for {risk_id}: {}",
            row[10]
        );
        assert!(
            !row[11].is_empty(),
            "evidence pointer is required for {risk_id}"
        );
    }
}

#[test]
fn review_cadence_contains_weekly_phase_and_incident_checks() {
    let register = read_risk_register();
    let required_lines = [
        "- Weekly: review active risk indicators and update status/owner actions.",
        "- Per-phase-gate: complete full risk review before gate sign-off.",
        "- Per-incident: add or amend risks discovered during incident analysis.",
    ];

    for line in required_lines {
        assert!(
            register.contains(line),
            "review cadence line is required: {line}"
        );
    }
}

#[test]
fn crossed_phase_gates_require_register_review_evidence() {
    let register = read_risk_register();
    let (header, rows) = parse_table_by_heading(&register, "## Phase Gate Review Log");

    let expected_header = vec![
        "Phase".to_string(),
        "Gate Status".to_string(),
        "Gate Date".to_string(),
        "Register Review Date".to_string(),
        "Reviewer".to_string(),
        "Evidence Link".to_string(),
        "Notes".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert_eq!(rows.len(), 5, "phase gate table must include phases A-E");

    let mut phases = BTreeSet::new();
    for row in rows {
        assert_eq!(row.len(), 7, "phase gate rows must have 7 columns");

        let phase = row[0].as_str();
        phases.insert(phase.to_string());
        assert!(
            ["A", "B", "C", "D", "E"].contains(&phase),
            "unknown phase in gate table: {phase}"
        );

        let gate_status = row[1].as_str();
        assert!(
            ["Pending", "Crossed"].contains(&gate_status),
            "invalid gate status for phase {phase}: {gate_status}"
        );

        if gate_status == "Crossed" {
            assert!(
                is_iso_date(row[2].as_str()),
                "crossed phase {phase} must have gate date"
            );
            assert!(
                is_iso_date(row[3].as_str()),
                "crossed phase {phase} must have register review date"
            );
            assert!(
                !row[4].eq_ignore_ascii_case("pending"),
                "crossed phase {phase} must define reviewer"
            );
            assert!(
                !row[5].eq_ignore_ascii_case("pending"),
                "crossed phase {phase} must define evidence link"
            );
        }
    }

    let expected_phases: BTreeSet<String> = ["A", "B", "C", "D", "E"]
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(phases, expected_phases, "phase gate table must cover A-E");
}
