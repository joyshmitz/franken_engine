use std::{collections::BTreeSet, fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_spec() -> String {
    let path = repo_root().join("docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md");
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

#[test]
fn benchmark_spec_contains_required_sections() {
    let spec = read_spec();
    let required_sections = [
        "## Required Benchmark Families",
        "## Scale Profile Matrix (Normative Defaults)",
        "## Per-Case Publication Requirements",
        "## Behavior-Equivalence Hard Gates",
        "## Scoring Formula (Binding)",
        "## Fairness and Denominator Contract",
        "## Required Metric Families",
        "## Workload and Result Schema Contract",
        "## Structured Event Contract",
        "## Reproducibility and Verifier Workflow",
        "## CI Publication Gate",
        "## Failure Semantics and Rollback",
        "## Independent Verifier Onboarding",
    ];

    for section in required_sections {
        assert!(
            spec.contains(section),
            "benchmark spec must include section: {section}"
        );
    }
}

#[test]
fn family_table_lists_all_required_families_with_required_profiles() {
    let spec = read_spec();
    let (header, rows) = parse_table_by_heading(&spec, "## Required Benchmark Families");

    let expected_header = vec![
        "Family ID".to_string(),
        "Purpose".to_string(),
        "Required Profiles".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert_eq!(
        rows.len(),
        5,
        "exactly five benchmark families are required"
    );

    let expected_families: BTreeSet<String> = [
        "`boot-storm`",
        "`capability-churn`",
        "`mixed-cpu-io-agent-mesh`",
        "`reload-revoke-churn`",
        "`adversarial-noise-under-load`",
    ]
    .iter()
    .map(|item| (*item).to_string())
    .collect();

    let observed_families: BTreeSet<String> = rows.iter().map(|row| row[0].clone()).collect();
    assert_eq!(
        observed_families, expected_families,
        "family table must include the normative five families"
    );

    for row in rows {
        assert_eq!(row.len(), 3, "family rows must have 3 columns");
        assert!(
            row[2].contains("`S`") && row[2].contains("`M`") && row[2].contains("`L`"),
            "every family must require S/M/L profiles"
        );
    }
}

#[test]
fn scale_profile_matrix_includes_s_m_l_defaults() {
    let spec = read_spec();
    let (header, rows) =
        parse_table_by_heading(&spec, "## Scale Profile Matrix (Normative Defaults)");

    let expected_header = vec![
        "Profile".to_string(),
        "Extension Count".to_string(),
        "Event Rate (events/sec)".to_string(),
        "Dependency Graph Size".to_string(),
        "Policy Complexity Tier".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert_eq!(rows.len(), 3, "scale matrix must include S/M/L rows");

    let expected_profiles: BTreeSet<String> = ["`S`", "`M`", "`L`"]
        .iter()
        .map(|item| (*item).to_string())
        .collect();
    let observed_profiles: BTreeSet<String> = rows.iter().map(|row| row[0].clone()).collect();
    assert_eq!(observed_profiles, expected_profiles);
}

#[test]
fn scoring_formula_and_threshold_clauses_are_declared() {
    let spec = read_spec();
    let required_fragments = [
        "score(engine, baseline) = exp(sum_i w_i * ln(throughput_engine_i / throughput_baseline_i))",
        "sum_i w_i = 1",
        "score_vs_node >= 3.0",
        "score_vs_bun >= 3.0",
    ];

    for fragment in required_fragments {
        assert!(
            spec.contains(fragment),
            "scoring section must contain: {fragment}"
        );
    }
}

#[test]
fn required_metric_families_and_event_keys_are_declared() {
    let spec = read_spec();
    let metric_fragments = [
        "throughput/latency under extension-heavy load",
        "containment quality",
        "replay correctness",
        "revocation/quarantine propagation",
        "adversarial resilience",
        "information-flow security",
        "security-proof specialization uplift",
    ];
    for fragment in metric_fragments {
        assert!(
            spec.contains(fragment),
            "required metric family missing: {fragment}"
        );
    }

    let event_keys = [
        "`trace_id`",
        "`decision_id`",
        "`policy_id`",
        "`component`",
        "`event`",
        "`outcome`",
        "`error_code`",
    ];
    for key in event_keys {
        assert!(spec.contains(key), "structured event key missing: {key}");
    }
}

#[test]
fn verifier_workflow_and_bundle_requirements_are_explicit() {
    let spec = read_spec();
    let required_items = [
        "`env.json`",
        "`manifest.json`",
        "`repro.lock`",
        "`commands.txt`",
        "`results.json`",
        "frankenctl benchmark verify --bundle",
        "CI must fail publication",
    ];

    for item in required_items {
        assert!(
            spec.contains(item),
            "verifier/bundle requirement missing: {item}"
        );
    }
}
