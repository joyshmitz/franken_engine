use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, GrammarCoverageStatus, ParserMode, ParserOptions,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SemanticFixtureSpec {
    id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_hash: String,
}

#[derive(Debug, Deserialize)]
struct SemanticFixtureCatalog {
    schema_version: String,
    parser_mode: String,
    fixtures: Vec<SemanticFixtureSpec>,
}

#[derive(Debug, Deserialize)]
struct GrammarClosureFamily {
    family_id: String,
    es2020_clause: String,
    current_status: String,
    implementation_slice: String,
    owner: String,
    fixture_ids: Vec<String>,
    replay_commands: Vec<String>,
    unit_test_targets: Vec<String>,
    property_test_targets: Vec<String>,
    e2e_conformance_scripts: Vec<String>,
    evidence_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GrammarClosureBacklogCatalog {
    schema_version: String,
    parser_mode: String,
    matrix_schema_version: String,
    coverage_target_family_count: u64,
    families: Vec<GrammarClosureFamily>,
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown goal in fixture catalog: {other}"),
    }
}

fn coverage_score(status: GrammarCoverageStatus) -> u64 {
    match status {
        GrammarCoverageStatus::Supported | GrammarCoverageStatus::NotApplicable => 1000,
        GrammarCoverageStatus::Partial => 500,
        GrammarCoverageStatus::Unsupported => 0,
    }
}

fn aggregate_family_status(
    script: GrammarCoverageStatus,
    module: GrammarCoverageStatus,
) -> &'static str {
    match (coverage_score(script) + coverage_score(module)) / 2 {
        1000 => "supported",
        0 => "unsupported",
        _ => "partial",
    }
}

fn load_semantic_fixture_catalog() -> SemanticFixtureCatalog {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read parser phase0 semantic fixture catalog");
    serde_json::from_slice(&bytes).expect("deserialize parser phase0 semantic fixture catalog")
}

fn load_grammar_closure_backlog() -> GrammarClosureBacklogCatalog {
    let path = Path::new("tests/fixtures/parser_grammar_closure_backlog.json");
    let bytes = fs::read(path).expect("read parser grammar closure backlog catalog");
    serde_json::from_slice(&bytes).expect("deserialize parser grammar closure backlog catalog")
}

#[test]
fn grammar_closure_backlog_matches_scalar_reference_matrix() {
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    let backlog = load_grammar_closure_backlog();

    assert_eq!(
        backlog.schema_version,
        "franken-engine.parser-grammar-closure-backlog.v1"
    );
    assert_eq!(backlog.parser_mode, ParserMode::ScalarReference.as_str());
    assert_eq!(backlog.matrix_schema_version, matrix.schema_version);
    assert_eq!(
        backlog.coverage_target_family_count as usize,
        matrix.families.len()
    );
    assert_eq!(backlog.families.len(), matrix.families.len());
    assert_eq!(backlog.coverage_target_family_count, 20);

    let mut matrix_by_family: BTreeMap<&str, (&str, GrammarCoverageStatus, GrammarCoverageStatus)> =
        BTreeMap::new();
    for family in &matrix.families {
        let replaced = matrix_by_family.insert(
            family.family_id.as_str(),
            (
                family.es2020_clause.as_str(),
                family.script_goal,
                family.module_goal,
            ),
        );
        assert!(
            replaced.is_none(),
            "duplicate matrix family id: {}",
            family.family_id
        );
    }

    let matrix_ids: BTreeSet<&str> = matrix_by_family.keys().copied().collect();
    let mut backlog_ids: BTreeSet<&str> = BTreeSet::new();

    for family in &backlog.families {
        assert!(
            backlog_ids.insert(family.family_id.as_str()),
            "duplicate backlog family id: {}",
            family.family_id
        );

        let (matrix_clause, script_goal, module_goal) = matrix_by_family
            .get(family.family_id.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "backlog family not present in parser matrix: {}",
                    family.family_id
                )
            });

        assert_eq!(family.es2020_clause, *matrix_clause);
        assert_eq!(
            family.current_status,
            aggregate_family_status(*script_goal, *module_goal),
            "status drift for family {}",
            family.family_id
        );
        assert!(!family.implementation_slice.trim().is_empty());
        assert!(!family.owner.trim().is_empty());
        assert!(!family.fixture_ids.is_empty());
        assert!(!family.replay_commands.is_empty());
        assert!(!family.unit_test_targets.is_empty());
        assert!(!family.property_test_targets.is_empty());
        assert!(!family.e2e_conformance_scripts.is_empty());
        assert!(!family.evidence_paths.is_empty());

        for replay in &family.replay_commands {
            assert!(replay.contains("rch exec --"));
            assert!(
                replay.contains(family.family_id.as_str()),
                "replay command must be family-scoped: {}",
                family.family_id
            );
        }

        for script in &family.e2e_conformance_scripts {
            assert!(script.starts_with("./scripts/"));
        }
    }

    assert_eq!(
        backlog_ids, matrix_ids,
        "backlog family set must match parser matrix family set"
    );
}

#[test]
fn grammar_closure_backlog_fixture_bindings_are_valid() {
    let semantic_fixtures = load_semantic_fixture_catalog();
    let backlog = load_grammar_closure_backlog();

    assert_eq!(
        semantic_fixtures.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(
        semantic_fixtures.parser_mode,
        ParserMode::ScalarReference.as_str()
    );

    let mut fixtures_by_id = BTreeMap::new();
    for fixture in &semantic_fixtures.fixtures {
        let replaced = fixtures_by_id.insert(fixture.id.as_str(), fixture);
        assert!(
            replaced.is_none(),
            "duplicate semantic fixture id: {}",
            fixture.id
        );
    }

    for family in &backlog.families {
        for fixture_id in &family.fixture_ids {
            let fixture = fixtures_by_id.get(fixture_id.as_str()).unwrap_or_else(|| {
                panic!(
                    "missing fixture `{fixture_id}` for family `{}`",
                    family.family_id
                )
            });
            assert_eq!(fixture.family_id, family.family_id);
            assert!(
                fixture.expected_hash.starts_with("sha256:"),
                "fixture hash missing sha256 prefix: {}",
                fixture.id
            );
        }
    }
}

#[test]
fn parser_grammar_closure_backlog_fixtures_are_replayable_by_family() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let semantic_fixtures = load_semantic_fixture_catalog();
    let backlog = load_grammar_closure_backlog();

    let selected_family = std::env::var("PARSER_GRAMMAR_FAMILY").ok();
    if let Some(ref family_id) = selected_family {
        assert!(
            backlog
                .families
                .iter()
                .any(|family| family.family_id == *family_id),
            "unknown PARSER_GRAMMAR_FAMILY `{family_id}`"
        );
    }

    let fixtures_by_id: BTreeMap<&str, &SemanticFixtureSpec> = semantic_fixtures
        .fixtures
        .iter()
        .map(|fixture| (fixture.id.as_str(), fixture))
        .collect();

    let mut executed_families = 0usize;
    for family in &backlog.families {
        if let Some(ref only_family) = selected_family
            && &family.family_id != only_family
        {
            continue;
        }

        executed_families = executed_families.saturating_add(1);
        for fixture_id in &family.fixture_ids {
            let fixture = fixtures_by_id
                .get(fixture_id.as_str())
                .unwrap_or_else(|| panic!("fixture not found for replay: {fixture_id}"));

            let tree = parser
                .parse_with_options(
                    fixture.source.as_str(),
                    parse_goal(fixture.goal.as_str()),
                    &options,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "fixture `{}` for family `{}` failed to parse during replay: {error}",
                        fixture.id, family.family_id
                    )
                });

            assert_eq!(
                tree.canonical_hash(),
                fixture.expected_hash,
                "fixture hash drift for family `{}` fixture `{}`",
                family.family_id,
                fixture.id
            );
        }
    }

    assert!(executed_families > 0, "no families executed in replay loop");
}
