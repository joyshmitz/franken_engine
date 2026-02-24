use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserMode, ParserOptions};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureSpec {
    id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_hash: String,
}

#[derive(Debug, Deserialize)]
struct FixtureCatalog {
    schema_version: String,
    parser_mode: String,
    fixtures: Vec<FixtureSpec>,
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown goal in fixture catalog: {other}"),
    }
}

#[test]
fn parser_phase0_semantic_fixtures_match_expected_hashes() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read parser phase0 fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize parser phase0 fixture catalog");

    assert_eq!(
        catalog.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(catalog.parser_mode, ParserMode::ScalarReference.as_str());
    assert!(
        !catalog.fixtures.is_empty(),
        "parser phase0 fixture catalog must include fixtures"
    );

    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    for fixture in &catalog.fixtures {
        assert!(
            fixture.expected_hash.starts_with("sha256:"),
            "fixture `{}` missing expected hash prefix",
            fixture.id
        );

        let tree = parser
            .parse_with_options(
                fixture.source.as_str(),
                parse_goal(fixture.goal.as_str()),
                &options,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "fixture `{}` (`{}`) failed to parse: {error}",
                    fixture.id, fixture.family_id
                )
            });
        let actual = tree.canonical_hash();
        assert_eq!(
            actual, fixture.expected_hash,
            "fixture `{}` (`{}`) hash drift",
            fixture.id, fixture.family_id
        );
    }
}

#[test]
#[ignore]
fn print_parser_phase0_fixture_hashes() {
    let path = Path::new("tests/fixtures/parser_phase0_semantic_fixtures.json");
    let bytes = fs::read(path).expect("read parser phase0 fixture catalog");
    let catalog: FixtureCatalog =
        serde_json::from_slice(&bytes).expect("deserialize parser phase0 fixture catalog");
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    for fixture in &catalog.fixtures {
        let tree = parser
            .parse_with_options(
                fixture.source.as_str(),
                parse_goal(fixture.goal.as_str()),
                &options,
            )
            .unwrap_or_else(|error| panic!("fixture `{}` parse failed: {error}", fixture.id));
        println!("{}\t{}", fixture.id, tree.canonical_hash());
    }
}
