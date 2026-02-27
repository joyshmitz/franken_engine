use frankenengine_engine::ast::{ExportKind, ParseGoal, Statement, SyntaxTree};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParseBudgetKind, ParseErrorCode, ParserBudget, ParserMode,
    ParserOptions,
};
use serde_json::json;

const TRACE_PREFIX: &str = "trace-parser-property";
const DECISION_PREFIX: &str = "decision-parser-property";
const POLICY_ID: &str = "policy-parser-property-regression-v1";
const COMPONENT: &str = "parser_property_regression";

#[derive(Debug, Clone)]
struct GeneratedCase {
    source: String,
    goal: ParseGoal,
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn generate_identifier(state: &mut u64) -> String {
    format!("v{}", lcg_next(state) % 10_000)
}

fn generate_case(seed: u64) -> GeneratedCase {
    let mut state = seed ^ 0x9E3779B97F4A7C15;
    let variant = (lcg_next(&mut state) % 9) as u8;

    let ident_a = generate_identifier(&mut state);
    let ident_b = generate_identifier(&mut state);
    let ident_c = generate_identifier(&mut state);
    let num = (lcg_next(&mut state) % 1000) as i64 - 500;
    let txt = format!("txt{}", lcg_next(&mut state) % 5000);
    let pkg = format!("pkg{}", lcg_next(&mut state) % 128);

    match variant {
        0 => GeneratedCase {
            source: ident_a,
            goal: ParseGoal::Script,
        },
        1 => GeneratedCase {
            source: num.to_string(),
            goal: ParseGoal::Script,
        },
        2 => GeneratedCase {
            source: format!("\"{txt}\""),
            goal: ParseGoal::Script,
        },
        3 => GeneratedCase {
            source: format!("await {ident_a}"),
            goal: ParseGoal::Script,
        },
        4 => GeneratedCase {
            source: format!("{ident_a} + {ident_b} * {ident_c}"),
            goal: ParseGoal::Script,
        },
        5 => GeneratedCase {
            source: format!("{ident_a};\n{num};\n\"{txt}\";\n"),
            goal: ParseGoal::Script,
        },
        6 => GeneratedCase {
            source: format!("import {ident_a} from \"{pkg}\";\nexport default {ident_a}"),
            goal: ParseGoal::Module,
        },
        7 => GeneratedCase {
            source: format!("import \"{pkg}\";\nexport {{ {ident_b}, {ident_c} }}"),
            goal: ParseGoal::Module,
        },
        _ => GeneratedCase {
            source: format!("export default \"{txt}\""),
            goal: ParseGoal::Module,
        },
    }
}

fn goal_label(goal: ParseGoal) -> &'static str {
    match goal {
        ParseGoal::Script => "script",
        ParseGoal::Module => "module",
    }
}

fn failure_context(test_name: &str, seed: u64, goal: ParseGoal, source: &str) -> String {
    let trace_id = format!("{TRACE_PREFIX}-{seed:016x}");
    let decision_id = format!("{DECISION_PREFIX}-{seed:016x}");
    json!({
        "schema_version": "franken-engine.parser-test-failure.v1",
        "trace_id": trace_id,
        "decision_id": decision_id,
        "policy_id": POLICY_ID,
        "component": COMPONENT,
        "event": "assertion_failure_context",
        "seed": seed,
        "goal": goal_label(goal),
        "source": source,
        "replay_command": format!(
            "cargo test -p frankenengine-engine --test parser_property_regression -- --exact {test_name}"
        )
    })
    .to_string()
}

fn semantic_signature(tree: &SyntaxTree) -> Vec<String> {
    tree.body
        .iter()
        .map(|statement| match statement {
            Statement::Expression(expr) => {
                let payload = serde_json::to_string(&expr.expression.canonical_value())
                    .expect("serialize expression signature");
                format!("expression:{payload}")
            }
            Statement::Import(import_decl) => {
                let binding = import_decl.binding.as_deref().unwrap_or("<none>");
                format!("import:{binding}:{}", import_decl.source)
            }
            Statement::Export(export_decl) => match &export_decl.kind {
                ExportKind::Default(expression) => {
                    let payload = serde_json::to_string(&expression.canonical_value())
                        .expect("serialize default export signature");
                    format!("export_default:{payload}")
                }
                ExportKind::NamedClause(clause) => format!("export_named:{clause}"),
            },
            Statement::VariableDeclaration(_) => format!("variable_decl"),
        })
        .collect()
}

#[test]
fn generated_programs_are_deterministic_across_repeated_runs() {
    let parser = CanonicalEs2020Parser;

    for seed in 0_u64..256 {
        let generated = generate_case(seed);
        let first = parser
            .parse(generated.source.as_str(), generated.goal)
            .unwrap_or_else(|error| {
                panic!(
                    "{}",
                    failure_context(
                        "generated_programs_are_deterministic_across_repeated_runs",
                        seed,
                        generated.goal,
                        generated.source.as_str()
                    ) + &format!(" parse_error={error}")
                )
            })
            .canonical_hash();

        for _ in 0..4 {
            let observed = parser
                .parse(generated.source.as_str(), generated.goal)
                .unwrap_or_else(|error| {
                    panic!(
                        "{}",
                        failure_context(
                            "generated_programs_are_deterministic_across_repeated_runs",
                            seed,
                            generated.goal,
                            generated.source.as_str()
                        ) + &format!(" parse_error={error}")
                    )
                })
                .canonical_hash();

            assert_eq!(
                observed,
                first,
                "{}",
                failure_context(
                    "generated_programs_are_deterministic_across_repeated_runs",
                    seed,
                    generated.goal,
                    generated.source.as_str()
                )
            );
        }
    }
}

#[test]
fn generated_module_whitespace_transform_is_semantically_stable() {
    let parser = CanonicalEs2020Parser;

    for seed in 0_u64..128 {
        let mut state = seed ^ 0xD1B54A32D192ED03;
        let binding = generate_identifier(&mut state);
        let pkg = format!("pkg{}", lcg_next(&mut state) % 256);

        let baseline_source = format!("import {binding} from \"{pkg}\";\nexport default {binding}");
        let transformed_source = format!(
            "  import   {binding}   from   \"{pkg}\" ;\n\n  export   default   {binding}  "
        );

        let baseline_tree = parser
            .parse(baseline_source.as_str(), ParseGoal::Module)
            .expect("baseline parse should succeed");
        let transformed_tree = parser
            .parse(transformed_source.as_str(), ParseGoal::Module)
            .expect("transformed parse should succeed");

        assert_eq!(
            semantic_signature(&baseline_tree),
            semantic_signature(&transformed_tree),
            "{}",
            failure_context(
                "generated_module_whitespace_transform_is_semantically_stable",
                seed,
                ParseGoal::Module,
                baseline_source.as_str()
            )
        );
    }
}

#[test]
fn recursion_budget_failure_witness_is_seed_stable() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 16_384,
            max_token_count: 16_384,
            max_recursion_depth: 1,
        },
    };

    for seed in 0_u64..64 {
        let source = format!("await await await v{seed}");
        let left = parser
            .parse_with_options(source.as_str(), ParseGoal::Script, &options)
            .expect_err("left parse should fail recursion budget");
        let right = parser
            .parse_with_options(source.as_str(), ParseGoal::Script, &options)
            .expect_err("right parse should fail recursion budget");

        assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
        assert_eq!(left, right);

        let witness = left.witness.expect("budget failure should include witness");
        assert_eq!(witness.mode, ParserMode::ScalarReference);
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::RecursionDepth));
        assert!(witness.max_recursion_observed > witness.max_recursion_depth);
    }
}

#[test]
fn regression_failure_catalog_has_stable_error_codes() {
    let parser = CanonicalEs2020Parser;
    let cases = [
        (0_u64, "", ParseGoal::Script, ParseErrorCode::EmptySource),
        (
            1_u64,
            "   \n  \t",
            ParseGoal::Module,
            ParseErrorCode::EmptySource,
        ),
        (
            2_u64,
            "import",
            ParseGoal::Module,
            ParseErrorCode::UnsupportedSyntax,
        ),
        (
            3_u64,
            "import x from pkg",
            ParseGoal::Module,
            ParseErrorCode::UnsupportedSyntax,
        ),
        (
            4_u64,
            "export default x",
            ParseGoal::Script,
            ParseErrorCode::InvalidGoal,
        ),
        (
            5_u64,
            "import x from 'pkg'",
            ParseGoal::Script,
            ParseErrorCode::InvalidGoal,
        ),
    ];

    for (seed, source, goal, expected_code) in cases {
        let error = parser.parse(source, goal).expect_err("case should fail");
        assert_eq!(
            error.code,
            expected_code,
            "{}",
            failure_context(
                "regression_failure_catalog_has_stable_error_codes",
                seed,
                goal,
                source
            )
        );
    }
}
