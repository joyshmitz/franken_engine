use frankenengine_engine::ast::{ExportKind, Expression, ParseGoal, Statement, SyntaxTree};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn parser() -> CanonicalEs2020Parser {
    CanonicalEs2020Parser
}

fn parse_hash(source: &str, goal: ParseGoal) -> String {
    parser()
        .parse(source, goal)
        .unwrap_or_else(|error| panic!("failed to parse `{source}`: {error}"))
        .canonical_hash()
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
            Statement::VariableDeclaration(var_decl) => {
                format!("variable_declaration:{}", var_decl.declarations.len())
            }
        })
        .collect()
}

#[test]
fn phase0_corpus_hashes_are_stable_across_repeated_runs() {
    let fixtures = [
        ("alpha", ParseGoal::Script),
        ("-7", ParseGoal::Script),
        ("await work", ParseGoal::Script),
        (
            "import dep from 'pkg'; export default dep",
            ParseGoal::Module,
        ),
        ("export { a, b }", ParseGoal::Module),
    ];

    for (source, goal) in fixtures {
        let expected = parse_hash(source, goal);
        for _ in 0..8 {
            let observed = parse_hash(source, goal);
            assert_eq!(observed, expected, "hash drift for source `{source}`");
        }
    }
}

#[test]
fn raw_expression_whitespace_relation_is_semantically_stable() {
    let baseline = parser()
        .parse("a + b * c", ParseGoal::Script)
        .expect("baseline parse");
    let transformed = parser()
        .parse("  a    +   b   *   c  ", ParseGoal::Script)
        .expect("transformed parse");

    assert_eq!(
        semantic_signature(&baseline),
        semantic_signature(&transformed),
        "raw-expression whitespace transform should preserve semantic signature"
    );
}

#[test]
fn import_quote_style_relation_is_hash_equivalent() {
    let single = parse_hash(
        "import dep from 'pkg'; export default dep",
        ParseGoal::Module,
    );
    let double = parse_hash(
        "import dep from \"pkg\"; export default dep",
        ParseGoal::Module,
    );
    assert_eq!(single, double);
}

#[test]
fn named_export_spacing_relation_is_semantically_equivalent() {
    let left = parser()
        .parse("export { a, b }", ParseGoal::Module)
        .expect("left parse");
    let right = parser()
        .parse("export  {  a,   b  }", ParseGoal::Module)
        .expect("right parse");
    assert_eq!(semantic_signature(&left), semantic_signature(&right));
}

#[test]
fn statement_delimiter_relation_preserves_semantic_signature() {
    let semicolon_form = parser()
        .parse("x;42;'ok';", ParseGoal::Script)
        .expect("semicolon parse");
    let newline_form = parser()
        .parse("x\n42\n'ok'\n", ParseGoal::Script)
        .expect("newline parse");

    assert_eq!(
        semantic_signature(&semicolon_form),
        semantic_signature(&newline_form),
        "statement delimiter relation should preserve semantic signature"
    );
}

#[test]
fn await_nesting_relation_preserves_nested_identifier_target() {
    let baseline = parser()
        .parse("await await value", ParseGoal::Script)
        .expect("baseline parse");
    let transformed = parser()
        .parse("await   await   value", ParseGoal::Script)
        .expect("transformed parse");

    let extract = |tree: &SyntaxTree| -> String {
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::Await(level_1) => match level_1.as_ref() {
                    Expression::Await(level_2) => match level_2.as_ref() {
                        Expression::Identifier(value) => value.clone(),
                        other => panic!("expected nested identifier, got {other:?}"),
                    },
                    other => panic!("expected nested await, got {other:?}"),
                },
                other => panic!("expected await expression, got {other:?}"),
            },
            other => panic!("expected expression statement, got {other:?}"),
        }
    };

    assert_eq!(extract(&baseline), extract(&transformed));
}
