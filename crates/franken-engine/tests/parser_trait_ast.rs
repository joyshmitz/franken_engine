use std::fs;
use std::io::Cursor;

use frankenengine_engine::ast::{Expression, ParseGoal, Statement};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParseErrorCode, StreamInput,
};

#[test]
fn parser_goal_and_statement_hierarchy_are_emitted_deterministically() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("alpha;\n42;\n'hello';\nawait beta;\n", ParseGoal::Script)
        .expect("script parse should succeed");

    assert_eq!(tree.goal, ParseGoal::Script);
    assert_eq!(tree.body.len(), 4);
    assert!(matches!(
        &tree.body[0],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::Identifier(name) if name == "alpha")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::NumericLiteral(42))
    ));
    assert!(matches!(
        &tree.body[2],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::StringLiteral(value) if value == "hello")
    ));
    assert!(matches!(
        &tree.body[3],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::Await(_))
    ));
}

#[test]
fn parser_accepts_stream_and_file_inputs_with_equal_canonical_hash() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";

    let stream_tree = parser
        .parse(
            StreamInput::new(Cursor::new(source), "stdin"),
            ParseGoal::Module,
        )
        .expect("stream parse should succeed");

    let temp_path = std::env::temp_dir().join("franken_engine_parser_trait_ast_test.js");
    fs::write(&temp_path, source).expect("write temporary source file");
    let file_tree = parser
        .parse(temp_path.as_path(), ParseGoal::Module)
        .expect("file parse should succeed");

    assert_eq!(stream_tree.canonical_bytes(), file_tree.canonical_bytes());
    assert_eq!(stream_tree.canonical_hash(), file_tree.canonical_hash());
}

#[test]
fn script_goal_rejects_module_only_declarations() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("export default value;", ParseGoal::Script)
        .expect_err("script goal should reject export");
    assert_eq!(error.code, ParseErrorCode::InvalidGoal);
}
