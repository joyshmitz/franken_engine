use frankenengine_engine::ast::{ParseGoal, SourceSpan, SyntaxTree};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

#[test]
fn module_source_lowers_across_all_passes() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            r#"import foo from "pkg"; export default foo; await foo;"#,
            ParseGoal::Module,
        )
        .expect("module parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "module_fixture.ts");
    let context = LoweringContext::new("trace-lower", "decision-lower", "policy-lower");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert!(!output.ir1.ops.is_empty());
    assert!(!output.ir2.ops.is_empty());
    assert!(!output.ir3.instructions.is_empty());
}

#[test]
fn hostcall_literal_preserves_capability_intent_into_ir2() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(r#"hostcall<"fs.read">();"#, ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "hostcall_fixture.ts");
    let context = LoweringContext::new("trace-hostcall", "decision-hostcall", "policy-hostcall");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    let capabilities = output
        .ir2
        .required_capabilities
        .iter()
        .map(|cap| cap.0.as_str())
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&"fs.read"));
}

#[test]
fn pipeline_is_deterministic_for_identical_parse_tree() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42; await 42;", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "deterministic_fixture.js");
    let context = LoweringContext::new("trace-det", "decision-det", "policy-det");

    let first = lower_ir0_to_ir3(&ir0, &context).expect("first pipeline run should pass");
    let second = lower_ir0_to_ir3(&ir0, &context).expect("second pipeline run should pass");

    assert_eq!(first.ir1.content_hash(), second.ir1.content_hash());
    assert_eq!(first.ir2.content_hash(), second.ir2.content_hash());
    assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
    assert_eq!(first.witnesses, second.witnesses);
}

#[test]
fn events_contain_required_structured_fields() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "events_fixture.js");
    let context = LoweringContext::new("trace-events", "decision-events", "policy-events");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    assert!(output.events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && !event.component.is_empty()
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
}

#[test]
fn empty_ir0_tree_is_rejected() {
    let empty_tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: Vec::new(),
        span: SourceSpan::new(0, 0, 1, 1, 1, 1),
    };
    let ir0 = Ir0Module::from_syntax_tree(empty_tree, "empty_fixture.js");
    let context = LoweringContext::new("trace-empty", "decision-empty", "policy-empty");
    let error = lower_ir0_to_ir3(&ir0, &context).expect_err("empty tree should fail");

    assert_eq!(error, LoweringPipelineError::EmptyIr0Body);
}
