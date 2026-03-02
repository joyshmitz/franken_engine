use frankenengine_engine::ast::{ParseGoal, SourceSpan, SyntaxTree};
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir1, lower_ir0_to_ir3, lower_ir1_to_ir2,
    lower_ir2_to_ir3, validate_ir0_static_semantics,
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
fn dynamic_hostcall_path_inserts_runtime_ifc_guard() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("doWork();", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "dynamic_hostcall_fixture.ts");
    let context = LoweringContext::new("trace-dynamic", "decision-dynamic", "policy-dynamic");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

    let hostcall_caps = output
        .ir3
        .instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(hostcall_caps.contains(&"ifc.check_flow"));
    assert!(hostcall_caps.contains(&"hostcall.invoke"));
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

// ────────────────────────────────────────────────────────────
// Enrichment: individual passes, validation, determinism, errors
// ────────────────────────────────────────────────────────────

#[test]
fn individual_passes_succeed_for_simple_source() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "individual_passes.js");

    let pass1 = lower_ir0_to_ir1(&ir0).expect("ir0 -> ir1 should succeed");
    assert!(!pass1.module.ops.is_empty());
    assert!(!pass1.witness.pass_id.is_empty());

    let pass2 = lower_ir1_to_ir2(&pass1.module).expect("ir1 -> ir2 should succeed");
    assert!(!pass2.module.ops.is_empty());
    assert!(!pass2.witness.pass_id.is_empty());

    let pass3 = lower_ir2_to_ir3(&pass2.module).expect("ir2 -> ir3 should succeed");
    assert!(!pass3.module.instructions.is_empty());
    assert!(!pass3.witness.pass_id.is_empty());
}

#[test]
fn static_semantics_validation_on_simple_source() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let x = 1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "semantics_fixture.js");
    let result = validate_ir0_static_semantics(&ir0);
    assert!(result.is_valid());
}

#[test]
fn pipeline_produces_flow_proof_artifact() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "flow_proof_fixture.js");
    let context = LoweringContext::new("trace-fp", "decision-fp", "policy-fp");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    assert!(!output.ir2_flow_proof_artifact.module_id.is_empty());
    assert!(!output.ir2_flow_proof_artifact.artifact_id.is_empty());
    assert!(!output.ir2_flow_proof_artifact.schema_version.is_empty());
}

#[test]
fn witnesses_are_consistent_with_isomorphism_ledger() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "witness_consistency.js");
    let context = LoweringContext::new("trace-wc", "decision-wc", "policy-wc");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    assert_eq!(output.witnesses.len(), output.isomorphism_ledger.len());
    for witness in &output.witnesses {
        assert!(!witness.pass_id.is_empty());
        assert!(!witness.input_hash.is_empty());
        assert!(!witness.output_hash.is_empty());
    }
}

#[test]
fn lowering_context_fields_propagate_to_events() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("1;", ParseGoal::Script)
        .expect("parse should succeed");
    let ir0 = Ir0Module::from_syntax_tree(tree, "context_propagation.js");
    let context = LoweringContext::new("trace-ctx", "decision-ctx", "policy-ctx");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should pass");

    for event in &output.events {
        assert_eq!(event.trace_id, "trace-ctx");
        assert_eq!(event.decision_id, "decision-ctx");
        assert_eq!(event.policy_id, "policy-ctx");
    }
}

#[test]
fn lowering_pipeline_error_display_is_non_empty() {
    let err = LoweringPipelineError::EmptyIr0Body;
    assert!(!err.to_string().is_empty());

    let err2 = LoweringPipelineError::InvariantViolation {
        detail: "test invariant",
    };
    assert!(!err2.to_string().is_empty());
    assert!(err2.to_string().contains("test invariant"));
}

#[test]
fn content_hashes_differ_for_different_sources() {
    let parser = CanonicalEs2020Parser;

    let tree_a = parser.parse("1;", ParseGoal::Script).expect("parse a");
    let ir0_a = Ir0Module::from_syntax_tree(tree_a, "diff_a.js");
    let ctx = LoweringContext::new("trace-diff", "decision-diff", "policy-diff");
    let out_a = lower_ir0_to_ir3(&ir0_a, &ctx).expect("pipeline a");

    let tree_b = parser.parse("999;", ParseGoal::Script).expect("parse b");
    let ir0_b = Ir0Module::from_syntax_tree(tree_b, "diff_b.js");
    let out_b = lower_ir0_to_ir3(&ir0_b, &ctx).expect("pipeline b");

    assert_ne!(out_a.ir1.content_hash(), out_b.ir1.content_hash());
}

#[test]
fn module_parse_goal_produces_different_ir_than_script() {
    let parser = CanonicalEs2020Parser;
    let ctx = LoweringContext::new("trace-goal", "decision-goal", "policy-goal");

    let script_tree = parser.parse("42;", ParseGoal::Script).expect("script");
    let ir0_script = Ir0Module::from_syntax_tree(script_tree, "goal_script.js");
    let script_out = lower_ir0_to_ir3(&ir0_script, &ctx).expect("script pipeline");

    let module_tree = parser
        .parse(r#"import x from "y"; 42;"#, ParseGoal::Module)
        .expect("module");
    let ir0_module = Ir0Module::from_syntax_tree(module_tree, "goal_module.mjs");
    let module_out = lower_ir0_to_ir3(&ir0_module, &ctx).expect("module pipeline");

    // Module parse has import handling, so IR should differ
    assert_ne!(script_out.ir1.content_hash(), module_out.ir1.content_hash());
}
