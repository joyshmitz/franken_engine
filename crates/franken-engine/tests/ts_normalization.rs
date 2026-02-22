#[path = "../src/ts_normalization.rs"]
mod ts_normalization;

use ts_normalization::{
    TsCompilerOptions, TsNormalizationConfig, TsNormalizationError, normalize_typescript_to_es2020,
};

#[test]
fn normalization_is_deterministic_for_same_input_and_options() {
    let source = r#"
import type { Foo } from "./types";
const point: { x: number; y: number } = { x: 1, y: 2 };
const view = <Widget />;
"#;

    let config = TsNormalizationConfig::default();
    let first =
        normalize_typescript_to_es2020(source, &config, "trace-1", "decision-1", "policy-1")
            .expect("first normalization should pass");
    let second =
        normalize_typescript_to_es2020(source, &config, "trace-1", "decision-1", "policy-1")
            .expect("second normalization should pass");

    assert_eq!(first.normalized_source, second.normalized_source);
    assert_eq!(first.witness.source_hash, second.witness.source_hash);
    assert_eq!(
        first.witness.normalized_hash,
        second.witness.normalized_hash
    );
    assert_eq!(
        first.witness.compiler_options_hash,
        second.witness.compiler_options_hash
    );
    assert_eq!(first.capability_intents, second.capability_intents);
}

#[test]
fn type_annotations_and_const_assertions_are_removed() {
    let source = r#"
const answer: number = 42 as const;
let maybe!: string;
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-2",
        "decision-2",
        "policy-2",
    )
    .expect("normalization should pass");

    assert!(!output.normalized_source.contains(": number"));
    assert!(!output.normalized_source.contains("as const"));
    assert!(!output.normalized_source.contains("!:"));
}

#[test]
fn namespace_merging_is_lowered_deterministically() {
    let source = r#"
namespace Demo { export const value = 1; }
namespace Demo { export const other = 2; }
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-3",
        "decision-3",
        "policy-3",
    )
    .expect("simple namespace merge should normalize");

    assert!(output.normalized_source.contains("const Demo = (() => {"));
    assert!(output.normalized_source.contains("ns.value = 1;"));
    assert!(output.normalized_source.contains("ns.other = 2;"));
}

#[test]
fn witness_and_events_carry_governance_fields() {
    let source = r#"
enum Mode { Fast, Safe }
const read = hostcall<"fs.read">();
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-governance",
        "decision-governance",
        "policy-governance",
    )
    .expect("normalization should pass");

    assert_eq!(output.witness.trace_id, "trace-governance");
    assert_eq!(output.witness.decision_id, "decision-governance");
    assert_eq!(output.witness.policy_id, "policy-governance");
    assert!(!output.witness.source_hash.is_empty());
    assert!(!output.witness.normalized_hash.is_empty());
    assert!(!output.witness.compiler_options_hash.is_empty());
    assert!(output.events.iter().all(|event| !event.trace_id.is_empty()
        && !event.decision_id.is_empty()
        && !event.policy_id.is_empty()
        && !event.component.is_empty()
        && !event.event.is_empty()
        && !event.outcome.is_empty()));
}

#[test]
fn rejects_unsupported_compiler_target() {
    let config = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            strict: true,
            target: "es2017".to_string(),
            module: "esnext".to_string(),
            jsx: "react-jsx".to_string(),
        },
    };

    let error = normalize_typescript_to_es2020(
        "const v: number = 1;",
        &config,
        "trace-target",
        "decision-target",
        "policy-target",
    )
    .expect_err("unsupported target should fail");

    assert_eq!(
        error,
        TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: "es2017".to_string(),
        }
    );
}

#[test]
fn jsx_is_preserved_when_jsx_mode_is_preserve() {
    let config = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            strict: true,
            target: "es2020".to_string(),
            module: "esnext".to_string(),
            jsx: "preserve".to_string(),
        },
    };

    let output = normalize_typescript_to_es2020(
        "const view = <Widget />;",
        &config,
        "trace-jsx-preserve",
        "decision-jsx-preserve",
        "policy-jsx-preserve",
    )
    .expect("preserve mode should not fail");

    assert!(output.normalized_source.contains("<Widget />"));
}

#[test]
fn abstract_class_keyword_is_lowered() {
    let output = normalize_typescript_to_es2020(
        "abstract class Base { abstract run(): void; }",
        &TsNormalizationConfig::default(),
        "trace-abstract",
        "decision-abstract",
        "policy-abstract",
    )
    .expect("normalization should pass");

    assert!(output.normalized_source.contains("class Base"));
    assert!(!output.normalized_source.contains("abstract class"));
}

#[test]
fn class_decorator_is_lowered_to_wrapper_application() {
    let source = r#"
@sealed
class Widget {}
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-decorator",
        "decision-decorator",
        "policy-decorator",
    )
    .expect("class decorator lowering should pass");

    assert!(
        output
            .normalized_source
            .contains("function __applyClassDecorator(decorator, target)")
    );
    assert!(
        output
            .normalized_source
            .contains("let Widget = class Widget {};")
    );
    assert!(
        output
            .normalized_source
            .contains("Widget = __applyClassDecorator(sealed, Widget);")
    );
}

#[test]
fn unsupported_decorator_target_fails() {
    let source = r#"
@trace
const value = 1;
"#;

    let error = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-bad-decorator",
        "decision-bad-decorator",
        "policy-bad-decorator",
    )
    .expect_err("non-class decorator target should fail");

    assert_eq!(
        error,
        TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported decorator target",
        }
    );
}
