#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsCompilerOptions {
    pub strict: bool,
    pub target: String,
    pub module: String,
    pub jsx: String,
}

impl Default for TsCompilerOptions {
    fn default() -> Self {
        Self {
            strict: true,
            target: "es2020".to_string(),
            module: "esnext".to_string(),
            jsx: "react-jsx".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TsNormalizationConfig {
    pub compiler_options: TsCompilerOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMapEntry {
    pub normalized_line: usize,
    pub original_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityIntent {
    pub symbol: String,
    pub capability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationDecision {
    pub step: String,
    pub changed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsNormalizationWitness {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub source_hash: String,
    pub normalized_hash: String,
    pub compiler_options_hash: String,
    pub decisions: Vec<NormalizationDecision>,
    pub capability_intents: Vec<CapabilityIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsNormalizationOutput {
    pub normalized_source: String,
    pub capability_intents: Vec<CapabilityIntent>,
    pub source_map: Vec<SourceMapEntry>,
    pub witness: TsNormalizationWitness,
    pub events: Vec<NormalizationEvent>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TsNormalizationError {
    #[error("TS source is empty after normalization")]
    EmptySource,
    #[error("unsupported syntax: {feature}")]
    UnsupportedSyntax { feature: &'static str },
    #[error("unsupported compiler option: {option}={value}")]
    UnsupportedCompilerOption { option: &'static str, value: String },
}

pub fn normalize_typescript_to_es2020(
    source: &str,
    config: &TsNormalizationConfig,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<TsNormalizationOutput, TsNormalizationError> {
    let mut events = Vec::<NormalizationEvent>::new();
    let mut decisions = Vec::<NormalizationDecision>::new();

    let normalized_newlines = normalize_newlines(source);
    let mut current = normalized_newlines.trim().to_string();
    if current.is_empty() {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "normalize",
            "FE-TSNORM-0001",
        ));
        return Err(TsNormalizationError::EmptySource);
    }

    let target = config.compiler_options.target.trim().to_ascii_lowercase();
    if target != "es2020" {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "target_validation",
            "FE-TSNORM-0004",
        ));
        return Err(TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: config.compiler_options.target.clone(),
        });
    }

    let module_kind = config.compiler_options.module.trim().to_ascii_lowercase();
    if module_kind != "esnext" && module_kind != "commonjs" {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "module_validation",
            "FE-TSNORM-0005",
        ));
        return Err(TsNormalizationError::UnsupportedCompilerOption {
            option: "module",
            value: config.compiler_options.module.clone(),
        });
    }

    let jsx_mode = config.compiler_options.jsx.trim().to_ascii_lowercase();
    if jsx_mode != "react-jsx" && jsx_mode != "react" && jsx_mode != "preserve" {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "jsx_validation",
            "FE-TSNORM-0006",
        ));
        return Err(TsNormalizationError::UnsupportedCompilerOption {
            option: "jsx",
            value: config.compiler_options.jsx.clone(),
        });
    }
    let jsx_preserve = jsx_mode == "preserve";

    let no_type_imports = elide_type_only_imports(&current);
    decisions.push(build_decision(
        "type_only_import_elision",
        no_type_imports != current,
        "Type-only imports were elided from runtime output.",
    ));
    current = no_type_imports;

    let namespace_lowered = match lower_simple_namespaces(&current) {
        Ok(lowered) => lowered,
        Err(error) => {
            events.push(failure_event(
                trace_id,
                decision_id,
                policy_id,
                "ts_normalization",
                "namespace_normalization",
                "FE-TSNORM-0002",
            ));
            return Err(error);
        }
    };
    decisions.push(build_decision(
        "namespace_lowering",
        namespace_lowered != current,
        "Simple namespace declarations lowered with deterministic merge semantics.",
    ));
    current = namespace_lowered;

    let decorator_lowered = match lower_simple_class_decorators(&current) {
        Ok(lowered) => lowered,
        Err(error) => {
            events.push(failure_event(
                trace_id,
                decision_id,
                policy_id,
                "ts_normalization",
                "decorator_normalization",
                "FE-TSNORM-0003",
            ));
            return Err(error);
        }
    };
    decisions.push(build_decision(
        "decorator_lowering",
        decorator_lowered != current,
        "Simple legacy class decorators lowered to deterministic wrapper application.",
    ));
    current = decorator_lowered;

    let definite_assignment_removed = current.replace("!:", ":");
    decisions.push(build_decision(
        "definite_assignment_normalization",
        definite_assignment_removed != current,
        "Definite assignment assertions normalized.",
    ));
    current = definite_assignment_removed;

    let const_assertion_removed = current.replace(" as const", "");
    decisions.push(build_decision(
        "const_assertion_normalization",
        const_assertion_removed != current,
        "Const assertions were stripped from runtime normalization output.",
    ));
    current = const_assertion_removed;

    let type_annotations_stripped = strip_type_annotations(&current);
    decisions.push(build_decision(
        "type_annotation_stripping",
        type_annotations_stripped != current,
        "Type annotations were removed while preserving runtime expressions.",
    ));
    current = type_annotations_stripped;

    let enum_lowered = lower_simple_enums(&current);
    decisions.push(build_decision(
        "enum_lowering",
        enum_lowered != current,
        "Simple enum declarations lowered to ES2020 object freeze forms.",
    ));
    current = enum_lowered;

    let parameter_property_lowered = lower_constructor_parameter_properties(&current);
    decisions.push(build_decision(
        "parameter_property_lowering",
        parameter_property_lowered != current,
        "Constructor parameter properties lowered into explicit assignments.",
    ));
    current = parameter_property_lowered;

    let abstract_class_lowered = lower_abstract_class_keywords(&current);
    decisions.push(build_decision(
        "abstract_class_lowering",
        abstract_class_lowered != current,
        "Abstract class declarations lowered to runtime-equivalent class declarations.",
    ));
    current = abstract_class_lowered;

    let jsx_lowered = if jsx_preserve {
        current.clone()
    } else {
        lower_simple_jsx(&current)
    };
    decisions.push(build_decision(
        "jsx_lowering",
        jsx_lowered != current,
        "Simple JSX forms lowered to createElement calls.",
    ));
    current = jsx_lowered;

    let normalized_source = normalize_spacing(current);
    if normalized_source.trim().is_empty() {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "post_normalization_validation",
            "FE-TSNORM-0001",
        ));
        return Err(TsNormalizationError::EmptySource);
    }

    let capability_intents = extract_capability_intents(&normalized_source);
    decisions.push(build_decision(
        "capability_intent_extraction",
        !capability_intents.is_empty(),
        "Capability intents were extracted from typed hostcall forms.",
    ));

    let source_map = build_identity_source_map(&normalized_newlines, &normalized_source);

    let witness = TsNormalizationWitness {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        source_hash: sha256_hex(&normalized_newlines),
        normalized_hash: sha256_hex(&normalized_source),
        compiler_options_hash: sha256_hex(
            &serde_json::to_string(&config.compiler_options)
                .expect("compiler options should serialize deterministically"),
        ),
        decisions,
        capability_intents: capability_intents.clone(),
    };

    events.push(success_event(
        trace_id,
        decision_id,
        policy_id,
        "ts_normalization",
        "normalize",
    ));

    Ok(TsNormalizationOutput {
        normalized_source,
        capability_intents,
        source_map,
        witness,
        events,
    })
}

fn normalize_newlines(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

fn normalize_spacing(source: String) -> String {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_decision(step: &str, changed: bool, detail: &str) -> NormalizationDecision {
    NormalizationDecision {
        step: step.to_string(),
        changed,
        detail: detail.to_string(),
    }
}

fn success_event(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    component: &str,
    event: &str,
) -> NormalizationEvent {
    NormalizationEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: component.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn failure_event(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    component: &str,
    event: &str,
    error_code: &str,
) -> NormalizationEvent {
    NormalizationEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: component.to_string(),
        event: event.to_string(),
        outcome: "fail".to_string(),
        error_code: Some(error_code.to_string()),
    }
}

fn elide_type_only_imports(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("import type "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn lower_simple_namespaces(source: &str) -> Result<String, TsNormalizationError> {
    let mut namespace_order = Vec::<String>::new();
    let mut namespace_assignments = BTreeMap::<String, Vec<String>>::new();
    let mut with_placeholders = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("namespace ") {
            with_placeholders.push(line.to_string());
            continue;
        }

        let Some(rest) = trimmed.strip_prefix("namespace ") else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        };
        let Some(brace_start) = rest.find('{') else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        };
        let Some(brace_end) = rest.rfind('}') else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        };
        if brace_end < brace_start {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        }

        let namespace_name = rest[..brace_start].trim();
        if namespace_name.is_empty() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        }

        let body = rest[brace_start + 1..brace_end].trim();
        let parsed_assignments = parse_namespace_exports(body)?;
        if !namespace_assignments.contains_key(namespace_name) {
            namespace_order.push(namespace_name.to_string());
            namespace_assignments.insert(namespace_name.to_string(), Vec::new());
            with_placeholders.push(format!("/*__namespace:{namespace_name}__*/"));
        }

        if let Some(assignments) = namespace_assignments.get_mut(namespace_name) {
            assignments.extend(parsed_assignments);
        }
    }

    let mut rendered = Vec::<String>::new();
    for line in with_placeholders {
        if let Some(namespace_name) = line
            .strip_prefix("/*__namespace:")
            .and_then(|value| value.strip_suffix("__*/"))
        {
            if let Some(assignments) = namespace_assignments.get(namespace_name) {
                rendered.extend(render_namespace_block(namespace_name, assignments));
            }
            continue;
        }
        rendered.push(line);
    }

    if namespace_order.is_empty() {
        Ok(source.to_string())
    } else {
        Ok(rendered.join("\n"))
    }
}

fn parse_namespace_exports(body: &str) -> Result<Vec<String>, TsNormalizationError> {
    let mut assignments = Vec::<String>::new();

    for statement in body.split(';') {
        let normalized = statement.trim();
        if normalized.is_empty() {
            continue;
        }

        let Some(exported) = normalized.strip_prefix("export ") else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };

        let declaration = if let Some(value) = exported.strip_prefix("const ") {
            value
        } else if let Some(value) = exported.strip_prefix("let ") {
            value
        } else if let Some(value) = exported.strip_prefix("var ") {
            value
        } else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };

        let Some((lhs, rhs)) = declaration.split_once('=') else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };
        let symbol = lhs.split(':').next().unwrap_or(lhs).trim();
        if symbol.is_empty() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        }

        assignments.push(format!("  ns.{symbol} = {};", rhs.trim()));
    }

    Ok(assignments)
}

fn render_namespace_block(namespace_name: &str, assignments: &[String]) -> Vec<String> {
    let mut lines = Vec::<String>::new();
    lines.push(format!("const {namespace_name} = (() => {{"));
    lines.push("  const ns = {};".to_string());
    lines.extend(assignments.iter().cloned());
    lines.push("  return ns;".to_string());
    lines.push("})();".to_string());
    lines
}

fn lower_simple_class_decorators(source: &str) -> Result<String, TsNormalizationError> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut lowered = Vec::<String>::new();
    let mut index = 0usize;
    let mut lowered_any = false;

    while index < lines.len() {
        let trimmed = lines[index].trim();
        if !trimmed.starts_with('@') {
            lowered.push(lines[index].to_string());
            index += 1;
            continue;
        }

        let decorator_expr = trimmed.trim_start_matches('@').trim().trim_end_matches(';');
        if decorator_expr.is_empty() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator declaration form",
            });
        }

        index += 1;
        while index < lines.len() && lines[index].trim().is_empty() {
            index += 1;
        }

        if index >= lines.len() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            });
        }

        let class_line = lines[index].trim();
        if !class_line.starts_with("class ") {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            });
        }
        let Some(class_name) = parse_class_declaration_name(class_line) else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            });
        };

        let mut class_expr = class_line.to_string();
        if !class_expr.ends_with(';') {
            class_expr.push(';');
        }

        lowered.push(format!("let {class_name} = {class_expr}"));
        lowered.push(format!(
            "{class_name} = __applyClassDecorator({decorator_expr}, {class_name});"
        ));

        lowered_any = true;
        index += 1;
    }

    if !lowered_any || source.contains("function __applyClassDecorator(") {
        return Ok(lowered.join("\n"));
    }

    let mut with_helper = vec![
        "function __applyClassDecorator(decorator, target) {".to_string(),
        "  const next = decorator(target);".to_string(),
        "  return next ?? target;".to_string(),
        "}".to_string(),
    ];
    with_helper.extend(lowered);
    Ok(with_helper.join("\n"))
}

fn parse_class_declaration_name(class_declaration: &str) -> Option<String> {
    let remainder = class_declaration.strip_prefix("class ")?;
    let mut identifier = String::new();
    for ch in remainder.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            identifier.push(ch);
            continue;
        }
        break;
    }

    if identifier.is_empty() {
        None
    } else {
        Some(identifier)
    }
}

fn lower_simple_enums(source: &str) -> String {
    let mut out = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("enum ") {
            out.push(line.to_string());
            continue;
        }

        let Some(rest) = trimmed.strip_prefix("enum ") else {
            out.push(line.to_string());
            continue;
        };
        let Some(brace_start) = rest.find('{') else {
            out.push(line.to_string());
            continue;
        };
        let Some(brace_end) = rest.rfind('}') else {
            out.push(line.to_string());
            continue;
        };

        let enum_name = rest[..brace_start].trim();
        let body = rest[brace_start + 1..brace_end].trim();
        if enum_name.is_empty() {
            out.push(line.to_string());
            continue;
        }

        let mut entries = Vec::<String>::new();
        let mut numeric_counter = 0i64;

        for raw_member in body.split(',') {
            let member = raw_member.trim();
            if member.is_empty() {
                continue;
            }

            if let Some((name, value)) = member.split_once('=') {
                let key = name.trim();
                let value_trimmed = value.trim();
                if key.is_empty() {
                    continue;
                }
                entries.push(format!("{key}: {value_trimmed}"));
                if let Ok(parsed) = value_trimmed.parse::<i64>() {
                    numeric_counter = parsed.saturating_add(1);
                }
            } else {
                let key = member;
                entries.push(format!("{key}: {numeric_counter}"));
                numeric_counter = numeric_counter.saturating_add(1);
            }
        }

        if entries.is_empty() {
            out.push(line.to_string());
            continue;
        }

        out.push(format!(
            "const {enum_name} = Object.freeze({{{}}});",
            entries.join(", ")
        ));
    }

    out.join("\n")
}

fn lower_constructor_parameter_properties(source: &str) -> String {
    let mut out = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("constructor(") {
            out.push(line.to_string());
            continue;
        }

        let Some(args_start) = trimmed.find('(') else {
            out.push(line.to_string());
            continue;
        };
        let Some(args_end) = trimmed.find(')') else {
            out.push(line.to_string());
            continue;
        };

        let args_text = &trimmed[args_start + 1..args_end];
        let mut normalized_args = Vec::<String>::new();
        let mut injected_assignments = Vec::<String>::new();

        for argument in args_text.split(',') {
            let raw_arg = argument.trim();
            if raw_arg.is_empty() {
                continue;
            }

            let (visibility, remaining) = if let Some(rest) = raw_arg.strip_prefix("private ") {
                (Some("private"), rest)
            } else if let Some(rest) = raw_arg.strip_prefix("public ") {
                (Some("public"), rest)
            } else if let Some(rest) = raw_arg.strip_prefix("protected ") {
                (Some("protected"), rest)
            } else {
                (None, raw_arg)
            };

            let no_readonly = remaining
                .strip_prefix("readonly ")
                .unwrap_or(remaining)
                .trim();

            let param_name = no_readonly.split(':').next().unwrap_or(no_readonly).trim();

            normalized_args.push(no_readonly.to_string());

            if visibility.is_some() && !param_name.is_empty() {
                injected_assignments.push(format!("this.{param_name} = {param_name};"));
            }
        }

        let mut rebuilt = String::new();
        rebuilt.push_str("constructor(");
        rebuilt.push_str(&normalized_args.join(", "));
        rebuilt.push(')');

        if let Some(brace_open) = trimmed.find('{') {
            let body_start = brace_open + 1;
            let body_end = trimmed.rfind('}').unwrap_or(trimmed.len());
            let existing_body = trimmed[body_start..body_end].trim();
            rebuilt.push_str(" {");
            if !injected_assignments.is_empty() {
                rebuilt.push(' ');
                rebuilt.push_str(&injected_assignments.join(" "));
            }
            if !existing_body.is_empty() {
                rebuilt.push(' ');
                rebuilt.push_str(existing_body);
            }
            rebuilt.push_str(" }");
        } else {
            rebuilt.push(';');
        }

        out.push(rebuilt);
    }

    out.join("\n")
}

fn lower_abstract_class_keywords(source: &str) -> String {
    source.replace("abstract class", "class")
}

fn strip_type_annotations(source: &str) -> String {
    let mut output = String::new();
    let mut chars = source.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            output.push(ch);
            continue;
        }
        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            output.push(ch);
            continue;
        }

        if in_single_quote || in_double_quote {
            output.push(ch);
            continue;
        }

        if ch == ':' {
            while let Some(next) = chars.peek() {
                if matches!(next, ',' | ')' | '=' | ';' | '{' | '}' | '\n') {
                    break;
                }
                let _ = chars.next();
            }
            continue;
        }

        output.push(ch);
    }

    output
}

fn lower_simple_jsx(source: &str) -> String {
    let mut out = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('<') && trimmed.ends_with("/>") {
            let tag = trimmed
                .trim_start_matches('<')
                .trim_end_matches("/>")
                .trim();
            if !tag.is_empty() {
                out.push(format!("createElement(\"{tag}\", null);"));
                continue;
            }
        }

        if trimmed.starts_with('<') && trimmed.contains('>') && trimmed.contains("</") {
            let Some(open_end) = trimmed.find('>') else {
                out.push(line.to_string());
                continue;
            };
            let open_tag = trimmed[1..open_end].trim();
            let close_tag = format!("</{open_tag}>");
            if trimmed.ends_with(&close_tag) {
                let inner = trimmed[open_end + 1..trimmed.len() - close_tag.len()].trim();
                out.push(format!("createElement(\"{open_tag}\", null, {inner});"));
                continue;
            }
        }

        out.push(line.to_string());
    }

    out.join("\n")
}

fn extract_capability_intents(source: &str) -> Vec<CapabilityIntent> {
    let mut intents = Vec::<CapabilityIntent>::new();

    for token in source.split_whitespace() {
        if let Some(rest) = token.strip_prefix("hostcall<\"")
            && let Some(capability_end) = rest.find("\">")
        {
            let capability = rest[..capability_end].trim().to_string();
            intents.push(CapabilityIntent {
                symbol: "hostcall".to_string(),
                capability,
            });
        }
    }

    intents.sort_by(|left, right| {
        left.symbol
            .cmp(&right.symbol)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    intents.dedup();
    intents
}

fn build_identity_source_map(original: &str, normalized: &str) -> Vec<SourceMapEntry> {
    let original_count = original.lines().count().max(1);
    normalized
        .lines()
        .enumerate()
        .map(|(idx, _)| SourceMapEntry {
            normalized_line: idx + 1,
            original_line: (idx + 1).min(original_count),
        })
        .collect()
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::{TsNormalizationConfig, TsNormalizationError, normalize_typescript_to_es2020};

    #[test]
    fn strips_type_only_imports() {
        let source = r#"
import type { Foo } from "./types";
import { bar } from "./bar";
const value: number = 1;
"#;

        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert!(!output.normalized_source.contains("import type"));
        assert!(output.normalized_source.contains("import { bar }"));
    }

    #[test]
    fn lowers_simple_enum() {
        let source = "enum Status { Ready, Busy = 3 }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert!(
            output
                .normalized_source
                .contains("const Status = Object.freeze(")
        );
        assert!(output.normalized_source.contains("Ready: 0"));
        assert!(output.normalized_source.contains("Busy"));
    }

    #[test]
    fn lowers_parameter_properties() {
        let source = "constructor(private service: Service, public count: number) { doWork(); }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert!(output.normalized_source.contains("this.service = service;"));
        assert!(output.normalized_source.contains("this.count = count;"));
    }

    #[test]
    fn lowers_simple_jsx_to_create_element() {
        let source = "<Widget />";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert_eq!(output.normalized_source, "createElement(\"Widget\", null);");
    }

    #[test]
    fn captures_capability_intents() {
        let source = r#"const read = hostcall<"fs.read">();"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert_eq!(output.capability_intents.len(), 1);
        assert_eq!(output.capability_intents[0].capability, "fs.read");
    }

    #[test]
    fn lowers_simple_namespace_declaration() {
        let source = "namespace Demo { export const value = 1; }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("namespace normalization should pass");

        assert!(output.normalized_source.contains("const Demo = (() => {"));
        assert!(output.normalized_source.contains("ns.value = 1;"));
    }

    #[test]
    fn rejects_unsupported_namespace_export_forms() {
        let source = "namespace Demo { export function run() { return 1; } }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect_err("unsupported namespace export should fail");

        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            }
        );
    }

    #[test]
    fn returns_error_for_empty_source() {
        let error = normalize_typescript_to_es2020(
            "  \n  ",
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect_err("empty source should fail");

        assert_eq!(error, TsNormalizationError::EmptySource);
    }

    #[test]
    fn allows_at_symbol_inside_string_literals() {
        let source = r#"const email = "person@example.com";"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("string literal should not be treated as decorator syntax");

        assert!(output.normalized_source.contains("person@example.com"));
    }
}
