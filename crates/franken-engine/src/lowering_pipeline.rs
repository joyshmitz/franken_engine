#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ast::{ExportKind, Expression, ParseGoal, Statement};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::Label;
use crate::ir_contract::{
    BindingId, BindingKind, CapabilityTag, EffectBoundary, FlowAnnotation, Ir0Module, Ir1Literal,
    Ir1Module, Ir1Op, Ir2Module, Ir2Op, Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrError,
    IrLevel, Reg, RegRange, ResolvedBinding, ScopeId, ScopeKind, ScopeNode, verify_ir1_source,
    verify_ir3_specialization,
};

const COMPONENT: &str = "lowering_pipeline";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl LoweringContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassWitness {
    pub pass_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub rollback_token: String,
    pub invariant_checks: Vec<InvariantCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsomorphismLedgerEntry {
    pub pass_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub input_op_count: u64,
    pub output_op_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringPassResult<T> {
    pub module: T,
    pub witness: PassWitness,
    pub ledger_entry: IsomorphismLedgerEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringPipelineOutput {
    pub ir1: Ir1Module,
    pub ir2: Ir2Module,
    pub ir3: Ir3Module,
    pub witnesses: Vec<PassWitness>,
    pub isomorphism_ledger: Vec<IsomorphismLedgerEntry>,
    pub events: Vec<LoweringEvent>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoweringPipelineError {
    #[error("IR0 module has no statements")]
    EmptyIr0Body,
    #[error("IR contract validation failed ({code}) at {level}: {message}")]
    IrContractValidation {
        code: String,
        level: IrLevel,
        message: String,
    },
    #[error("deterministic invariant failed: {detail}")]
    InvariantViolation { detail: &'static str },
}

pub fn lower_ir0_to_ir3(
    ir0: &Ir0Module,
    context: &LoweringContext,
) -> Result<LoweringPipelineOutput, LoweringPipelineError> {
    let mut events = Vec::<LoweringEvent>::new();

    let ir1_result = match lower_ir0_to_ir1(ir0) {
        Ok(result) => {
            events.push(success_event(context, "ir0_to_ir1_lowered"));
            result
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir0_to_ir1_lowered",
                "FE-LOWER-0001",
            ));
            return Err(error);
        }
    };

    let ir2_result = match lower_ir1_to_ir2(&ir1_result.module) {
        Ok(result) => {
            events.push(success_event(context, "ir1_to_ir2_lowered"));
            result
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir1_to_ir2_lowered",
                "FE-LOWER-0002",
            ));
            return Err(error);
        }
    };

    let ir3_result = match lower_ir2_to_ir3(&ir2_result.module) {
        Ok(result) => {
            events.push(success_event(context, "ir2_to_ir3_lowered"));
            result
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir2_to_ir3_lowered",
                "FE-LOWER-0003",
            ));
            return Err(error);
        }
    };

    Ok(LoweringPipelineOutput {
        ir1: ir1_result.module,
        ir2: ir2_result.module,
        ir3: ir3_result.module,
        witnesses: vec![ir1_result.witness, ir2_result.witness, ir3_result.witness],
        isomorphism_ledger: vec![
            ir1_result.ledger_entry,
            ir2_result.ledger_entry,
            ir3_result.ledger_entry,
        ],
        events,
    })
}

pub fn lower_ir0_to_ir1(
    ir0: &Ir0Module,
) -> Result<LoweringPassResult<Ir1Module>, LoweringPipelineError> {
    if ir0.tree.body.is_empty() {
        return Err(LoweringPipelineError::EmptyIr0Body);
    }

    let ir0_hash = ir0.content_hash();
    let mut ir1 = Ir1Module::new(ir0_hash.clone(), ir0.header.source_label.clone());
    let mut binding_index = 0u32;
    let root_scope_id = ScopeId { depth: 0, index: 0 };
    let root_scope_kind = match ir0.tree.goal {
        ParseGoal::Script => ScopeKind::Global,
        ParseGoal::Module => ScopeKind::Module,
    };
    let mut bindings = Vec::<ResolvedBinding>::new();
    let mut binding_lookup = BTreeMap::<String, BindingId>::new();
    let mut synthetic_export_index = 0u32;

    for statement in &ir0.tree.body {
        match statement {
            Statement::Import(import) => {
                ir1.ops.push(Ir1Op::ImportModule {
                    specifier: import.source.clone(),
                });
                if let Some(binding_name) = &import.binding {
                    let binding_id = alloc_binding(
                        &mut bindings,
                        &mut binding_lookup,
                        &mut binding_index,
                        root_scope_id,
                        binding_name,
                        BindingKind::Import,
                    );
                    ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                }
            }
            Statement::Export(export) => match &export.kind {
                ExportKind::Default(expression) => {
                    lower_expression_to_ir1(
                        expression,
                        &mut ir1.ops,
                        &mut bindings,
                        &mut binding_lookup,
                        &mut binding_index,
                        root_scope_id,
                    );
                    let binding_name = format!("__default_export_{synthetic_export_index}");
                    synthetic_export_index = synthetic_export_index.saturating_add(1);
                    let binding_id = alloc_binding(
                        &mut bindings,
                        &mut binding_lookup,
                        &mut binding_index,
                        root_scope_id,
                        &binding_name,
                        BindingKind::Const,
                    );
                    ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                    ir1.ops.push(Ir1Op::ExportBinding {
                        name: "default".to_string(),
                        binding_id,
                    });
                }
                ExportKind::NamedClause(clause) => {
                    let binding_id = match binding_lookup.get(clause) {
                        Some(existing) => *existing,
                        None => {
                            let binding_name =
                                format!("__named_export_{synthetic_export_index}_{clause}");
                            synthetic_export_index = synthetic_export_index.saturating_add(1);
                            alloc_binding(
                                &mut bindings,
                                &mut binding_lookup,
                                &mut binding_index,
                                root_scope_id,
                                &binding_name,
                                BindingKind::Const,
                            )
                        }
                    };
                    ir1.ops.push(Ir1Op::ExportBinding {
                        name: clause.clone(),
                        binding_id,
                    });
                }
            },
            Statement::Expression(statement) => {
                lower_expression_to_ir1(
                    &statement.expression,
                    &mut ir1.ops,
                    &mut bindings,
                    &mut binding_lookup,
                    &mut binding_index,
                    root_scope_id,
                );
            }
        }
    }

    ir1.ops.push(Ir1Op::Return);
    ir1.scopes.push(ScopeNode {
        scope_id: root_scope_id,
        parent: None,
        kind: root_scope_kind,
        bindings,
    });

    verify_ir1_source(&ir1, &ir0_hash).map_err(lowering_error_from_ir_error)?;

    let binding_ids_are_unique = scope_binding_ids_are_unique(&ir1.scopes);
    let checks = vec![
        InvariantCheck {
            name: "source_hash_linkage".to_string(),
            passed: true,
            detail: "IR1 source_hash references IR0 hash".to_string(),
        },
        InvariantCheck {
            name: "scope_binding_ids_unique".to_string(),
            passed: binding_ids_are_unique,
            detail: "All scope binding IDs are unique".to_string(),
        },
    ];
    ensure_checks_pass(&checks, "duplicate binding IDs in IR1 scope graph")?;

    let ir1_hash = ir1.content_hash();
    Ok(LoweringPassResult {
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "ir0_to_ir1".to_string(),
            input_hash: hash_string(&ir0_hash),
            output_hash: hash_string(&ir1_hash),
            input_op_count: ir0.tree.body.len() as u64,
            output_op_count: ir1.ops.len() as u64,
        },
        witness: PassWitness {
            pass_id: "ir0_to_ir1".to_string(),
            input_hash: hash_string(&ir0_hash),
            output_hash: hash_string(&ir1_hash),
            rollback_token: hash_string(&ir0_hash),
            invariant_checks: checks,
        },
        module: ir1,
    })
}

pub fn lower_ir1_to_ir2(
    ir1: &Ir1Module,
) -> Result<LoweringPassResult<Ir2Module>, LoweringPipelineError> {
    let ir1_hash = ir1.content_hash();
    let mut ir2 = Ir2Module::new(ir1_hash.clone(), ir1.header.source_label.clone());
    ir2.scopes = ir1.scopes.clone();

    let mut required_capabilities = BTreeSet::<String>::new();
    for op in &ir1.ops {
        let (effect, required_capability, flow) = classify_ir1_op(op);
        if let Some(capability) = &required_capability {
            required_capabilities.insert(capability.0.clone());
        }
        ir2.ops.push(Ir2Op {
            inner: op.clone(),
            effect,
            required_capability,
            flow,
        });
    }
    ir2.required_capabilities = required_capabilities
        .into_iter()
        .map(CapabilityTag)
        .collect();

    let source_hash_matches = ir2.header.source_hash.as_ref() == Some(&ir1_hash);
    let hostcall_effects_have_capability = ir2
        .ops
        .iter()
        .filter(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
        .all(|op| op.required_capability.is_some());
    let checks = vec![
        InvariantCheck {
            name: "source_hash_linkage".to_string(),
            passed: source_hash_matches,
            detail: "IR2 source_hash references IR1 hash".to_string(),
        },
        InvariantCheck {
            name: "hostcall_capability_required".to_string(),
            passed: hostcall_effects_have_capability,
            detail: "Hostcall effects always carry capability tags".to_string(),
        },
    ];
    ensure_checks_pass(&checks, "IR2 invariants failed")?;

    let ir2_hash = ir2.content_hash();
    Ok(LoweringPassResult {
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "ir1_to_ir2".to_string(),
            input_hash: hash_string(&ir1_hash),
            output_hash: hash_string(&ir2_hash),
            input_op_count: ir1.ops.len() as u64,
            output_op_count: ir2.ops.len() as u64,
        },
        witness: PassWitness {
            pass_id: "ir1_to_ir2".to_string(),
            input_hash: hash_string(&ir1_hash),
            output_hash: hash_string(&ir2_hash),
            rollback_token: hash_string(&ir1_hash),
            invariant_checks: checks,
        },
        module: ir2,
    })
}

pub fn lower_ir2_to_ir3(
    ir2: &Ir2Module,
) -> Result<LoweringPassResult<Ir3Module>, LoweringPipelineError> {
    let ir2_hash = ir2.content_hash();
    let mut ir3 = Ir3Module::new(ir2_hash.clone(), ir2.header.source_label.clone());
    let mut register_cursor: Reg = 0;
    let mut binding_registers = BTreeMap::<BindingId, Reg>::new();
    let mut required_capabilities = BTreeSet::<String>::new();
    let mut last_value_register: Option<Reg> = None;

    for op in &ir2.ops {
        if matches!(op.effect, EffectBoundary::HostcallEffect) {
            let capability = op
                .required_capability
                .clone()
                .unwrap_or_else(|| CapabilityTag("hostcall.invoke".to_string()));
            required_capabilities.insert(capability.0.clone());
            let args_start = last_value_register.unwrap_or(0);
            let dst = alloc_register(&mut register_cursor);
            ir3.instructions.push(Ir3Instruction::HostCall {
                capability,
                args: RegRange {
                    start: args_start,
                    count: 1,
                },
                dst,
            });
            last_value_register = Some(dst);
            continue;
        }

        match &op.inner {
            Ir1Op::LoadLiteral { value } => {
                let dst = alloc_register(&mut register_cursor);
                lower_literal_to_ir3(value, dst, &mut ir3.instructions, &mut ir3.constant_pool);
                last_value_register = Some(dst);
            }
            Ir1Op::LoadBinding { binding_id } => {
                let source_reg = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::Move {
                    dst,
                    src: source_reg,
                });
                last_value_register = Some(dst);
            }
            Ir1Op::StoreBinding { binding_id } => {
                let dst = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                let src = last_value_register.unwrap_or(dst);
                ir3.instructions.push(Ir3Instruction::Move { dst, src });
                last_value_register = Some(dst);
            }
            Ir1Op::Call { arg_count } => {
                let callee = last_value_register.unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::Call {
                    callee,
                    args: RegRange {
                        start: 0,
                        count: *arg_count,
                    },
                    dst,
                });
                last_value_register = Some(dst);
            }
            Ir1Op::ImportModule { specifier } => {
                let string_reg = alloc_register(&mut register_cursor);
                let pool_index = push_constant(&mut ir3.constant_pool, specifier);
                ir3.instructions.push(Ir3Instruction::LoadStr {
                    dst: string_reg,
                    pool_index,
                });
                last_value_register = Some(string_reg);
            }
            Ir1Op::ExportBinding { .. } => {
                let register =
                    last_value_register.unwrap_or_else(|| alloc_register(&mut register_cursor));
                ir3.instructions.push(Ir3Instruction::Move {
                    dst: register,
                    src: register,
                });
            }
            Ir1Op::Await => {
                let current = last_value_register.unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions
                    .push(Ir3Instruction::Move { dst, src: current });
                last_value_register = Some(dst);
            }
            Ir1Op::Return => {
                let value = last_value_register.unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Return { value });
            }
            Ir1Op::Nop => {
                let register =
                    last_value_register.unwrap_or_else(|| alloc_register(&mut register_cursor));
                ir3.instructions.push(Ir3Instruction::Move {
                    dst: register,
                    src: register,
                });
            }
        }
    }

    if !matches!(ir3.instructions.last(), Some(Ir3Instruction::Halt)) {
        ir3.instructions.push(Ir3Instruction::Halt);
    }
    ir3.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: register_cursor.max(1),
        name: Some("main".to_string()),
    });
    ir3.required_capabilities = required_capabilities
        .into_iter()
        .map(CapabilityTag)
        .collect();

    verify_ir3_specialization(&ir3).map_err(lowering_error_from_ir_error)?;

    let source_hash_matches = ir3.header.source_hash.as_ref() == Some(&ir2_hash);
    let has_main_function = !ir3.function_table.is_empty();
    let has_terminal_halt = matches!(ir3.instructions.last(), Some(Ir3Instruction::Halt));
    let checks = vec![
        InvariantCheck {
            name: "source_hash_linkage".to_string(),
            passed: source_hash_matches,
            detail: "IR3 source_hash references IR2 hash".to_string(),
        },
        InvariantCheck {
            name: "function_table_present".to_string(),
            passed: has_main_function,
            detail: "IR3 function table contains a deterministic main entry".to_string(),
        },
        InvariantCheck {
            name: "terminal_halt_instruction".to_string(),
            passed: has_terminal_halt,
            detail: "IR3 instruction stream ends with HALT".to_string(),
        },
    ];
    ensure_checks_pass(&checks, "IR3 invariants failed")?;

    let ir3_hash = ir3.content_hash();
    Ok(LoweringPassResult {
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "ir2_to_ir3".to_string(),
            input_hash: hash_string(&ir2_hash),
            output_hash: hash_string(&ir3_hash),
            input_op_count: ir2.ops.len() as u64,
            output_op_count: ir3.instructions.len() as u64,
        },
        witness: PassWitness {
            pass_id: "ir2_to_ir3".to_string(),
            input_hash: hash_string(&ir2_hash),
            output_hash: hash_string(&ir3_hash),
            rollback_token: hash_string(&ir2_hash),
            invariant_checks: checks,
        },
        module: ir3,
    })
}

fn alloc_binding(
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope: ScopeId,
    name: &str,
    kind: BindingKind,
) -> BindingId {
    if let Some(existing) = binding_lookup.get(name) {
        return *existing;
    }

    let binding_id = *binding_index;
    *binding_index = binding_index.saturating_add(1);
    bindings.push(ResolvedBinding {
        name: name.to_string(),
        binding_id,
        scope,
        kind,
    });
    binding_lookup.insert(name.to_string(), binding_id);
    binding_id
}

fn lower_expression_to_ir1(
    expression: &Expression,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    root_scope_id: ScopeId,
) {
    match expression {
        Expression::Identifier(name) => {
            let binding_id = alloc_binding(
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                name,
                BindingKind::Let,
            );
            ops.push(Ir1Op::LoadBinding { binding_id });
        }
        Expression::StringLiteral(value) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(value.clone()),
            });
        }
        Expression::NumericLiteral(value) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(*value),
            });
        }
        Expression::Await(inner) => {
            lower_expression_to_ir1(
                inner,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
            );
            ops.push(Ir1Op::Await);
        }
        Expression::Raw(raw) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(raw.clone()),
            });
            if raw.contains('(') {
                ops.push(Ir1Op::Call { arg_count: 0 });
            }
        }
    }
}

fn classify_ir1_op(
    op: &Ir1Op,
) -> (
    EffectBoundary,
    Option<CapabilityTag>,
    Option<FlowAnnotation>,
) {
    match op {
        Ir1Op::ImportModule { .. } => (
            EffectBoundary::ReadEffect,
            Some(CapabilityTag("module.import".to_string())),
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::Call { .. } => (
            EffectBoundary::HostcallEffect,
            Some(CapabilityTag("hostcall.invoke".to_string())),
            Some(FlowAnnotation {
                data_label: Label::Confidential,
                sink_clearance: Label::Confidential,
                declassification_required: false,
            }),
        ),
        Ir1Op::Await => (
            EffectBoundary::ReadEffect,
            None,
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(raw),
        } => {
            if let Some(capability) = extract_hostcall_capability(raw) {
                return (
                    EffectBoundary::HostcallEffect,
                    Some(CapabilityTag(capability)),
                    Some(FlowAnnotation {
                        data_label: Label::Confidential,
                        sink_clearance: Label::Confidential,
                        declassification_required: false,
                    }),
                );
            }
            (EffectBoundary::Pure, None, None)
        }
        _ => (EffectBoundary::Pure, None, None),
    }
}

fn extract_hostcall_capability(raw: &str) -> Option<String> {
    let marker = "hostcall<\"";
    let start = raw.find(marker)?;
    let remainder = &raw[start + marker.len()..];
    let end = remainder.find("\">")?;
    let capability = remainder[..end].trim();
    if capability.is_empty() {
        None
    } else {
        Some(capability.to_string())
    }
}

fn lower_literal_to_ir3(
    value: &Ir1Literal,
    dst: Reg,
    instructions: &mut Vec<Ir3Instruction>,
    constant_pool: &mut Vec<String>,
) {
    match value {
        Ir1Literal::String(text) => {
            let pool_index = push_constant(constant_pool, text);
            instructions.push(Ir3Instruction::LoadStr { dst, pool_index });
        }
        Ir1Literal::Integer(value) => {
            instructions.push(Ir3Instruction::LoadInt { dst, value: *value })
        }
        Ir1Literal::Boolean(value) => {
            instructions.push(Ir3Instruction::LoadBool { dst, value: *value })
        }
        Ir1Literal::Null => instructions.push(Ir3Instruction::LoadNull { dst }),
        Ir1Literal::Undefined => instructions.push(Ir3Instruction::LoadUndefined { dst }),
    }
}

fn push_constant(pool: &mut Vec<String>, value: &str) -> u32 {
    if let Some(index) = pool.iter().position(|entry| entry == value) {
        return index as u32;
    }

    pool.push(value.to_string());
    (pool.len() - 1) as u32
}

fn alloc_register(cursor: &mut Reg) -> Reg {
    let register = *cursor;
    *cursor = cursor.saturating_add(1);
    register
}

fn scope_binding_ids_are_unique(scopes: &[ScopeNode]) -> bool {
    let mut seen = BTreeSet::<BindingId>::new();
    for scope in scopes {
        for binding in &scope.bindings {
            if !seen.insert(binding.binding_id) {
                return false;
            }
        }
    }
    true
}

fn hash_string(hash: &ContentHash) -> String {
    format!("sha256:{}", hex::encode(hash.as_bytes()))
}

fn lowering_error_from_ir_error(error: IrError) -> LoweringPipelineError {
    LoweringPipelineError::IrContractValidation {
        code: error.code.as_str().to_string(),
        level: error.level,
        message: error.message,
    }
}

fn ensure_checks_pass(
    checks: &[InvariantCheck],
    failure_detail: &'static str,
) -> Result<(), LoweringPipelineError> {
    if checks.iter().any(|check| !check.passed) {
        return Err(LoweringPipelineError::InvariantViolation {
            detail: failure_detail,
        });
    }
    Ok(())
}

fn success_event(context: &LoweringContext, event: &str) -> LoweringEvent {
    LoweringEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn failure_event(context: &LoweringContext, event: &str, error_code: &str) -> LoweringEvent {
    LoweringEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "fail".to_string(),
        error_code: Some(error_code.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{
        Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
    };

    fn span() -> SourceSpan {
        SourceSpan::new(0, 1, 1, 1, 1, 2)
    }

    fn script_ir0() -> Ir0Module {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(42),
                span: span(),
            })],
            span: span(),
        };
        Ir0Module::from_syntax_tree(tree, "fixture.js")
    }

    #[test]
    fn lower_ir0_to_ir1_emits_witness_and_scope() {
        let ir0 = script_ir0();
        let result = lower_ir0_to_ir1(&ir0).expect("IR0->IR1 should succeed");

        assert_eq!(result.witness.pass_id, "ir0_to_ir1");
        assert_eq!(result.module.header.level, IrLevel::Ir1);
        assert_eq!(result.module.scopes.len(), 1);
        assert!(!result.module.ops.is_empty());
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .all(|check| check.passed)
        );
    }

    #[test]
    fn lower_ir1_to_ir2_collects_capabilities_deterministically() {
        let ir0 = script_ir0();
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("IR0->IR1 should succeed")
            .module;
        let result = lower_ir1_to_ir2(&ir1).expect("IR1->IR2 should succeed");

        assert_eq!(result.witness.pass_id, "ir1_to_ir2");
        assert_eq!(result.module.header.level, IrLevel::Ir2);
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .all(|check| check.passed)
        );
    }

    #[test]
    fn lower_ir2_to_ir3_produces_exec_instructions() {
        let ir0 = script_ir0();
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("IR0->IR1 should succeed")
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let result = lower_ir2_to_ir3(&ir2).expect("IR2->IR3 should succeed");

        assert_eq!(result.witness.pass_id, "ir2_to_ir3");
        assert_eq!(result.module.header.level, IrLevel::Ir3);
        assert!(!result.module.instructions.is_empty());
        assert!(matches!(
            result.module.instructions.last(),
            Some(Ir3Instruction::Halt)
        ));
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .all(|check| check.passed)
        );
    }

    #[test]
    fn pipeline_emits_structured_events_with_governance_fields() {
        let ir0 = script_ir0();
        let context = LoweringContext::new("trace-a", "decision-a", "policy-a");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

        assert_eq!(output.events.len(), 3);
        assert!(output.events.iter().all(|event| {
            !event.trace_id.is_empty()
                && !event.decision_id.is_empty()
                && !event.policy_id.is_empty()
                && !event.component.is_empty()
                && !event.event.is_empty()
                && !event.outcome.is_empty()
        }));
        assert_eq!(output.witnesses.len(), 3);
        assert_eq!(output.isomorphism_ledger.len(), 3);
    }

    #[test]
    fn pipeline_is_deterministic_for_identical_input() {
        let ir0 = script_ir0();
        let context = LoweringContext::new("trace-b", "decision-b", "policy-b");
        let first = lower_ir0_to_ir3(&ir0, &context).expect("first run should succeed");
        let second = lower_ir0_to_ir3(&ir0, &context).expect("second run should succeed");

        assert_eq!(first.ir1.content_hash(), second.ir1.content_hash());
        assert_eq!(first.ir2.content_hash(), second.ir2.content_hash());
        assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
        assert_eq!(first.witnesses, second.witnesses);
        assert_eq!(first.isomorphism_ledger, second.isomorphism_ledger);
    }

    #[test]
    fn empty_ir0_body_fails_deterministically() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: Vec::new(),
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "empty.js");
        let error = lower_ir0_to_ir1(&ir0).expect_err("empty IR0 should fail");
        assert_eq!(error, LoweringPipelineError::EmptyIr0Body);
    }
}
