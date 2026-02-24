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
const IFC_RUNTIME_GUARD_CAPABILITY: &str = "ifc.check_flow";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowInferenceMetrics {
    total_flow_ops: u64,
    static_proven_ops: u64,
    runtime_check_ops: u64,
}

impl FlowInferenceMetrics {
    fn static_coverage_millionths(self) -> u64 {
        if self.total_flow_ops == 0 {
            return 1_000_000;
        }
        (self.static_proven_ops.saturating_mul(1_000_000)) / self.total_flow_ops
    }
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
    let flow_metrics = infer_ir2_flow_annotations(&mut ir2);

    let source_hash_matches = ir2.header.source_hash.as_ref() == Some(&ir1_hash);
    let hostcall_effects_have_capability = ir2
        .ops
        .iter()
        .filter(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
        .all(|op| op.required_capability.is_some());
    let flow_metrics_consistent = flow_metrics.static_proven_ops + flow_metrics.runtime_check_ops
        == flow_metrics.total_flow_ops;
    let static_coverage_millionths = flow_metrics.static_coverage_millionths();
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
        InvariantCheck {
            name: "ir2_flow_metrics_consistent".to_string(),
            passed: flow_metrics_consistent,
            detail: format!(
                "flow_ops={} static_proven={} runtime_checks={}",
                flow_metrics.total_flow_ops,
                flow_metrics.static_proven_ops,
                flow_metrics.runtime_check_ops
            ),
        },
        InvariantCheck {
            name: "ir2_static_flow_coverage_ratio".to_string(),
            passed: true,
            detail: format!(
                "static_coverage_millionths={} static_proven={} total_flow_ops={}",
                static_coverage_millionths,
                flow_metrics.static_proven_ops,
                flow_metrics.total_flow_ops
            ),
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
            let hostcall_arg = last_value_register.unwrap_or(0);
            if flow_requires_runtime_check(op.flow.as_ref(), &capability) {
                required_capabilities.insert(IFC_RUNTIME_GUARD_CAPABILITY.to_string());
                let guard_dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::HostCall {
                    capability: CapabilityTag(IFC_RUNTIME_GUARD_CAPABILITY.to_string()),
                    args: RegRange {
                        start: hostcall_arg,
                        count: 1,
                    },
                    dst: guard_dst,
                });
            }
            required_capabilities.insert(capability.0.clone());
            let dst = alloc_register(&mut register_cursor);
            ir3.instructions.push(Ir3Instruction::HostCall {
                capability,
                args: RegRange {
                    start: hostcall_arg,
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
        Expression::BooleanLiteral(value) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(*value),
            });
        }
        Expression::NullLiteral => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Null,
            });
        }
        Expression::UndefinedLiteral => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
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

fn infer_ir2_flow_annotations(ir2: &mut Ir2Module) -> FlowInferenceMetrics {
    let mut binding_labels = BTreeMap::<BindingId, Label>::new();
    let mut last_label = Label::Public;
    let mut metrics = FlowInferenceMetrics {
        total_flow_ops: 0,
        static_proven_ops: 0,
        runtime_check_ops: 0,
    };

    for op in &mut ir2.ops {
        let inferred_data_label =
            infer_data_label_for_op(&op.inner, &binding_labels, last_label.clone());
        let inferred_sink_clearance = infer_sink_clearance(
            &op.effect,
            op.required_capability.as_ref(),
            &inferred_data_label,
        );
        let requires_declassification = !inferred_data_label.can_flow_to(&inferred_sink_clearance);
        let runtime_guard_needed = op.required_capability.as_ref().is_some_and(|capability| {
            flow_requires_runtime_check(
                Some(&FlowAnnotation {
                    data_label: inferred_data_label.clone(),
                    sink_clearance: inferred_sink_clearance.clone(),
                    declassification_required: requires_declassification,
                }),
                capability,
            )
        });
        let should_annotate = op.flow.is_some() || !matches!(op.effect, EffectBoundary::Pure);
        if should_annotate {
            metrics.total_flow_ops = metrics.total_flow_ops.saturating_add(1);
            if requires_declassification || runtime_guard_needed {
                metrics.runtime_check_ops = metrics.runtime_check_ops.saturating_add(1);
            } else {
                metrics.static_proven_ops = metrics.static_proven_ops.saturating_add(1);
            }
            op.flow = Some(FlowAnnotation {
                data_label: inferred_data_label.clone(),
                sink_clearance: inferred_sink_clearance,
                declassification_required: requires_declassification,
            });
        } else {
            op.flow = None;
        }

        if let Ir1Op::StoreBinding { binding_id } = &op.inner {
            binding_labels.insert(*binding_id, inferred_data_label.clone());
        }
        if let Ir1Op::LoadBinding { binding_id } = &op.inner
            && let Some(existing) = binding_labels.get(binding_id)
        {
            last_label = existing.clone();
            continue;
        }
        last_label = inferred_data_label;
    }

    metrics
}

fn infer_data_label_for_op(
    op: &Ir1Op,
    binding_labels: &BTreeMap<BindingId, Label>,
    last_label: Label,
) -> Label {
    match op {
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(raw),
        } => {
            let lowered = raw.to_ascii_lowercase();
            if lowered.contains("secret")
                || lowered.contains("token")
                || lowered.contains("api_key")
                || lowered.contains("password")
                || lowered.contains("credential")
            {
                Label::Secret
            } else {
                Label::Public
            }
        }
        Ir1Op::LoadLiteral { .. } => Label::Public,
        Ir1Op::LoadBinding { binding_id } => binding_labels
            .get(binding_id)
            .cloned()
            .unwrap_or(Label::Internal),
        Ir1Op::StoreBinding { .. } => last_label,
        Ir1Op::ImportModule { .. } | Ir1Op::Await => Label::Internal,
        Ir1Op::Call { .. } => last_label,
        Ir1Op::ExportBinding { .. } => last_label,
        Ir1Op::Return | Ir1Op::Nop => last_label,
    }
}

fn infer_sink_clearance(
    effect: &EffectBoundary,
    required_capability: Option<&CapabilityTag>,
    data_label: &Label,
) -> Label {
    if let Some(capability) = required_capability {
        return sink_clearance_from_capability(&capability.0);
    }

    match effect {
        EffectBoundary::NetworkEffect => Label::Public,
        EffectBoundary::FsEffect => Label::Internal,
        EffectBoundary::ReadEffect | EffectBoundary::WriteEffect => Label::Internal,
        EffectBoundary::HostcallEffect => Label::Internal,
        EffectBoundary::Pure => data_label.clone(),
    }
}

fn sink_clearance_from_capability(capability: &str) -> Label {
    let normalized = capability.to_ascii_lowercase();
    if normalized == "hostcall.invoke" {
        return Label::Internal;
    }
    if normalized.contains("net.")
        || normalized.contains("net_")
        || normalized.contains("network")
        || normalized.contains("process.")
        || normalized.contains("process_")
        || normalized.contains("spawn")
    {
        return Label::Public;
    }
    if normalized.contains("credential") || normalized.contains("key_material") {
        return Label::TopSecret;
    }
    if normalized.contains("secret") || normalized.contains("token") || normalized.contains("key") {
        return Label::Secret;
    }
    if normalized.contains("fs.read") {
        return Label::Secret;
    }
    if normalized.contains("fs.write")
        || normalized.contains("module.import")
        || normalized.contains("import")
    {
        return Label::Internal;
    }
    if normalized.contains("declassify") {
        return Label::Public;
    }
    Label::Internal
}

fn flow_requires_runtime_check(flow: Option<&FlowAnnotation>, capability: &CapabilityTag) -> bool {
    let capability_is_dynamic = capability.0 == "hostcall.invoke";
    let flow_is_ambiguous = flow.is_some_and(|annotation| {
        matches!(annotation.data_label, Label::Custom { .. })
            || matches!(annotation.sink_clearance, Label::Custom { .. })
    });
    let flow_requires_declassification =
        flow.is_some_and(|annotation| annotation.declassification_required);
    capability_is_dynamic || flow_is_ambiguous || flow_requires_declassification
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
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .any(|check| check.name == "ir2_static_flow_coverage_ratio")
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
    fn dynamic_hostcall_paths_insert_runtime_ifc_guard() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("secret_token".to_string()),
        });
        ir1.ops.push(Ir1Op::Call { arg_count: 1 });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let call_op = ir2
            .ops
            .iter()
            .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
            .expect("call op");
        assert!(
            call_op
                .flow
                .as_ref()
                .expect("flow annotation")
                .declassification_required
        );

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should succeed")
            .module;
        let hostcall_caps: Vec<&str> = ir3
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
                _ => None,
            })
            .collect();
        assert!(hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY));
        assert!(hostcall_caps.contains(&"hostcall.invoke"));

        let guard_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                    if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
                )
            })
            .expect("guard hostcall");
        let invoke_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                    if capability.0 == "hostcall.invoke"
                )
            })
            .expect("dynamic hostcall");
        assert!(guard_index < invoke_index);
    }

    #[test]
    fn statically_proven_hostcall_skips_runtime_ifc_guard() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "static_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let hostcall_op = ir2
            .ops
            .iter()
            .find(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
            .expect("hostcall op");
        let flow = hostcall_op.flow.as_ref().expect("flow annotation");
        assert!(!flow.declassification_required);
        assert_eq!(flow.data_label, Label::Public);

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should succeed")
            .module;
        let hostcall_caps: Vec<&str> = ir3
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
                _ => None,
            })
            .collect();
        assert!(hostcall_caps.contains(&"fs.read"));
        assert!(!hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY));
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

    // ================================================================
    // Additional coverage tests
    // ================================================================

    use crate::ast::{ExportDeclaration, ExportKind, ImportDeclaration};

    // -- LoweringContext --

    #[test]
    fn lowering_context_new() {
        let ctx = LoweringContext::new("trace-1", "decision-1", "policy-1");
        assert_eq!(ctx.trace_id, "trace-1");
        assert_eq!(ctx.decision_id, "decision-1");
        assert_eq!(ctx.policy_id, "policy-1");
    }

    #[test]
    fn lowering_context_serde_roundtrip() {
        let ctx = LoweringContext::new("t", "d", "p");
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: LoweringContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, parsed);
    }

    // -- LoweringEvent serde --

    #[test]
    fn lowering_event_serde_roundtrip() {
        let event = LoweringEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "lowering_pipeline".to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("FE-LOWER-0001".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LoweringEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -- InvariantCheck serde --

    #[test]
    fn invariant_check_serde_roundtrip() {
        let check = InvariantCheck {
            name: "test_check".to_string(),
            passed: true,
            detail: "detail".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let parsed: InvariantCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, parsed);
    }

    // -- PassWitness serde --

    #[test]
    fn pass_witness_serde_roundtrip() {
        let witness = PassWitness {
            pass_id: "ir0_to_ir1".to_string(),
            input_hash: "sha256:abc".to_string(),
            output_hash: "sha256:def".to_string(),
            rollback_token: "sha256:abc".to_string(),
            invariant_checks: vec![InvariantCheck {
                name: "check1".to_string(),
                passed: true,
                detail: "ok".to_string(),
            }],
        };
        let json = serde_json::to_string(&witness).unwrap();
        let parsed: PassWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, parsed);
    }

    // -- IsomorphismLedgerEntry serde --

    #[test]
    fn isomorphism_ledger_entry_serde_roundtrip() {
        let entry = IsomorphismLedgerEntry {
            pass_id: "ir1_to_ir2".to_string(),
            input_hash: "sha256:123".to_string(),
            output_hash: "sha256:456".to_string(),
            input_op_count: 10,
            output_op_count: 15,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: IsomorphismLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    // -- FlowInferenceMetrics --

    #[test]
    fn flow_inference_metrics_zero_ops_returns_million() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 0,
            static_proven_ops: 0,
            runtime_check_ops: 0,
        };
        assert_eq!(metrics.static_coverage_millionths(), 1_000_000);
    }

    #[test]
    fn flow_inference_metrics_all_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 10,
            static_proven_ops: 10,
            runtime_check_ops: 0,
        };
        assert_eq!(metrics.static_coverage_millionths(), 1_000_000);
    }

    #[test]
    fn flow_inference_metrics_half_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 10,
            static_proven_ops: 5,
            runtime_check_ops: 5,
        };
        assert_eq!(metrics.static_coverage_millionths(), 500_000);
    }

    #[test]
    fn flow_inference_metrics_none_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 4,
            static_proven_ops: 0,
            runtime_check_ops: 4,
        };
        assert_eq!(metrics.static_coverage_millionths(), 0);
    }

    // -- extract_hostcall_capability --

    #[test]
    fn extract_hostcall_capability_valid() {
        assert_eq!(
            extract_hostcall_capability("hostcall<\"fs.read\">"),
            Some("fs.read".to_string())
        );
    }

    #[test]
    fn extract_hostcall_capability_embedded() {
        assert_eq!(
            extract_hostcall_capability("something hostcall<\"net.write\"> more"),
            Some("net.write".to_string())
        );
    }

    #[test]
    fn extract_hostcall_capability_no_marker() {
        assert_eq!(extract_hostcall_capability("plain string"), None);
    }

    #[test]
    fn extract_hostcall_capability_empty_capability() {
        assert_eq!(extract_hostcall_capability("hostcall<\"\">"), None);
    }

    #[test]
    fn extract_hostcall_capability_whitespace_only() {
        assert_eq!(extract_hostcall_capability("hostcall<\"   \">"), None);
    }

    #[test]
    fn extract_hostcall_capability_missing_close() {
        assert_eq!(extract_hostcall_capability("hostcall<\"fs.read"), None);
    }

    // -- sink_clearance_from_capability --

    #[test]
    fn sink_clearance_hostcall_invoke() {
        assert_eq!(
            sink_clearance_from_capability("hostcall.invoke"),
            Label::Internal
        );
    }

    #[test]
    fn sink_clearance_network_capabilities() {
        assert_eq!(sink_clearance_from_capability("net.write"), Label::Public);
        assert_eq!(sink_clearance_from_capability("net_connect"), Label::Public);
        assert_eq!(
            sink_clearance_from_capability("network.send"),
            Label::Public
        );
        assert_eq!(
            sink_clearance_from_capability("process.spawn"),
            Label::Public
        );
        assert_eq!(
            sink_clearance_from_capability("process_exec"),
            Label::Public
        );
        assert_eq!(
            sink_clearance_from_capability("spawn_worker"),
            Label::Public
        );
    }

    #[test]
    fn sink_clearance_credential_capabilities() {
        assert_eq!(
            sink_clearance_from_capability("credential.read"),
            Label::TopSecret
        );
        assert_eq!(
            sink_clearance_from_capability("key_material.derive"),
            Label::TopSecret
        );
    }

    #[test]
    fn sink_clearance_secret_capabilities() {
        assert_eq!(sink_clearance_from_capability("read_secret"), Label::Secret);
        assert_eq!(
            sink_clearance_from_capability("token.validate"),
            Label::Secret
        );
        assert_eq!(
            sink_clearance_from_capability("api_key.fetch"),
            Label::Secret
        );
    }

    #[test]
    fn sink_clearance_fs_capabilities() {
        assert_eq!(sink_clearance_from_capability("fs.read"), Label::Secret);
        assert_eq!(sink_clearance_from_capability("fs.write"), Label::Internal);
    }

    #[test]
    fn sink_clearance_import_capabilities() {
        assert_eq!(
            sink_clearance_from_capability("module.import"),
            Label::Internal
        );
        assert_eq!(
            sink_clearance_from_capability("import.resolve"),
            Label::Internal
        );
    }

    #[test]
    fn sink_clearance_declassify() {
        assert_eq!(
            sink_clearance_from_capability("declassify.check"),
            Label::Public
        );
    }

    #[test]
    fn sink_clearance_unknown_defaults_internal() {
        assert_eq!(sink_clearance_from_capability("custom.op"), Label::Internal);
    }

    // -- classify_ir1_op --

    #[test]
    fn classify_import_module() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::ImportModule {
            specifier: "mod".to_string(),
        });
        assert_eq!(effect, EffectBoundary::ReadEffect);
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().0, "module.import");
        assert!(flow.is_some());
    }

    #[test]
    fn classify_call() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Call { arg_count: 1 });
        assert_eq!(effect, EffectBoundary::HostcallEffect);
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().0, "hostcall.invoke");
        assert!(flow.is_some());
    }

    #[test]
    fn classify_await() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Await);
        assert_eq!(effect, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
        assert!(flow.is_some());
    }

    #[test]
    fn classify_load_literal_string_hostcall() {
        let (effect, cap, _flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
        });
        assert_eq!(effect, EffectBoundary::HostcallEffect);
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().0, "fs.read");
    }

    #[test]
    fn classify_load_literal_string_plain() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hello".to_string()),
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_integer() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_boolean() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(true),
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_null() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Null,
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_undefined() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_binding() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadBinding { binding_id: 0 });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_store_binding() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::StoreBinding { binding_id: 0 });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_export_binding() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::ExportBinding {
            name: "foo".to_string(),
            binding_id: 0,
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_return() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Return);
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_nop() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Nop);
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    // -- push_constant dedup --

    #[test]
    fn push_constant_deduplicates() {
        let mut pool = Vec::new();
        let idx1 = push_constant(&mut pool, "hello");
        let idx2 = push_constant(&mut pool, "world");
        let idx3 = push_constant(&mut pool, "hello");
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // dedup
        assert_eq!(pool.len(), 2);
    }

    // -- lower_literal_to_ir3 --

    #[test]
    fn lower_literal_string_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(
            &Ir1Literal::String("hello".to_string()),
            0,
            &mut instructions,
            &mut pool,
        );
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0
            }
        ));
        assert_eq!(pool, vec!["hello"]);
    }

    #[test]
    fn lower_literal_integer_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Integer(99), 1, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadInt { dst: 1, value: 99 }
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn lower_literal_boolean_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Boolean(true), 2, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadBool {
                dst: 2,
                value: true
            }
        ));
    }

    #[test]
    fn lower_literal_null_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Null, 3, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadNull { dst: 3 }
        ));
    }

    #[test]
    fn lower_literal_undefined_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Undefined, 4, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadUndefined { dst: 4 }
        ));
    }

    // -- flow_requires_runtime_check --

    #[test]
    fn flow_requires_runtime_check_dynamic_capability() {
        let cap = CapabilityTag("hostcall.invoke".to_string());
        assert!(flow_requires_runtime_check(None, &cap));
    }

    #[test]
    fn flow_requires_runtime_check_declassification() {
        let cap = CapabilityTag("fs.read".to_string());
        let annotation = FlowAnnotation {
            data_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_required: true,
        };
        assert!(flow_requires_runtime_check(Some(&annotation), &cap));
    }

    #[test]
    fn flow_requires_runtime_check_custom_label() {
        let cap = CapabilityTag("fs.read".to_string());
        let annotation = FlowAnnotation {
            data_label: Label::Custom {
                name: "my_label".to_string(),
                level: 50,
            },
            sink_clearance: Label::Internal,
            declassification_required: false,
        };
        assert!(flow_requires_runtime_check(Some(&annotation), &cap));
    }

    #[test]
    fn flow_requires_runtime_check_static_safe() {
        let cap = CapabilityTag("fs.read".to_string());
        let annotation = FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Internal,
            declassification_required: false,
        };
        assert!(!flow_requires_runtime_check(Some(&annotation), &cap));
    }

    #[test]
    fn flow_requires_runtime_check_none_flow_static_cap() {
        let cap = CapabilityTag("fs.read".to_string());
        assert!(!flow_requires_runtime_check(None, &cap));
    }

    // -- LoweringPipelineError Display --

    #[test]
    fn lowering_pipeline_error_display_empty_ir0() {
        let err = LoweringPipelineError::EmptyIr0Body;
        assert_eq!(err.to_string(), "IR0 module has no statements");
    }

    #[test]
    fn lowering_pipeline_error_display_ir_contract() {
        let err = LoweringPipelineError::IrContractValidation {
            code: "FE-IR-001".to_string(),
            level: IrLevel::Ir1,
            message: "bad scope".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("FE-IR-001"));
        assert!(display.contains("bad scope"));
    }

    #[test]
    fn lowering_pipeline_error_display_invariant() {
        let err = LoweringPipelineError::InvariantViolation {
            detail: "duplicate binding IDs in IR1 scope graph",
        };
        assert!(err.to_string().contains("duplicate binding IDs"));
    }

    // -- Module lowering with imports --

    #[test]
    fn lower_module_with_import() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Import(ImportDeclaration {
                source: "lodash".to_string(),
                binding: Some("_".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "module_import.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_import = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ImportModule { specifier } if specifier == "lodash"));
        assert!(has_import);
        assert_eq!(result.module.scopes[0].kind, ScopeKind::Module);
    }

    #[test]
    fn lower_module_with_default_export() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::NumericLiteral(42)),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "default_export.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "default"));
        assert!(has_export);
    }

    #[test]
    fn lower_module_with_named_export() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Expression(ExpressionStatement {
                    expression: Expression::Identifier("foo".to_string()),
                    span: span(),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("foo".to_string()),
                    span: span(),
                }),
            ],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "named_export.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "foo"));
        assert!(has_export);
    }

    #[test]
    fn lower_module_with_named_export_unknown_binding() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("bar".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "named_unknown.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "bar"));
        assert!(has_export);
    }

    // -- Module lowering with await --

    #[test]
    fn lower_await_expression() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier(
                    "promise".to_string(),
                ))),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "await.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_await = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Await));
        assert!(has_await);
    }

    // -- Raw expression with call --

    #[test]
    fn lower_raw_expression_with_call_pattern() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Raw("console.log(42)".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "raw_call.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_call = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { .. }));
        assert!(has_call);
    }

    #[test]
    fn lower_raw_expression_without_call_pattern() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Raw("console".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "raw_no_call.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_call = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { .. }));
        assert!(!has_call);
    }

    // -- Full pipeline with imports/exports --

    #[test]
    fn full_pipeline_module_with_import_and_export() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    source: "lodash".to_string(),
                    binding: Some("_".to_string()),
                    span: span(),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(Expression::Identifier("_".to_string())),
                    span: span(),
                }),
            ],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "full_pipeline.mjs");
        let context = LoweringContext::new("trace-fp", "decision-fp", "policy-fp");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("full pipeline should succeed");

        assert_eq!(output.witnesses.len(), 3);
        assert_eq!(output.isomorphism_ledger.len(), 3);
        assert_eq!(output.events.len(), 3);
        assert!(
            output
                .events
                .iter()
                .all(|e| e.outcome == "pass" && e.component == "lowering_pipeline")
        );
        assert!(matches!(
            output.ir3.instructions.last(),
            Some(Ir3Instruction::Halt)
        ));
    }

    // -- Pipeline with string literal --

    #[test]
    fn full_pipeline_string_literal() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("hello world".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "string_lit.js");
        let context = LoweringContext::new("trace-sl", "decision-sl", "policy-sl");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

        assert!(
            output
                .ir3
                .constant_pool
                .contains(&"hello world".to_string())
        );
    }

    // -- scope_binding_ids_are_unique --

    #[test]
    fn scope_binding_ids_unique_empty() {
        assert!(scope_binding_ids_are_unique(&[]));
    }

    #[test]
    fn scope_binding_ids_unique_single_scope() {
        let scope = ScopeNode {
            scope_id: ScopeId { depth: 0, index: 0 },
            parent: None,
            kind: ScopeKind::Global,
            bindings: vec![
                ResolvedBinding {
                    name: "a".to_string(),
                    binding_id: 0,
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
                ResolvedBinding {
                    name: "b".to_string(),
                    binding_id: 1,
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
            ],
        };
        assert!(scope_binding_ids_are_unique(&[scope]));
    }

    #[test]
    fn scope_binding_ids_duplicate_detected() {
        let scope = ScopeNode {
            scope_id: ScopeId { depth: 0, index: 0 },
            parent: None,
            kind: ScopeKind::Global,
            bindings: vec![
                ResolvedBinding {
                    name: "a".to_string(),
                    binding_id: 0,
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
                ResolvedBinding {
                    name: "b".to_string(),
                    binding_id: 0, // duplicate
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
            ],
        };
        assert!(!scope_binding_ids_are_unique(&[scope]));
    }

    // -- infer_data_label_for_op --

    #[test]
    fn infer_data_label_secret_patterns() {
        let labels = BTreeMap::new();
        let secret = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("my_secret_key".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(secret, Label::Secret);

        let token = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("AUTH_TOKEN".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(token, Label::Secret);

        let api_key = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("my_api_key_here".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(api_key, Label::Secret);

        let password = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("user_password".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(password, Label::Secret);

        let credential = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("credential_store".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(credential, Label::Secret);
    }

    #[test]
    fn infer_data_label_public_string() {
        let labels = BTreeMap::new();
        let public = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("hello world".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(public, Label::Public);
    }

    #[test]
    fn infer_data_label_numeric_literal() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(42),
            },
            &labels,
            Label::Secret,
        );
        assert_eq!(label, Label::Public);
    }

    #[test]
    fn infer_data_label_load_binding_known() {
        let mut labels = BTreeMap::new();
        labels.insert(5u32, Label::Confidential);
        let label = infer_data_label_for_op(
            &Ir1Op::LoadBinding { binding_id: 5 },
            &labels,
            Label::Public,
        );
        assert_eq!(label, Label::Confidential);
    }

    #[test]
    fn infer_data_label_load_binding_unknown() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(
            &Ir1Op::LoadBinding { binding_id: 99 },
            &labels,
            Label::Public,
        );
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_data_label_import_is_internal() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(
            &Ir1Op::ImportModule {
                specifier: "lodash".to_string(),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_data_label_return_uses_last_label() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(&Ir1Op::Return, &labels, Label::Confidential);
        assert_eq!(label, Label::Confidential);
    }

    // -- success_event / failure_event --

    #[test]
    fn success_event_fields() {
        let ctx = LoweringContext::new("t", "d", "p");
        let event = success_event(&ctx, "test_pass");
        assert_eq!(event.trace_id, "t");
        assert_eq!(event.decision_id, "d");
        assert_eq!(event.policy_id, "p");
        assert_eq!(event.component, "lowering_pipeline");
        assert_eq!(event.event, "test_pass");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn failure_event_fields() {
        let ctx = LoweringContext::new("t", "d", "p");
        let event = failure_event(&ctx, "test_fail", "FE-LOWER-9999");
        assert_eq!(event.outcome, "fail");
        assert_eq!(event.error_code, Some("FE-LOWER-9999".to_string()));
    }

    // -- infer_sink_clearance --

    #[test]
    fn infer_sink_clearance_network_effect() {
        let label = infer_sink_clearance(&EffectBoundary::NetworkEffect, None, &Label::Secret);
        assert_eq!(label, Label::Public);
    }

    #[test]
    fn infer_sink_clearance_fs_effect() {
        let label = infer_sink_clearance(&EffectBoundary::FsEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_read_effect() {
        let label = infer_sink_clearance(&EffectBoundary::ReadEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_write_effect() {
        let label = infer_sink_clearance(&EffectBoundary::WriteEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_hostcall_effect() {
        let label = infer_sink_clearance(&EffectBoundary::HostcallEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_pure_uses_data_label() {
        let label = infer_sink_clearance(&EffectBoundary::Pure, None, &Label::Secret);
        assert_eq!(label, Label::Secret);
    }

    #[test]
    fn infer_sink_clearance_with_capability_overrides() {
        let cap = CapabilityTag("net.write".to_string());
        let label = infer_sink_clearance(&EffectBoundary::Pure, Some(&cap), &Label::Secret);
        assert_eq!(label, Label::Public);
    }

    // -- alloc_register --

    #[test]
    fn alloc_register_increments() {
        let mut cursor: Reg = 0;
        let r0 = alloc_register(&mut cursor);
        let r1 = alloc_register(&mut cursor);
        let r2 = alloc_register(&mut cursor);
        assert_eq!(r0, 0);
        assert_eq!(r1, 1);
        assert_eq!(r2, 2);
        assert_eq!(cursor, 3);
    }

    // -- hash_string --

    #[test]
    fn hash_string_format() {
        let hash = ContentHash::compute(b"test");
        let s = hash_string(&hash);
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    // -- ensure_checks_pass --

    #[test]
    fn ensure_checks_pass_all_pass() {
        let checks = vec![
            InvariantCheck {
                name: "a".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            InvariantCheck {
                name: "b".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
        ];
        assert!(ensure_checks_pass(&checks, "should not fail").is_ok());
    }

    #[test]
    fn ensure_checks_pass_one_fails() {
        let checks = vec![
            InvariantCheck {
                name: "a".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            InvariantCheck {
                name: "b".to_string(),
                passed: false,
                detail: "bad".to_string(),
            },
        ];
        let err = ensure_checks_pass(&checks, "test failure").unwrap_err();
        assert!(matches!(
            err,
            LoweringPipelineError::InvariantViolation {
                detail: "test failure"
            }
        ));
    }
}
