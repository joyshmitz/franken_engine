//! Deterministic bytecode VM substrate with inline-cache support.
//!
//! This module provides a compact, replay-stable VM that can execute a small
//! instruction set, plus a deterministic inline-cache surface for property
//! loads. It is designed as a dependency-safe foundation for RGC-601.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const COMPONENT: &str = "bytecode_vm";

/// Register index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Register(pub u16);

impl Register {
    fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Heap object handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u32);

/// VM value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Value {
    Undefined,
    Bool(bool),
    Int(i64),
    Object(ObjectId),
}

impl Value {
    fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined => false,
            Self::Bool(v) => *v,
            Self::Int(v) => *v != 0,
            Self::Object(_) => true,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Object(_) => "object",
        }
    }
}

/// Instruction set for the deterministic bytecode VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    LoadConst {
        dst: Register,
        const_index: u16,
    },
    Move {
        dst: Register,
        src: Register,
    },
    Add {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Sub {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Mul {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Div {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    NewObject {
        dst: Register,
    },
    StoreProp {
        object: Register,
        property_index: u16,
        value: Register,
    },
    LoadPropCached {
        dst: Register,
        object: Register,
        property_index: u16,
    },
    Jump {
        target: u32,
    },
    JumpIfFalse {
        condition: Register,
        target: u32,
    },
    Return {
        src: Register,
    },
}

impl Instruction {
    fn opcode_name(&self) -> &'static str {
        match self {
            Self::LoadConst { .. } => "load_const",
            Self::Move { .. } => "move",
            Self::Add { .. } => "add",
            Self::Sub { .. } => "sub",
            Self::Mul { .. } => "mul",
            Self::Div { .. } => "div",
            Self::NewObject { .. } => "new_object",
            Self::StoreProp { .. } => "store_prop",
            Self::LoadPropCached { .. } => "load_prop_cached",
            Self::Jump { .. } => "jump",
            Self::JumpIfFalse { .. } => "jump_if_false",
            Self::Return { .. } => "return",
        }
    }
}

/// Bytecode program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Program {
    pub constants: Vec<Value>,
    pub property_pool: Vec<String>,
    pub instructions: Vec<Instruction>,
}

/// VM execution failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmError {
    RegisterOutOfBounds {
        register: u16,
        register_count: usize,
    },
    ConstantOutOfBounds {
        const_index: u16,
        constant_count: usize,
    },
    PropertyIndexOutOfBounds {
        property_index: u16,
        property_count: usize,
    },
    ObjectNotFound {
        object_id: u32,
    },
    TypeMismatch {
        expected: &'static str,
        got: &'static str,
    },
    DivisionByZero,
    InvalidJumpTarget {
        target: u32,
        instruction_count: usize,
    },
    MissingReturn,
    BudgetExhausted {
        executed_steps: u64,
        step_budget: u64,
    },
}

impl VmError {
    fn code(&self) -> &'static str {
        match self {
            Self::RegisterOutOfBounds { .. } => "register_oob",
            Self::ConstantOutOfBounds { .. } => "constant_oob",
            Self::PropertyIndexOutOfBounds { .. } => "property_oob",
            Self::ObjectNotFound { .. } => "object_not_found",
            Self::TypeMismatch { .. } => "type_mismatch",
            Self::DivisionByZero => "division_by_zero",
            Self::InvalidJumpTarget { .. } => "invalid_jump_target",
            Self::MissingReturn => "missing_return",
            Self::BudgetExhausted { .. } => "budget_exhausted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeapObject {
    shape_id: u64,
    keys: Vec<String>,
    slots: Vec<Value>,
    key_to_slot: BTreeMap<String, usize>,
}

impl HeapObject {
    fn new(shape_id: u64) -> Self {
        Self {
            shape_id,
            keys: Vec::new(),
            slots: Vec::new(),
            key_to_slot: BTreeMap::new(),
        }
    }

    fn load(&self, key: &str) -> Option<(usize, Value)> {
        self.key_to_slot
            .get(key)
            .and_then(|slot| self.slots.get(*slot).map(|value| (*slot, value.clone())))
    }

    fn load_slot(&self, slot_index: usize) -> Option<Value> {
        self.slots.get(slot_index).cloned()
    }

    fn store(&mut self, key: &str, value: Value, next_shape_id: &mut u64) {
        if let Some(slot) = self.key_to_slot.get(key).copied() {
            self.slots[slot] = value;
            return;
        }

        let slot = self.slots.len();
        self.keys.push(key.to_string());
        self.slots.push(value);
        self.key_to_slot.insert(key.to_string(), slot);
        self.shape_id = *next_shape_id;
        *next_shape_id += 1;
    }
}

/// Inline cache entry keyed by instruction pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InlineCacheEntry {
    pub shape_id: u64,
    pub property_index: u16,
    pub slot_index: usize,
    pub hits: u64,
    pub misses: u64,
}

/// Aggregate cache statistics for one VM execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InlineCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}

/// Structured execution event for deterministic replay and triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmEvent {
    pub trace_id: String,
    pub component: String,
    pub step: u64,
    pub ip: u32,
    pub opcode: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub cache_hit: Option<bool>,
}

/// Final execution report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub trace_id: String,
    pub result: Value,
    pub steps: u64,
    pub cache_stats: InlineCacheStats,
    pub state_hash: String,
    pub events: Vec<VmEvent>,
}

enum ControlFlow {
    Continue {
        next_ip: usize,
        cache_hit: Option<bool>,
    },
    Return {
        value: Value,
        cache_hit: Option<bool>,
    },
}

struct EventRecord<'a> {
    step: u64,
    ip: u32,
    opcode: &'a str,
    event: &'a str,
    outcome: &'a str,
    error_code: Option<String>,
    cache_hit: Option<bool>,
}

/// Deterministic bytecode VM.
#[derive(Debug, Clone)]
pub struct BytecodeVm {
    trace_id: String,
    registers: Vec<Value>,
    heap: Vec<HeapObject>,
    inline_cache: BTreeMap<u32, InlineCacheEntry>,
    step_budget: u64,
    next_shape_id: u64,
    events: Vec<VmEvent>,
}

impl BytecodeVm {
    /// Create a VM with explicit register and step budgets.
    pub fn new(trace_id: impl Into<String>, register_count: usize, step_budget: u64) -> Self {
        Self {
            trace_id: trace_id.into(),
            registers: vec![Value::Undefined; register_count],
            heap: Vec::new(),
            inline_cache: BTreeMap::new(),
            step_budget,
            next_shape_id: 1,
            events: Vec::new(),
        }
    }

    /// Execute a program deterministically.
    pub fn execute(&mut self, program: &Program) -> Result<ExecutionReport, VmError> {
        self.events.clear();
        self.inline_cache.clear();
        self.heap.clear();
        self.registers.fill(Value::Undefined);
        self.next_shape_id = 1;

        let mut ip = 0usize;
        let mut steps = 0u64;

        loop {
            if steps >= self.step_budget {
                let error = VmError::BudgetExhausted {
                    executed_steps: steps,
                    step_budget: self.step_budget,
                };
                self.record_event(EventRecord {
                    step: steps,
                    ip: ip as u32,
                    opcode: "budget",
                    event: "instruction",
                    outcome: "error",
                    error_code: Some(error.code().to_string()),
                    cache_hit: None,
                });
                return Err(error);
            }

            let instruction = match program.instructions.get(ip).cloned() {
                Some(value) => value,
                None => {
                    let error = VmError::MissingReturn;
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: "eof",
                        event: "instruction",
                        outcome: "error",
                        error_code: Some(error.code().to_string()),
                        cache_hit: None,
                    });
                    return Err(error);
                }
            };

            steps += 1;
            let opcode = instruction.opcode_name().to_string();

            match self.execute_instruction(program, ip, instruction) {
                Ok(ControlFlow::Continue { next_ip, cache_hit }) => {
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: &opcode,
                        event: "instruction",
                        outcome: "ok",
                        error_code: None,
                        cache_hit,
                    });
                    ip = next_ip;
                }
                Ok(ControlFlow::Return { value, cache_hit }) => {
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: &opcode,
                        event: "return",
                        outcome: "ok",
                        error_code: None,
                        cache_hit,
                    });

                    let cache_stats = self.cache_stats();
                    let state_hash = self.compute_state_hash(&value, steps, &cache_stats);

                    return Ok(ExecutionReport {
                        trace_id: self.trace_id.clone(),
                        result: value,
                        steps,
                        cache_stats,
                        state_hash,
                        events: self.events.clone(),
                    });
                }
                Err(error) => {
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: &opcode,
                        event: "instruction",
                        outcome: "error",
                        error_code: Some(error.code().to_string()),
                        cache_hit: None,
                    });
                    return Err(error);
                }
            }
        }
    }

    fn execute_instruction(
        &mut self,
        program: &Program,
        ip: usize,
        instruction: Instruction,
    ) -> Result<ControlFlow, VmError> {
        match instruction {
            Instruction::LoadConst { dst, const_index } => {
                let constant = program
                    .constants
                    .get(usize::from(const_index))
                    .cloned()
                    .ok_or(VmError::ConstantOutOfBounds {
                        const_index,
                        constant_count: program.constants.len(),
                    })?;
                self.write_register(dst, constant)?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Move { dst, src } => {
                let value = self.read_register(src)?.clone();
                self.write_register(dst, value)?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Add { dst, lhs, rhs } => {
                let value = self.binary_int_op(lhs, rhs, |l, r| l + r)?;
                self.write_register(dst, Value::Int(value))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Sub { dst, lhs, rhs } => {
                let value = self.binary_int_op(lhs, rhs, |l, r| l - r)?;
                self.write_register(dst, Value::Int(value))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Mul { dst, lhs, rhs } => {
                let value = self.binary_int_op(lhs, rhs, |l, r| l * r)?;
                self.write_register(dst, Value::Int(value))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Div { dst, lhs, rhs } => {
                let left = self.read_int(lhs)?;
                let right = self.read_int(rhs)?;
                if right == 0 {
                    return Err(VmError::DivisionByZero);
                }
                self.write_register(dst, Value::Int(left / right))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::NewObject { dst } => {
                let object_id = ObjectId(self.heap.len() as u32);
                let object = HeapObject::new(self.next_shape_id);
                self.next_shape_id += 1;
                self.heap.push(object);
                self.write_register(dst, Value::Object(object_id))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::StoreProp {
                object,
                property_index,
                value,
            } => {
                let object_id = self.read_object_id(object)?;
                let property_name = program
                    .property_pool
                    .get(usize::from(property_index))
                    .ok_or(VmError::PropertyIndexOutOfBounds {
                        property_index,
                        property_count: program.property_pool.len(),
                    })?
                    .clone();
                let stored_value = self.read_register(value)?.clone();
                let heap_object =
                    self.heap
                        .get_mut(object_id.0 as usize)
                        .ok_or(VmError::ObjectNotFound {
                            object_id: object_id.0,
                        })?;
                heap_object.store(&property_name, stored_value, &mut self.next_shape_id);

                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::LoadPropCached {
                dst,
                object,
                property_index,
            } => {
                let object_id = self.read_object_id(object)?;
                let property_name = program
                    .property_pool
                    .get(usize::from(property_index))
                    .ok_or(VmError::PropertyIndexOutOfBounds {
                        property_index,
                        property_count: program.property_pool.len(),
                    })?;

                let object_ref =
                    self.heap
                        .get(object_id.0 as usize)
                        .ok_or(VmError::ObjectNotFound {
                            object_id: object_id.0,
                        })?;
                let object_shape = object_ref.shape_id;

                let cache_key = ip as u32;
                let mut cache_hit = false;
                let mut loaded = Value::Undefined;

                if let Some(entry) = self.inline_cache.get_mut(&cache_key)
                    && entry.shape_id == object_shape
                    && entry.property_index == property_index
                    && let Some(value) = object_ref.load_slot(entry.slot_index)
                {
                    entry.hits += 1;
                    cache_hit = true;
                    loaded = value;
                }

                if !cache_hit {
                    let (slot_index, value) = object_ref
                        .load(property_name)
                        .unwrap_or((usize::MAX, Value::Undefined));
                    loaded = value;

                    let entry = self.inline_cache.entry(cache_key).or_default();
                    entry.shape_id = object_shape;
                    entry.property_index = property_index;
                    entry.slot_index = slot_index;
                    entry.misses += 1;
                }

                self.write_register(dst, loaded)?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: Some(cache_hit),
                })
            }
            Instruction::Jump { target } => {
                let target_index = target as usize;
                if target_index >= program.instructions.len() {
                    return Err(VmError::InvalidJumpTarget {
                        target,
                        instruction_count: program.instructions.len(),
                    });
                }
                Ok(ControlFlow::Continue {
                    next_ip: target_index,
                    cache_hit: None,
                })
            }
            Instruction::JumpIfFalse { condition, target } => {
                let condition_value = self.read_register(condition)?.clone();
                if condition_value.is_truthy() {
                    return Ok(ControlFlow::Continue {
                        next_ip: ip + 1,
                        cache_hit: None,
                    });
                }

                let target_index = target as usize;
                if target_index >= program.instructions.len() {
                    return Err(VmError::InvalidJumpTarget {
                        target,
                        instruction_count: program.instructions.len(),
                    });
                }
                Ok(ControlFlow::Continue {
                    next_ip: target_index,
                    cache_hit: None,
                })
            }
            Instruction::Return { src } => Ok(ControlFlow::Return {
                value: self.read_register(src)?.clone(),
                cache_hit: None,
            }),
        }
    }

    fn read_register(&self, register: Register) -> Result<&Value, VmError> {
        self.registers
            .get(register.index())
            .ok_or(VmError::RegisterOutOfBounds {
                register: register.0,
                register_count: self.registers.len(),
            })
    }

    fn write_register(&mut self, register: Register, value: Value) -> Result<(), VmError> {
        let register_count = self.registers.len();
        let slot =
            self.registers
                .get_mut(register.index())
                .ok_or(VmError::RegisterOutOfBounds {
                    register: register.0,
                    register_count,
                })?;
        *slot = value;
        Ok(())
    }

    fn read_int(&self, register: Register) -> Result<i64, VmError> {
        match self.read_register(register)? {
            Value::Int(value) => Ok(*value),
            other => Err(VmError::TypeMismatch {
                expected: "int",
                got: other.kind(),
            }),
        }
    }

    fn read_object_id(&self, register: Register) -> Result<ObjectId, VmError> {
        match self.read_register(register)? {
            Value::Object(object_id) => Ok(*object_id),
            other => Err(VmError::TypeMismatch {
                expected: "object",
                got: other.kind(),
            }),
        }
    }

    fn binary_int_op<F>(&self, lhs: Register, rhs: Register, operation: F) -> Result<i64, VmError>
    where
        F: FnOnce(i64, i64) -> i64,
    {
        let left = self.read_int(lhs)?;
        let right = self.read_int(rhs)?;
        Ok(operation(left, right))
    }

    fn cache_stats(&self) -> InlineCacheStats {
        let hits = self
            .inline_cache
            .values()
            .map(|entry| entry.hits)
            .sum::<u64>();
        let misses = self
            .inline_cache
            .values()
            .map(|entry| entry.misses)
            .sum::<u64>();

        InlineCacheStats {
            entries: self.inline_cache.len(),
            hits,
            misses,
        }
    }

    fn compute_state_hash(
        &self,
        result: &Value,
        steps: u64,
        cache_stats: &InlineCacheStats,
    ) -> String {
        #[derive(Serialize)]
        struct HashEnvelope<'a> {
            trace_id: &'a str,
            result: &'a Value,
            steps: u64,
            cache_stats: &'a InlineCacheStats,
            registers: &'a [Value],
            cache_entries: &'a BTreeMap<u32, InlineCacheEntry>,
            heap: &'a [HeapObject],
        }

        let envelope = HashEnvelope {
            trace_id: &self.trace_id,
            result,
            steps,
            cache_stats,
            registers: &self.registers,
            cache_entries: &self.inline_cache,
            heap: &self.heap,
        };

        let payload =
            serde_json::to_vec(&envelope).expect("bytecode-vm hash envelope must be serializable");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }

    fn record_event(&mut self, event: EventRecord<'_>) {
        self.events.push(VmEvent {
            trace_id: self.trace_id.clone(),
            component: COMPONENT.to_string(),
            step: event.step,
            ip: event.ip,
            opcode: event.opcode.to_string(),
            event: event.event.to_string(),
            outcome: event.outcome.to_string(),
            error_code: event.error_code,
            cache_hit: event.cache_hit,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BytecodeVm, InlineCacheStats, Instruction, ObjectId, Program, Register, Value, VmError,
    };

    fn r(index: u16) -> Register {
        Register(index)
    }

    #[test]
    fn executes_arithmetic_program_deterministically() {
        let program = Program {
            constants: vec![Value::Int(6), Value::Int(7)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Mul {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-arithmetic", 8, 128);
        let report = vm.execute(&program).expect("program should execute");

        assert_eq!(report.result, Value::Int(42));
        assert_eq!(report.steps, 4);
        assert_eq!(
            report.cache_stats,
            InlineCacheStats {
                entries: 0,
                hits: 0,
                misses: 0
            }
        );
        assert!(!report.state_hash.is_empty());
    }

    #[test]
    fn inline_cache_accumulates_hits_on_repeated_property_loads() {
        let program = Program {
            constants: vec![Value::Int(41), Value::Int(3), Value::Int(1)],
            property_pool: vec!["answer".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadConst {
                    dst: r(2),
                    const_index: 1,
                },
                Instruction::LoadPropCached {
                    dst: r(3),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(4),
                    const_index: 2,
                },
                Instruction::Sub {
                    dst: r(2),
                    lhs: r(2),
                    rhs: r(4),
                },
                Instruction::JumpIfFalse {
                    condition: r(2),
                    target: 9,
                },
                Instruction::Jump { target: 4 },
                Instruction::Return { src: r(3) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-cache-hit", 12, 256);
        let report = vm.execute(&program).expect("program should execute");

        assert_eq!(report.result, Value::Int(41));
        assert_eq!(report.cache_stats.entries, 1);
        assert_eq!(report.cache_stats.misses, 1);
        assert_eq!(report.cache_stats.hits, 2);
        assert!(
            report
                .events
                .iter()
                .any(|event| event.opcode == "load_prop_cached" && event.cache_hit == Some(true))
        );
    }

    #[test]
    fn inline_cache_misses_when_shape_changes() {
        let program = Program {
            constants: vec![Value::Int(10), Value::Int(20), Value::Int(2), Value::Int(1)],
            property_pool: vec!["a".to_string(), "b".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadConst {
                    dst: r(4),
                    const_index: 2,
                },
                Instruction::LoadPropCached {
                    dst: r(2),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(3),
                    const_index: 1,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 1,
                    value: r(3),
                },
                Instruction::LoadConst {
                    dst: r(5),
                    const_index: 3,
                },
                Instruction::Sub {
                    dst: r(4),
                    lhs: r(4),
                    rhs: r(5),
                },
                Instruction::JumpIfFalse {
                    condition: r(4),
                    target: 11,
                },
                Instruction::Jump { target: 4 },
                Instruction::Return { src: r(2) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-shape-change", 16, 256);
        let report = vm.execute(&program).expect("program should execute");

        assert_eq!(report.result, Value::Int(10));
        assert_eq!(report.cache_stats.entries, 1);
        assert_eq!(report.cache_stats.misses, 2);
        assert_eq!(report.cache_stats.hits, 0);
        assert!(
            report
                .events
                .iter()
                .filter(|event| event.opcode == "load_prop_cached")
                .all(|event| event.cache_hit == Some(false))
        );
    }

    #[test]
    fn returns_error_for_invalid_jump_target() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Jump { target: 9_999 },
            ],
        };

        let mut vm = BytecodeVm::new("trace-invalid-jump", 8, 32);
        let error = vm.execute(&program).expect_err("jump should fail");
        assert_eq!(
            error,
            VmError::InvalidJumpTarget {
                target: 9_999,
                instruction_count: 2
            }
        );
    }

    #[test]
    fn value_object_round_trip_preserves_identity() {
        let object_id = ObjectId(7);
        let value = Value::Object(object_id);
        assert_eq!(value, Value::Object(ObjectId(7)));
    }
}
