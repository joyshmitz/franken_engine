use frankenengine_engine::bytecode_vm::{
    BytecodeVm, Instruction, Program, Register, Value, VmError,
};

fn r(index: u16) -> Register {
    Register(index)
}

fn sample_program() -> Program {
    Program {
        constants: vec![Value::Int(7), Value::Int(35)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::NewObject { dst: r(3) },
            Instruction::StoreProp {
                object: r(3),
                property_index: 0,
                value: r(2),
            },
            Instruction::LoadPropCached {
                dst: r(4),
                object: r(3),
                property_index: 0,
            },
            Instruction::Return { src: r(4) },
        ],
    }
}

#[test]
fn report_is_deterministic_for_fixed_trace_and_program() {
    let program = sample_program();

    let mut left = BytecodeVm::new("trace-fixed", 16, 256);
    let mut right = BytecodeVm::new("trace-fixed", 16, 256);

    let left_report = left.execute(&program).expect("left report");
    let right_report = right.execute(&program).expect("right report");

    assert_eq!(left_report.result, Value::Int(42));
    assert_eq!(left_report, right_report);
}

#[test]
fn structured_events_include_required_fields() {
    let program = sample_program();
    let mut vm = BytecodeVm::new("trace-events", 16, 256);
    let report = vm.execute(&program).expect("report");

    assert!(!report.events.is_empty());
    for event in &report.events {
        assert_eq!(event.component, "bytecode_vm");
        assert_eq!(event.trace_id, "trace-events");
        assert!(!event.opcode.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn invalid_jump_fails_with_stable_error_code_variant() {
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![Instruction::Jump { target: 5 }],
    };
    let mut vm = BytecodeVm::new("trace-bad-jump", 4, 32);

    let error = vm.execute(&program).expect_err("invalid jump must fail");
    assert_eq!(
        error,
        VmError::InvalidJumpTarget {
            target: 5,
            instruction_count: 1
        }
    );
}
