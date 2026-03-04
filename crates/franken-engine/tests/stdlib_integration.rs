//! Integration tests for the ES2020 standard library baseline (bd-1lsy.4.6 / RGC-306).
//!
//! Validates: install_stdlib initialization, prototype chain wiring, builtin
//! registry completeness, math/string/number/JSON method execution, determinism,
//! serde round-trips, and error taxonomy coverage.

use frankenengine_engine::object_model::{JsValue, ObjectHeap, PropertyKey};
use frankenengine_engine::stdlib::{
    BuiltinId, GlobalEnvironment, StdlibError, exec_math, exec_number_method, exec_string_method,
    install_stdlib, json_parse, json_stringify,
};

const FP_SCALE: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// install_stdlib smoke tests
// ---------------------------------------------------------------------------

#[test]
fn install_stdlib_returns_valid_global_environment() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    // Global object should exist on the heap with constructor properties.
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Array"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Object"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("String"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Number"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Boolean"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Math"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("JSON"))
            .is_ok()
    );
}

#[test]
fn install_stdlib_registers_builtins_in_registry() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    assert!(env.registry.len() > 0, "registry should not be empty");
}

#[test]
fn install_stdlib_prototype_chain_object_proto_is_root() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    // Object.prototype has null [[Prototype]] (it's the root).
    let proto = env.prototypes.object_prototype;
    let parent = heap.get_prototype_of(proto).unwrap();
    assert!(
        parent.is_none(),
        "Object.prototype should have null [[Prototype]]"
    );
}

#[test]
fn install_stdlib_prototype_chain_array_inherits_object() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    // Array.prototype.[[Prototype]] should be Object.prototype.
    let array_proto_parent = heap
        .get_prototype_of(env.prototypes.array_prototype)
        .unwrap();
    assert_eq!(
        array_proto_parent,
        Some(env.prototypes.object_prototype),
        "Array.prototype should inherit from Object.prototype"
    );
}

#[test]
fn install_stdlib_determinism_across_invocations() {
    let env1 = {
        let mut heap = ObjectHeap::new();
        install_stdlib(&mut heap)
    };
    let env2 = {
        let mut heap = ObjectHeap::new();
        install_stdlib(&mut heap)
    };
    assert_eq!(env1.registry.len(), env2.registry.len());
}

// ---------------------------------------------------------------------------
// Math method tests
// ---------------------------------------------------------------------------

#[test]
fn math_abs_positive() {
    let result = exec_math(BuiltinId::MathAbs, &[JsValue::Int(-5 * FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Int(5 * FP_SCALE));
}

#[test]
fn math_abs_zero() {
    let result = exec_math(BuiltinId::MathAbs, &[JsValue::Int(0)]).unwrap();
    assert_eq!(result, JsValue::Int(0));
}

#[test]
fn math_ceil() {
    let result = exec_math(BuiltinId::MathCeil, &[JsValue::Int(2_300_000)]).unwrap();
    assert_eq!(result, JsValue::Int(3 * FP_SCALE));
}

#[test]
fn math_floor() {
    let result = exec_math(BuiltinId::MathFloor, &[JsValue::Int(2_700_000)]).unwrap();
    assert_eq!(result, JsValue::Int(2 * FP_SCALE));
}

#[test]
fn math_round() {
    assert_eq!(
        exec_math(BuiltinId::MathRound, &[JsValue::Int(2_500_000)]).unwrap(),
        JsValue::Int(3 * FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathRound, &[JsValue::Int(2_499_999)]).unwrap(),
        JsValue::Int(2 * FP_SCALE)
    );
}

#[test]
fn math_trunc() {
    assert_eq!(
        exec_math(BuiltinId::MathTrunc, &[JsValue::Int(3_700_000)]).unwrap(),
        JsValue::Int(3 * FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathTrunc, &[JsValue::Int(-3_700_000)]).unwrap(),
        JsValue::Int(-3 * FP_SCALE)
    );
}

#[test]
fn math_sign() {
    assert_eq!(
        exec_math(BuiltinId::MathSign, &[JsValue::Int(42 * FP_SCALE)]).unwrap(),
        JsValue::Int(FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathSign, &[JsValue::Int(-1 * FP_SCALE)]).unwrap(),
        JsValue::Int(-FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathSign, &[JsValue::Int(0)]).unwrap(),
        JsValue::Int(0)
    );
}

#[test]
fn math_max_min() {
    let args = vec![
        JsValue::Int(3 * FP_SCALE),
        JsValue::Int(1 * FP_SCALE),
        JsValue::Int(5 * FP_SCALE),
    ];
    assert_eq!(
        exec_math(BuiltinId::MathMax, &args).unwrap(),
        JsValue::Int(5 * FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathMin, &args).unwrap(),
        JsValue::Int(1 * FP_SCALE)
    );
}

#[test]
fn math_pow() {
    let result = exec_math(
        BuiltinId::MathPow,
        &[JsValue::Int(2 * FP_SCALE), JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(8 * FP_SCALE));
}

#[test]
fn math_clz32() {
    let result = exec_math(BuiltinId::MathClz32, &[JsValue::Int(1 * FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Int(31 * FP_SCALE));
}

#[test]
fn math_imul() {
    let result = exec_math(
        BuiltinId::MathImul,
        &[JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(12 * FP_SCALE));
}

// ---------------------------------------------------------------------------
// String method tests
// ---------------------------------------------------------------------------

#[test]
fn string_char_at() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharAt,
        "hello",
        &[JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("h".into()));
}

#[test]
fn string_char_at_end() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharAt,
        "hello",
        &[JsValue::Int(4 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("o".into()));
}

#[test]
fn string_char_at_out_of_bounds() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharAt,
        "hi",
        &[JsValue::Int(10 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str(String::new()));
}

#[test]
fn string_includes() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeIncludes,
        "hello world",
        &[JsValue::Str("world".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Bool(true));

    let result2 = exec_string_method(
        BuiltinId::StringPrototypeIncludes,
        "hello",
        &[JsValue::Str("xyz".into())],
    )
    .unwrap();
    assert_eq!(result2, JsValue::Bool(false));
}

#[test]
fn string_starts_with() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeStartsWith,
            "hello",
            &[JsValue::Str("hel".into())]
        )
        .unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeStartsWith,
            "hello",
            &[JsValue::Str("llo".into())]
        )
        .unwrap(),
        JsValue::Bool(false)
    );
}

#[test]
fn string_ends_with() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeEndsWith,
            "hello",
            &[JsValue::Str("llo".into())]
        )
        .unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn string_to_upper_lower() {
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeToUpperCase, "hello", &[]).unwrap(),
        JsValue::Str("HELLO".into())
    );
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeToLowerCase, "HELLO", &[]).unwrap(),
        JsValue::Str("hello".into())
    );
}

#[test]
fn string_trim() {
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeTrim, "  hello  ", &[]).unwrap(),
        JsValue::Str("hello".into())
    );
}

#[test]
fn string_trim_start_end() {
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeTrimStart, "  hello  ", &[]).unwrap(),
        JsValue::Str("hello  ".into())
    );
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeTrimEnd, "  hello  ", &[]).unwrap(),
        JsValue::Str("  hello".into())
    );
}

#[test]
fn string_repeat() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeRepeat,
            "ab",
            &[JsValue::Int(3 * FP_SCALE)]
        )
        .unwrap(),
        JsValue::Str("ababab".into())
    );
}

#[test]
fn string_pad_start_end() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypePadStart,
            "5",
            &[JsValue::Int(3 * FP_SCALE), JsValue::Str("0".into())]
        )
        .unwrap(),
        JsValue::Str("005".into())
    );
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypePadEnd,
            "5",
            &[JsValue::Int(3 * FP_SCALE), JsValue::Str("0".into())]
        )
        .unwrap(),
        JsValue::Str("500".into())
    );
}

#[test]
fn string_index_of() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeIndexOf,
            "hello world",
            &[JsValue::Str("world".into())]
        )
        .unwrap(),
        JsValue::Int(6 * FP_SCALE)
    );
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeIndexOf,
            "hello",
            &[JsValue::Str("xyz".into())]
        )
        .unwrap(),
        JsValue::Int(-1 * FP_SCALE)
    );
}

#[test]
fn string_slice() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeSlice,
            "hello world",
            &[JsValue::Int(6 * FP_SCALE)]
        )
        .unwrap(),
        JsValue::Str("world".into())
    );
}

#[test]
fn string_substring() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeSubstring,
            "hello",
            &[JsValue::Int(1 * FP_SCALE), JsValue::Int(3 * FP_SCALE)]
        )
        .unwrap(),
        JsValue::Str("el".into())
    );
}

#[test]
fn string_split() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeSplit,
        "a,b,c",
        &[JsValue::Str(",".into())],
    )
    .unwrap();
    assert!(matches!(result, JsValue::Str(_)));
}

#[test]
fn string_concat() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeConcat,
            "hello",
            &[JsValue::Str(" world".into())]
        )
        .unwrap(),
        JsValue::Str("hello world".into())
    );
}

// ---------------------------------------------------------------------------
// Number method tests
// ---------------------------------------------------------------------------

#[test]
fn number_is_finite() {
    // Static method — this_val is conventional 0.
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsFinite, 42 * FP_SCALE, &[]).unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn number_is_integer() {
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsInteger, 5 * FP_SCALE, &[]).unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsInteger, 5_500_000, &[]).unwrap(),
        JsValue::Bool(false)
    );
}

#[test]
fn number_is_nan() {
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsNaN, 0, &[]).unwrap(),
        JsValue::Bool(false)
    );
}

/// `Number.parseInt` is a static constructor method installed via `install_builtin_fn`,
/// not dispatched through `exec_number_method`. Verify it is installed on the constructor.
#[test]
fn number_parse_int_installed_on_constructor() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let prop = heap
        .get_property(number_ctor, &PropertyKey::from("parseInt"))
        .unwrap();
    assert!(
        matches!(prop, JsValue::Function(_)),
        "Number.parseInt should be installed as a Function on the constructor"
    );
}

/// `Number.parseFloat` is a static constructor method installed via `install_builtin_fn`,
/// not dispatched through `exec_number_method`. Verify it is installed on the constructor.
#[test]
fn number_parse_float_installed_on_constructor() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let prop = heap
        .get_property(number_ctor, &PropertyKey::from("parseFloat"))
        .unwrap();
    assert!(
        matches!(prop, JsValue::Function(_)),
        "Number.parseFloat should be installed as a Function on the constructor"
    );
}

// ---------------------------------------------------------------------------
// JSON tests
// ---------------------------------------------------------------------------

#[test]
fn json_stringify_null() {
    assert_eq!(
        json_stringify(&JsValue::Null).unwrap(),
        JsValue::Str("null".into())
    );
}

#[test]
fn json_stringify_bool() {
    assert_eq!(
        json_stringify(&JsValue::Bool(true)).unwrap(),
        JsValue::Str("true".into())
    );
    assert_eq!(
        json_stringify(&JsValue::Bool(false)).unwrap(),
        JsValue::Str("false".into())
    );
}

#[test]
fn json_stringify_int() {
    assert_eq!(
        json_stringify(&JsValue::Int(42 * FP_SCALE)).unwrap(),
        JsValue::Str("42".into())
    );
    assert_eq!(
        json_stringify(&JsValue::Int(3_141_593)).unwrap(),
        JsValue::Str("3.141593".into())
    );
}

#[test]
fn json_stringify_string_with_escapes() {
    assert_eq!(
        json_stringify(&JsValue::Str("hello \"world\"".into())).unwrap(),
        JsValue::Str("\"hello \\\"world\\\"\"".into())
    );
    assert_eq!(
        json_stringify(&JsValue::Str("line\nnewline".into())).unwrap(),
        JsValue::Str("\"line\\nnewline\"".into())
    );
}

#[test]
fn json_stringify_undefined_returns_undefined() {
    assert_eq!(
        json_stringify(&JsValue::Undefined).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn json_parse_primitives() {
    assert_eq!(json_parse("null").unwrap(), JsValue::Null);
    assert_eq!(json_parse("true").unwrap(), JsValue::Bool(true));
    assert_eq!(json_parse("false").unwrap(), JsValue::Bool(false));
    assert_eq!(json_parse("42").unwrap(), JsValue::Int(42 * FP_SCALE));
}

#[test]
fn json_parse_string() {
    assert_eq!(
        json_parse("\"hello\"").unwrap(),
        JsValue::Str("hello".into())
    );
}

#[test]
fn json_parse_compound_returns_placeholder() {
    let result = json_parse("[1,2,3]").unwrap();
    assert!(matches!(result, JsValue::Str(s) if s.starts_with("[json-compound:")));
}

#[test]
fn json_parse_invalid_returns_error() {
    let result = json_parse("not_valid_json");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// StdlibError taxonomy
// ---------------------------------------------------------------------------

#[test]
fn stdlib_error_type_error_display() {
    let err = StdlibError::TypeError("bad argument".into());
    let msg = format!("{err}");
    assert!(msg.contains("TypeError"), "should contain TypeError");
    assert!(msg.contains("bad argument"), "should contain message");
}

#[test]
fn stdlib_error_arity_display() {
    let err = StdlibError::ArityError {
        builtin: "Array.from".into(),
        expected_min: 1,
        expected_max: 3,
        got: 0,
    };
    let msg = format!("{err}");
    assert!(msg.contains("Array.from"));
}

#[test]
fn stdlib_error_range_error_display() {
    let err = StdlibError::RangeError("out of range".into());
    let msg = format!("{err}");
    assert!(msg.contains("RangeError"));
}

// ---------------------------------------------------------------------------
// BuiltinId completeness and Display
// ---------------------------------------------------------------------------

#[test]
fn builtin_id_display_distinguishes_methods() {
    let cases = [
        (BuiltinId::MathAbs, "Math.abs"),
        (BuiltinId::ArrayPrototypePush, "Array.prototype.push"),
        (BuiltinId::ObjectKeys, "Object.keys"),
        (BuiltinId::StringPrototypeSlice, "String.prototype.slice"),
        (BuiltinId::JsonParse, "JSON.parse"),
        (BuiltinId::JsonStringify, "JSON.stringify"),
    ];
    for (id, expected) in cases {
        assert_eq!(
            format!("{id}"),
            expected,
            "BuiltinId::{id:?} should display as {expected}"
        );
    }
}

// ---------------------------------------------------------------------------
// Serde round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn builtin_id_serde_roundtrip() {
    let ids = [
        BuiltinId::MathAbs,
        BuiltinId::ArrayPrototypePush,
        BuiltinId::ObjectKeys,
        BuiltinId::JsonParse,
        BuiltinId::StringPrototypeCharAt,
        BuiltinId::NumberIsFinite,
    ];
    for id in ids {
        let json = serde_json::to_string(&id).unwrap();
        let back: BuiltinId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back, "serde roundtrip failed for {id:?}");
    }
}

#[test]
fn stdlib_error_serde_roundtrip() {
    let err = StdlibError::TypeError("test".into());
    let json = serde_json::to_string(&err).unwrap();
    let back: StdlibError = serde_json::from_str(&json).unwrap();
    assert_eq!(format!("{err}"), format!("{back}"));
}

#[test]
fn global_environment_serde_roundtrip() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let json = serde_json::to_string(&env).unwrap();
    let back: GlobalEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(env.registry.len(), back.registry.len());
}

// ---------------------------------------------------------------------------
// Determinism verification
// ---------------------------------------------------------------------------

#[test]
fn math_operations_deterministic_across_runs() {
    let ops: Vec<(BuiltinId, Vec<JsValue>)> = vec![
        (BuiltinId::MathAbs, vec![JsValue::Int(-42 * FP_SCALE)]),
        (
            BuiltinId::MathPow,
            vec![JsValue::Int(2 * FP_SCALE), JsValue::Int(10 * FP_SCALE)],
        ),
        (BuiltinId::MathCeil, vec![JsValue::Int(1_100_000)]),
        (BuiltinId::MathFloor, vec![JsValue::Int(1_900_000)]),
    ];

    for _ in 0..5 {
        for (op, args) in &ops {
            let r1 = exec_math(*op, args).unwrap();
            let r2 = exec_math(*op, args).unwrap();
            assert_eq!(r1, r2, "math op {op:?} not deterministic");
        }
    }
}

#[test]
fn string_operations_deterministic_across_runs() {
    for _ in 0..5 {
        let r1 =
            exec_string_method(BuiltinId::StringPrototypeToUpperCase, "determinism", &[]).unwrap();
        let r2 =
            exec_string_method(BuiltinId::StringPrototypeToUpperCase, "determinism", &[]).unwrap();
        assert_eq!(r1, r2);
    }
}

// ---------------------------------------------------------------------------
// Number constants via heap
// ---------------------------------------------------------------------------

#[test]
fn number_max_safe_integer_is_accessible() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let max_safe = heap
        .get_property(number_ctor, &PropertyKey::from("MAX_SAFE_INTEGER"))
        .unwrap();
    if let JsValue::Int(v) = max_safe {
        assert!(v > 0, "MAX_SAFE_INTEGER should be positive");
        assert_eq!(v % FP_SCALE, 0, "should be an exact integer in fixed-point");
    } else {
        panic!("MAX_SAFE_INTEGER should be a JsValue::Int");
    }
}

#[test]
fn number_epsilon_is_one() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let epsilon = heap
        .get_property(number_ctor, &PropertyKey::from("EPSILON"))
        .unwrap();
    assert_eq!(epsilon, JsValue::Int(1));
}
