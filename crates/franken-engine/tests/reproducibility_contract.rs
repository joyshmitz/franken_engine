use serde_json::Value;
use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_file(path: &str) -> String {
    let file_path = repo_root().join(path);
    fs::read_to_string(&file_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", file_path.display()))
}

fn parse_json_file(path: &str) -> Value {
    let raw = read_file(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("{path} must be valid JSON template: {err}"))
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .unwrap_or_else(|| panic!("missing required path `{}`", path.join(".")));
    }
    current
}

fn assert_string_field(value: &Value, path: &[&str]) {
    assert!(
        value_at_path(value, path).as_str().is_some(),
        "expected string at `{}`",
        path.join(".")
    );
}

fn assert_bool_field(value: &Value, path: &[&str]) {
    assert!(
        value_at_path(value, path).as_bool().is_some(),
        "expected bool at `{}`",
        path.join(".")
    );
}

fn assert_array_field(value: &Value, path: &[&str]) {
    assert!(
        value_at_path(value, path).as_array().is_some(),
        "expected array at `{}`",
        path.join(".")
    );
}

fn canonicalize_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).expect("json string serialization"),
        Value::Array(items) => {
            let canonical_items: Vec<String> = items.iter().map(canonicalize_json).collect();
            format!("[{}]", canonical_items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let key_json = serde_json::to_string(key).expect("json key serialization");
                let value_json = canonicalize_json(map.get(key).expect("key from map.keys exists"));
                parts.push(format!("{key_json}:{value_json}"));
            }
            format!("{{{}}}", parts.join(","))
        }
    }
}

#[test]
fn reproducibility_contract_doc_contains_required_sections() {
    let doc = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let required_sections = [
        "## Artifact Schema Contracts",
        "## Version Compatibility Policy",
        "## Canonical Serialization and Hash Boundaries",
        "## Provenance Linkage Rules",
        "## Deterministic Validation CLI/API Contract",
        "## Fail-Closed and Degraded Mode Policy",
        "## CI Publication Gate Contract",
        "## Neutral Verifier Flow",
        "## Retention and Rotation Policy",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "reproducibility contract doc must include section: {section}"
        );
    }
}

#[test]
fn reproducibility_contract_doc_declares_stable_error_codes() {
    let doc = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let required_codes = [
        "FE-REPRO-0001",
        "FE-REPRO-0002",
        "FE-REPRO-0003",
        "FE-REPRO-0004",
        "FE-REPRO-0005",
        "FE-REPRO-0006",
        "FE-REPRO-0007",
        "FE-REPRO-0008",
    ];

    for code in required_codes {
        assert!(
            doc.contains(code),
            "reproducibility contract must include stable error code: {code}"
        );
    }
}

#[test]
fn template_guide_declares_validator_and_ci_gate_behavior() {
    let guide = read_file("docs/REPRODUCIBILITY_CONTRACT_TEMPLATE.md");
    let required_clauses = [
        "frankenctl repro verify --bundle",
        "## Validator Contract (Deterministic)",
        "## CI Gate Contract",
        "## Fail-Closed and Degraded Mode",
        "## Schema Compatibility Rules",
    ];

    for clause in required_clauses {
        assert!(
            guide.contains(clause),
            "template guide must include clause: {clause}"
        );
    }
}

#[test]
fn env_template_has_required_contract_fields() {
    let env = parse_json_file("docs/templates/env.json.template");

    assert_eq!(
        value_at_path(&env, &["schema_version"])
            .as_str()
            .expect("schema_version is string"),
        "franken-engine.env.v1"
    );

    assert_string_field(&env, &["schema_hash"]);
    assert_string_field(&env, &["captured_at_utc"]);
    assert_string_field(&env, &["project", "name"]);
    assert_string_field(&env, &["project", "commit"]);
    assert_string_field(&env, &["host", "arch"]);
    assert_string_field(&env, &["toolchain", "rustc"]);
    assert_string_field(&env, &["runtime", "mode"]);
    assert_bool_field(&env, &["runtime", "safe_mode_enabled"]);
    assert_array_field(&env, &["runtime", "feature_flags"]);
    assert_string_field(&env, &["policy", "policy_id"]);
    assert_string_field(&env, &["policy", "policy_digest_sha256"]);
}

#[test]
fn manifest_template_has_provenance_and_retention_fields() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");

    assert_eq!(
        value_at_path(&manifest, &["schema_version"])
            .as_str()
            .expect("schema_version is string"),
        "franken-engine.manifest.v1"
    );

    assert_string_field(&manifest, &["schema_hash"]);
    assert_string_field(&manifest, &["manifest_id"]);
    assert_string_field(&manifest, &["claim", "claim_id"]);
    assert_string_field(&manifest, &["claim", "class"]);
    assert_string_field(&manifest, &["provenance", "trace_id"]);
    assert_string_field(&manifest, &["provenance", "decision_id"]);
    assert_string_field(&manifest, &["provenance", "policy_id"]);
    assert_string_field(&manifest, &["provenance", "replay_pointer"]);
    assert_string_field(&manifest, &["provenance", "evidence_pointer"]);
    assert_array_field(&manifest, &["provenance", "receipt_ids"]);
    assert_string_field(&manifest, &["canonicalization", "hash_algorithm"]);
    assert_string_field(&manifest, &["validation", "validator"]);
    assert_string_field(&manifest, &["validation", "error_taxonomy"]);
    assert_string_field(&manifest, &["retention", "rotation_policy"]);
}

#[test]
fn repro_lock_template_has_deterministic_verifier_contract_fields() {
    let lock = parse_json_file("docs/templates/repro.lock.template");

    assert_eq!(
        value_at_path(&lock, &["schema_version"])
            .as_str()
            .expect("schema_version is string"),
        "franken-engine.repro-lock.v1"
    );

    assert_string_field(&lock, &["schema_hash"]);
    assert_string_field(&lock, &["lock_id"]);
    assert_string_field(&lock, &["manifest_id"]);
    assert_bool_field(&lock, &["determinism", "allow_network"]);
    assert_bool_field(&lock, &["determinism", "allow_wall_clock"]);
    assert_bool_field(&lock, &["determinism", "allow_randomness"]);
    assert_array_field(&lock, &["commands"]);
    assert_array_field(&lock, &["inputs"]);
    assert_array_field(&lock, &["expected_outputs"]);
    assert_string_field(&lock, &["replay", "trace_id"]);
    assert_string_field(&lock, &["replay", "replay_pointer"]);
    assert_string_field(&lock, &["verification", "command"]);
    assert_string_field(&lock, &["verification", "expected_verdict"]);

    let verify_command = value_at_path(&lock, &["verification", "command"])
        .as_str()
        .expect("verification.command is string");
    assert!(
        verify_command.contains("frankenctl repro verify --bundle"),
        "verification command must use one-command verifier flow"
    );
}

#[test]
fn json_templates_are_canonicalization_stable() {
    let template_paths = [
        "docs/templates/env.json.template",
        "docs/templates/manifest.json.template",
        "docs/templates/repro.lock.template",
    ];

    for path in template_paths {
        let value = parse_json_file(path);
        let canonical_once = canonicalize_json(&value);
        let reparsed: Value = serde_json::from_str(&canonical_once)
            .unwrap_or_else(|err| panic!("canonical JSON for {path} must parse: {err}"));
        let canonical_twice = canonicalize_json(&reparsed);
        assert_eq!(
            canonical_once, canonical_twice,
            "canonicalization must be stable for {path}"
        );
    }
}

// ---------- read_file helper ----------

#[test]
fn read_file_returns_nonempty() {
    let content = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    assert!(!content.is_empty());
}

// ---------- parse_json_file helper ----------

#[test]
fn parse_json_file_returns_valid_value() {
    let value = parse_json_file("docs/templates/env.json.template");
    assert!(value.is_object());
}

// ---------- value_at_path ----------

#[test]
fn value_at_path_navigates_nested() {
    let value: Value = serde_json::json!({
        "a": { "b": { "c": "deep" } }
    });
    let result = value_at_path(&value, &["a", "b", "c"]);
    assert_eq!(result.as_str(), Some("deep"));
}

// ---------- canonicalize_json ----------

#[test]
fn canonicalize_json_null() {
    assert_eq!(canonicalize_json(&Value::Null), "null");
}

#[test]
fn canonicalize_json_bool() {
    assert_eq!(canonicalize_json(&Value::Bool(true)), "true");
    assert_eq!(canonicalize_json(&Value::Bool(false)), "false");
}

#[test]
fn canonicalize_json_string() {
    let val = Value::String("hello".to_string());
    assert_eq!(canonicalize_json(&val), "\"hello\"");
}

#[test]
fn canonicalize_json_array() {
    let val: Value = serde_json::json!([1, 2, 3]);
    let result = canonicalize_json(&val);
    assert_eq!(result, "[1,2,3]");
}

#[test]
fn canonicalize_json_object_sorts_keys() {
    let val: Value = serde_json::json!({"z": 1, "a": 2});
    let result = canonicalize_json(&val);
    assert!(result.starts_with("{\"a\":2"));
}

#[test]
fn canonicalize_json_is_idempotent() {
    let val: Value = serde_json::json!({"b": [1, null], "a": true});
    let once = canonicalize_json(&val);
    let reparsed: Value = serde_json::from_str(&once).expect("parse");
    let twice = canonicalize_json(&reparsed);
    assert_eq!(once, twice);
}

// ---------- assert helpers ----------

#[test]
fn assert_string_field_passes_for_string() {
    let val: Value = serde_json::json!({"key": "value"});
    assert_string_field(&val, &["key"]);
}

#[test]
fn assert_bool_field_passes_for_bool() {
    let val: Value = serde_json::json!({"flag": true});
    assert_bool_field(&val, &["flag"]);
}

#[test]
fn assert_array_field_passes_for_array() {
    let val: Value = serde_json::json!({"items": [1, 2]});
    assert_array_field(&val, &["items"]);
}

#[test]
fn canonicalize_json_deterministic_for_same_input() {
    let val: Value = serde_json::json!({"b": 2, "a": 1});
    let a = canonicalize_json(&val);
    let b = canonicalize_json(&val);
    assert_eq!(a, b);
}

#[test]
fn read_file_returns_nonempty_for_contract() {
    let content = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    assert!(!content.is_empty());
}

#[test]
fn parse_json_template_returns_object() {
    let val = parse_json_file("docs/templates/env.json.template");
    assert!(val.is_object());
}
