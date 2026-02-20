use std::collections::BTreeMap;

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::proof_schema::{
    AttestationRequirementPolicy, AttestationValidityWindow, OptReceipt, OptimizationClass,
    ProofSchemaError, ReceiptAttestationBindings, ReceiptNonceRegistry, SchemaVersion,
    validate_receipt, validate_receipt_with_policy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tee_attestation_policy::DecisionImpact;

const TEST_KEY: &[u8] = b"integration-signing-key-32-bytes!!";

fn signer_key_id() -> EngineObjectId {
    derive_id(
        ObjectDomain::KeyBundle,
        "integration-zone",
        &SchemaId::from_definition(b"integration-signer"),
        b"key-material",
    )
    .expect("derive signer key id")
}

fn measurement_id() -> EngineObjectId {
    derive_id(
        ObjectDomain::Attestation,
        "integration-zone",
        &SchemaId::from_definition(b"integration-measurement"),
        b"measurement-material",
    )
    .expect("derive measurement id")
}

fn base_receipt(schema_version: SchemaVersion, impact: DecisionImpact) -> OptReceipt {
    OptReceipt {
        schema_version,
        optimization_id: "opt-attested-1".to_string(),
        optimization_class: OptimizationClass::TraceSpecialization,
        baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
        candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
        translation_witness_hash: ContentHash::compute(b"translation-witness"),
        invariance_digest: ContentHash::compute(b"invariance-digest"),
        rollback_token_id: "rtk-attested-1".to_string(),
        replay_compatibility: BTreeMap::from([
            ("engine_version".to_string(), "0.1.0".to_string()),
            ("target_arch".to_string(), "x86_64".to_string()),
        ]),
        policy_epoch: SecurityEpoch::from_raw(42),
        timestamp_ticks: 1_000,
        signer_key_id: signer_key_id(),
        correlation_id: "corr-attested-1".to_string(),
        decision_impact: impact,
        attestation_bindings: None,
        signature: AuthenticityHash::compute(b"placeholder"),
    }
}

fn attestation_bindings() -> ReceiptAttestationBindings {
    ReceiptAttestationBindings {
        quote_digest: ContentHash::compute(b"full-tee-quote"),
        measurement_id: measurement_id(),
        attested_signer_key_id: signer_key_id(),
        nonce: [11u8; 32],
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 900,
            end_timestamp_ticks: 1_500,
        },
    }
}

#[test]
fn attested_receipt_round_trip_through_transparency_log_and_verifier() {
    let mut receipt = base_receipt(SchemaVersion::CURRENT, DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let transparency_log = [serde_json::to_vec(&signed).expect("serialize receipt")];

    let restored: OptReceipt =
        serde_json::from_slice(transparency_log.last().expect("entry")).expect("deserialize");
    let mut nonce_registry = ReceiptNonceRegistry::new();
    let result = validate_receipt_with_policy(
        &restored,
        TEST_KEY,
        SecurityEpoch::from_raw(42),
        &AttestationRequirementPolicy::default(),
        Some(&mut nonce_registry),
    );
    assert!(result.is_ok());
}

#[test]
fn verifier_rejects_tampered_attestation_binding() {
    let mut receipt = base_receipt(SchemaVersion::CURRENT, DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let mut signed = receipt.sign(TEST_KEY);
    signed.attestation_bindings.as_mut().unwrap().quote_digest = ContentHash::compute(b"tampered");

    assert!(matches!(
        validate_receipt_with_policy(
            &signed,
            TEST_KEY,
            SecurityEpoch::from_raw(42),
            &AttestationRequirementPolicy::default(),
            None,
        ),
        Err(ProofSchemaError::InvalidSignature { .. })
    ));
}

#[test]
fn legacy_format_receipt_parseable_and_distinguishable() {
    let legacy = base_receipt(SchemaVersion::V1_0, DecisionImpact::Standard).sign(TEST_KEY);
    let mut legacy_json_value = serde_json::to_value(&legacy).expect("to value");
    let serde_json::Value::Object(ref mut map) = legacy_json_value else {
        panic!("expected object");
    };
    map.remove("decision_impact");
    map.remove("attestation_bindings");
    let legacy_json = serde_json::to_string(&legacy_json_value).expect("to json");

    let parsed_legacy: OptReceipt = serde_json::from_str(&legacy_json).expect("parse legacy");
    assert_eq!(parsed_legacy.schema_version, SchemaVersion::V1_0);
    assert_eq!(parsed_legacy.decision_impact, DecisionImpact::Standard);
    assert!(parsed_legacy.attestation_bindings.is_none());
    assert!(validate_receipt(&parsed_legacy, TEST_KEY, SecurityEpoch::from_raw(42)).is_ok());

    let mut attested = base_receipt(SchemaVersion::CURRENT, DecisionImpact::HighImpact);
    attested.attestation_bindings = Some(attestation_bindings());
    let attested = attested.sign(TEST_KEY);
    assert_ne!(parsed_legacy.schema_version, attested.schema_version);
    assert!(attested.attestation_bindings.is_some());
}

#[test]
fn serialization_is_byte_identical_for_identical_inputs() {
    let mut receipt = base_receipt(SchemaVersion::CURRENT, DecisionImpact::HighImpact);
    receipt.attestation_bindings = Some(attestation_bindings());
    let signed = receipt.sign(TEST_KEY);

    let a = serde_json::to_vec(&signed).expect("serialize");
    let b = serde_json::to_vec(&signed).expect("serialize");
    assert_eq!(a, b);
}
