use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::attested_execution_cell::{
    SoftwareTrustRoot, TrustLevel, TrustRootBackend,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::mmr_proof::MerkleMountainRange;
use frankenengine_engine::proof_schema::{
    AttestationValidityWindow, OptReceipt, OptimizationClass, ReceiptAttestationBindings,
    proof_schema_version_current,
};
use frankenengine_engine::receipt_verifier_pipeline::{
    AttestationLayerInput, ConsistencyProofInput, LogOperatorKey, ReceiptVerifierCliInput,
    SignatureLayerInput, SignedLogCheckpoint, SignerRevocationCache, TransparencyLayerInput,
    UnifiedReceiptVerificationRequest,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{Signature, SigningKey, sign_preimage};
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, AttestationQuote as PolicyAttestationQuote, DecisionImpact,
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, RevocationFallback,
    RevocationProbeStatus, RevocationSource, RevocationSourceType, TeeAttestationPolicy,
    TeePlatform, TrustRootPinning, TrustRootSource,
};

fn digest_hex(byte: u8, byte_len: usize) -> String {
    let mut out = String::with_capacity(byte_len * 2);
    for _ in 0..byte_len {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sample_policy(
    policy_epoch: SecurityEpoch,
    intel_digest_hex: String,
    trust_root_id: &str,
) -> TeeAttestationPolicy {
    let mut approved_measurements = BTreeMap::new();
    approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: intel_digest_hex,
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmTrustZone,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmCca,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::AmdSev,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        }],
    );

    TeeAttestationPolicy {
        schema_version: 1,
        policy_epoch,
        approved_measurements,
        freshness_window: AttestationFreshnessWindow {
            standard_max_age_secs: 120,
            high_impact_max_age_secs: 30,
        },
        revocation_sources: vec![
            RevocationSource {
                source_id: "intel_pcs".to_string(),
                source_type: RevocationSourceType::IntelPcs,
                endpoint: "https://intel.example/pcs".to_string(),
                on_unavailable: RevocationFallback::TryNextSource,
            },
            RevocationSource {
                source_id: "internal_ledger".to_string(),
                source_type: RevocationSourceType::InternalLedger,
                endpoint: "sqlite://revocations".to_string(),
                on_unavailable: RevocationFallback::FailClosed,
            },
        ],
        platform_trust_roots: vec![
            PlatformTrustRoot {
                root_id: trust_root_id.to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN KEY-----intel-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "arm-root".to_string(),
                platform: TeePlatform::ArmTrustZone,
                trust_anchor_pem: "-----BEGIN KEY-----arm-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "cca-root".to_string(),
                platform: TeePlatform::ArmCca,
                trust_anchor_pem: "-----BEGIN KEY-----cca-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "amd-root".to_string(),
                platform: TeePlatform::AmdSev,
                trust_anchor_pem: "-----BEGIN KEY-----amd-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
        ],
    }
}

fn build_cli_input(wrong_signature_key: bool) -> ReceiptVerifierCliInput {
    let receipt_id = "rcpt-001".to_string();
    let signer_key_id = EngineObjectId([0x44; 32]);
    let signer_key_bytes = vec![0x55; 32];

    let software_root = SoftwareTrustRoot::new("root-1", 7);
    let measurement = software_root.measure(
        b"code-v1",
        b"cfg-v1",
        b"policy-v1",
        b"schema-v1",
        "runtime-v1",
    );
    let nonce = [7u8; 32];
    let mut attestation_quote = software_root.attest(&measurement, nonce, 30_000_000_000);
    attestation_quote.issued_at_ns = 10_000_000_000;
    attestation_quote.trust_level = TrustLevel::SoftwareOnly;

    let measurement_zone = "measurement-zone-test".to_string();
    let measurement_id = measurement
        .derive_id(&measurement_zone)
        .expect("measurement ID");
    let quote_digest =
        ContentHash::compute(&serde_json::to_vec(&attestation_quote).expect("quote json"));

    let mut replay_compatibility = BTreeMap::new();
    replay_compatibility.insert("arch".to_string(), "x86_64".to_string());
    replay_compatibility.insert("engine".to_string(), "franken-v1".to_string());

    let bindings = ReceiptAttestationBindings {
        quote_digest,
        measurement_id,
        attested_signer_key_id: signer_key_id.clone(),
        nonce,
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 100,
            end_timestamp_ticks: 2_000,
        },
    };

    let unsigned_receipt = OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-01".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline"),
        candidate_ir_hash: ContentHash::compute(b"candidate"),
        translation_witness_hash: ContentHash::compute(b"translation"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: "rollback-01".to_string(),
        replay_compatibility,
        policy_epoch: SecurityEpoch::from_raw(5),
        timestamp_ticks: 1_000,
        signer_key_id: signer_key_id.clone(),
        correlation_id: "corr-01".to_string(),
        decision_impact: DecisionImpact::HighImpact,
        attestation_bindings: Some(bindings),
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
    };
    let receipt = unsigned_receipt.sign(&signer_key_bytes);
    let expected_preimage_hash = ContentHash::compute(&receipt.signing_preimage());

    let receipt_leaf_hash = ContentHash::compute(&receipt.signing_preimage());
    let leaf0 = ContentHash::compute(b"leaf0");
    let leaf1 = ContentHash::compute(b"leaf1");

    let mut old_mmr = MerkleMountainRange::new(5);
    old_mmr.append(leaf0.clone());
    old_mmr.append(leaf1.clone());
    let old_root = old_mmr.root_hash().expect("old root");

    let mut mmr = MerkleMountainRange::new(5);
    mmr.append(leaf0);
    mmr.append(leaf1);
    mmr.append(receipt_leaf_hash.clone());
    let inclusion_proof = mmr.inclusion_proof(2).expect("inclusion");
    let consistency_proof = mmr.consistency_proof(2).expect("consistency");
    let current_root = mmr.root_hash().expect("root");

    let operator_signing_key = SigningKey::from_bytes([9u8; 32]);
    let operator_verification_key = operator_signing_key.verification_key();
    let checkpoint_stub = SignedLogCheckpoint {
        checkpoint_seq: 1,
        log_length: inclusion_proof.stream_length,
        root_hash: current_root,
        timestamp_ns: 20_000_000_000,
        operator_key_id: "operator-1".to_string(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let mut checkpoint = checkpoint_stub.clone();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"FrankenEngine.ReceiptTransparencyCheckpoint.v1");
    preimage.extend_from_slice(&checkpoint_stub.checkpoint_seq.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.log_length.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.root_hash.as_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.timestamp_ns.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.operator_key_id.as_bytes());
    checkpoint.signature = sign_preimage(&operator_signing_key, &preimage).expect("checkpoint sig");

    let measurement_digest_hex = measurement.composite_hash().to_hex();
    let policy = sample_policy(SecurityEpoch::from_raw(5), measurement_digest_hex, "root-1");
    let mut revocation_observations = BTreeMap::new();
    revocation_observations.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    revocation_observations.insert(
        "internal_ledger".to_string(),
        RevocationProbeStatus::Unavailable,
    );
    let policy_quote = PolicyAttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: measurement.composite_hash().to_hex(),
        },
        quote_age_secs: 10,
        trust_root_id: "root-1".to_string(),
        revocation_observations,
    };

    let mut receipts = BTreeMap::new();
    receipts.insert(
        receipt_id,
        UnifiedReceiptVerificationRequest {
            trace_id: "trace-verify-01".to_string(),
            decision_id: "decision-verify-01".to_string(),
            policy_id: "policy-verify-01".to_string(),
            verification_timestamp_ns: 20_000_000_000,
            receipt,
            signature: SignatureLayerInput {
                expected_preimage_hash,
                signing_key_bytes: if wrong_signature_key {
                    vec![1u8; 32]
                } else {
                    signer_key_bytes
                },
                signer_revocation: SignerRevocationCache {
                    signer_key_id,
                    source: "offline-signer-revocations".to_string(),
                    is_revoked: false,
                    cache_stale: false,
                },
            },
            transparency: TransparencyLayerInput {
                leaf_hash: receipt_leaf_hash,
                leaf_index: 2,
                inclusion_proof,
                consistency_proofs: vec![ConsistencyProofInput {
                    from_root: old_root,
                    proof: consistency_proof,
                }],
                checkpoint,
                operator_keys: vec![LogOperatorKey {
                    key_id: "operator-1".to_string(),
                    verification_key: operator_verification_key,
                    revoked: false,
                }],
                cache_stale: false,
            },
            attestation: AttestationLayerInput {
                attestation_quote,
                policy_quote,
                policy,
                decision_impact: DecisionImpact::HighImpact,
                runtime_epoch: SecurityEpoch::from_raw(5),
                verification_time_ns: 20_000_000_000,
                measurement_zone,
                trust_roots: vec![software_root],
                policy_cache_stale: false,
                revocation_cache_stale: false,
            },
        },
    );

    ReceiptVerifierCliInput { receipts }
}

fn write_input_file(input: &ReceiptVerifierCliInput) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!(
        "receipt_verifier_pipeline_test_{}_{}.json",
        std::process::id(),
        nonce
    ));
    fs::write(
        &path,
        serde_json::to_vec_pretty(input).expect("input serialization"),
    )
    .expect("input write");
    path
}

#[test]
fn franken_verify_receipt_command_succeeds_for_valid_input() {
    let input = build_cli_input(false);
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "receipt",
            "rcpt-001",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("command executes");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("receipt=rcpt-001"));
    assert!(stdout.contains("passed=true"));
    assert!(stdout.contains("exit_code=0"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_receipt_command_returns_signature_failure_exit_code() {
    let input = build_cli_input(true);
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "receipt",
            "rcpt-001",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("command executes");

    assert_eq!(output.status.code(), Some(20));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("passed=false"));
    assert!(stdout.contains("failure_class=signature"));

    let _ = fs::remove_file(input_path);
}
