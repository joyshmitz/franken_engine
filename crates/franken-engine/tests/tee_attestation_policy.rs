use std::collections::BTreeMap;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, AttestationQuote, DecisionImpact, DecisionReceiptEmitter,
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, PolicyGovernanceEvent,
    RevocationFallback, RevocationProbeStatus, RevocationSource, RevocationSourceType,
    SignedTrustRootOverrideArtifact, TeeAttestationPolicy, TeeAttestationPolicyError,
    TeeAttestationPolicyStore, TeePlatform, TemporaryTrustRootOverride,
    TrustRootOverrideArtifactInput, TrustRootPinning, TrustRootSource,
};

fn digest_hex(byte: u8, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes * 2);
    for _ in 0..bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sample_policy(epoch: u64) -> TeeAttestationPolicy {
    let mut approved = BTreeMap::new();
    approved.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        }],
    );
    approved.insert(
        TeePlatform::ArmTrustZone,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        }],
    );
    approved.insert(
        TeePlatform::AmdSev,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        }],
    );

    TeeAttestationPolicy {
        schema_version: 1,
        policy_epoch: SecurityEpoch::from_raw(epoch),
        approved_measurements: approved,
        freshness_window: AttestationFreshnessWindow {
            standard_max_age_secs: 300,
            high_impact_max_age_secs: 60,
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
                root_id: "sgx-root-a".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----SGX-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "tz-root-a".to_string(),
                platform: TeePlatform::ArmTrustZone,
                trust_anchor_pem: "-----BEGIN CERT-----TZ-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "sev-root-a".to_string(),
                platform: TeePlatform::AmdSev,
                trust_anchor_pem: "-----BEGIN CERT-----SEV-A".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(0),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
        ],
    }
}

fn sgx_quote(trust_root_id: &str) -> AttestationQuote {
    let mut rev = BTreeMap::new();
    rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
    rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    AttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        },
        quote_age_secs: 8,
        trust_root_id: trust_root_id.to_string(),
        revocation_observations: rev,
    }
}

#[test]
fn policy_epoch_transition_requires_pickup_within_one_epoch_boundary() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(10), "trace-load-1", "decision-load-1")
        .expect("load epoch 10");

    let mut emitter = DecisionReceiptEmitter::new("emitter-a");
    emitter.sync_policy(&store).expect("initial sync");

    store
        .load_policy(sample_policy(11), "trace-load-2", "decision-load-2")
        .expect("load epoch 11");
    emitter
        .can_emit(SecurityEpoch::from_raw(11), &store)
        .expect("one-epoch lag is allowed");

    store
        .load_policy(sample_policy(12), "trace-load-3", "decision-load-3")
        .expect("load epoch 12");
    let err = emitter
        .can_emit(SecurityEpoch::from_raw(12), &store)
        .expect_err("two-epoch lag must be rejected");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::EmitterPolicyStale { .. }
    ));

    emitter.sync_policy(&store).expect("resync to epoch 12");
    emitter
        .can_emit(SecurityEpoch::from_raw(12), &store)
        .expect("resynced emitter should pass");
}

#[test]
fn parse_failure_halts_emission_fail_closed() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(2), "trace-load-ok", "decision-load-ok")
        .expect("valid baseline");

    let mut emitter = DecisionReceiptEmitter::new("emitter-b");
    emitter.sync_policy(&store).expect("sync baseline");
    emitter
        .can_emit(SecurityEpoch::from_raw(2), &store)
        .expect("baseline emit allowed");

    let err = store
        .load_policy_json(
            "{\"schema_version\":\"broken\"}",
            "trace-fail",
            "decision-fail",
        )
        .expect_err("parse should fail");
    assert_eq!(err.error_code(), "tee_policy_parse_failed");
    assert!(store.receipt_emission_halted());

    let err = emitter
        .can_emit(SecurityEpoch::from_raw(2), &store)
        .expect_err("emit blocked");
    assert!(matches!(
        err,
        TeeAttestationPolicyError::ReceiptEmissionHalted
    ));
}

#[test]
fn temporary_override_enables_new_root_for_quote_validation() {
    let mut store = TeeAttestationPolicyStore::default();
    store
        .load_policy(sample_policy(20), "trace-load-ovr", "decision-load-ovr")
        .expect("load epoch 20");

    let signer = SigningKey::from_bytes([19u8; 32]);
    let verifier = signer.verification_key();
    let artifact = SignedTrustRootOverrideArtifact::create_signed(
        &signer,
        TrustRootOverrideArtifactInput {
            actor: "operator-tee".to_string(),
            justification: "temporary SGX root during cert rollover".to_string(),
            evidence_refs: vec!["evidence-123".to_string()],
            target_platform: TeePlatform::IntelSgx,
            target_root_id: "sgx-root-temp".to_string(),
            issued_epoch: SecurityEpoch::from_raw(20),
            expires_epoch: SecurityEpoch::from_raw(22),
        },
    )
    .expect("signed override artifact");

    let request = TemporaryTrustRootOverride {
        override_id: "ovr-tee-1".to_string(),
        trust_root: PlatformTrustRoot {
            root_id: "sgx-root-temp".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(20),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-rollover".to_string(),
            },
            source: TrustRootSource::Policy,
        },
        artifact,
    };

    store
        .apply_temporary_trust_root_override(
            request,
            &verifier,
            SecurityEpoch::from_raw(20),
            "trace-apply-ovr",
            "decision-apply-ovr",
        )
        .expect("override apply");

    store
        .evaluate_quote(
            &sgx_quote("sgx-root-temp"),
            DecisionImpact::Standard,
            SecurityEpoch::from_raw(20),
            "trace-quote-ovr",
            "decision-quote-ovr",
        )
        .expect("new temporary root should verify");

    let events: &[PolicyGovernanceEvent] = store.governance_ledger();
    let has_override_event = events
        .iter()
        .any(|entry| entry.event == "temporary_trust_root_override_applied");
    assert!(has_override_event);
}
