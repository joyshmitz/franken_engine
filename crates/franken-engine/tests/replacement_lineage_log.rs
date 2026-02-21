use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{self, ObjectDomain};
use frankenengine_engine::replacement_lineage_log::{
    LineageLogConfig, LineageLogError, LineageQuery, ReplacementKind, ReplacementLineageLog,
    verify_consistency_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    ReplacementReceipt, SchemaVersion, SignatureBundle, ValidationArtifactKind,
    ValidationArtifactRef,
};
use frankenengine_engine::slot_registry::SlotId;

fn slot_id(name: &str) -> SlotId {
    SlotId::new(name).expect("valid slot id")
}

fn receipt(slot_name: &str, old: &str, new: &str, ts: u64) -> ReplacementReceipt {
    let sid = slot_id(slot_name);
    let receipt_id = engine_object_id::derive_id(
        ObjectDomain::CheckpointArtifact,
        "lineage-itest-zone",
        &engine_object_id::SchemaId::from_definition(b"lineage-itest-receipt"),
        &format!("{slot_name}|{old}|{new}|{ts}").into_bytes(),
    )
    .expect("derive receipt id");

    ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id: sid,
        old_cell_digest: old.to_string(),
        new_cell_digest: new.to_string(),
        validation_artifacts: vec![ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "itest-artifact".to_string(),
            passed: true,
            summary: "integration-test artifact".to_string(),
        }],
        rollback_token: format!("rollback-{old}"),
        promotion_rationale: "integration test".to_string(),
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(11),
        zone: "lineage-itest-zone".to_string(),
        signature_bundle: SignatureBundle::new(1),
    }
}

#[test]
fn checkpoint_consistency_proof_verifies_and_detects_tamper() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..6 {
        let r = receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .expect("append");
        if i == 2 || i == 5 {
            log.create_checkpoint(i * 100, SecurityEpoch::from_raw(11))
                .expect("checkpoint");
        }
    }

    let proof = log.consistency_proof(0, 1).expect("proof");
    assert!(verify_consistency_proof(&proof));

    let mut tampered = proof.clone();
    tampered.newer_entry_hashes[0] =
        frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered");
    assert!(!verify_consistency_proof(&tampered));
}

#[test]
fn verifier_surface_supports_lineage_verify_and_audit_workflow() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    log.append(
        receipt("slot-a", "delegate-v1", "native-v1", 100),
        ReplacementKind::DelegateToNative,
        100,
    )
    .expect("append");
    log.append(
        receipt("slot-a", "native-v1", "delegate-v1", 200),
        ReplacementKind::Demotion,
        200,
    )
    .expect("append");
    log.append(
        receipt("slot-a", "delegate-v1", "native-v2", 300),
        ReplacementKind::RePromotion,
        300,
    )
    .expect("append");
    log.append(
        receipt("slot-b", "delegate-b1", "native-b1", 400),
        ReplacementKind::DelegateToNative,
        400,
    )
    .expect("append");
    log.create_checkpoint(450, SecurityEpoch::from_raw(11))
        .expect("checkpoint");

    let verify = log.verify_slot_lineage(&slot_id("slot-a"));
    assert!(verify.chain_valid);
    assert_eq!(verify.total_entries, 3);
    assert!(verify.issues.is_empty());

    let lineage = log.slot_lineage(&slot_id("slot-a"));
    assert_eq!(lineage.len(), 3);
    assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(lineage[1].kind, ReplacementKind::Demotion);
    assert_eq!(lineage[2].kind, ReplacementKind::RePromotion);

    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_slots, 2);
    assert_eq!(audit.checkpoint_count, 1);
}

#[test]
fn serialized_roundtrip_preserves_query_and_audit_results() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        let kind = if i % 2 == 0 {
            ReplacementKind::DelegateToNative
        } else {
            ReplacementKind::Rollback
        };
        let r = receipt(
            "slot-a",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 100,
        );
        log.append(r, kind, (i + 1) * 100).expect("append");
    }
    log.create_checkpoint(600, SecurityEpoch::from_raw(11))
        .expect("checkpoint");

    let mut kinds = BTreeSet::new();
    kinds.insert(ReplacementKind::Rollback);
    let query = LineageQuery {
        slot_id: Some(slot_id("slot-a")),
        kinds: Some(kinds),
        min_timestamp_ns: Some(200),
        max_timestamp_ns: Some(500),
    };

    let before_count = log.query(&query).len();
    let before_audit = log.audit();

    let encoded = serde_json::to_vec(&log).expect("serialize log");
    let decoded: ReplacementLineageLog = serde_json::from_slice(&encoded).expect("deserialize log");

    assert_eq!(before_count, decoded.query(&query).len());
    assert_eq!(before_audit, decoded.audit());
}

#[test]
fn consistency_proof_requires_older_then_newer_checkpoint_order() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..2 {
        let r = receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .expect("append");
        log.create_checkpoint(i * 100, SecurityEpoch::from_raw(11))
            .expect("checkpoint");
    }

    let err = log
        .consistency_proof(1, 0)
        .expect_err("must reject reversed order");
    assert!(matches!(
        err,
        LineageLogError::InvalidCheckpointOrder { older: 1, newer: 0 }
    ));
}
