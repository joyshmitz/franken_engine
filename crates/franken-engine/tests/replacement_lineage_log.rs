use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{self, ObjectDomain};
use frankenengine_engine::replacement_lineage_log::{
    DemotionReceiptInput, EvidenceCategory, EvidencePointerInput, LineageLogConfig,
    LineageLogError, LineageQuery, ReplacementKind, ReplacementLineageEvidenceIndex,
    ReplacementLineageLog, ReplayJoinQuery, SlotLineageQuery, verify_consistency_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    ReplacementReceipt, SchemaVersion, SignatureBundle, ValidationArtifactKind,
    ValidationArtifactRef,
};
use frankenengine_engine::slot_registry::SlotId;
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

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

fn index_context() -> EventContext {
    EventContext::new(
        "trace-lineage-index",
        "decision-lineage-index",
        "policy-lineage-index",
    )
    .expect("context")
}

fn replacement_receipt_id_hex(receipt: &ReplacementReceipt) -> String {
    hex::encode(receipt.receipt_id.as_bytes())
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

#[test]
fn lineage_index_supports_content_address_lookup_and_ordered_slot_chain() {
    let context = index_context();
    let adapter = InMemoryStorageAdapter::new();
    let mut index = ReplacementLineageEvidenceIndex::new(adapter);

    let r1 = receipt("slot-x", "delegate-v1", "native-v1", 100);
    let r2 = receipt("slot-x", "native-v1", "native-v2", 300);
    let replacement_1 = index
        .index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &context)
        .expect("index replacement r1");
    let replacement_2 = index
        .index_replacement_receipt(
            &r2,
            ReplacementKind::RePromotion,
            &[EvidencePointerInput {
                category: EvidenceCategory::SentinelRiskScore,
                artifact_digest: "risk-300".to_string(),
                passed: Some(true),
                summary: "risk remains inside envelope".to_string(),
            }],
            &context,
        )
        .expect("index replacement r2");

    let demotion = index
        .index_demotion_receipt(
            DemotionReceiptInput {
                receipt_id: "demotion-slot-x-1".to_string(),
                slot_id: slot_id("slot-x"),
                demoted_cell_digest: "native-v2".to_string(),
                restored_cell_digest: "native-v1".to_string(),
                demotion_reason: "semantic_divergence".to_string(),
                timestamp_ns: 450,
                rollback_token_used: "rollback-native-v1".to_string(),
                linked_replacement_receipt_id: Some(replacement_2.receipt_id.clone()),
                evidence: vec![EvidencePointerInput {
                    category: EvidenceCategory::DifferentialExecutionLog,
                    artifact_digest: "divergence-slot-x-1".to_string(),
                    passed: Some(false),
                    summary: "burn-in divergence on canonical scenario".to_string(),
                }],
            },
            &context,
        )
        .expect("index demotion");

    let loaded_r1 = index
        .replacement_by_content_hash(&replacement_1.receipt_content_hash, &context)
        .expect("lookup replacement by hash")
        .expect("replacement exists");
    assert_eq!(loaded_r1.receipt_id, replacement_1.receipt_id);
    assert_eq!(loaded_r1.slot_id, slot_id("slot-x"));
    assert_eq!(loaded_r1.receipt_id, replacement_receipt_id_hex(&r1));

    let loaded_demotion = index
        .demotion_by_content_hash(&demotion.receipt_content_hash, &context)
        .expect("lookup demotion by hash")
        .expect("demotion exists");
    assert_eq!(loaded_demotion.receipt_id, "demotion-slot-x-1");
    assert_eq!(loaded_demotion.demotion_reason, "semantic_divergence");

    let chain = index
        .slot_lineage(
            &slot_id("slot-x"),
            &SlotLineageQuery {
                min_timestamp_ns: Some(100),
                max_timestamp_ns: Some(500),
                limit: None,
            },
            &context,
        )
        .expect("slot lineage");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].timestamp_ns, 100);
    assert_eq!(chain[1].timestamp_ns, 300);
    assert_eq!(chain[2].timestamp_ns, 450);
    assert_eq!(chain[2].kind, ReplacementKind::Demotion);
}

#[test]
fn replay_join_includes_demotion_and_evidence_categories() {
    let context = index_context();
    let adapter = InMemoryStorageAdapter::new();
    let mut index = ReplacementLineageEvidenceIndex::new(adapter);

    let replacement_receipt = receipt("slot-r", "delegate-r1", "native-r1", 120);
    let replacement_record = index
        .index_replacement_receipt(
            &replacement_receipt,
            ReplacementKind::DelegateToNative,
            &[
                EvidencePointerInput {
                    category: EvidenceCategory::GateResult,
                    artifact_digest: "gate-r1".to_string(),
                    passed: Some(true),
                    summary: "promotion gate passed".to_string(),
                },
                EvidencePointerInput {
                    category: EvidenceCategory::SentinelRiskScore,
                    artifact_digest: "risk-r1".to_string(),
                    passed: Some(true),
                    summary: "risk posterior below threshold".to_string(),
                },
                EvidencePointerInput {
                    category: EvidenceCategory::Additional,
                    artifact_digest: "operator-note-r1".to_string(),
                    passed: None,
                    summary: "operator attached note".to_string(),
                },
            ],
            &context,
        )
        .expect("index replacement");

    index
        .index_demotion_receipt(
            DemotionReceiptInput {
                receipt_id: "demotion-slot-r-1".to_string(),
                slot_id: slot_id("slot-r"),
                demoted_cell_digest: "native-r1".to_string(),
                restored_cell_digest: "delegate-r1".to_string(),
                demotion_reason: "risk_threshold_breach".to_string(),
                timestamp_ns: 180,
                rollback_token_used: "rollback-r1".to_string(),
                linked_replacement_receipt_id: Some(replacement_record.receipt_id.clone()),
                evidence: vec![
                    EvidencePointerInput {
                        category: EvidenceCategory::SentinelRiskScore,
                        artifact_digest: "risk-breach-r1".to_string(),
                        passed: Some(false),
                        summary: "risk above threshold".to_string(),
                    },
                    EvidencePointerInput {
                        category: EvidenceCategory::DifferentialExecutionLog,
                        artifact_digest: "diff-r1".to_string(),
                        passed: Some(false),
                        summary: "output mismatch".to_string(),
                    },
                ],
            },
            &context,
        )
        .expect("index demotion");

    let rows = index
        .replay_join(
            &ReplayJoinQuery {
                slot_id: Some(slot_id("slot-r")),
                min_timestamp_ns: None,
                max_timestamp_ns: None,
                limit: None,
            },
            &context,
        )
        .expect("replay join");

    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.slot_id, slot_id("slot-r"));
    assert_eq!(row.replacement_receipt_id, replacement_record.receipt_id);
    assert_eq!(
        row.demotion_reason.as_deref(),
        Some("risk_threshold_breach")
    );
    assert_eq!(row.gate_results.len(), 1);
    assert_eq!(row.performance_benchmarks.len(), 0);
    assert_eq!(row.sentinel_risk_scores.len(), 2);
    assert_eq!(row.differential_execution_logs.len(), 2);
    assert_eq!(row.additional_evidence.len(), 1);
}

#[test]
fn replay_join_order_is_deterministic_across_ingest_order() {
    let context = index_context();

    let mut index_a = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let mut index_b = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());

    let r1 = receipt("slot-d", "delegate-a", "native-a", 200);
    let r2 = receipt("slot-d", "native-a", "native-b", 100);

    index_a
        .index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &context)
        .expect("index_a r1");
    index_a
        .index_replacement_receipt(&r2, ReplacementKind::RePromotion, &[], &context)
        .expect("index_a r2");

    index_b
        .index_replacement_receipt(&r2, ReplacementKind::RePromotion, &[], &context)
        .expect("index_b r2");
    index_b
        .index_replacement_receipt(&r1, ReplacementKind::DelegateToNative, &[], &context)
        .expect("index_b r1");

    let rows_a = index_a
        .replay_join(&ReplayJoinQuery::default(), &context)
        .expect("rows_a");
    let rows_b = index_b
        .replay_join(&ReplayJoinQuery::default(), &context)
        .expect("rows_b");
    assert_eq!(rows_a, rows_b);
    assert_eq!(rows_a.len(), 2);
    assert!(rows_a[0].promotion_timestamp_ns <= rows_a[1].promotion_timestamp_ns);
}
