use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::capability_witness::{
    CapabilityWitness, ConfidenceInterval, LifecycleState, PromotionTheoremInput, ProofKind,
    ProofObligation, PublicationEntryKind, SourceCapabilitySet, WitnessBuilder,
    WitnessPublicationConfig, WitnessPublicationError, WitnessPublicationEvent,
    WitnessPublicationPipeline, WitnessPublicationQuery,
};
use frankenengine_engine::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};

fn synthesizer_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(13).wrapping_add(7);
    }
    SigningKey::from_bytes(bytes)
}

fn tree_head_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x44; 32])
}

fn extension_id(seed: u64) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "witness-publication-test-extension",
        &SchemaId::from_definition(b"WitnessPublicationTestExtension.v1"),
        &seed.to_be_bytes(),
    )
    .expect("derive extension id")
}

fn policy_id() -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "witness-publication-test-policy",
        &SchemaId::from_definition(b"WitnessPublicationTestPolicy.v1"),
        b"policy-main",
    )
    .expect("derive policy id")
}

fn proof_artifact_id(seed: u64) -> EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "witness-publication-test-proof",
        &SchemaId::from_definition(b"WitnessPublicationTestProof.v1"),
        &seed.to_be_bytes(),
    )
    .expect("derive proof id")
}

fn make_proof(seed: u64, capability: &Capability) -> ProofObligation {
    ProofObligation {
        capability: capability.clone(),
        kind: ProofKind::DynamicAblation,
        proof_artifact_id: proof_artifact_id(seed),
        justification: format!("proof for {}", capability),
        artifact_hash: ContentHash::compute(format!("proof-{seed}-{capability}").as_bytes()),
    }
}

fn rebind_witness(witness: &mut CapabilityWitness, signing_key: &SigningKey) {
    let unsigned = witness.synthesis_unsigned_bytes();
    witness.content_hash = ContentHash::compute(&unsigned);

    let mut canonical = Vec::new();
    canonical.extend_from_slice(witness.extension_id.as_bytes());
    canonical.extend_from_slice(witness.policy_id.as_bytes());
    canonical.extend_from_slice(&witness.epoch.as_u64().to_be_bytes());
    canonical.extend_from_slice(&witness.timestamp_ns.to_be_bytes());
    canonical.extend_from_slice(witness.content_hash.as_bytes());
    witness.witness_id = engine_object_id::derive_id(
        ObjectDomain::Attestation,
        "capability-witness",
        &SchemaId::from_definition(b"CapabilityWitness.v1"),
        &canonical,
    )
    .expect("derive witness id");

    let signature = sign_preimage(signing_key, &unsigned).expect("sign witness");
    witness.synthesizer_signature = signature.to_bytes().to_vec();
}

fn build_promoted_witness(seed: u64, signing_key: &SigningKey) -> CapabilityWitness {
    let capability = Capability::new(format!("read-slot-{seed}"));
    let mut witness = WitnessBuilder::new(
        extension_id(seed),
        policy_id(),
        SecurityEpoch::from_raw(1_000 + seed),
        100_000 + seed,
        signing_key.clone(),
    )
    .require(capability.clone())
    .proof(make_proof(seed, &capability))
    .confidence(ConfidenceInterval::from_trials(128, 123))
    .replay_seed(seed)
    .transcript_hash(ContentHash::compute(
        format!("transcript-{seed}").as_bytes(),
    ))
    .build()
    .expect("build witness");

    let theorem_input = PromotionTheoremInput {
        source_capability_sets: vec![SourceCapabilitySet {
            source_id: format!("source-{seed}"),
            capabilities: witness.required_capabilities.clone(),
        }],
        manifest_capabilities: witness.required_capabilities.clone(),
        capability_lattice: BTreeMap::new(),
        non_interference_dependencies: BTreeMap::new(),
        custom_extensions: Vec::new(),
    };
    let report = witness
        .evaluate_promotion_theorems(&theorem_input)
        .expect("evaluate promotion theorems");
    assert!(report.all_passed, "promotion theorem report must pass");
    witness.apply_promotion_theorem_report(&report);
    rebind_witness(&mut witness, signing_key);

    witness
        .transition_to(LifecycleState::Validated)
        .expect("draft -> validated");
    witness
        .transition_to(LifecycleState::Promoted)
        .expect("validated -> promoted");
    witness
}

fn build_pipeline() -> WitnessPublicationPipeline {
    WitnessPublicationPipeline::new(
        SecurityEpoch::from_raw(2_000),
        tree_head_signing_key(),
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "witness-publication-test-policy".to_string(),
            governance_ledger_config: None,
        },
    )
    .expect("build publication pipeline")
}

fn assert_structured_event(event: &WitnessPublicationEvent, expected_event: &str) {
    assert!(!event.trace_id.is_empty(), "trace_id must be present");
    assert!(!event.decision_id.is_empty(), "decision_id must be present");
    assert!(!event.policy_id.is_empty(), "policy_id must be present");
    assert!(!event.component.is_empty(), "component must be present");
    assert_eq!(event.event, expected_event);
    assert_eq!(event.outcome, "success");
    assert_eq!(event.error_code, None);
}

#[test]
fn e2e_publish_revoke_verify_and_query_keeps_stable_event_fields() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();

    let witness = build_promoted_witness(7, &synthesizer_key);
    let witness_id = witness.witness_id.clone();
    let extension_id = witness.extension_id.clone();
    let witness_epoch = witness.epoch;
    let witness_content_hash = witness.content_hash.clone();

    let publication_id = pipeline
        .publish_witness(witness, 90_000)
        .expect("publish witness");
    pipeline
        .verify_publication(
            &publication_id,
            &synthesizer_key.verification_key(),
            &tree_head_signing_key().verification_key(),
        )
        .expect("verify published witness");

    pipeline
        .revoke_witness(&witness_id, "incident drill", 91_000)
        .expect("revoke witness");
    pipeline
        .verify_publication(
            &publication_id,
            &synthesizer_key.verification_key(),
            &tree_head_signing_key().verification_key(),
        )
        .expect("verify revoked witness");

    assert_eq!(pipeline.publications().len(), 1);
    assert!(pipeline.publications()[0].is_revoked());
    assert_eq!(
        pipeline.publications()[0].publication_proof.log_entry.kind,
        PublicationEntryKind::Publish
    );
    assert_eq!(pipeline.evidence_entries().len(), 2);

    let filtered = pipeline.query(&WitnessPublicationQuery {
        extension_id: Some(extension_id),
        policy_id: Some(policy_id()),
        epoch: Some(witness_epoch),
        content_hash: Some(witness_content_hash),
        include_revoked: true,
    });
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].publication_id, publication_id);

    assert_eq!(pipeline.events().len(), 2);
    assert_structured_event(&pipeline.events()[0], "publish_witness");
    assert_structured_event(&pipeline.events()[1], "revoke_witness");
}

#[test]
fn publication_artifact_is_deterministic_for_identical_inputs() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline_a = build_pipeline();
    let mut pipeline_b = build_pipeline();

    let witness_a = build_promoted_witness(99, &synthesizer_key);
    let witness_b = build_promoted_witness(99, &synthesizer_key);

    let publication_id_a = pipeline_a
        .publish_witness(witness_a, 123_456)
        .expect("publish in pipeline A");
    let publication_id_b = pipeline_b
        .publish_witness(witness_b, 123_456)
        .expect("publish in pipeline B");

    let artifact_a = &pipeline_a.publications()[0];
    let artifact_b = &pipeline_b.publications()[0];
    assert_eq!(publication_id_a, publication_id_b);
    assert_eq!(artifact_a.publication_id, artifact_b.publication_id);
    assert_eq!(artifact_a.published_hash, artifact_b.published_hash);
    assert_eq!(
        artifact_a.publication_proof.log_entry.leaf_hash,
        artifact_b.publication_proof.log_entry.leaf_hash
    );
}

#[test]
fn tampered_log_entry_hash_is_rejected_deterministically() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();
    let witness = build_promoted_witness(123, &synthesizer_key);
    pipeline
        .publish_witness(witness, 222_222)
        .expect("publish witness");

    let mut tampered = pipeline.publications()[0].clone();
    tampered.publication_proof.log_entry.leaf_hash = ContentHash([0xAB; 32]);

    let err = WitnessPublicationPipeline::verify_artifact(
        &tampered,
        &synthesizer_key.verification_key(),
        &tree_head_signing_key().verification_key(),
    )
    .expect_err("tampered log entry hash must fail verification");
    assert!(matches!(err, WitnessPublicationError::LogEntryHashMismatch));
}

#[test]
fn capability_divergence_inputs_do_not_leak_into_query_filtering() {
    let synthesizer_key = synthesizer_signing_key();
    let mut pipeline = build_pipeline();

    let witness_a = build_promoted_witness(10, &synthesizer_key);
    let witness_b = build_promoted_witness(11, &synthesizer_key);
    let w_a_id = witness_a.witness_id.clone();

    pipeline
        .publish_witness(witness_a, 1_000)
        .expect("publish witness A");
    pipeline
        .publish_witness(witness_b, 2_000)
        .expect("publish witness B");
    pipeline
        .revoke_witness(&w_a_id, "test revocation", 3_000)
        .expect("revoke witness A");

    let live_only = pipeline.query(&WitnessPublicationQuery {
        extension_id: None,
        policy_id: None,
        epoch: None,
        content_hash: None,
        include_revoked: false,
    });
    assert_eq!(live_only.len(), 1);

    let all = pipeline.query(&WitnessPublicationQuery::all());
    assert_eq!(all.len(), 2);

    let seen_policy_ids: BTreeSet<_> = all
        .iter()
        .map(|entry| entry.witness.policy_id.clone())
        .collect();
    assert_eq!(seen_policy_ids.len(), 1);
}
