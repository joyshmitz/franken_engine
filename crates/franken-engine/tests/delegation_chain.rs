use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::{
    CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder, TokenId,
};
use frankenengine_engine::delegation_chain::{
    ChainError, DelegationChain, DelegationVerificationContext, NoRevocationOracle,
    RevocationOracle, principal_id_from_verification_key, verify_chain,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

fn make_sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_principal(seed: u8) -> PrincipalId {
    PrincipalId::from_bytes([seed; 32])
}

fn make_bound_token(
    issuer_sk: &SigningKey,
    delegate: PrincipalId,
    caps: &[RuntimeCapability],
) -> frankenengine_engine::capability_token::CapabilityToken {
    let mut builder = TokenBuilder::new(
        issuer_sk.clone(),
        DeterministicTimestamp(100),
        DeterministicTimestamp(1_000),
        SecurityEpoch::GENESIS,
        "zone-a",
    )
    .add_audience(delegate)
    .bind_checkpoint(CheckpointRef {
        min_checkpoint_seq: 5,
        checkpoint_id: EngineObjectId([7; 32]),
    })
    .bind_revocation_freshness(RevocationFreshnessRef {
        min_revocation_seq: 3,
        revocation_head_hash: ContentHash::compute(b"rev-head"),
    });

    for cap in caps {
        builder = builder.add_capability(*cap);
    }
    builder.build().expect("token should build")
}

fn make_ctx(root_sk: &SigningKey) -> DelegationVerificationContext {
    let mut roots = BTreeSet::new();
    roots.insert(root_sk.verification_key());
    DelegationVerificationContext {
        current_tick: 500,
        verifier_checkpoint_seq: 10,
        verifier_revocation_seq: 10,
        max_chain_depth: 8,
        authorized_roots: roots,
        required_zone: Some("zone-a".to_string()),
    }
}

#[test]
fn end_to_end_owner_issuer_delegate_chain_authorizes_leaf_action() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(42);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );
    let link1 = make_bound_token(
        &issuer_sk,
        principal_id_from_verification_key(&delegate_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    let link2 = make_bound_token(
        &delegate_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );

    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let ctx = make_ctx(&root_sk);
    let proof = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &NoRevocationOracle,
    )
    .expect("chain should authorize action");

    assert_eq!(proof.leaf_delegate, leaf_delegate);
    assert_eq!(proof.chain_summary.len(), 3);
    assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
}

struct SetRevocationOracle {
    revoked: BTreeSet<TokenId>,
}

impl RevocationOracle for SetRevocationOracle {
    fn is_revoked(&self, token_id: &TokenId) -> bool {
        self.revoked.contains(token_id)
    }
}

#[test]
fn revoking_middle_link_invalidates_downstream_authorization() {
    let root_sk = make_sk(1);
    let issuer_sk = make_sk(2);
    let delegate_sk = make_sk(3);
    let leaf_delegate = make_principal(55);

    let link0 = make_bound_token(
        &root_sk,
        principal_id_from_verification_key(&issuer_sk.verification_key()),
        &[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ],
    );
    let link1 = make_bound_token(
        &issuer_sk,
        principal_id_from_verification_key(&delegate_sk.verification_key()),
        &[RuntimeCapability::VmDispatch],
    );
    let link2 = make_bound_token(
        &delegate_sk,
        leaf_delegate.clone(),
        &[RuntimeCapability::VmDispatch],
    );

    let chain = DelegationChain::new(vec![link0, link1, link2]);
    let ctx = make_ctx(&root_sk);
    let mut revoked = BTreeSet::new();
    revoked.insert(chain.links[1].jti.clone());
    let oracle = SetRevocationOracle { revoked };

    let err = verify_chain(
        &chain,
        RuntimeCapability::VmDispatch,
        &leaf_delegate,
        &ctx,
        &oracle,
    )
    .expect_err("revoked middle link must invalidate authorization");

    assert!(matches!(err, ChainError::RevokedLink { index: 1, .. }));
}
