//! Delegated capability attenuation-chain verification.
//!
//! This module enforces explicit, non-ambient authority delegation:
//! - every link is a signed capability token
//! - every link is verified against audience/temporal/checkpoint/revocation
//!   freshness bindings
//! - every child link must attenuate (subset) parent capabilities
//! - root issuer must be an authorized root authority
//! - chain depth is bounded
//! - any revoked link invalidates the chain tail
//!
//! Plan references: Section 10.10 item 10, 9E.4.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::capability_token::{
    CapabilityToken, PrincipalId, TokenError, TokenId,
    VerificationContext as TokenVerificationContext, verify_token,
};
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::VerificationKey;

/// Default maximum delegation-chain depth.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 8;

/// Ordered delegation chain from root grant to leaf token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChain {
    pub links: Vec<CapabilityToken>,
}

impl DelegationChain {
    pub fn new(links: Vec<CapabilityToken>) -> Self {
        Self { links }
    }

    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn verify<R: RevocationOracle>(
        &self,
        required_capability: RuntimeCapability,
        leaf_delegate: &PrincipalId,
        context: &DelegationVerificationContext,
        revocation_oracle: &R,
    ) -> Result<AuthorizationProof, ChainError> {
        verify_chain(
            self,
            required_capability,
            leaf_delegate,
            context,
            revocation_oracle,
        )
    }
}

/// Context for delegation-chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationVerificationContext {
    pub current_tick: u64,
    pub verifier_checkpoint_seq: u64,
    pub verifier_revocation_seq: u64,
    pub max_chain_depth: usize,
    pub authorized_roots: BTreeSet<VerificationKey>,
    pub required_zone: Option<String>,
}

impl Default for DelegationVerificationContext {
    fn default() -> Self {
        Self {
            current_tick: 0,
            verifier_checkpoint_seq: 0,
            verifier_revocation_seq: 0,
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            authorized_roots: BTreeSet::new(),
            required_zone: None,
        }
    }
}

impl DelegationVerificationContext {
    pub fn with_authorized_root(root: VerificationKey) -> Self {
        let mut roots = BTreeSet::new();
        roots.insert(root);
        Self {
            authorized_roots: roots,
            ..Self::default()
        }
    }

    fn as_token_context(&self) -> TokenVerificationContext {
        TokenVerificationContext {
            current_tick: self.current_tick,
            verifier_checkpoint_seq: self.verifier_checkpoint_seq,
            verifier_revocation_seq: self.verifier_revocation_seq,
        }
    }
}

/// Chain verification error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainError {
    /// No chain means no authority: explicit no-ambient-authority invariant.
    EmptyChain,
    /// Chain exceeds configured depth limit.
    DepthExceeded {
        max_depth: usize,
        actual_depth: usize,
    },
    /// Root grant is not signed by an authorized root.
    UnauthorizedRoot { root_issuer: VerificationKey },
    /// Token missing mandatory checkpoint binding.
    MissingCheckpointBinding { index: usize },
    /// Token missing mandatory revocation-freshness binding.
    MissingRevocationFreshnessBinding { index: usize },
    /// Token-level verification failure.
    TokenVerificationFailed { index: usize, error: TokenError },
    /// Chain amplification detected.
    AttenuationViolation {
        index: usize,
        parent_capability_count: usize,
        child_capability_count: usize,
        amplified_capabilities: BTreeSet<RuntimeCapability>,
    },
    /// Zone mismatch across links or against required zone.
    ZoneMismatch {
        index: usize,
        expected_zone: String,
        actual_zone: String,
    },
    /// Revoked link invalidates the chain tail.
    RevokedLink { index: usize, token_id: TokenId },
    /// Required capability is not present on the leaf grant.
    MissingCapabilityAtLeaf {
        required: RuntimeCapability,
        leaf_capabilities: BTreeSet<RuntimeCapability>,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "delegation chain is empty (no ambient authority)"),
            Self::DepthExceeded {
                max_depth,
                actual_depth,
            } => write!(
                f,
                "delegation chain depth exceeded: max={max_depth}, actual={actual_depth}"
            ),
            Self::UnauthorizedRoot { root_issuer } => {
                write!(f, "unauthorized root issuer: {root_issuer}")
            }
            Self::MissingCheckpointBinding { index } => {
                write!(f, "delegation link {index} missing checkpoint binding")
            }
            Self::MissingRevocationFreshnessBinding { index } => write!(
                f,
                "delegation link {index} missing revocation freshness binding"
            ),
            Self::TokenVerificationFailed { index, error } => {
                write!(f, "delegation link {index} verification failed: {error}")
            }
            Self::AttenuationViolation {
                index,
                parent_capability_count,
                child_capability_count,
                amplified_capabilities,
            } => write!(
                f,
                "delegation attenuation violation at link {index}: parent caps={}, \
                 child caps={}, amplified={:?}",
                parent_capability_count, child_capability_count, amplified_capabilities
            ),
            Self::ZoneMismatch {
                index,
                expected_zone,
                actual_zone,
            } => write!(
                f,
                "delegation link {index} zone mismatch: expected `{expected_zone}`, got `{actual_zone}`"
            ),
            Self::RevokedLink { index, token_id } => write!(
                f,
                "delegation link {index} revoked: token_id={}",
                token_id.to_hex()
            ),
            Self::MissingCapabilityAtLeaf {
                required,
                leaf_capabilities,
            } => write!(
                f,
                "leaf token missing required capability `{required}` (leaf caps={leaf_capabilities:?})"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Lightweight revocation lookup for delegation links.
pub trait RevocationOracle {
    fn is_revoked(&self, token_id: &TokenId) -> bool;
}

/// Default oracle that treats all links as not revoked.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRevocationOracle;

impl RevocationOracle for NoRevocationOracle {
    fn is_revoked(&self, _token_id: &TokenId) -> bool {
        false
    }
}

/// One verified delegation link summary in authorization proof material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationLinkSummary {
    pub index: usize,
    pub token_id: TokenId,
    pub issuer: PrincipalId,
    pub delegate: PrincipalId,
    pub capability_count: usize,
    pub zone: String,
    pub not_before_tick: u64,
    pub expiry_tick: u64,
}

/// Verifiable proof returned after successful chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProof {
    pub chain_hash: ContentHash,
    pub authorized_capability: RuntimeCapability,
    pub root_issuer: PrincipalId,
    pub leaf_delegate: PrincipalId,
    pub verified_at_tick: u64,
    pub chain_summary: Vec<DelegationLinkSummary>,
}

/// Deterministically derive principal identity from a verification key.
pub fn principal_id_from_verification_key(vk: &VerificationKey) -> PrincipalId {
    PrincipalId::from_verification_key(vk)
}

/// Verify a delegated capability chain for a specific action capability.
pub fn verify_chain<R: RevocationOracle>(
    chain: &DelegationChain,
    required_capability: RuntimeCapability,
    leaf_delegate: &PrincipalId,
    context: &DelegationVerificationContext,
    revocation_oracle: &R,
) -> Result<AuthorizationProof, ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    if chain.len() > context.max_chain_depth {
        return Err(ChainError::DepthExceeded {
            max_depth: context.max_chain_depth,
            actual_depth: chain.len(),
        });
    }

    let root_issuer = chain.links[0].issuer.clone();
    if !context.authorized_roots.contains(&root_issuer) {
        return Err(ChainError::UnauthorizedRoot { root_issuer });
    }

    let expected_zone = context
        .required_zone
        .as_deref()
        .unwrap_or(&chain.links[0].zone)
        .to_string();

    let mut summary = Vec::with_capacity(chain.len());
    let token_ctx = context.as_token_context();

    for (index, token) in chain.links.iter().enumerate() {
        if token.zone != expected_zone {
            return Err(ChainError::ZoneMismatch {
                index,
                expected_zone: expected_zone.clone(),
                actual_zone: token.zone.clone(),
            });
        }

        if token.checkpoint_binding.is_none() {
            return Err(ChainError::MissingCheckpointBinding { index });
        }
        if token.revocation_freshness.is_none() {
            return Err(ChainError::MissingRevocationFreshnessBinding { index });
        }
        if revocation_oracle.is_revoked(&token.jti) {
            return Err(ChainError::RevokedLink {
                index,
                token_id: token.jti.clone(),
            });
        }

        let delegate = if index + 1 < chain.len() {
            principal_id_from_verification_key(&chain.links[index + 1].issuer)
        } else {
            leaf_delegate.clone()
        };

        verify_token(token, &delegate, &token_ctx)
            .map_err(|error| ChainError::TokenVerificationFailed { index, error })?;

        if index + 1 < chain.len() {
            let child = &chain.links[index + 1];
            if !child.capabilities.is_subset(&token.capabilities) {
                let amplified = child
                    .capabilities
                    .difference(&token.capabilities)
                    .copied()
                    .collect::<BTreeSet<_>>();
                return Err(ChainError::AttenuationViolation {
                    index: index + 1,
                    parent_capability_count: token.capabilities.len(),
                    child_capability_count: child.capabilities.len(),
                    amplified_capabilities: amplified,
                });
            }
        }

        summary.push(DelegationLinkSummary {
            index,
            token_id: token.jti.clone(),
            issuer: principal_id_from_verification_key(&token.issuer),
            delegate,
            capability_count: token.capabilities.len(),
            zone: token.zone.clone(),
            not_before_tick: token.nbf.0,
            expiry_tick: token.expiry.0,
        });
    }

    let leaf = chain
        .links
        .last()
        .expect("non-empty delegation chain must have leaf");
    if !leaf.capabilities.contains(&required_capability) {
        return Err(ChainError::MissingCapabilityAtLeaf {
            required: required_capability,
            leaf_capabilities: leaf.capabilities.clone(),
        });
    }

    Ok(AuthorizationProof {
        chain_hash: chain_hash(&chain.links, leaf_delegate),
        authorized_capability: required_capability,
        root_issuer: principal_id_from_verification_key(&chain.links[0].issuer),
        leaf_delegate: leaf_delegate.clone(),
        verified_at_tick: context.current_tick,
        chain_summary: summary,
    })
}

fn chain_hash(links: &[CapabilityToken], leaf_delegate: &PrincipalId) -> ContentHash {
    let mut material = Vec::new();
    for token in links {
        material.extend_from_slice(token.jti.as_bytes());
        material.extend_from_slice(token.issuer.as_bytes());
        material.extend_from_slice(token.zone.as_bytes());
        material.push(0xff);
        for cap in &token.capabilities {
            material.extend_from_slice(cap.to_string().as_bytes());
            material.push(0x1f);
        }
    }
    material.extend_from_slice(leaf_delegate.as_bytes());
    ContentHash::compute(&material)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::capability_token::{CheckpointRef, RevocationFreshnessRef, TokenBuilder};
    use crate::engine_object_id::EngineObjectId;
    use crate::policy_checkpoint::DeterministicTimestamp;
    use crate::security_epoch::SecurityEpoch;
    use crate::signature_preimage::{Signature, SigningKey};

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
    ) -> CapabilityToken {
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

    fn valid_chain_fixture() -> (DelegationChain, SigningKey, PrincipalId) {
        let root_sk = make_sk(1);
        let issuer_sk = make_sk(2);
        let delegate_sk = make_sk(3);
        let leaf_delegate = make_principal(99);

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

        (
            DelegationChain::new(vec![link0, link1, link2]),
            root_sk,
            leaf_delegate,
        )
    }

    fn make_ctx(root_sk: &SigningKey) -> DelegationVerificationContext {
        let mut roots = BTreeSet::new();
        roots.insert(root_sk.verification_key());
        DelegationVerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 10,
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            authorized_roots: roots,
            required_zone: Some("zone-a".to_string()),
        }
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
    fn valid_three_link_chain_verifies() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("chain should verify");

        assert_eq!(proof.authorized_capability, RuntimeCapability::VmDispatch);
        assert_eq!(proof.chain_summary.len(), 3);
        assert_eq!(proof.leaf_delegate, leaf_delegate);
    }

    #[test]
    fn rejects_attenuation_violation() {
        let root_sk = make_sk(1);
        let issuer_sk = make_sk(2);
        let delegate_sk = make_sk(3);
        let leaf_delegate = make_principal(99);

        let link0 = make_bound_token(
            &root_sk,
            principal_id_from_verification_key(&issuer_sk.verification_key()),
            &[RuntimeCapability::VmDispatch],
        );
        let link1 = make_bound_token(
            &issuer_sk,
            principal_id_from_verification_key(&delegate_sk.verification_key()),
            &[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::NetworkEgress,
            ],
        );
        let link2 = make_bound_token(
            &delegate_sk,
            leaf_delegate.clone(),
            &[RuntimeCapability::VmDispatch],
        );
        let chain = DelegationChain::new(vec![link0, link1, link2]);
        let ctx = make_ctx(&root_sk);

        let err = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("attenuation amplification must fail");

        match err {
            ChainError::AttenuationViolation {
                index,
                amplified_capabilities,
                ..
            } => {
                assert_eq!(index, 1);
                assert!(amplified_capabilities.contains(&RuntimeCapability::NetworkEgress));
            }
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_middle_signature() {
        let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
        chain.links[1].signature = Signature::from_bytes([0xAB; 64]);
        let ctx = make_ctx(&root_sk);

        let err = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("invalid signature should fail");

        match err {
            ChainError::TokenVerificationFailed { index, error } => {
                assert_eq!(index, 1);
                assert!(matches!(error, TokenError::SignatureInvalid { .. }));
            }
            other => panic!("expected token verification failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_depth_exceeded() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let mut ctx = make_ctx(&root_sk);
        ctx.max_chain_depth = 2;

        let err = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("depth overflow must fail");

        assert_eq!(
            err,
            ChainError::DepthExceeded {
                max_depth: 2,
                actual_depth: 3,
            }
        );
    }

    #[test]
    fn revoked_middle_link_invalidates_chain() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
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
        .expect_err("revoked link must fail");

        match err {
            ChainError::RevokedLink { index, token_id } => {
                assert_eq!(index, 1);
                assert_eq!(token_id, chain.links[1].jti);
            }
            other => panic!("expected revoked-link error, got {other:?}"),
        }
    }

    #[test]
    fn root_must_be_authorized() {
        let (chain, _root_sk, leaf_delegate) = valid_chain_fixture();
        let wrong_root = make_sk(77);
        let ctx = make_ctx(&wrong_root);

        let err = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("unauthorized root must fail");

        assert!(matches!(err, ChainError::UnauthorizedRoot { .. }));
    }

    #[test]
    fn proof_contains_complete_chain_summary() {
        let (chain, root_sk, leaf_delegate) = valid_chain_fixture();
        let ctx = make_ctx(&root_sk);
        let proof = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect("chain should verify");

        assert_eq!(proof.chain_summary.len(), 3);
        assert_eq!(proof.chain_summary[0].index, 0);
        assert_eq!(proof.chain_summary[1].index, 1);
        assert_eq!(proof.chain_summary[2].index, 2);
        assert_eq!(
            proof.chain_summary[0].delegate,
            principal_id_from_verification_key(&chain.links[1].issuer)
        );
        assert_eq!(proof.chain_summary[2].delegate, leaf_delegate);
    }

    #[test]
    fn no_ambient_authority_empty_chain_is_rejected() {
        let empty = DelegationChain::new(Vec::new());
        let root_sk = make_sk(1);
        let ctx = make_ctx(&root_sk);
        let leaf_delegate = make_principal(9);

        let err = verify_chain(
            &empty,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("empty chain should fail");

        assert_eq!(err, ChainError::EmptyChain);
    }

    #[test]
    fn missing_checkpoint_binding_is_rejected() {
        let (mut chain, root_sk, leaf_delegate) = valid_chain_fixture();
        chain.links[0].checkpoint_binding = None;
        let ctx = make_ctx(&root_sk);

        let err = verify_chain(
            &chain,
            RuntimeCapability::VmDispatch,
            &leaf_delegate,
            &ctx,
            &NoRevocationOracle,
        )
        .expect_err("missing checkpoint binding should fail");

        assert_eq!(err, ChainError::MissingCheckpointBinding { index: 0 });
    }
}
