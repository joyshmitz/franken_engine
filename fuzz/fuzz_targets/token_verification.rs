#![no_main]

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::{
    CapabilityToken, CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder,
    VerificationContext, verify_token,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use libfuzzer_sys::fuzz_target;

const MAX_MUTATIONS: usize = 64;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let Some(mut token) = build_token(data) else {
        return;
    };
    mutate_token(&mut token, data);

    let presenter = PrincipalId::from_bytes(bytes32(data, 9));
    let ctx = VerificationContext {
        current_tick: u64::from(byte(data, 10)) + u64::from(byte(data, 11)),
        verifier_checkpoint_seq: u64::from(byte(data, 12)),
        verifier_revocation_seq: u64::from(byte(data, 13)),
    };

    let _ = verify_token(&token, &presenter, &ctx);

    if let Ok(json) = serde_json::to_string(&token)
        && let Ok(decoded) = serde_json::from_str::<CapabilityToken>(&json)
    {
        let _ = verify_token(&decoded, &presenter, &ctx);
    }
});

fn build_token(data: &[u8]) -> Option<CapabilityToken> {
    let sk = SigningKey::from_bytes(bytes32(data, 0));
    let presenter = PrincipalId::from_bytes(bytes32(data, 1));

    let nbf = DeterministicTimestamp(u64::from(byte(data, 2)));
    let expiry = DeterministicTimestamp(nbf.0.saturating_add(1 + u64::from(byte(data, 3))));
    let epoch = SecurityEpoch::from_raw(u64::from(byte(data, 4)).saturating_add(1));

    TokenBuilder::new(sk, nbf, expiry, epoch, "fuzz-zone")
        .add_audience(presenter)
        .add_capability(RuntimeCapability::VmDispatch)
        .add_capability(RuntimeCapability::FsRead)
        .build()
        .ok()
}

fn mutate_token(token: &mut CapabilityToken, data: &[u8]) {
    for (index, value) in data.iter().copied().take(MAX_MUTATIONS).enumerate() {
        match value % 8 {
            0 => {
                token.signature.lower[index % 32] ^= value;
            }
            1 => {
                token.signature.upper[index % 32] ^= value.rotate_left(1);
            }
            2 => {
                token.nbf = DeterministicTimestamp(u64::from(value));
            }
            3 => {
                token.expiry =
                    DeterministicTimestamp(u64::from(value) + u64::from(byte(data, index + 1)));
            }
            4 => {
                token.audience.clear();
                if value & 1 == 0 {
                    token
                        .audience
                        .insert(PrincipalId::from_bytes(bytes32(data, index + 2)));
                }
            }
            5 => {
                token.zone = format!("fuzz-zone-{value}");
            }
            6 => {
                token.checkpoint_binding = Some(CheckpointRef {
                    min_checkpoint_seq: u64::from(value),
                    checkpoint_id: EngineObjectId([value; 32]),
                });
            }
            _ => {
                token.revocation_freshness = Some(RevocationFreshnessRef {
                    min_revocation_seq: u64::from(value),
                    revocation_head_hash: ContentHash::compute(&[value]),
                });
            }
        }
    }
}

fn bytes32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = byte(data, offset + index);
    }
    out
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}
