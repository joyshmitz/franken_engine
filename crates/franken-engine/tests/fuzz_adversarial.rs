use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::{
    CapabilityToken, CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder,
    VerificationContext, verify_token,
};
use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaRegistry, decode_value, deserialize_with_schema, encode_value,
    serialize_with_schema,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::session_hostcall_channel::{
    AeadAlgorithm, DataPlaneDirection, SequencePolicy, SessionConfig, SessionHandshake,
    SessionHostcallChannel, SharedSendInput, derive_deterministic_aead_nonce,
};
use frankenengine_engine::signature_preimage::SigningKey;

const MAX_CORPUS_BYTES: usize = 64 * 1024;
const MAX_HANDSHAKE_STEPS: usize = 96;
const MAX_PAYLOAD_BYTES: usize = 128;
const MAX_TOKEN_MUTATIONS: usize = 64;

#[test]
fn decode_dos_corpus_regression_is_panic_free() {
    for input in read_corpus_bytes("decode_dos") {
        run_decode_program(&input);
    }

    // Explicit malformed length-prefix case from decode-DoS threat model.
    run_decode_program(&[0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn handshake_replay_corpus_regression_is_panic_free() {
    for input in read_corpus_bytes("handshake_replay") {
        run_handshake_program(&input);
    }
}

#[test]
fn token_verification_corpus_regression_is_panic_free() {
    for input in read_corpus_bytes("token_verification") {
        run_token_program(&input);
    }
}

fn run_decode_program(data: &[u8]) {
    if data.len() > MAX_CORPUS_BYTES {
        return;
    }

    let _ = decode_value(data);

    if data.len() >= 32 {
        let mut schema_bytes = [0u8; 32];
        schema_bytes.copy_from_slice(&data[..32]);
        let schema = frankenengine_engine::deterministic_serde::SchemaHash(schema_bytes);
        let _ = deserialize_with_schema(&schema, data);
    }

    let synthetic = synthetic_value(data);
    let mut registry = SchemaRegistry::new();
    let schema = registry.register("tests.decode_dos", 1, b"tests.decode_dos.schema.v1");
    let encoded = serialize_with_schema(&schema, &synthetic);
    let _ = registry.deserialize_checked(&encoded);

    if let Ok(decoded) = decode_value(&encode_value(&synthetic)) {
        let _ = encode_value(&decoded);
    }
}

fn synthetic_value(data: &[u8]) -> CanonicalValue {
    match byte(data, 0) % 5 {
        0 => CanonicalValue::U64(u64::from(byte(data, 1))),
        1 => CanonicalValue::Bytes(data.iter().copied().take(128).collect()),
        2 => CanonicalValue::String(
            data.iter()
                .copied()
                .take(64)
                .map(|b| char::from(b'a' + (b % 26)))
                .collect(),
        ),
        3 => CanonicalValue::Array(
            data.iter()
                .copied()
                .take(16)
                .map(|item| CanonicalValue::U64(u64::from(item)))
                .collect(),
        ),
        _ => {
            let mut map = BTreeMap::new();
            for (index, value) in data.iter().copied().take(12).enumerate() {
                map.insert(
                    format!("k{index:02x}"),
                    CanonicalValue::U64(u64::from(value)),
                );
            }
            CanonicalValue::Map(map)
        }
    }
}

fn run_handshake_program(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut channel = SessionHostcallChannel::new();
    let extension_signing_key = SigningKey::from_bytes(bytes32(data, 0));
    let host_signing_key = SigningKey::from_bytes(bytes32(data, 17));
    let config = SessionConfig {
        max_lifetime_ticks: 16 + u64::from(byte(data, 1)),
        max_messages: 8 + u64::from(byte(data, 2)),
        max_buffered_messages: 1 + usize::from(byte(data, 3) % 16),
        sequence_policy: if byte(data, 4) % 2 == 0 {
            SequencePolicy::Monotonic
        } else {
            SequencePolicy::Strict
        },
        replay_drop_threshold: 1 + u64::from(byte(data, 5) % 8),
        replay_drop_window_ticks: 1 + u64::from(byte(data, 6) % 32),
    };

    let start_tick = u64::from(byte(data, 7)) + 1;
    let handshake_a = SessionHandshake {
        session_id: make_id("sess-a", data, 8),
        extension_id: make_id("ext-a", data, 22),
        host_id: make_id("host-a", data, 36),
        extension_nonce: u64::from(byte(data, 10)),
        host_nonce: u64::from(byte(data, 11)),
        timestamp_ticks: start_tick,
        trace_id: "test-trace-a".to_string(),
    };

    let handle_a = match channel.create_session(
        handshake_a.clone(),
        &extension_signing_key,
        &host_signing_key,
        config.clone(),
    ) {
        Ok(handle) => handle,
        Err(_) => return,
    };

    let handshake_b = SessionHandshake {
        session_id: make_id("sess-b", data, 46),
        extension_id: make_id("ext-b", data, 60),
        host_id: make_id("host-b", data, 74),
        extension_nonce: u64::from(byte(data, 12)) + 1,
        host_nonce: u64::from(byte(data, 13)) + 1,
        timestamp_ticks: start_tick.saturating_add(1),
        trace_id: "test-trace-b".to_string(),
    };
    let handle_b = channel
        .create_session(
            handshake_b,
            &extension_signing_key,
            &host_signing_key,
            config.clone(),
        )
        .ok();

    let mut now_tick = start_tick.saturating_add(2);
    let mut cursor = 14usize;
    for _ in 0..MAX_HANDSHAKE_STEPS {
        let opcode = byte(data, cursor);
        cursor = cursor.saturating_add(1);

        match opcode % 8 {
            0 => {
                let payload_len = usize::from(byte(data, cursor)) % MAX_PAYLOAD_BYTES;
                cursor = cursor.saturating_add(1);
                let payload = (0..payload_len)
                    .map(|offset| byte(data, cursor.saturating_add(offset)))
                    .collect::<Vec<_>>();
                let _ = channel.send(
                    &handle_a,
                    payload,
                    "test-send",
                    now_tick,
                    Some("test-decision"),
                    Some("test-policy"),
                );
                cursor = cursor.saturating_add(payload_len);
            }
            1 => {
                let _ = channel.receive(
                    &handle_a,
                    "test-recv",
                    now_tick,
                    Some("test-decision"),
                    Some("test-policy"),
                );
            }
            2 => {
                // Duplicate-handshake replay attempt on same session_id.
                let replay = SessionHandshake {
                    session_id: handshake_a.session_id.clone(),
                    extension_id: handshake_a.extension_id.clone(),
                    host_id: handshake_a.host_id.clone(),
                    extension_nonce: handshake_a.extension_nonce,
                    host_nonce: handshake_a.host_nonce,
                    timestamp_ticks: now_tick,
                    trace_id: "test-replay".to_string(),
                };
                let _ = channel.create_session(
                    replay,
                    &extension_signing_key,
                    &host_signing_key,
                    config.clone(),
                );
            }
            3 => {
                let _ = channel.close_session(
                    &handle_a,
                    "test-close",
                    now_tick,
                    Some("test-decision"),
                    Some("test-policy"),
                );
            }
            4 => {
                let payload_len = usize::from(byte(data, cursor)) % MAX_PAYLOAD_BYTES;
                cursor = cursor.saturating_add(1);
                let payload = (0..payload_len)
                    .map(|offset| byte(data, cursor.saturating_add(offset)))
                    .collect::<Vec<_>>();
                let _ = channel.send_shared_buffer(
                    &handle_a,
                    SharedSendInput {
                        region_id: u64::from(byte(data, cursor)),
                        payload: &payload,
                        trace_id: "test-shared-send",
                        timestamp_ticks: now_tick,
                        decision_id: Some("test-decision"),
                        policy_id: Some("test-policy"),
                    },
                );
                cursor = cursor.saturating_add(payload_len);
            }
            5 => {
                // Session splicing attempt via cross-session signal verification.
                if let Some(ref handle) = handle_b
                    && let Ok(envelope) = channel.authenticated_backpressure_signal(
                        handle,
                        usize::from(byte(data, cursor)),
                        16,
                        "test-splice",
                        now_tick,
                    )
                {
                    let _ = channel.verify_authenticated_signal(&handle_a, &envelope);
                }
            }
            6 => {
                let sequence = if opcode & 1 == 0 {
                    u64::MAX
                } else {
                    u64::from(byte(data, cursor)) << 16
                };
                cursor = cursor.saturating_add(1);
                let algorithm = match byte(data, cursor) % 3 {
                    0 => AeadAlgorithm::ChaCha20Poly1305,
                    1 => AeadAlgorithm::Aes256Gcm,
                    _ => AeadAlgorithm::XChaCha20Poly1305,
                };
                let _ = derive_deterministic_aead_nonce(
                    &bytes32(data, cursor),
                    DataPlaneDirection::ExtensionToHost,
                    sequence,
                    algorithm,
                );
                cursor = cursor.saturating_add(1);
            }
            _ => {
                let _ = channel.drain_events();
                let _ = channel.queue_len(&handle_a);
                let _ = channel.session_state(&handle_a);
            }
        }

        now_tick = now_tick.saturating_add(1 + u64::from(opcode & 0x0f));
    }
}

fn run_token_program(data: &[u8]) {
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
}

fn build_token(data: &[u8]) -> Option<CapabilityToken> {
    let sk = SigningKey::from_bytes(bytes32(data, 0));
    let presenter = PrincipalId::from_bytes(bytes32(data, 1));
    let nbf = DeterministicTimestamp(u64::from(byte(data, 2)));
    let expiry = DeterministicTimestamp(nbf.0.saturating_add(1 + u64::from(byte(data, 3))));
    let epoch = SecurityEpoch::from_raw(u64::from(byte(data, 4)).saturating_add(1));

    TokenBuilder::new(sk, nbf, expiry, epoch, "test-zone")
        .add_audience(presenter)
        .add_capability(RuntimeCapability::VmDispatch)
        .add_capability(RuntimeCapability::FsRead)
        .build()
        .ok()
}

fn mutate_token(token: &mut CapabilityToken, data: &[u8]) {
    for (index, value) in data.iter().copied().take(MAX_TOKEN_MUTATIONS).enumerate() {
        match value % 8 {
            0 => token.signature.lower[index % 32] ^= value,
            1 => token.signature.upper[index % 32] ^= value.rotate_left(1),
            2 => token.nbf = DeterministicTimestamp(u64::from(value)),
            3 => {
                token.expiry =
                    DeterministicTimestamp(u64::from(value) + u64::from(byte(data, index + 1)))
            }
            4 => {
                token.audience.clear();
                if value & 1 == 0 {
                    token
                        .audience
                        .insert(PrincipalId::from_bytes(bytes32(data, index + 2)));
                }
            }
            5 => token.zone = format!("test-zone-{value}"),
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

fn read_corpus_bytes(name: &str) -> Vec<Vec<u8>> {
    let repo = repo_root();
    let candidate_dirs = [
        repo.join("fuzz").join("corpus").join(name),
        repo.join("crates")
            .join("franken-engine")
            .join("tests")
            .join("fixtures")
            .join("fuzz_adversarial")
            .join(name),
    ];

    for corpus_dir in candidate_dirs {
        if !corpus_dir.exists() {
            continue;
        }

        let entries = collect_files(&corpus_dir);
        if entries.is_empty() {
            continue;
        }

        return entries
            .into_iter()
            .map(|path| {
                fs::read(&path).unwrap_or_else(|error| {
                    panic!("failed reading corpus file {}: {error}", path.display())
                })
            })
            .collect();
    }

    panic!("no corpus files found for target {name}");
}

fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read corpus dir {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    out.sort();
    out
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn make_id(prefix: &str, data: &[u8], offset: usize) -> String {
    let mut id = String::from(prefix);
    id.push('-');
    for index in 0..8 {
        let value = byte(data, offset.saturating_add(index));
        id.push(char::from(b'a' + (value % 26)));
    }
    id
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
