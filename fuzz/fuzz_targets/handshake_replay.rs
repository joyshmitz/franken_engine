#![no_main]

use frankenengine_engine::session_hostcall_channel::{
    AeadAlgorithm, DataPlaneDirection, SequencePolicy, SessionConfig, SessionHandshake,
    SessionHostcallChannel, SharedSendInput, derive_deterministic_aead_nonce,
};
use frankenengine_engine::signature_preimage::SigningKey;
use libfuzzer_sys::fuzz_target;

const MAX_STEPS: usize = 96;
const MAX_PAYLOAD_BYTES: usize = 128;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    run_handshake_program(data);
});

fn run_handshake_program(data: &[u8]) {
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
        trace_id: "fuzz-trace-a".to_string(),
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
        trace_id: "fuzz-trace-b".to_string(),
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
    for _ in 0..MAX_STEPS {
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
                    "fuzz-send",
                    now_tick,
                    Some("fuzz-decision"),
                    Some("fuzz-policy"),
                );
                cursor = cursor.saturating_add(payload_len);
            }
            1 => {
                let _ = channel.receive(
                    &handle_a,
                    "fuzz-recv",
                    now_tick,
                    Some("fuzz-decision"),
                    Some("fuzz-policy"),
                );
            }
            2 => {
                // Replay-style duplicate handshake attempt (same session_id).
                let replay = SessionHandshake {
                    session_id: handshake_a.session_id.clone(),
                    extension_id: handshake_a.extension_id.clone(),
                    host_id: handshake_a.host_id.clone(),
                    extension_nonce: handshake_a.extension_nonce,
                    host_nonce: handshake_a.host_nonce,
                    timestamp_ticks: now_tick,
                    trace_id: "fuzz-trace-replay".to_string(),
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
                    "fuzz-close",
                    now_tick,
                    Some("fuzz-decision"),
                    Some("fuzz-policy"),
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
                        trace_id: "fuzz-shared-send",
                        timestamp_ticks: now_tick,
                        decision_id: Some("fuzz-decision"),
                        policy_id: Some("fuzz-policy"),
                    },
                );
                cursor = cursor.saturating_add(payload_len);
            }
            5 => {
                // Splicing attempt: verify session-B signal against session-A binding.
                if let Some(ref handle) = handle_b
                    && let Ok(envelope) = channel.authenticated_backpressure_signal(
                        handle,
                        usize::from(byte(data, cursor)),
                        16,
                        "fuzz-splice",
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
        *slot = byte(data, offset.saturating_add(index));
    }
    out
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}
