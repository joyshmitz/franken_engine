//! Session-authenticated extension hostcall channel with per-message MAC.
//!
//! This module amortizes asymmetric authentication into a deterministic
//! handshake and then authenticates each hostcall envelope with a keyed MAC.
//! Each session is bound to `(session_id, extension_id, host_id)`, enforces
//! monotonic sequences, and provides authenticated backpressure signaling.
//!
//! Plan references: Section 10.10 item 14, 9E.6 (session-authenticated
//! hostcall channel).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::signature_preimage::{
    Signature, SignatureError, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Session state / config
// ---------------------------------------------------------------------------

/// Session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Init,
    Established,
    Expired,
    Closed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => write!(f, "init"),
            Self::Established => write!(f, "established"),
            Self::Expired => write!(f, "expired"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Receiver-side sequence progression policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequencePolicy {
    /// Require `received_seq == last_seen + 1`.
    Strict,
    /// Require only `received_seq > last_seen`.
    Monotonic,
}

impl fmt::Display for SequencePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Monotonic => write!(f, "monotonic"),
        }
    }
}

/// Session behavior limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum wall-clock/virtual lifetime in ticks.
    pub max_lifetime_ticks: u64,
    /// Maximum total messages (send+receive) before forced re-handshake.
    pub max_messages: u64,
    /// Maximum queued inbound messages before backpressure.
    pub max_buffered_messages: usize,
    /// Sequence progression policy for replay/out-of-order handling.
    pub sequence_policy: SequencePolicy,
    /// Replay drop count threshold before escalation to session expiry.
    pub replay_drop_threshold: u64,
    /// Tick window used for replay-drop rate limiting.
    pub replay_drop_window_ticks: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_lifetime_ticks: 10_000,
            max_messages: 10_000,
            max_buffered_messages: 256,
            sequence_policy: SequencePolicy::Monotonic,
            replay_drop_threshold: 8,
            replay_drop_window_ticks: 1_000,
        }
    }
}

/// Handle returned to callers once a session is established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandle {
    pub session_id: String,
}

/// Input bundle for shared-buffer sends to keep API ergonomics clippy-clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSendInput<'a> {
    pub region_id: u64,
    pub payload: &'a [u8],
    pub trace_id: &'a str,
    pub timestamp_ticks: u64,
    pub decision_id: Option<&'a str>,
    pub policy_id: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Handshake transcript
// ---------------------------------------------------------------------------

/// Input used to build and verify a deterministic mutual-auth handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandshake {
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub extension_nonce: u64,
    pub host_nonce: u64,
    pub timestamp_ticks: u64,
    pub trace_id: String,
}

/// Signed extension->host handshake request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub extension_nonce: u64,
    pub timestamp_ticks: u64,
    pub extension_key: VerificationKey,
    pub signature: Signature,
}

/// Signed host->extension handshake response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub session_id: String,
    pub extension_nonce: u64,
    pub host_nonce: u64,
    pub host_key: VerificationKey,
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// Envelope / payload types
// ---------------------------------------------------------------------------

/// Descriptor for shared-memory payload transport (zero-copy style).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedPayloadDescriptor {
    pub region_id: u64,
    pub payload_len: usize,
    pub payload_hash: ContentHash,
}

/// Authenticated backpressure signal payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureSignal {
    pub pending_messages: usize,
    pub limit: usize,
}

/// Payload carried by a hostcall envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelPayload {
    Inline(Vec<u8>),
    Shared(SharedPayloadDescriptor),
    Backpressure(BackpressureSignal),
}

/// Supported AEAD algorithms for data-plane envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl AeadAlgorithm {
    pub fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 | Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub fn max_messages_per_key(self) -> u64 {
        match self {
            // Conservative cap from 96-bit nonce guidance.
            Self::Aes256Gcm => 1u64 << 32,
            // Treated as effectively unbounded within u64 session sequencing.
            Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => u64::MAX,
        }
    }

    #[allow(dead_code)]
    fn as_tag(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
            Self::XChaCha20Poly1305 => 3,
        }
    }
}

/// Direction discriminator for nonce derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataPlaneDirection {
    HostToExtension,
    ExtensionToHost,
}

impl DataPlaneDirection {
    #[allow(dead_code)]
    fn as_byte(self) -> u8 {
        match self {
            Self::HostToExtension => 0x00,
            Self::ExtensionToHost => 0x01,
        }
    }
}

/// Deterministically derived AEAD nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicNonce {
    bytes: Vec<u8>,
}

impl DeterministicNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Envelope authenticated per message with session MAC key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallEnvelope {
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub sequence: u64,
    pub payload: ChannelPayload,
    pub mac: AuthenticityHash,
    pub trace_id: String,
    pub sent_at_tick: u64,
}

// ---------------------------------------------------------------------------
// Errors / events
// ---------------------------------------------------------------------------

/// Errors from session channel operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChannelError {
    InvalidIdentity {
        field: String,
    },
    InvalidHandshake {
        detail: String,
    },
    SignatureFailure(SignatureError),
    SessionAlreadyExists {
        session_id: String,
    },
    SessionNotFound {
        session_id: String,
    },
    SessionNotEstablished {
        session_id: String,
        state: SessionState,
    },
    SessionExpired {
        session_id: String,
        reason: String,
    },
    Backpressure {
        session_id: String,
        pending: usize,
        limit: usize,
    },
    NoMessageAvailable {
        session_id: String,
    },
    SessionBindingMismatch {
        expected_session_id: String,
        actual_session_id: String,
    },
    MacMismatch {
        session_id: String,
        sequence: u64,
    },
    ReplayDetected {
        session_id: String,
        sequence: u64,
        last_seen: u64,
    },
    OutOfOrderDetected {
        session_id: String,
        sequence: u64,
        expected_min: u64,
    },
    NonceExhausted {
        sequence: u64,
        limit: u64,
        algorithm: AeadAlgorithm,
    },
}

impl fmt::Display for SessionChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity { field } => write!(f, "invalid identity field: {field}"),
            Self::InvalidHandshake { detail } => write!(f, "invalid handshake: {detail}"),
            Self::SignatureFailure(err) => write!(f, "signature failure: {err}"),
            Self::SessionAlreadyExists { session_id } => {
                write!(f, "session already exists: {session_id}")
            }
            Self::SessionNotFound { session_id } => write!(f, "session not found: {session_id}"),
            Self::SessionNotEstablished { session_id, state } => {
                write!(f, "session {session_id} not established (state: {state})")
            }
            Self::SessionExpired { session_id, reason } => {
                write!(f, "session {session_id} expired: {reason}")
            }
            Self::Backpressure {
                session_id,
                pending,
                limit,
            } => write!(
                f,
                "session {session_id} backpressure: pending={pending}, limit={limit}"
            ),
            Self::NoMessageAvailable { session_id } => {
                write!(f, "no message available for session {session_id}")
            }
            Self::SessionBindingMismatch {
                expected_session_id,
                actual_session_id,
            } => write!(
                f,
                "session binding mismatch: expected {expected_session_id}, got {actual_session_id}"
            ),
            Self::MacMismatch {
                session_id,
                sequence,
            } => {
                write!(f, "MAC mismatch on {session_id} sequence {sequence}")
            }
            Self::ReplayDetected {
                session_id,
                sequence,
                last_seen,
            } => write!(
                f,
                "replay detected on {session_id}: sequence={sequence}, last_seen={last_seen}"
            ),
            Self::OutOfOrderDetected {
                session_id,
                sequence,
                expected_min,
            } => write!(
                f,
                "out-of-order sequence on {session_id}: sequence={sequence}, expected_min={expected_min}"
            ),
            Self::NonceExhausted {
                sequence,
                limit,
                algorithm,
            } => write!(
                f,
                "nonce budget exhausted for {algorithm:?}: sequence={sequence}, limit={limit}"
            ),
        }
    }
}

impl std::error::Error for SessionChannelError {}

impl From<SignatureError> for SessionChannelError {
    fn from(value: SignatureError) -> Self {
        Self::SignatureFailure(value)
    }
}

/// Structured observability event for session channel operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChannelEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub sequence: Option<u64>,
    pub expected_min_seq: Option<u64>,
    pub received_seq: Option<u64>,
    pub drop_reason: Option<String>,
    pub source_principal: Option<String>,
    pub timestamp_ticks: u64,
}

/// Replay/drop classification for sequence policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayDropReason {
    Replay,
    Duplicate,
    OutOfOrder,
}

impl ReplayDropReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Duplicate => "duplicate",
            Self::OutOfOrder => "out_of_order",
        }
    }
}

// ---------------------------------------------------------------------------
// SessionHostcallChannel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SessionRecord {
    session_id: String,
    extension_id: String,
    host_id: String,
    state: SessionState,
    session_key: [u8; 32],
    expires_at_tick: u64,
    max_messages: u64,
    sent_messages: u64,
    received_messages: u64,
    next_sequence: u64,
    last_received_sequence: u64,
    sequence_policy: SequencePolicy,
    replay_drop_threshold: u64,
    replay_drop_window_ticks: u64,
    replay_drop_count_in_window: u64,
    replay_drop_window_start_tick: u64,
    max_buffered_messages: usize,
    inbound: VecDeque<HostcallEnvelope>,
}

/// Session-authenticated channel for extension hostcalls.
#[derive(Debug, Default)]
pub struct SessionHostcallChannel {
    sessions: BTreeMap<String, SessionRecord>,
    events: Vec<SessionChannelEvent>,
}

impl SessionHostcallChannel {
    /// Create an empty channel registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build, verify, and establish a new session using deterministic
    /// mutually-signed handshake transcript.
    pub fn create_session(
        &mut self,
        handshake: SessionHandshake,
        extension_signing_key: &SigningKey,
        host_signing_key: &SigningKey,
        config: SessionConfig,
    ) -> Result<SessionHandle, SessionChannelError> {
        validate_identity_field("session_id", &handshake.session_id)?;
        validate_identity_field("extension_id", &handshake.extension_id)?;
        validate_identity_field("host_id", &handshake.host_id)?;
        if handshake.extension_id == handshake.host_id {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "extension_id and host_id must differ".to_string(),
            });
        }
        if self.sessions.contains_key(&handshake.session_id) {
            return Err(SessionChannelError::SessionAlreadyExists {
                session_id: handshake.session_id,
            });
        }
        if config.max_messages == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "max_messages must be > 0".to_string(),
            });
        }
        if config.max_lifetime_ticks == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "max_lifetime_ticks must be > 0".to_string(),
            });
        }
        if config.max_buffered_messages == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "max_buffered_messages must be > 0".to_string(),
            });
        }
        if config.replay_drop_threshold > 0 && config.replay_drop_window_ticks == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "replay_drop_window_ticks must be > 0 when replay_drop_threshold > 0"
                    .to_string(),
            });
        }

        let extension_key = extension_signing_key.verification_key();
        let host_key = host_signing_key.verification_key();

        let request_preimage = handshake_request_preimage(&handshake, &extension_key);
        let request_sig = sign_preimage(extension_signing_key, &request_preimage)?;
        verify_signature(&extension_key, &request_preimage, &request_sig)?;

        let request = HandshakeRequest {
            session_id: handshake.session_id.clone(),
            extension_id: handshake.extension_id.clone(),
            host_id: handshake.host_id.clone(),
            extension_nonce: handshake.extension_nonce,
            timestamp_ticks: handshake.timestamp_ticks,
            extension_key: extension_key.clone(),
            signature: request_sig.clone(),
        };

        let response_preimage =
            handshake_response_preimage(&request, handshake.host_nonce, &host_key);
        let response_sig = sign_preimage(host_signing_key, &response_preimage)?;
        verify_signature(&host_key, &response_preimage, &response_sig)?;

        let response = HandshakeResponse {
            session_id: handshake.session_id.clone(),
            extension_nonce: handshake.extension_nonce,
            host_nonce: handshake.host_nonce,
            host_key,
            signature: response_sig,
        };

        let session_key =
            derive_session_key(&request_preimage, &response_preimage, &request, &response);
        let expires_at_tick = handshake
            .timestamp_ticks
            .saturating_add(config.max_lifetime_ticks);

        self.sessions.insert(
            handshake.session_id.clone(),
            SessionRecord {
                session_id: handshake.session_id.clone(),
                extension_id: handshake.extension_id.clone(),
                host_id: handshake.host_id.clone(),
                state: SessionState::Established,
                session_key,
                expires_at_tick,
                max_messages: config.max_messages,
                sent_messages: 0,
                received_messages: 0,
                next_sequence: 1,
                last_received_sequence: 0,
                sequence_policy: config.sequence_policy,
                replay_drop_threshold: config.replay_drop_threshold,
                replay_drop_window_ticks: config.replay_drop_window_ticks,
                replay_drop_count_in_window: 0,
                replay_drop_window_start_tick: handshake.timestamp_ticks,
                max_buffered_messages: config.max_buffered_messages,
                inbound: VecDeque::new(),
            },
        );

        self.emit_event(SessionEventInput {
            trace_id: handshake.trace_id,
            decision_id: None,
            policy_id: None,
            event: "session_created",
            outcome: "ok",
            error_code: None,
            session_id: handshake.session_id.clone(),
            extension_id: handshake.extension_id,
            host_id: handshake.host_id,
            sequence: None,
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks: handshake.timestamp_ticks,
        });

        Ok(SessionHandle {
            session_id: handshake.session_id,
        })
    }

    /// Send an inline payload on an established session.
    pub fn send(
        &mut self,
        handle: &SessionHandle,
        payload: Vec<u8>,
        trace_id: &str,
        timestamp_ticks: u64,
        decision_id: Option<&str>,
        policy_id: Option<&str>,
    ) -> Result<u64, SessionChannelError> {
        let (sequence, session_id, extension_id, host_id) = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            ensure_session_active(session, timestamp_ticks)?;

            if session.inbound.len() >= session.max_buffered_messages {
                return Err(SessionChannelError::Backpressure {
                    session_id: session.session_id.clone(),
                    pending: session.inbound.len(),
                    limit: session.max_buffered_messages,
                });
            }

            if session.next_sequence == u64::MAX {
                session.state = SessionState::Expired;
                return Err(SessionChannelError::SessionExpired {
                    session_id: session.session_id.clone(),
                    reason: "sequence_exhausted".to_string(),
                });
            }

            let sequence = session.next_sequence;
            let mut envelope = HostcallEnvelope {
                session_id: session.session_id.clone(),
                extension_id: session.extension_id.clone(),
                host_id: session.host_id.clone(),
                sequence,
                payload: ChannelPayload::Inline(payload),
                mac: AuthenticityHash([0u8; 32]),
                trace_id: trace_id.to_string(),
                sent_at_tick: timestamp_ticks,
            };
            envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
            session.inbound.push_back(envelope);
            session.next_sequence += 1;
            session.sent_messages = session.sent_messages.saturating_add(1);
            (
                sequence,
                session.session_id.clone(),
                session.extension_id.clone(),
                session.host_id.clone(),
            )
        };

        self.emit_event(SessionEventInput {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(ToOwned::to_owned),
            policy_id: policy_id.map(ToOwned::to_owned),
            event: "message_sent",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: Some(sequence),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks,
        });

        Ok(sequence)
    }

    /// Send a shared-memory descriptor payload without copying message bytes.
    pub fn send_shared_buffer(
        &mut self,
        handle: &SessionHandle,
        input: SharedSendInput<'_>,
    ) -> Result<u64, SessionChannelError> {
        let descriptor = SharedPayloadDescriptor {
            region_id: input.region_id,
            payload_len: input.payload.len(),
            payload_hash: ContentHash::compute(input.payload),
        };

        let (sequence, session_id, extension_id, host_id) = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            ensure_session_active(session, input.timestamp_ticks)?;

            if session.inbound.len() >= session.max_buffered_messages {
                return Err(SessionChannelError::Backpressure {
                    session_id: session.session_id.clone(),
                    pending: session.inbound.len(),
                    limit: session.max_buffered_messages,
                });
            }

            if session.next_sequence == u64::MAX {
                session.state = SessionState::Expired;
                return Err(SessionChannelError::SessionExpired {
                    session_id: session.session_id.clone(),
                    reason: "sequence_exhausted".to_string(),
                });
            }

            let sequence = session.next_sequence;
            let mut envelope = HostcallEnvelope {
                session_id: session.session_id.clone(),
                extension_id: session.extension_id.clone(),
                host_id: session.host_id.clone(),
                sequence,
                payload: ChannelPayload::Shared(descriptor),
                mac: AuthenticityHash([0u8; 32]),
                trace_id: input.trace_id.to_string(),
                sent_at_tick: input.timestamp_ticks,
            };
            envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
            session.inbound.push_back(envelope);
            session.next_sequence += 1;
            session.sent_messages = session.sent_messages.saturating_add(1);
            (
                sequence,
                session.session_id.clone(),
                session.extension_id.clone(),
                session.host_id.clone(),
            )
        };

        self.emit_event(SessionEventInput {
            trace_id: input.trace_id.to_string(),
            decision_id: input.decision_id.map(ToOwned::to_owned),
            policy_id: input.policy_id.map(ToOwned::to_owned),
            event: "shared_payload_sent",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: Some(sequence),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks: input.timestamp_ticks,
        });

        Ok(sequence)
    }

    /// Receive and verify the next queued envelope for a session.
    pub fn receive(
        &mut self,
        handle: &SessionHandle,
        trace_id: &str,
        timestamp_ticks: u64,
        decision_id: Option<&str>,
        policy_id: Option<&str>,
    ) -> Result<ChannelPayload, SessionChannelError> {
        let mut drop_event: Option<SessionEventInput> = None;
        let mut escalation_event: Option<SessionEventInput> = None;

        let receive_result = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            ensure_session_active(session, timestamp_ticks)?;

            let envelope = session.inbound.pop_front().ok_or_else(|| {
                SessionChannelError::NoMessageAvailable {
                    session_id: session.session_id.clone(),
                }
            })?;

            if envelope.session_id != session.session_id {
                return Err(SessionChannelError::SessionBindingMismatch {
                    expected_session_id: session.session_id.clone(),
                    actual_session_id: envelope.session_id,
                });
            }
            if envelope.extension_id != session.extension_id || envelope.host_id != session.host_id
            {
                return Err(SessionChannelError::SessionBindingMismatch {
                    expected_session_id: session.session_id.clone(),
                    actual_session_id: envelope.session_id,
                });
            }

            let expected_mac = compute_envelope_mac(&session.session_key, &envelope);
            if !expected_mac.constant_time_eq(&envelope.mac) {
                return Err(SessionChannelError::MacMismatch {
                    session_id: session.session_id.clone(),
                    sequence: envelope.sequence,
                });
            }

            let expected_min_seq = session.last_received_sequence.saturating_add(1);
            let drop_reason = if envelope.sequence == session.last_received_sequence {
                Some(ReplayDropReason::Duplicate)
            } else if envelope.sequence < session.last_received_sequence {
                Some(ReplayDropReason::Replay)
            } else if session.sequence_policy == SequencePolicy::Strict
                && envelope.sequence != expected_min_seq
            {
                Some(ReplayDropReason::OutOfOrder)
            } else {
                None
            };

            if let Some(reason) = drop_reason {
                let source_principal = envelope.extension_id.clone();
                let error = match reason {
                    ReplayDropReason::OutOfOrder => SessionChannelError::OutOfOrderDetected {
                        session_id: session.session_id.clone(),
                        sequence: envelope.sequence,
                        expected_min: expected_min_seq,
                    },
                    ReplayDropReason::Replay | ReplayDropReason::Duplicate => {
                        SessionChannelError::ReplayDetected {
                            session_id: session.session_id.clone(),
                            sequence: envelope.sequence,
                            last_seen: session.last_received_sequence,
                        }
                    }
                };

                let error_code = match reason {
                    ReplayDropReason::Replay => "FE-5003",
                    ReplayDropReason::Duplicate => "FE-5004",
                    ReplayDropReason::OutOfOrder => "FE-5005",
                };

                drop_event = Some(SessionEventInput {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.map(ToOwned::to_owned),
                    policy_id: policy_id.map(ToOwned::to_owned),
                    event: "message_dropped",
                    outcome: "drop",
                    error_code: Some(error_code),
                    session_id: session.session_id.clone(),
                    extension_id: session.extension_id.clone(),
                    host_id: session.host_id.clone(),
                    sequence: Some(envelope.sequence),
                    expected_min_seq: Some(expected_min_seq),
                    received_seq: Some(envelope.sequence),
                    drop_reason: Some(reason.as_str()),
                    source_principal: Some(source_principal.clone()),
                    timestamp_ticks,
                });

                if register_replay_drop(session, timestamp_ticks) {
                    session.state = SessionState::Expired;
                    escalation_event = Some(SessionEventInput {
                        trace_id: trace_id.to_string(),
                        decision_id: decision_id.map(ToOwned::to_owned),
                        policy_id: policy_id.map(ToOwned::to_owned),
                        event: "replay_drop_threshold_exceeded",
                        outcome: "escalated",
                        error_code: Some("FE-5009"),
                        session_id: session.session_id.clone(),
                        extension_id: session.extension_id.clone(),
                        host_id: session.host_id.clone(),
                        sequence: Some(envelope.sequence),
                        expected_min_seq: Some(expected_min_seq),
                        received_seq: Some(envelope.sequence),
                        drop_reason: Some(reason.as_str()),
                        source_principal: Some(source_principal),
                        timestamp_ticks,
                    });
                    Err(SessionChannelError::SessionExpired {
                        session_id: session.session_id.clone(),
                        reason: "replay_drop_threshold_exceeded".to_string(),
                    })
                } else {
                    Err(error)
                }
            } else {
                session.last_received_sequence = envelope.sequence;
                session.received_messages = session.received_messages.saturating_add(1);
                Ok((
                    envelope.payload,
                    session.session_id.clone(),
                    session.extension_id.clone(),
                    session.host_id.clone(),
                    envelope.sequence,
                ))
            }
        };

        if let Some(event) = drop_event {
            self.emit_event(event);
        }
        if let Some(event) = escalation_event {
            self.emit_event(event);
        }

        let (payload, session_id, extension_id, host_id, sequence) = receive_result?;

        self.emit_event(SessionEventInput {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(ToOwned::to_owned),
            policy_id: policy_id.map(ToOwned::to_owned),
            event: "message_received",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: Some(sequence),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks,
        });

        Ok(payload)
    }

    /// Close an active session.
    pub fn close_session(
        &mut self,
        handle: &SessionHandle,
        trace_id: &str,
        timestamp_ticks: u64,
        decision_id: Option<&str>,
        policy_id: Option<&str>,
    ) -> Result<(), SessionChannelError> {
        let (session_id, extension_id, host_id) = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            if session.state == SessionState::Closed {
                return Err(SessionChannelError::SessionNotEstablished {
                    session_id: session.session_id.clone(),
                    state: session.state,
                });
            }
            session.state = SessionState::Closed;
            (
                session.session_id.clone(),
                session.extension_id.clone(),
                session.host_id.clone(),
            )
        };

        self.emit_event(SessionEventInput {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(ToOwned::to_owned),
            policy_id: policy_id.map(ToOwned::to_owned),
            event: "session_closed",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: None,
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks,
        });

        Ok(())
    }

    /// Create an authenticated backpressure signal envelope.
    pub fn authenticated_backpressure_signal(
        &self,
        handle: &SessionHandle,
        pending_messages: usize,
        limit: usize,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> Result<HostcallEnvelope, SessionChannelError> {
        let session = self.sessions.get(&handle.session_id).ok_or_else(|| {
            SessionChannelError::SessionNotFound {
                session_id: handle.session_id.clone(),
            }
        })?;
        if session.state != SessionState::Established {
            return Err(SessionChannelError::SessionNotEstablished {
                session_id: session.session_id.clone(),
                state: session.state,
            });
        }

        let mut envelope = HostcallEnvelope {
            session_id: session.session_id.clone(),
            extension_id: session.extension_id.clone(),
            host_id: session.host_id.clone(),
            sequence: session.next_sequence,
            payload: ChannelPayload::Backpressure(BackpressureSignal {
                pending_messages,
                limit,
            }),
            mac: AuthenticityHash([0u8; 32]),
            trace_id: trace_id.to_string(),
            sent_at_tick: timestamp_ticks,
        };
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        Ok(envelope)
    }

    /// Verify an authenticated control/backpressure signal.
    pub fn verify_authenticated_signal(
        &self,
        handle: &SessionHandle,
        envelope: &HostcallEnvelope,
    ) -> Result<(), SessionChannelError> {
        let session = self.sessions.get(&handle.session_id).ok_or_else(|| {
            SessionChannelError::SessionNotFound {
                session_id: handle.session_id.clone(),
            }
        })?;
        if envelope.session_id != session.session_id {
            return Err(SessionChannelError::SessionBindingMismatch {
                expected_session_id: session.session_id.clone(),
                actual_session_id: envelope.session_id.clone(),
            });
        }
        let expected = compute_envelope_mac(&session.session_key, envelope);
        if expected.constant_time_eq(&envelope.mac) {
            Ok(())
        } else {
            Err(SessionChannelError::MacMismatch {
                session_id: session.session_id.clone(),
                sequence: envelope.sequence,
            })
        }
    }

    /// Current queue length for a session.
    pub fn queue_len(&self, handle: &SessionHandle) -> Option<usize> {
        self.sessions
            .get(&handle.session_id)
            .map(|s| s.inbound.len())
    }

    /// Session state for a handle.
    pub fn session_state(&self, handle: &SessionHandle) -> Option<SessionState> {
        self.sessions.get(&handle.session_id).map(|s| s.state)
    }

    /// Drain accumulated structured events.
    pub fn drain_events(&mut self) -> Vec<SessionChannelEvent> {
        std::mem::take(&mut self.events)
    }

    fn emit_event(&mut self, input: SessionEventInput) {
        self.events.push(SessionChannelEvent {
            trace_id: input.trace_id,
            decision_id: input.decision_id,
            policy_id: input.policy_id,
            component: "session_hostcall_channel".to_string(),
            event: input.event.to_string(),
            outcome: input.outcome.to_string(),
            error_code: input.error_code.map(ToOwned::to_owned),
            session_id: input.session_id,
            extension_id: input.extension_id,
            host_id: input.host_id,
            sequence: input.sequence,
            expected_min_seq: input.expected_min_seq,
            received_seq: input.received_seq,
            drop_reason: input.drop_reason.map(ToOwned::to_owned),
            source_principal: input.source_principal,
            timestamp_ticks: input.timestamp_ticks,
        });
    }
}

/// Deterministically derive an AEAD nonce from session key + direction + sequence.
///
/// This is the only supported nonce construction path for session data-plane
/// envelopes; ad-hoc/random nonces are intentionally not exposed.
pub fn derive_deterministic_aead_nonce(
    session_key: &[u8; 32],
    direction: DataPlaneDirection,
    sequence: u64,
    algorithm: AeadAlgorithm,
) -> Result<DeterministicNonce, SessionChannelError> {
    enforce_nonce_budget(sequence, algorithm)?;

    let mut info = Vec::new();
    info.extend_from_slice(b"fe::hostcall::aead-nonce");
    info.push(direction.as_byte());
    info.push(algorithm.as_tag());
    info.extend_from_slice(&sequence.to_be_bytes());

    Ok(DeterministicNonce {
        bytes: hkdf_expand(session_key, &info, algorithm.nonce_len()),
    })
}

/// Build deterministic AEAD associated-data bytes for context binding.
pub fn build_aead_associated_data(session_id: &str, message_type: &str, flags: u32) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(b"fe::hostcall::aead-ad");
    append_str(&mut ad, session_id);
    append_str(&mut ad, message_type);
    ad.extend_from_slice(&flags.to_be_bytes());
    ad
}

fn enforce_nonce_budget(
    sequence: u64,
    algorithm: AeadAlgorithm,
) -> Result<(), SessionChannelError> {
    let limit = algorithm.max_messages_per_key();
    if sequence >= limit {
        return Err(SessionChannelError::NonceExhausted {
            sequence,
            limit,
            algorithm,
        });
    }
    Ok(())
}

#[derive(Debug)]
struct SessionEventInput {
    trace_id: String,
    decision_id: Option<String>,
    policy_id: Option<String>,
    event: &'static str,
    outcome: &'static str,
    error_code: Option<&'static str>,
    session_id: String,
    extension_id: String,
    host_id: String,
    sequence: Option<u64>,
    expected_min_seq: Option<u64>,
    received_seq: Option<u64>,
    drop_reason: Option<&'static str>,
    source_principal: Option<String>,
    timestamp_ticks: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_identity_field(field: &str, value: &str) -> Result<(), SessionChannelError> {
    if value.is_empty() {
        return Err(SessionChannelError::InvalidIdentity {
            field: field.to_string(),
        });
    }
    if value.len() > 128 {
        return Err(SessionChannelError::InvalidIdentity {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn ensure_session_active(
    session: &mut SessionRecord,
    now_ticks: u64,
) -> Result<(), SessionChannelError> {
    if session.state != SessionState::Established {
        return Err(SessionChannelError::SessionNotEstablished {
            session_id: session.session_id.clone(),
            state: session.state,
        });
    }
    if now_ticks > session.expires_at_tick {
        session.state = SessionState::Expired;
        return Err(SessionChannelError::SessionExpired {
            session_id: session.session_id.clone(),
            reason: "lifetime_exceeded".to_string(),
        });
    }
    if session
        .sent_messages
        .saturating_add(session.received_messages)
        >= session.max_messages
    {
        session.state = SessionState::Expired;
        return Err(SessionChannelError::SessionExpired {
            session_id: session.session_id.clone(),
            reason: "message_budget_exceeded".to_string(),
        });
    }
    Ok(())
}

fn register_replay_drop(session: &mut SessionRecord, now_ticks: u64) -> bool {
    if session.replay_drop_threshold == 0 || session.replay_drop_window_ticks == 0 {
        return false;
    }

    let elapsed = now_ticks.saturating_sub(session.replay_drop_window_start_tick);
    if elapsed >= session.replay_drop_window_ticks {
        session.replay_drop_window_start_tick = now_ticks;
        session.replay_drop_count_in_window = 0;
    }

    session.replay_drop_count_in_window = session.replay_drop_count_in_window.saturating_add(1);
    session.replay_drop_count_in_window >= session.replay_drop_threshold
}

fn handshake_request_preimage(
    handshake: &SessionHandshake,
    extension_key: &VerificationKey,
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"fe::hostcall::handshake::request");
    append_str(&mut preimage, &handshake.session_id);
    append_str(&mut preimage, &handshake.extension_id);
    append_str(&mut preimage, &handshake.host_id);
    preimage.extend_from_slice(&handshake.extension_nonce.to_be_bytes());
    preimage.extend_from_slice(&handshake.timestamp_ticks.to_be_bytes());
    preimage.extend_from_slice(extension_key.as_bytes());
    preimage
}

fn handshake_response_preimage(
    request: &HandshakeRequest,
    host_nonce: u64,
    host_key: &VerificationKey,
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"fe::hostcall::handshake::response");
    append_str(&mut preimage, &request.session_id);
    append_str(&mut preimage, &request.extension_id);
    append_str(&mut preimage, &request.host_id);
    preimage.extend_from_slice(&request.extension_nonce.to_be_bytes());
    preimage.extend_from_slice(&host_nonce.to_be_bytes());
    preimage.extend_from_slice(host_key.as_bytes());
    preimage.extend_from_slice(&request.signature.to_bytes());
    preimage
}

fn derive_session_key(
    request_preimage: &[u8],
    response_preimage: &[u8],
    request: &HandshakeRequest,
    response: &HandshakeResponse,
) -> [u8; 32] {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(request_preimage);
    transcript.extend_from_slice(&request.signature.to_bytes());
    transcript.extend_from_slice(response_preimage);
    transcript.extend_from_slice(&response.signature.to_bytes());

    let transcript_hash = ContentHash::compute(&transcript);

    // HKDF-Extract input keying material: authenticated transcript artifacts.
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&request.signature.to_bytes());
    ikm.extend_from_slice(&response.signature.to_bytes());
    ikm.extend_from_slice(request.extension_key.as_bytes());
    ikm.extend_from_slice(response.host_key.as_bytes());
    ikm.extend_from_slice(request_preimage);
    ikm.extend_from_slice(response_preimage);

    // Context-bound salt couples identity/session/timing/nonce fields.
    let mut salt = Vec::new();
    salt.extend_from_slice(b"fe::hostcall::hkdf::salt");
    append_str(&mut salt, &request.session_id);
    append_str(&mut salt, &request.extension_id);
    append_str(&mut salt, &request.host_id);
    salt.extend_from_slice(&request.timestamp_ticks.to_be_bytes());
    salt.extend_from_slice(&request.extension_nonce.to_be_bytes());
    salt.extend_from_slice(&response.host_nonce.to_be_bytes());
    salt.extend_from_slice(transcript_hash.as_bytes());
    let prk = hkdf_extract(&salt, &ikm);

    // HKDF-Expand info is domain-separated and includes transcript hash.
    let mut info = Vec::new();
    info.extend_from_slice(b"fe::hostcall::hkdf::session-mac-key");
    append_str(&mut info, &request.session_id);
    append_str(&mut info, &request.extension_id);
    append_str(&mut info, &request.host_id);
    info.extend_from_slice(&request.timestamp_ticks.to_be_bytes());
    info.extend_from_slice(&request.extension_nonce.to_be_bytes());
    info.extend_from_slice(&response.host_nonce.to_be_bytes());
    info.extend_from_slice(transcript_hash.as_bytes());

    hkdf_expand_32(&prk, &info)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // Tier-3 keyed hash acts as the HMAC primitive for extract.
    AuthenticityHash::compute_keyed(salt, ikm).0
}

fn hkdf_expand_32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let okm = hkdf_expand(prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    if out_len == 0 {
        return Vec::new();
    }

    let mut okm = Vec::with_capacity(out_len);
    let mut previous_block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while okm.len() < out_len {
        let mut block_input = Vec::with_capacity(previous_block.len() + info.len() + 1);
        if !previous_block.is_empty() {
            block_input.extend_from_slice(&previous_block);
        }
        block_input.extend_from_slice(info);
        block_input.push(counter);

        let block = AuthenticityHash::compute_keyed(prk, &block_input);
        previous_block = block.0.to_vec();
        okm.extend_from_slice(&previous_block);

        if counter == u8::MAX {
            break;
        }
        counter = counter.saturating_add(1);
    }

    okm.truncate(out_len);
    okm
}

fn compute_envelope_mac(session_key: &[u8; 32], envelope: &HostcallEnvelope) -> AuthenticityHash {
    let mut preimage = Vec::new();
    append_str(&mut preimage, &envelope.session_id);
    append_str(&mut preimage, &envelope.extension_id);
    append_str(&mut preimage, &envelope.host_id);
    preimage.extend_from_slice(&envelope.sequence.to_be_bytes());
    preimage.extend_from_slice(&envelope.sent_at_tick.to_be_bytes());
    append_str(&mut preimage, &envelope.trace_id);
    append_payload(&mut preimage, &envelope.payload);
    AuthenticityHash::compute_keyed(session_key, &preimage)
}

fn append_payload(preimage: &mut Vec<u8>, payload: &ChannelPayload) {
    match payload {
        ChannelPayload::Inline(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            preimage.extend_from_slice(bytes);
        }
        ChannelPayload::Shared(descriptor) => {
            preimage.push(2);
            preimage.extend_from_slice(&descriptor.region_id.to_be_bytes());
            preimage.extend_from_slice(&(descriptor.payload_len as u64).to_be_bytes());
            preimage.extend_from_slice(descriptor.payload_hash.as_bytes());
        }
        ChannelPayload::Backpressure(signal) => {
            preimage.push(3);
            preimage.extend_from_slice(&(signal.pending_messages as u64).to_be_bytes());
            preimage.extend_from_slice(&(signal.limit as u64).to_be_bytes());
        }
    }
}

fn append_str(preimage: &mut Vec<u8>, value: &str) {
    preimage.extend_from_slice(&(value.len() as u32).to_be_bytes());
    preimage.extend_from_slice(value.as_bytes());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes([byte; 32])
    }

    fn handshake(session_id: &str, trace_id: &str, tick: u64) -> SessionHandshake {
        SessionHandshake {
            session_id: session_id.to_string(),
            extension_id: "extension-a".to_string(),
            host_id: "host-a".to_string(),
            extension_nonce: 7,
            host_nonce: 11,
            timestamp_ticks: tick,
            trace_id: trace_id.to_string(),
        }
    }

    fn create_basic_session(
        channel: &mut SessionHostcallChannel,
        session_id: &str,
    ) -> SessionHandle {
        create_session_with_config(channel, session_id, SessionConfig::default())
    }

    fn create_session_with_config(
        channel: &mut SessionHostcallChannel,
        session_id: &str,
        config: SessionConfig,
    ) -> SessionHandle {
        channel
            .create_session(
                handshake(session_id, "trace-create", 100),
                &signing_key(1),
                &signing_key(2),
                config,
            )
            .expect("session should be created")
    }

    #[test]
    fn create_session_performs_mutual_signature_handshake() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-1");
        assert_eq!(handle.session_id, "sess-1");
        assert_eq!(
            channel.session_state(&handle),
            Some(SessionState::Established)
        );

        let events = channel.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "session_created");
        assert_eq!(events[0].trace_id, "trace-create");
    }

    #[test]
    fn send_and_receive_round_trip_with_mac_verification() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-2");
        let seq = channel
            .send(
                &handle,
                b"hello".to_vec(),
                "trace-send",
                101,
                Some("dec-1"),
                Some("policy-1"),
            )
            .expect("send should pass");
        assert_eq!(seq, 1);

        let payload = channel
            .receive(&handle, "trace-recv", 102, Some("dec-2"), Some("policy-1"))
            .expect("receive should pass");
        assert_eq!(payload, ChannelPayload::Inline(b"hello".to_vec()));
        assert_eq!(channel.queue_len(&handle), Some(0));
    }

    #[test]
    fn tampered_payload_fails_mac_verification() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-3");
        channel
            .send(&handle, b"hello".to_vec(), "trace-send", 101, None, None)
            .expect("send should pass");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let envelope = session.inbound.front_mut().expect("envelope exists");
        envelope.payload = ChannelPayload::Inline(b"tampered".to_vec());

        let err = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
    }

    #[test]
    fn tampered_sequence_fails_mac_verification() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-seq-mac");
        channel
            .send(&handle, b"hello".to_vec(), "trace-send", 101, None, None)
            .expect("send should pass");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let envelope = session.inbound.front_mut().expect("envelope exists");
        envelope.sequence = 99;

        let err = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
    }

    #[test]
    fn replayed_sequence_is_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-4");
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send should pass");

        let replay_envelope = {
            let session = channel
                .sessions
                .get(&handle.session_id)
                .expect("session exists");
            session.inbound.front().cloned().expect("envelope exists")
        };

        let first = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive should pass");
        assert_eq!(first, ChannelPayload::Inline(b"first".to_vec()));

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        session.inbound.push_back(replay_envelope);

        let err = channel
            .receive(&handle, "trace-recv-2", 103, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));
    }

    #[test]
    fn lower_sequence_is_rejected_as_replay() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-lower");
        channel
            .send(&handle, b"first".to_vec(), "trace-send-1", 101, None, None)
            .expect("first send");
        let _ = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive");

        channel
            .send(&handle, b"second".to_vec(), "trace-send-2", 103, None, None)
            .expect("second send");
        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let mut envelope = session.inbound.pop_front().expect("envelope exists");
        envelope.sequence = 0;
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        session.inbound.push_front(envelope);

        let err = channel
            .receive(&handle, "trace-recv-2", 104, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));
    }

    #[test]
    fn strict_policy_rejects_sequence_gaps() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-strict",
            SessionConfig {
                sequence_policy: SequencePolicy::Strict,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let mut envelope = session.inbound.pop_front().expect("envelope exists");
        envelope.sequence = 3;
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        session.inbound.push_front(envelope);

        let err = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::OutOfOrderDetected { .. }
        ));
    }

    #[test]
    fn monotonic_policy_accepts_sequence_gaps() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-monotonic",
            SessionConfig {
                sequence_policy: SequencePolicy::Monotonic,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let mut envelope = session.inbound.pop_front().expect("envelope exists");
        envelope.sequence = 3;
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        session.inbound.push_front(envelope);

        let payload = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .expect("gap should be accepted in monotonic mode");
        assert_eq!(payload, ChannelPayload::Inline(b"first".to_vec()));
    }

    #[test]
    fn replay_drop_emits_structured_telemetry() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-telemetry");
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let replay = {
            let session = channel
                .sessions
                .get(&handle.session_id)
                .expect("session exists");
            session.inbound.front().cloned().expect("envelope exists")
        };

        let _ = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive");
        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        session.inbound.push_back(replay);

        let err = channel
            .receive(&handle, "trace-recv-2", 103, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));

        let events = channel.drain_events();
        let dropped = events
            .iter()
            .find(|event| event.event == "message_dropped")
            .expect("drop event present");
        assert_eq!(dropped.expected_min_seq, Some(2));
        assert_eq!(dropped.received_seq, Some(1));
        assert_eq!(dropped.drop_reason.as_deref(), Some("duplicate"));
        assert_eq!(dropped.source_principal.as_deref(), Some("extension-a"));
    }

    #[test]
    fn replay_drop_rate_limit_escalates_session() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-drop-limit",
            SessionConfig {
                replay_drop_threshold: 2,
                replay_drop_window_ticks: 100,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let replay = {
            let session = channel
                .sessions
                .get(&handle.session_id)
                .expect("session exists");
            session.inbound.front().cloned().expect("envelope exists")
        };

        let _ = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive");

        {
            let session = channel
                .sessions
                .get_mut(&handle.session_id)
                .expect("session exists");
            session.inbound.push_back(replay.clone());
        }
        let first_drop = channel
            .receive(&handle, "trace-recv-2", 103, None, None)
            .unwrap_err();
        assert!(matches!(
            first_drop,
            SessionChannelError::ReplayDetected { .. }
        ));

        {
            let session = channel
                .sessions
                .get_mut(&handle.session_id)
                .expect("session exists");
            session.inbound.push_back(replay);
        }
        let second_drop = channel
            .receive(&handle, "trace-recv-3", 104, None, None)
            .unwrap_err();
        assert!(matches!(
            second_drop,
            SessionChannelError::SessionExpired { .. }
        ));
        assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));
    }

    #[test]
    fn sender_sequence_exhaustion_expires_session() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-seq-exhaust");
        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        session.next_sequence = u64::MAX;

        let err = channel
            .send(&handle, b"x".to_vec(), "trace-send", 101, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::SessionExpired { .. }));
        assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));
    }

    #[test]
    fn session_binding_mismatch_rejects_cross_session_envelope() {
        let mut channel = SessionHostcallChannel::new();
        let handle_a = create_basic_session(&mut channel, "sess-a");
        let handle_b = create_basic_session(&mut channel, "sess-b");

        channel
            .send(&handle_a, b"a".to_vec(), "trace-a", 101, None, None)
            .expect("send a");

        let stolen = {
            let session_a = channel
                .sessions
                .get_mut(&handle_a.session_id)
                .expect("a exists");
            session_a.inbound.pop_front().expect("envelope exists")
        };
        let session_b = channel
            .sessions
            .get_mut(&handle_b.session_id)
            .expect("b exists");
        session_b.inbound.push_back(stolen);

        let err = channel
            .receive(&handle_b, "trace-b", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionBindingMismatch { .. }
        ));
    }

    #[test]
    fn session_expires_on_message_budget_and_lifetime() {
        let mut channel = SessionHostcallChannel::new();
        let handle = channel
            .create_session(
                handshake("sess-expire", "trace-expire", 100),
                &signing_key(3),
                &signing_key(4),
                SessionConfig {
                    max_lifetime_ticks: 2,
                    max_messages: 1,
                    max_buffered_messages: 2,
                    ..SessionConfig::default()
                },
            )
            .expect("session create");

        channel
            .send(&handle, b"one".to_vec(), "trace-send", 101, None, None)
            .expect("first send");
        let err_budget = channel
            .send(&handle, b"two".to_vec(), "trace-send-2", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err_budget,
            SessionChannelError::SessionExpired { .. }
        ));

        let handle2 = channel
            .create_session(
                handshake("sess-expire-2", "trace-expire-2", 100),
                &signing_key(5),
                &signing_key(6),
                SessionConfig {
                    max_lifetime_ticks: 1,
                    max_messages: 10,
                    max_buffered_messages: 2,
                    ..SessionConfig::default()
                },
            )
            .expect("session create");
        let err_lifetime = channel
            .send(&handle2, b"x".to_vec(), "trace-lifetime", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err_lifetime,
            SessionChannelError::SessionExpired { .. }
        ));
    }

    #[test]
    fn backpressure_limit_enforced_and_signal_is_authenticated() {
        let mut channel = SessionHostcallChannel::new();
        let handle = channel
            .create_session(
                handshake("sess-backpressure", "trace-backpressure", 100),
                &signing_key(7),
                &signing_key(8),
                SessionConfig {
                    max_lifetime_ticks: 100,
                    max_messages: 100,
                    max_buffered_messages: 1,
                    ..SessionConfig::default()
                },
            )
            .expect("session create");

        channel
            .send(&handle, b"one".to_vec(), "trace-send", 101, None, None)
            .expect("first send");
        let err = channel
            .send(&handle, b"two".to_vec(), "trace-send", 102, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::Backpressure { .. }));

        let mut signal = channel
            .authenticated_backpressure_signal(&handle, 1, 1, "trace-signal", 103)
            .expect("signal");
        channel
            .verify_authenticated_signal(&handle, &signal)
            .expect("auth should pass");

        signal.payload = ChannelPayload::Backpressure(BackpressureSignal {
            pending_messages: 999,
            limit: 1,
        });
        let err = channel
            .verify_authenticated_signal(&handle, &signal)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
    }

    #[test]
    fn shared_buffer_path_stores_descriptor_not_raw_payload() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-shared");
        let payload = b"large-hostcall-payload".to_vec();

        channel
            .send_shared_buffer(
                &handle,
                SharedSendInput {
                    region_id: 42,
                    payload: &payload,
                    trace_id: "trace-shared",
                    timestamp_ticks: 101,
                    decision_id: Some("dec-shared"),
                    policy_id: Some("policy-shared"),
                },
            )
            .expect("shared send");

        let received = channel
            .receive(&handle, "trace-shared-rx", 102, None, None)
            .expect("shared receive");

        let expected = ChannelPayload::Shared(SharedPayloadDescriptor {
            region_id: 42,
            payload_len: payload.len(),
            payload_hash: ContentHash::compute(&payload),
        });
        assert_eq!(received, expected);
    }

    #[test]
    fn session_key_derivation_binds_session_context() {
        let mut channel = SessionHostcallChannel::new();
        let handle_a = create_basic_session(&mut channel, "sess-context-a");
        let handle_b = create_basic_session(&mut channel, "sess-context-b");

        let key_a = channel
            .sessions
            .get(&handle_a.session_id)
            .expect("session a exists")
            .session_key;
        let key_b = channel
            .sessions
            .get(&handle_b.session_id)
            .expect("session b exists")
            .session_key;

        assert_ne!(
            key_a, key_b,
            "session key must be bound to session-specific HKDF context"
        );
    }

    #[test]
    fn deterministic_aead_nonce_is_reproducible() {
        let key = [0x11; 32];
        let nonce_a = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            42,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let nonce_b = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            42,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        assert_eq!(nonce_a, nonce_b);
    }

    #[test]
    fn deterministic_aead_nonce_changes_with_direction_sequence_and_key() {
        let key_a = [0x11; 32];
        let key_b = [0x22; 32];
        let base = derive_deterministic_aead_nonce(
            &key_a,
            DataPlaneDirection::HostToExtension,
            7,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let different_direction = derive_deterministic_aead_nonce(
            &key_a,
            DataPlaneDirection::ExtensionToHost,
            7,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let different_sequence = derive_deterministic_aead_nonce(
            &key_a,
            DataPlaneDirection::HostToExtension,
            8,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let different_key = derive_deterministic_aead_nonce(
            &key_b,
            DataPlaneDirection::HostToExtension,
            7,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");

        assert_ne!(base, different_direction);
        assert_ne!(base, different_sequence);
        assert_ne!(base, different_key);
    }

    #[test]
    fn deterministic_aead_nonce_respects_algorithm_nonce_lengths() {
        let key = [0x11; 32];
        let chacha = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let aes = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1,
            AeadAlgorithm::Aes256Gcm,
        )
        .expect("nonce derivation");
        let xchacha = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1,
            AeadAlgorithm::XChaCha20Poly1305,
        )
        .expect("nonce derivation");

        assert_eq!(chacha.as_bytes().len(), 12);
        assert_eq!(aes.as_bytes().len(), 12);
        assert_eq!(xchacha.as_bytes().len(), 24);
    }

    #[test]
    fn deterministic_aead_nonce_enforces_key_exhaustion_limits() {
        let key = [0x11; 32];
        let err = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1u64 << 32,
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap_err();
        assert!(matches!(err, SessionChannelError::NonceExhausted { .. }));
    }

    #[test]
    fn deterministic_aead_associated_data_binds_session_and_metadata() {
        let ad = build_aead_associated_data("sess-ad", "hostcall.invoke", 0b1010);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"fe::hostcall::aead-ad");
        append_str(&mut expected, "sess-ad");
        append_str(&mut expected, "hostcall.invoke");
        expected.extend_from_slice(&0b1010u32.to_be_bytes());
        assert_eq!(ad, expected);
    }

    #[test]
    fn deterministic_aead_nonce_matches_golden_vector() {
        let key = [0xA5; 32];
        let nonce = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::ExtensionToHost,
            0x0102_0304_0506_0708,
            AeadAlgorithm::XChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let actual_hex: String = nonce
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            actual_hex,
            "cee6bc63f72327ba706715040961d5750eeb758755abf711"
        );
    }

    #[test]
    fn structured_events_include_stable_keys() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-events");
        channel
            .send(
                &handle,
                b"evt".to_vec(),
                "trace-evt",
                101,
                Some("decision-evt"),
                Some("policy-evt"),
            )
            .expect("send");
        let _ = channel.receive(
            &handle,
            "trace-evt-rx",
            102,
            Some("decision-evt-rx"),
            Some("policy-evt"),
        );

        let events = channel.drain_events();
        assert!(events.iter().all(|event| !event.trace_id.is_empty()));
        assert!(events.iter().all(|event| !event.component.is_empty()));
        assert!(events.iter().all(|event| !event.event.is_empty()));
        assert!(events.iter().all(|event| !event.outcome.is_empty()));
        assert!(events.iter().all(|event| !event.session_id.is_empty()));
    }

    #[test]
    fn serialization_round_trip_for_envelope_and_event() {
        let envelope = HostcallEnvelope {
            session_id: "s".to_string(),
            extension_id: "e".to_string(),
            host_id: "h".to_string(),
            sequence: 7,
            payload: ChannelPayload::Inline(vec![1, 2, 3]),
            mac: AuthenticityHash::compute_keyed(b"k", b"v"),
            trace_id: "t".to_string(),
            sent_at_tick: 10,
        };
        let encoded = serde_json::to_string(&envelope).expect("serialize");
        let decoded: HostcallEnvelope = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(envelope, decoded);

        let event = SessionChannelEvent {
            trace_id: "trace".to_string(),
            decision_id: Some("dec".to_string()),
            policy_id: Some("policy".to_string()),
            component: "session_hostcall_channel".to_string(),
            event: "message_sent".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("FE-5000".to_string()),
            session_id: "s".to_string(),
            extension_id: "e".to_string(),
            host_id: "h".to_string(),
            sequence: Some(1),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks: 12,
        };
        let encoded_event = serde_json::to_string(&event).expect("serialize");
        let decoded_event: SessionChannelEvent =
            serde_json::from_str(&encoded_event).expect("deserialize");
        assert_eq!(event, decoded_event);
    }
}
