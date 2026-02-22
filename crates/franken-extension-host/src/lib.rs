#![forbid(unsafe_code)]

pub fn placeholder_extension_host_symbol() {}

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const CURRENT_ENGINE_VERSION: &str = "0.1.0";
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_VERSION_LEN: usize = 64;
pub const MAX_ENTRYPOINT_LEN: usize = 1024;
pub const MAX_TRUST_CHAIN_REF_LEN: usize = 256;

const COMPONENT: &str = "extension_manifest_validation";
const EMPTY_CAPABILITIES: &[Capability] = &[];
const WRITE_IMPLIES: &[Capability] = &[Capability::FsRead];

/// Extension capability identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    NetClient,
    HostCall,
    ProcessSpawn,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetClient => "net_client",
            Self::HostCall => "host_call",
            Self::ProcessSpawn => "process_spawn",
        }
    }

    pub const fn implied_capabilities(self) -> &'static [Capability] {
        match self {
            Self::FsWrite => WRITE_IMPLIES,
            Self::FsRead | Self::NetClient | Self::HostCall | Self::ProcessSpawn => {
                EMPTY_CAPABILITIES
            }
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Extension manifest trust posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestTrustLevel {
    Development,
    SignedSupplyChain,
}

/// Extension manifest from the engine's perspective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    #[serde(deserialize_with = "deserialize_capability_set")]
    pub capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub publisher_signature: Option<Vec<u8>>,
    #[serde(default)]
    pub content_hash: [u8; 32],
    #[serde(default)]
    pub trust_chain_ref: Option<String>,
    #[serde(default = "default_min_engine_version")]
    pub min_engine_version: String,
}

impl ExtensionManifest {
    pub fn inferred_trust_level(&self) -> ManifestTrustLevel {
        let has_trust_chain = self
            .trust_chain_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if has_trust_chain || self.publisher_signature.is_some() {
            ManifestTrustLevel::SignedSupplyChain
        } else {
            ManifestTrustLevel::Development
        }
    }
}

/// Compile-time static manifest representation used for const validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticExtensionManifest {
    pub name: &'static str,
    pub entrypoint: &'static str,
    pub min_engine_version: &'static str,
    pub capabilities: &'static [Capability],
}

/// Const-compatible error model for static manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticManifestValidationError {
    EmptyName,
    EmptyEntrypoint,
    UnsupportedEngineVersion,
    FieldTooLong,
    MissingImpliedCapability {
        declared: Capability,
        missing_implied: Capability,
    },
}

/// Runtime manifest validation error with deterministic codes/messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestValidationError {
    EmptyName,
    EmptyVersion,
    EmptyEntrypoint,
    UnsupportedEngineVersion {
        min_engine_version: String,
        supported_engine_version: &'static str,
    },
    InvalidCapabilityLattice {
        declared: Capability,
        missing_implied: Capability,
    },
    MissingPublisherSignature,
    MissingTrustChainRef,
    InvalidContentHash,
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    CanonicalSerialization(String),
}

impl ManifestValidationError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::EmptyName => "FE-MANIFEST-0001",
            Self::EmptyVersion => "FE-MANIFEST-0002",
            Self::EmptyEntrypoint => "FE-MANIFEST-0003",
            Self::UnsupportedEngineVersion { .. } => "FE-MANIFEST-0004",
            Self::InvalidCapabilityLattice { .. } => "FE-MANIFEST-0005",
            Self::MissingPublisherSignature => "FE-MANIFEST-0006",
            Self::MissingTrustChainRef => "FE-MANIFEST-0007",
            Self::InvalidContentHash => "FE-MANIFEST-0008",
            Self::CanonicalSerialization(_) => "FE-MANIFEST-0009",
            Self::FieldTooLong { .. } => "FE-MANIFEST-0010",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::EmptyName => "name must not be empty".to_string(),
            Self::EmptyVersion => "version must not be empty".to_string(),
            Self::EmptyEntrypoint => "entrypoint must not be empty".to_string(),
            Self::UnsupportedEngineVersion {
                min_engine_version,
                supported_engine_version,
            } => format!(
                "min_engine_version `{min_engine_version}` is unsupported (max supported `{supported_engine_version}`)"
            ),
            Self::InvalidCapabilityLattice {
                declared,
                missing_implied,
            } => format!(
                "capability `{declared}` requires implied capability `{missing_implied}`"
            ),
            Self::MissingPublisherSignature => {
                "publisher_signature is required for signed supply-chain manifests".to_string()
            }
            Self::MissingTrustChainRef => {
                "trust_chain_ref is required for signed supply-chain manifests".to_string()
            }
            Self::InvalidContentHash => {
                "content_hash does not match canonical manifest bytes".to_string()
            }
            Self::CanonicalSerialization(message) => {
                format!("canonical manifest serialization failed: {message}")
            }
            Self::FieldTooLong { field, max, actual } => {
                format!("field `{field}` exceeds max length {max} (actual {actual})")
            }
        }
    }

    pub fn structured_message(&self, trace_id: &str, extension_id: &str) -> String {
        format!(
            "trace_id={trace_id} extension_id={extension_id} component={COMPONENT} error_code={} message={}",
            self.error_code(),
            self.message()
        )
    }
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest validation error [{}]: {}", self.error_code(), self.message())
    }
}

impl std::error::Error for ManifestValidationError {}

/// Structured context for deterministic validation events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestValidationContext<'a> {
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub policy_id: &'a str,
    pub extension_id: &'a str,
}

impl<'a> ManifestValidationContext<'a> {
    pub const fn new(
        trace_id: &'a str,
        decision_id: &'a str,
        policy_id: &'a str,
        extension_id: &'a str,
    ) -> Self {
        Self {
            trace_id,
            decision_id,
            policy_id,
            extension_id,
        }
    }
}

/// Structured deterministic event for manifest validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestValidationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Validation report with structured event + optional runtime error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestValidationReport {
    pub event: ManifestValidationEvent,
    pub error: Option<ManifestValidationError>,
}

impl ManifestValidationReport {
    pub fn into_result(self) -> Result<(), ManifestValidationError> {
        if let Some(error) = self.error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

fn default_min_engine_version() -> String {
    CURRENT_ENGINE_VERSION.to_string()
}

fn deserialize_capability_set<'de, D>(deserializer: D) -> Result<BTreeSet<Capability>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let capabilities = Vec::<Capability>::deserialize(deserializer)?;
    let mut deduped = BTreeSet::new();
    for capability in capabilities {
        if !deduped.insert(capability) {
            return Err(serde::de::Error::custom(format!(
                "duplicate capability `{capability}`"
            )));
        }
    }
    Ok(deduped)
}

/// Validate a static manifest at compile time.
pub const fn validate_static_manifest(
    manifest: &StaticExtensionManifest,
) -> Result<(), StaticManifestValidationError> {
    if manifest.name.is_empty() {
        return Err(StaticManifestValidationError::EmptyName);
    }
    if manifest.name.len() > MAX_NAME_LEN
        || manifest.entrypoint.len() > MAX_ENTRYPOINT_LEN
        || manifest.min_engine_version.len() > MAX_VERSION_LEN
    {
        return Err(StaticManifestValidationError::FieldTooLong);
    }
    if manifest.entrypoint.is_empty() {
        return Err(StaticManifestValidationError::EmptyEntrypoint);
    }
    if !is_supported_engine_version_const(manifest.min_engine_version) {
        return Err(StaticManifestValidationError::UnsupportedEngineVersion);
    }

    let mut i = 0usize;
    while i < manifest.capabilities.len() {
        let declared = manifest.capabilities[i];
        let implied = declared.implied_capabilities();

        let mut j = 0usize;
        while j < implied.len() {
            if !has_capability_const(manifest.capabilities, implied[j]) {
                return Err(StaticManifestValidationError::MissingImpliedCapability {
                    declared,
                    missing_implied: implied[j],
                });
            }
            j += 1;
        }
        i += 1;
    }

    Ok(())
}

const fn has_capability_const(set: &[Capability], capability: Capability) -> bool {
    let mut idx = 0usize;
    while idx < set.len() {
        if set[idx] as u8 == capability as u8 {
            return true;
        }
        idx += 1;
    }
    false
}

const fn is_supported_engine_version_const(version: &str) -> bool {
    let bytes = version.as_bytes();
    bytes.len() >= 2 && bytes[0] == b'0' && bytes[1] == b'.'
}

/// Validate capability lattice implications.
pub fn validate_capability_lattice(
    capabilities: &BTreeSet<Capability>,
) -> Result<(), ManifestValidationError> {
    for declared in capabilities {
        for implied in declared.implied_capabilities() {
            if !capabilities.contains(implied) {
                return Err(ManifestValidationError::InvalidCapabilityLattice {
                    declared: *declared,
                    missing_implied: *implied,
                });
            }
        }
    }
    Ok(())
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Validate minimum engine-version constraints.
pub fn validate_engine_version(min_engine_version: &str) -> Result<(), ManifestValidationError> {
    let requested = parse_semver(min_engine_version.trim());
    let supported = parse_semver(CURRENT_ENGINE_VERSION).expect("static engine version is valid");
    let Some((requested_major, requested_minor, _)) = requested else {
        return Err(ManifestValidationError::UnsupportedEngineVersion {
            min_engine_version: min_engine_version.to_string(),
            supported_engine_version: CURRENT_ENGINE_VERSION,
        });
    };
    let (supported_major, supported_minor, _) = supported;
    if requested_major > supported_major
        || (requested_major == supported_major && requested_minor > supported_minor)
    {
        return Err(ManifestValidationError::UnsupportedEngineVersion {
            min_engine_version: min_engine_version.to_string(),
            supported_engine_version: CURRENT_ENGINE_VERSION,
        });
    }
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Canonical deterministic manifest serialization (sorted keys, compact output).
pub fn canonical_manifest_json(
    manifest: &ExtensionManifest,
) -> Result<String, ManifestValidationError> {
    let mut map = BTreeMap::<String, Value>::new();
    map.insert(
        "capabilities".to_string(),
        Value::Array(
            manifest
                .capabilities
                .iter()
                .map(|capability| Value::String(capability.as_str().to_string()))
                .collect(),
        ),
    );
    map.insert(
        "content_hash".to_string(),
        Value::String(bytes_to_hex(&manifest.content_hash)),
    );
    map.insert(
        "entrypoint".to_string(),
        Value::String(manifest.entrypoint.clone()),
    );
    map.insert(
        "min_engine_version".to_string(),
        Value::String(manifest.min_engine_version.clone()),
    );
    map.insert("name".to_string(), Value::String(manifest.name.clone()));
    map.insert(
        "publisher_signature".to_string(),
        match &manifest.publisher_signature {
            Some(signature) => Value::String(bytes_to_hex(signature)),
            None => Value::Null,
        },
    );
    map.insert(
        "trust_chain_ref".to_string(),
        match &manifest.trust_chain_ref {
            Some(reference) => Value::String(reference.clone()),
            None => Value::Null,
        },
    );
    map.insert("version".to_string(), Value::String(manifest.version.clone()));

    serde_json::to_string(&map).map_err(|error| {
        ManifestValidationError::CanonicalSerialization(format!(
            "json encoding failed: {error}"
        ))
    })
}

/// Canonical deterministic bytes for signature/hash workflows.
pub fn canonical_manifest_bytes(
    manifest: &ExtensionManifest,
) -> Result<Vec<u8>, ManifestValidationError> {
    Ok(canonical_manifest_json(manifest)?.into_bytes())
}

/// Compute canonical content hash (SHA-256) over canonical bytes with content_hash zeroed.
pub fn compute_content_hash(
    manifest: &ExtensionManifest,
) -> Result<[u8; 32], ManifestValidationError> {
    let mut to_hash = manifest.clone();
    to_hash.content_hash = [0; 32];
    let bytes = canonical_manifest_bytes(&to_hash)?;
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

/// Helper to fill `content_hash` deterministically from canonical bytes.
pub fn with_computed_content_hash(
    mut manifest: ExtensionManifest,
) -> Result<ExtensionManifest, ManifestValidationError> {
    manifest.content_hash = compute_content_hash(&manifest)?;
    Ok(manifest)
}

/// Validate provenance requirements based on trust level.
pub fn validate_provenance(
    manifest: &ExtensionManifest,
    trust_level: ManifestTrustLevel,
) -> Result<(), ManifestValidationError> {
    let has_signature = manifest
        .publisher_signature
        .as_deref()
        .is_some_and(|bytes| !bytes.is_empty());
    let has_trust_chain = manifest
        .trust_chain_ref
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let expected_hash = compute_content_hash(manifest)?;
    let hash_matches = manifest.content_hash == expected_hash;

    match trust_level {
        ManifestTrustLevel::Development => {
            if (has_signature || has_trust_chain) && !hash_matches {
                return Err(ManifestValidationError::InvalidContentHash);
            }
        }
        ManifestTrustLevel::SignedSupplyChain => {
            if !has_signature {
                return Err(ManifestValidationError::MissingPublisherSignature);
            }
            if !has_trust_chain {
                return Err(ManifestValidationError::MissingTrustChainRef);
            }
            if !hash_matches {
                return Err(ManifestValidationError::InvalidContentHash);
            }
        }
    }

    Ok(())
}

/// Validate an extension manifest.
pub fn validate_manifest(manifest: &ExtensionManifest) -> Result<(), ManifestValidationError> {
    if manifest.name.trim().is_empty() {
        return Err(ManifestValidationError::EmptyName);
    }
    if manifest.version.trim().is_empty() {
        return Err(ManifestValidationError::EmptyVersion);
    }
    if manifest.entrypoint.trim().is_empty() {
        return Err(ManifestValidationError::EmptyEntrypoint);
    }
    if manifest.name.len() > MAX_NAME_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "name",
            max: MAX_NAME_LEN,
            actual: manifest.name.len(),
        });
    }
    if manifest.version.len() > MAX_VERSION_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "version",
            max: MAX_VERSION_LEN,
            actual: manifest.version.len(),
        });
    }
    if manifest.entrypoint.len() > MAX_ENTRYPOINT_LEN {
        return Err(ManifestValidationError::FieldTooLong {
            field: "entrypoint",
            max: MAX_ENTRYPOINT_LEN,
            actual: manifest.entrypoint.len(),
        });
    }
    if manifest
        .trust_chain_ref
        .as_deref()
        .is_some_and(|value| value.len() > MAX_TRUST_CHAIN_REF_LEN)
    {
        return Err(ManifestValidationError::FieldTooLong {
            field: "trust_chain_ref",
            max: MAX_TRUST_CHAIN_REF_LEN,
            actual: manifest
                .trust_chain_ref
                .as_deref()
                .map_or(0, str::len),
        });
    }

    validate_engine_version(&manifest.min_engine_version)?;
    validate_capability_lattice(&manifest.capabilities)?;
    validate_provenance(manifest, manifest.inferred_trust_level())?;
    Ok(())
}

/// Validate and emit a structured deterministic event envelope.
pub fn validate_manifest_with_context(
    manifest: &ExtensionManifest,
    context: &ManifestValidationContext<'_>,
) -> ManifestValidationReport {
    match validate_manifest(manifest) {
        Ok(()) => ManifestValidationReport {
            event: ManifestValidationEvent {
                trace_id: context.trace_id.to_string(),
                decision_id: context.decision_id.to_string(),
                policy_id: context.policy_id.to_string(),
                component: COMPONENT.to_string(),
                event: "manifest_validation".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
            },
            error: None,
        },
        Err(error) => ManifestValidationReport {
            event: ManifestValidationEvent {
                trace_id: context.trace_id.to_string(),
                decision_id: context.decision_id.to_string(),
                policy_id: context.policy_id.to_string(),
                component: COMPONENT.to_string(),
                event: "manifest_validation".to_string(),
                outcome: "fail".to_string(),
                error_code: Some(error.error_code().to_string()),
            },
            error: Some(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_set(values: &[Capability]) -> BTreeSet<Capability> {
        values.iter().copied().collect()
    }

    fn signed_manifest(capabilities: &[Capability]) -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            name: "weather-ext".to_string(),
            version: "1.2.3".to_string(),
            entrypoint: "dist/index.js".to_string(),
            capabilities: capability_set(capabilities),
            publisher_signature: Some(vec![1, 2, 3, 4]),
            content_hash: [0; 32],
            trust_chain_ref: Some("chain/weather-team".to_string()),
            min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
        };
        manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
        manifest
    }

    #[test]
    fn signed_manifest_validates_with_matching_hash() {
        let manifest = signed_manifest(&[Capability::FsRead, Capability::FsWrite]);
        assert_eq!(validate_manifest(&manifest), Ok(()));
    }

    #[test]
    fn fs_write_requires_fs_read() {
        let manifest = signed_manifest(&[Capability::FsWrite]);
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::InvalidCapabilityLattice {
                declared: Capability::FsWrite,
                missing_implied: Capability::FsRead,
            })
        );
    }

    #[test]
    fn signed_supply_chain_requires_signature() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.publisher_signature = None;
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::MissingPublisherSignature)
        );
    }

    #[test]
    fn invalid_content_hash_is_rejected() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.content_hash[0] ^= 0xFF;
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::InvalidContentHash)
        );
    }

    #[test]
    fn unsupported_engine_version_is_rejected() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.min_engine_version = "0.2.0".to_string();
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::UnsupportedEngineVersion {
                min_engine_version: "0.2.0".to_string(),
                supported_engine_version: CURRENT_ENGINE_VERSION,
            })
        );
    }

    #[test]
    fn overly_long_name_is_rejected() {
        let mut manifest = signed_manifest(&[Capability::FsRead]);
        manifest.name = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            validate_manifest(&manifest),
            Err(ManifestValidationError::FieldTooLong {
                field: "name",
                max: MAX_NAME_LEN,
                actual: MAX_NAME_LEN + 1,
            })
        );
    }

    #[test]
    fn canonical_serialization_is_deterministic_and_compact() {
        let manifest_a = signed_manifest(&[Capability::FsRead, Capability::FsWrite]);
        let manifest_b = signed_manifest(&[Capability::FsWrite, Capability::FsRead]);

        let json_a = canonical_manifest_json(&manifest_a).expect("canonical json");
        let json_b = canonical_manifest_json(&manifest_b).expect("canonical json");
        assert_eq!(json_a, json_b);
        assert!(!json_a.contains('\n'));
        assert!(!json_a.contains(": "));
        assert!(json_a.contains("\"capabilities\""));
    }

    #[test]
    fn validation_report_emits_pass_event() {
        let context = ManifestValidationContext::new(
            "trace-001",
            "decision-001",
            "policy-001",
            "weather-ext",
        );
        let manifest = signed_manifest(&[Capability::FsRead, Capability::FsWrite]);
        let report = validate_manifest_with_context(&manifest, &context);

        assert_eq!(report.error, None);
        assert_eq!(report.event.outcome, "pass");
        assert_eq!(report.event.error_code, None);
    }

    #[test]
    fn validation_report_emits_fail_event_with_stable_error_code() {
        let context = ManifestValidationContext::new(
            "trace-002",
            "decision-002",
            "policy-002",
            "weather-ext",
        );
        let manifest = signed_manifest(&[Capability::FsWrite]);
        let report = validate_manifest_with_context(&manifest, &context);

        assert!(report.error.is_some());
        assert_eq!(report.event.outcome, "fail");
        assert_eq!(report.event.error_code.as_deref(), Some("FE-MANIFEST-0005"));
    }

    const STATIC_VALID_MANIFEST: StaticExtensionManifest = StaticExtensionManifest {
        name: "static-ext",
        entrypoint: "index.js",
        min_engine_version: "0.1.0",
        capabilities: &[Capability::FsRead, Capability::FsWrite],
    };
    const STATIC_VALID_RESULT: Result<(), StaticManifestValidationError> =
        validate_static_manifest(&STATIC_VALID_MANIFEST);

    const STATIC_INVALID_MANIFEST: StaticExtensionManifest = StaticExtensionManifest {
        name: "static-ext",
        entrypoint: "index.js",
        min_engine_version: "0.1.0",
        capabilities: &[Capability::FsWrite],
    };
    const STATIC_INVALID_RESULT: Result<(), StaticManifestValidationError> =
        validate_static_manifest(&STATIC_INVALID_MANIFEST);

    #[test]
    fn const_validation_path_is_const_evaluable() {
        assert_eq!(STATIC_VALID_RESULT, Ok(()));
        assert_eq!(
            STATIC_INVALID_RESULT,
            Err(StaticManifestValidationError::MissingImpliedCapability {
                declared: Capability::FsWrite,
                missing_implied: Capability::FsRead,
            })
        );
    }
}
