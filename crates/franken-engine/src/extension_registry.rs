//! Signed extension registry with enforceable provenance and revocation.
//!
//! Provides the ecosystem trust foundation: every published extension carries
//! a signed manifest with content-addressed artifacts, publisher identity
//! attestation, and revocation support. The registry enforces provenance
//! verification on installation and propagates revocation events to runtimes.
//!
//! ## Package Format
//!
//! An extension package consists of:
//! - A signed manifest (publisher key, version, capabilities, content hashes)
//! - Content-addressed artifact blobs (code, assets)
//! - Provenance metadata (build descriptors, dependency hashes)
//!
//! ## Namespace Model
//!
//! Extensions use scoped namespaces (`@org/extension-name`) to prevent
//! squatting. Namespace claims require publisher identity verification.
//!
//! Plan references: Section 15 Pillar 1, 9A.10 (Provenance+Revocation),
//! 9F.9 (Revocation Mesh SLO), 9F.11 (Semantic Build Graph).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::revocation_chain::{RevocationChain, RevocationTargetType};
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REGISTRY_ZONE: &str = "extension-registry";
const PACKAGE_SCHEMA_DEF: &[u8] = b"ExtensionPackage.v1";
const PUBLISHER_SCHEMA_DEF: &[u8] = b"ExtensionPublisher.v1";
const REVOCATION_SCHEMA_DEF: &[u8] = b"ExtensionRegistryRevocation.v1";

/// Maximum number of capabilities an extension may declare.
const MAX_CAPABILITIES: usize = 256;

/// Maximum number of artifacts in a single package.
const MAX_ARTIFACTS: usize = 1024;

/// Maximum length of a scope name (bytes).
const MAX_SCOPE_LEN: usize = 128;

/// Maximum length of an extension name (bytes).
const MAX_NAME_LEN: usize = 128;

// ---------------------------------------------------------------------------
// RegistryError
// ---------------------------------------------------------------------------

/// Errors produced by registry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryError {
    /// Publisher not found in the registry.
    PublisherNotFound { publisher_id: EngineObjectId },
    /// Publisher key has been revoked.
    PublisherRevoked { publisher_id: EngineObjectId },
    /// Package with this name and version already exists.
    PackageAlreadyExists {
        scope: String,
        name: String,
        version: PackageVersion,
    },
    /// Package not found.
    PackageNotFound {
        scope: String,
        name: String,
        version: PackageVersion,
    },
    /// Package has been revoked.
    PackageRevoked { package_id: EngineObjectId },
    /// Manifest signature verification failed.
    SignatureInvalid { reason: String },
    /// Content hash mismatch between manifest and artifact.
    ContentHashMismatch {
        artifact_name: String,
        expected: ContentHash,
        actual: ContentHash,
    },
    /// Namespace scope not owned by this publisher.
    ScopeNotOwned {
        scope: String,
        publisher_id: EngineObjectId,
    },
    /// Too many capabilities declared.
    TooManyCapabilities { count: usize, max: usize },
    /// Too many artifacts in package.
    TooManyArtifacts { count: usize, max: usize },
    /// Invalid scope name.
    InvalidScope { scope: String, reason: String },
    /// Invalid extension name.
    InvalidName { name: String, reason: String },
    /// Revocation event references unknown target.
    RevocationTargetUnknown { target_id: EngineObjectId },
    /// Build descriptor missing required fields.
    BuildDescriptorIncomplete { missing_field: String },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublisherNotFound { publisher_id } => {
                write!(f, "publisher not found: {publisher_id}")
            }
            Self::PublisherRevoked { publisher_id } => {
                write!(f, "publisher revoked: {publisher_id}")
            }
            Self::PackageAlreadyExists {
                scope,
                name,
                version,
            } => write!(f, "package already exists: @{scope}/{name}@{version}"),
            Self::PackageNotFound {
                scope,
                name,
                version,
            } => write!(f, "package not found: @{scope}/{name}@{version}"),
            Self::PackageRevoked { package_id } => {
                write!(f, "package revoked: {package_id}")
            }
            Self::SignatureInvalid { reason } => {
                write!(f, "signature invalid: {reason}")
            }
            Self::ContentHashMismatch {
                artifact_name,
                expected,
                actual,
            } => write!(
                f,
                "content hash mismatch for {artifact_name}: expected {expected}, got {actual}"
            ),
            Self::ScopeNotOwned {
                scope,
                publisher_id,
            } => write!(f, "scope @{scope} not owned by {publisher_id}"),
            Self::TooManyCapabilities { count, max } => {
                write!(f, "too many capabilities: {count} > {max}")
            }
            Self::TooManyArtifacts { count, max } => {
                write!(f, "too many artifacts: {count} > {max}")
            }
            Self::InvalidScope { scope, reason } => {
                write!(f, "invalid scope @{scope}: {reason}")
            }
            Self::InvalidName { name, reason } => {
                write!(f, "invalid name {name}: {reason}")
            }
            Self::RevocationTargetUnknown { target_id } => {
                write!(f, "revocation target unknown: {target_id}")
            }
            Self::BuildDescriptorIncomplete { missing_field } => {
                write!(f, "build descriptor incomplete: missing {missing_field}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PackageVersion — semantic versioning
// ---------------------------------------------------------------------------

/// Semantic version for extension packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl PackageVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// PublisherIdentity — cryptographic publisher registration
// ---------------------------------------------------------------------------

/// A registered publisher in the extension registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherIdentity {
    /// Deterministic ID derived from publisher verification key.
    pub id: EngineObjectId,
    /// Human-readable display name.
    pub display_name: String,
    /// The publisher's verification (public) key.
    pub verification_key: VerificationKey,
    /// Scopes this publisher owns.
    pub owned_scopes: BTreeSet<String>,
    /// When the publisher was registered.
    pub registered_at: DeterministicTimestamp,
    /// Whether this publisher identity has been revoked.
    pub revoked: bool,
    /// Revocation timestamp, if revoked.
    pub revoked_at: Option<DeterministicTimestamp>,
    /// Reason for revocation, if revoked.
    pub revocation_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// BuildDescriptor — reproducible build metadata
// ---------------------------------------------------------------------------

/// Describes how an extension package was built for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildDescriptor {
    /// Content hash of the build tool (compiler/bundler) binary.
    pub toolchain_hash: ContentHash,
    /// Version string of the build tool.
    pub toolchain_version: String,
    /// Content hash of the source tree at build time.
    pub source_hash: ContentHash,
    /// Deterministic build flags used.
    pub build_flags: Vec<String>,
    /// Content hashes of all direct dependencies.
    pub dependency_hashes: BTreeMap<String, ContentHash>,
    /// Whether the build is reproducible (same inputs always yield same outputs).
    pub reproducible: bool,
}

impl BuildDescriptor {
    /// Validate that all required fields are present.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.toolchain_version.is_empty() {
            return Err(RegistryError::BuildDescriptorIncomplete {
                missing_field: "toolchain_version".to_string(),
            });
        }
        Ok(())
    }

    /// Compute a canonical content hash of this descriptor.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.toolchain_hash.as_bytes());
        buf.extend_from_slice(self.toolchain_version.as_bytes());
        buf.extend_from_slice(self.source_hash.as_bytes());
        for flag in &self.build_flags {
            buf.extend_from_slice(flag.as_bytes());
        }
        for (dep_name, dep_hash) in &self.dependency_hashes {
            buf.extend_from_slice(dep_name.as_bytes());
            buf.extend_from_slice(dep_hash.as_bytes());
        }
        buf.push(u8::from(self.reproducible));
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// ArtifactEntry — content-addressed artifact
// ---------------------------------------------------------------------------

/// A single content-addressed artifact in a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Relative path of the artifact within the package.
    pub path: String,
    /// Content hash of the artifact bytes.
    pub content_hash: ContentHash,
    /// Size in bytes.
    pub size_bytes: u64,
    /// MIME type hint (informational).
    pub mime_type: Option<String>,
}

// ---------------------------------------------------------------------------
// CapabilityDeclaration — requested capabilities
// ---------------------------------------------------------------------------

/// A capability requested by the extension.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    /// Capability name (e.g. "net:outbound", "fs:read:/tmp").
    pub name: String,
    /// Reason the extension needs this capability.
    pub justification: String,
    /// Whether the extension can function without this capability.
    pub optional: bool,
}

// ---------------------------------------------------------------------------
// ExtensionManifest — the signed manifest
// ---------------------------------------------------------------------------

/// The manifest included in every extension package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    /// Scoped namespace (e.g. "myorg").
    pub scope: String,
    /// Extension name (e.g. "weather-ext").
    pub name: String,
    /// Semantic version.
    pub version: PackageVersion,
    /// Publisher ID that signed this manifest.
    pub publisher_id: EngineObjectId,
    /// Publisher verification key (for offline verification).
    pub publisher_key: VerificationKey,
    /// Capability declarations.
    pub capabilities: Vec<CapabilityDeclaration>,
    /// Content-addressed artifact list.
    pub artifacts: Vec<ArtifactEntry>,
    /// Build provenance descriptor.
    pub build: BuildDescriptor,
    /// Content hash of all artifact entries (deterministic ordering).
    pub artifacts_root_hash: ContentHash,
    /// Human-readable description.
    pub description: String,
    /// Optional license identifier.
    pub license: Option<String>,
    /// Dependency declarations (scoped package references).
    pub dependencies: BTreeMap<String, PackageVersion>,
}

impl ExtensionManifest {
    /// Compute the canonical unsigned bytes for signing.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.scope.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.version.major.to_le_bytes());
        buf.extend_from_slice(&self.version.minor.to_le_bytes());
        buf.extend_from_slice(&self.version.patch.to_le_bytes());
        buf.extend_from_slice(&self.publisher_id.0);
        buf.extend_from_slice(&self.publisher_key.0);
        for cap in &self.capabilities {
            buf.extend_from_slice(cap.name.as_bytes());
            buf.push(0);
            buf.extend_from_slice(cap.justification.as_bytes());
            buf.push(u8::from(cap.optional));
        }
        buf.extend_from_slice(self.artifacts_root_hash.as_bytes());
        buf.extend_from_slice(self.build.content_hash().as_bytes());
        buf.extend_from_slice(self.description.as_bytes());
        if let Some(ref lic) = self.license {
            buf.extend_from_slice(lic.as_bytes());
        }
        for (dep_name, dep_ver) in &self.dependencies {
            buf.extend_from_slice(dep_name.as_bytes());
            buf.extend_from_slice(&dep_ver.major.to_le_bytes());
            buf.extend_from_slice(&dep_ver.minor.to_le_bytes());
            buf.extend_from_slice(&dep_ver.patch.to_le_bytes());
        }
        buf
    }

    /// Compute the content hash of all artifact entries (deterministic).
    pub fn compute_artifacts_root(&self) -> ContentHash {
        let mut buf = Vec::new();
        for art in &self.artifacts {
            buf.extend_from_slice(art.path.as_bytes());
            buf.push(0);
            buf.extend_from_slice(art.content_hash.as_bytes());
            buf.extend_from_slice(&art.size_bytes.to_le_bytes());
        }
        ContentHash::compute(&buf)
    }

    /// Validate manifest structure (not signature).
    pub fn validate_structure(&self) -> Result<(), RegistryError> {
        validate_scope(&self.scope)?;
        validate_name(&self.name)?;
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(RegistryError::TooManyCapabilities {
                count: self.capabilities.len(),
                max: MAX_CAPABILITIES,
            });
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(RegistryError::TooManyArtifacts {
                count: self.artifacts.len(),
                max: MAX_ARTIFACTS,
            });
        }
        self.build.validate()?;
        // Verify artifacts root hash matches computed value.
        let computed = self.compute_artifacts_root();
        if computed != self.artifacts_root_hash {
            return Err(RegistryError::ContentHashMismatch {
                artifact_name: "<artifacts_root>".to_string(),
                expected: self.artifacts_root_hash,
                actual: computed,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SignedPackage — manifest + signature
// ---------------------------------------------------------------------------

/// A signed extension package ready for publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPackage {
    /// The extension manifest.
    pub manifest: ExtensionManifest,
    /// Signature over the manifest's unsigned bytes.
    pub signature: Signature,
    /// Deterministic package ID (derived from manifest content).
    pub package_id: EngineObjectId,
    /// When this package was published.
    pub published_at: DeterministicTimestamp,
    /// Whether this package has been revoked.
    pub revoked: bool,
    /// Revocation timestamp, if revoked.
    pub revoked_at: Option<DeterministicTimestamp>,
    /// Reason for revocation, if revoked.
    pub revocation_reason: Option<String>,
}

impl SignedPackage {
    /// Derive the package ID from manifest content.
    pub fn derive_package_id(
        manifest: &ExtensionManifest,
    ) -> Result<EngineObjectId, RegistryError> {
        let schema_id = SchemaId::new(PACKAGE_SCHEMA_DEF);
        engine_object_id::derive_id(
            ObjectDomain::SignedManifest,
            REGISTRY_ZONE,
            &schema_id,
            &manifest.unsigned_bytes(),
        )
        .map_err(|e| RegistryError::SignatureInvalid {
            reason: format!("failed to derive package ID: {e}"),
        })
    }
}

// ---------------------------------------------------------------------------
// RegistryEvent — structured audit events
// ---------------------------------------------------------------------------

/// Structured event emitted by registry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEvent {
    /// Event type.
    pub event_type: RegistryEventType,
    /// Component that emitted the event.
    pub component: &'static str,
    /// Outcome of the operation.
    pub outcome: EventOutcome,
    /// Associated publisher ID, if applicable.
    pub publisher_id: Option<EngineObjectId>,
    /// Associated package ID, if applicable.
    pub package_id: Option<EngineObjectId>,
    /// Scope, if applicable.
    pub scope: Option<String>,
    /// Extension name, if applicable.
    pub name: Option<String>,
    /// Version, if applicable.
    pub version: Option<PackageVersion>,
    /// Error code, if the operation failed.
    pub error_code: Option<String>,
    /// Timestamp of the event.
    pub timestamp: DeterministicTimestamp,
}

/// Type of registry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegistryEventType {
    PublisherRegistered,
    PublisherRevoked,
    ScopeClaimed,
    PackagePublished,
    PackageQueried,
    PackageVerified,
    PackageRevoked,
    VerificationFailed,
    RevocationPropagated,
}

impl fmt::Display for RegistryEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PublisherRegistered => "publisher_registered",
            Self::PublisherRevoked => "publisher_revoked",
            Self::ScopeClaimed => "scope_claimed",
            Self::PackagePublished => "package_published",
            Self::PackageQueried => "package_queried",
            Self::PackageVerified => "package_verified",
            Self::PackageRevoked => "package_revoked",
            Self::VerificationFailed => "verification_failed",
            Self::RevocationPropagated => "revocation_propagated",
        };
        f.write_str(name)
    }
}

/// Outcome of a registry operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventOutcome {
    Success,
    Denied,
    Error,
}

impl fmt::Display for EventOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Error => "error",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_scope(scope: &str) -> Result<(), RegistryError> {
    if scope.is_empty() {
        return Err(RegistryError::InvalidScope {
            scope: scope.to_string(),
            reason: "scope cannot be empty".to_string(),
        });
    }
    if scope.len() > MAX_SCOPE_LEN {
        return Err(RegistryError::InvalidScope {
            scope: scope.to_string(),
            reason: format!("scope exceeds maximum length of {MAX_SCOPE_LEN}"),
        });
    }
    if !scope
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(RegistryError::InvalidScope {
            scope: scope.to_string(),
            reason: "scope must contain only alphanumeric, hyphen, or underscore".to_string(),
        });
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() {
        return Err(RegistryError::InvalidName {
            name: name.to_string(),
            reason: "name cannot be empty".to_string(),
        });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(RegistryError::InvalidName {
            name: name.to_string(),
            reason: format!("name exceeds maximum length of {MAX_NAME_LEN}"),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(RegistryError::InvalidName {
            name: name.to_string(),
            reason: "name must contain only alphanumeric, hyphen, or underscore".to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ExtensionRegistry — the registry itself
// ---------------------------------------------------------------------------

/// Package key for lookup (scope + name + version).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageKey {
    pub scope: String,
    pub name: String,
    pub version: PackageVersion,
}

impl fmt::Display for PackageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}/{}@{}", self.scope, self.name, self.version)
    }
}

/// Query parameters for searching packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageQuery {
    /// Filter by scope (exact match).
    pub scope: Option<String>,
    /// Filter by name (exact match).
    pub name: Option<String>,
    /// Filter by publisher.
    pub publisher_id: Option<EngineObjectId>,
    /// Include revoked packages in results.
    pub include_revoked: bool,
    /// Maximum number of results.
    pub limit: usize,
}

impl Default for PackageQuery {
    fn default() -> Self {
        Self {
            scope: None,
            name: None,
            publisher_id: None,
            include_revoked: false,
            limit: 100,
        }
    }
}

/// Verification result for a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the package passed verification.
    pub valid: bool,
    /// Package ID that was verified.
    pub package_id: EngineObjectId,
    /// Publisher key used for verification.
    pub publisher_key: VerificationKey,
    /// Whether the publisher is currently active (not revoked).
    pub publisher_active: bool,
    /// Whether the package is currently active (not revoked).
    pub package_active: bool,
    /// Manifest structure valid.
    pub structure_valid: bool,
    /// Signature valid.
    pub signature_valid: bool,
    /// Artifacts root hash matches.
    pub artifacts_root_valid: bool,
    /// Errors encountered during verification, if any.
    pub errors: Vec<String>,
}

/// Signed extension registry providing publish, query, verify, and revoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionRegistry {
    /// Registered publishers by ID.
    publishers: BTreeMap<EngineObjectId, PublisherIdentity>,
    /// Scope ownership: scope name -> publisher ID.
    scope_owners: BTreeMap<String, EngineObjectId>,
    /// Published packages by key.
    packages: BTreeMap<PackageKey, SignedPackage>,
    /// Package index by ID for revocation lookups.
    package_index: BTreeMap<EngineObjectId, PackageKey>,
    /// Audit event log.
    events: Vec<RegistryEvent>,
    /// Current logical timestamp.
    current_tick: DeterministicTimestamp,
}

impl ExtensionRegistry {
    /// Create a new empty registry.
    pub fn new(start_tick: DeterministicTimestamp) -> Self {
        Self {
            publishers: BTreeMap::new(),
            scope_owners: BTreeMap::new(),
            packages: BTreeMap::new(),
            package_index: BTreeMap::new(),
            events: Vec::new(),
            current_tick: start_tick,
        }
    }

    /// Advance the logical clock.
    pub fn advance_tick(&mut self, tick: DeterministicTimestamp) {
        self.current_tick = tick;
    }

    /// Access the audit event log.
    pub fn events(&self) -> &[RegistryEvent] {
        &self.events
    }

    /// Count of published packages (including revoked).
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Count of registered publishers (including revoked).
    pub fn publisher_count(&self) -> usize {
        self.publishers.len()
    }

    // -----------------------------------------------------------------------
    // Publisher management
    // -----------------------------------------------------------------------

    /// Register a new publisher identity.
    pub fn register_publisher(
        &mut self,
        display_name: &str,
        verification_key: VerificationKey,
    ) -> Result<EngineObjectId, RegistryError> {
        let schema_id = SchemaId::new(PUBLISHER_SCHEMA_DEF);
        let publisher_id = engine_object_id::derive_id(
            ObjectDomain::SignedManifest,
            REGISTRY_ZONE,
            &schema_id,
            &verification_key.0,
        )
        .map_err(|e| RegistryError::SignatureInvalid {
            reason: format!("failed to derive publisher ID: {e}"),
        })?;

        let identity = PublisherIdentity {
            id: publisher_id,
            display_name: display_name.to_string(),
            verification_key,
            owned_scopes: BTreeSet::new(),
            registered_at: self.current_tick,
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
        };

        self.publishers.insert(publisher_id, identity);
        self.emit_event(
            RegistryEventType::PublisherRegistered,
            EventOutcome::Success,
            Some(publisher_id),
            None,
            None,
            None,
            None,
            None,
        );
        Ok(publisher_id)
    }

    /// Revoke a publisher identity. All packages from this publisher are
    /// transitively considered untrusted.
    pub fn revoke_publisher(
        &mut self,
        publisher_id: EngineObjectId,
        reason: &str,
    ) -> Result<(), RegistryError> {
        let publisher = self
            .publishers
            .get_mut(&publisher_id)
            .ok_or(RegistryError::PublisherNotFound { publisher_id })?;

        publisher.revoked = true;
        publisher.revoked_at = Some(self.current_tick);
        publisher.revocation_reason = Some(reason.to_string());

        self.emit_event(
            RegistryEventType::PublisherRevoked,
            EventOutcome::Success,
            Some(publisher_id),
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Look up a publisher by ID.
    pub fn get_publisher(&self, publisher_id: &EngineObjectId) -> Option<&PublisherIdentity> {
        self.publishers.get(publisher_id)
    }

    /// Check if a publisher is active (registered and not revoked).
    pub fn is_publisher_active(&self, publisher_id: &EngineObjectId) -> bool {
        self.publishers
            .get(publisher_id)
            .is_some_and(|p| !p.revoked)
    }

    // -----------------------------------------------------------------------
    // Scope management
    // -----------------------------------------------------------------------

    /// Claim a namespace scope for a publisher.
    pub fn claim_scope(
        &mut self,
        publisher_id: EngineObjectId,
        scope: &str,
    ) -> Result<(), RegistryError> {
        validate_scope(scope)?;

        if !self.publishers.contains_key(&publisher_id) {
            return Err(RegistryError::PublisherNotFound { publisher_id });
        }
        if self
            .publishers
            .get(&publisher_id)
            .is_some_and(|p| p.revoked)
        {
            return Err(RegistryError::PublisherRevoked { publisher_id });
        }

        // Check if scope is already owned by someone else.
        if let Some(existing_owner) = self.scope_owners.get(scope) {
            if *existing_owner != publisher_id {
                return Err(RegistryError::ScopeNotOwned {
                    scope: scope.to_string(),
                    publisher_id,
                });
            }
            // Already owned by this publisher — idempotent.
            return Ok(());
        }

        self.scope_owners.insert(scope.to_string(), publisher_id);
        if let Some(pub_entry) = self.publishers.get_mut(&publisher_id) {
            pub_entry.owned_scopes.insert(scope.to_string());
        }

        self.emit_event(
            RegistryEventType::ScopeClaimed,
            EventOutcome::Success,
            Some(publisher_id),
            None,
            Some(scope.to_string()),
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Check if a publisher owns a scope.
    pub fn publisher_owns_scope(&self, publisher_id: &EngineObjectId, scope: &str) -> bool {
        self.scope_owners
            .get(scope)
            .is_some_and(|owner| owner == publisher_id)
    }

    // -----------------------------------------------------------------------
    // Publish
    // -----------------------------------------------------------------------

    /// Publish a signed extension package.
    ///
    /// Validates manifest structure, publisher ownership, scope ownership,
    /// and signature before accepting.
    pub fn publish(
        &mut self,
        manifest: ExtensionManifest,
        signature: Signature,
    ) -> Result<EngineObjectId, RegistryError> {
        // 1. Validate manifest structure.
        manifest.validate_structure()?;

        // 2. Check publisher exists and is active.
        let publisher = self.publishers.get(&manifest.publisher_id).ok_or(
            RegistryError::PublisherNotFound {
                publisher_id: manifest.publisher_id,
            },
        )?;

        if publisher.revoked {
            return Err(RegistryError::PublisherRevoked {
                publisher_id: manifest.publisher_id,
            });
        }

        // 3. Verify scope ownership.
        if !self.publisher_owns_scope(&manifest.publisher_id, &manifest.scope) {
            return Err(RegistryError::ScopeNotOwned {
                scope: manifest.scope.clone(),
                publisher_id: manifest.publisher_id,
            });
        }

        // 4. Check for duplicate.
        let key = PackageKey {
            scope: manifest.scope.clone(),
            name: manifest.name.clone(),
            version: manifest.version,
        };
        if self.packages.contains_key(&key) {
            return Err(RegistryError::PackageAlreadyExists {
                scope: manifest.scope.clone(),
                name: manifest.name.clone(),
                version: manifest.version,
            });
        }

        // 5. Verify signature.
        let unsigned = manifest.unsigned_bytes();
        if !verify_signature(&publisher.verification_key, &unsigned, &signature) {
            self.emit_event(
                RegistryEventType::VerificationFailed,
                EventOutcome::Denied,
                Some(manifest.publisher_id),
                None,
                Some(manifest.scope.clone()),
                Some(manifest.name.clone()),
                Some(manifest.version),
                Some("signature_invalid".to_string()),
            );
            return Err(RegistryError::SignatureInvalid {
                reason: "manifest signature does not verify against publisher key".to_string(),
            });
        }

        // 6. Derive package ID and store.
        let package_id = SignedPackage::derive_package_id(&manifest)?;

        let package = SignedPackage {
            manifest,
            signature,
            package_id,
            published_at: self.current_tick,
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
        };

        let scope = package.manifest.scope.clone();
        let name = package.manifest.name.clone();
        let version = package.manifest.version;

        self.package_index.insert(package_id, key.clone());
        self.packages.insert(key, package);

        self.emit_event(
            RegistryEventType::PackagePublished,
            EventOutcome::Success,
            None,
            Some(package_id),
            Some(scope),
            Some(name),
            Some(version),
            None,
        );

        Ok(package_id)
    }

    // -----------------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------------

    /// Look up a specific package by scope, name, and version.
    pub fn get_package(
        &self,
        scope: &str,
        name: &str,
        version: PackageVersion,
    ) -> Option<&SignedPackage> {
        let key = PackageKey {
            scope: scope.to_string(),
            name: name.to_string(),
            version,
        };
        self.packages.get(&key)
    }

    /// Look up a package by its ID.
    pub fn get_package_by_id(&self, package_id: &EngineObjectId) -> Option<&SignedPackage> {
        self.package_index
            .get(package_id)
            .and_then(|key| self.packages.get(key))
    }

    /// Search packages using a query.
    pub fn search(&self, query: &PackageQuery) -> Vec<&SignedPackage> {
        let mut results: Vec<&SignedPackage> = self
            .packages
            .values()
            .filter(|pkg| {
                if !query.include_revoked && pkg.revoked {
                    return false;
                }
                if let Some(ref scope) = query.scope {
                    if pkg.manifest.scope != *scope {
                        return false;
                    }
                }
                if let Some(ref name) = query.name {
                    if pkg.manifest.name != *name {
                        return false;
                    }
                }
                if let Some(ref pub_id) = query.publisher_id {
                    if pkg.manifest.publisher_id != *pub_id {
                        return false;
                    }
                }
                true
            })
            .take(query.limit)
            .collect();
        results.sort_by(|a, b| {
            a.manifest
                .scope
                .cmp(&b.manifest.scope)
                .then(a.manifest.name.cmp(&b.manifest.name))
                .then(a.manifest.version.cmp(&b.manifest.version))
        });
        results
    }

    /// List all versions of a named package.
    pub fn list_versions(&self, scope: &str, name: &str) -> Vec<PackageVersion> {
        self.packages
            .keys()
            .filter(|k| k.scope == scope && k.name == name)
            .map(|k| k.version)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Verify
    // -----------------------------------------------------------------------

    /// Verify a package's integrity: signature, structure, provenance, and
    /// revocation status.
    pub fn verify_package(
        &mut self,
        scope: &str,
        name: &str,
        version: PackageVersion,
    ) -> Result<VerificationResult, RegistryError> {
        let key = PackageKey {
            scope: scope.to_string(),
            name: name.to_string(),
            version,
        };
        let pkg = self
            .packages
            .get(&key)
            .ok_or(RegistryError::PackageNotFound {
                scope: scope.to_string(),
                name: name.to_string(),
                version,
            })?;

        let mut errors = Vec::new();
        let structure_valid = pkg.manifest.validate_structure().is_ok();
        if !structure_valid {
            errors.push("manifest structure invalid".to_string());
        }

        let artifacts_root_valid =
            pkg.manifest.compute_artifacts_root() == pkg.manifest.artifacts_root_hash;
        if !artifacts_root_valid {
            errors.push("artifacts root hash mismatch".to_string());
        }

        let publisher_active = self.is_publisher_active(&pkg.manifest.publisher_id);
        if !publisher_active {
            errors.push("publisher revoked or not found".to_string());
        }

        let package_active = !pkg.revoked;
        if !package_active {
            errors.push("package has been revoked".to_string());
        }

        let unsigned = pkg.manifest.unsigned_bytes();
        let signature_valid =
            verify_signature(&pkg.manifest.publisher_key, &unsigned, &pkg.signature);
        if !signature_valid {
            errors.push("signature verification failed".to_string());
        }

        let valid = structure_valid
            && artifacts_root_valid
            && publisher_active
            && package_active
            && signature_valid;

        let outcome = if valid {
            EventOutcome::Success
        } else {
            EventOutcome::Denied
        };

        self.emit_event(
            if valid {
                RegistryEventType::PackageVerified
            } else {
                RegistryEventType::VerificationFailed
            },
            outcome,
            Some(pkg.manifest.publisher_id),
            Some(pkg.package_id),
            Some(scope.to_string()),
            Some(name.to_string()),
            Some(version),
            if errors.is_empty() {
                None
            } else {
                Some(errors.join("; "))
            },
        );

        Ok(VerificationResult {
            valid,
            package_id: pkg.package_id,
            publisher_key: pkg.manifest.publisher_key,
            publisher_active,
            package_active,
            structure_valid,
            signature_valid,
            artifacts_root_valid,
            errors,
        })
    }

    // -----------------------------------------------------------------------
    // Revoke
    // -----------------------------------------------------------------------

    /// Revoke a specific package version.
    pub fn revoke_package(
        &mut self,
        scope: &str,
        name: &str,
        version: PackageVersion,
        reason: &str,
    ) -> Result<(), RegistryError> {
        let key = PackageKey {
            scope: scope.to_string(),
            name: name.to_string(),
            version,
        };
        let pkg = self
            .packages
            .get_mut(&key)
            .ok_or(RegistryError::PackageNotFound {
                scope: scope.to_string(),
                name: name.to_string(),
                version,
            })?;

        pkg.revoked = true;
        pkg.revoked_at = Some(self.current_tick);
        pkg.revocation_reason = Some(reason.to_string());

        let package_id = pkg.package_id;

        self.emit_event(
            RegistryEventType::PackageRevoked,
            EventOutcome::Success,
            None,
            Some(package_id),
            Some(scope.to_string()),
            Some(name.to_string()),
            Some(version),
            None,
        );

        Ok(())
    }

    /// Revoke a package by its ID.
    pub fn revoke_package_by_id(
        &mut self,
        package_id: EngineObjectId,
        reason: &str,
    ) -> Result<(), RegistryError> {
        let key = self.package_index.get(&package_id).cloned().ok_or(
            RegistryError::RevocationTargetUnknown {
                target_id: package_id,
            },
        )?;
        let scope = key.scope.clone();
        let name = key.name.clone();
        let version = key.version;
        self.revoke_package(&scope, &name, version, reason)
    }

    /// Check if a package is revoked (directly or transitively via publisher).
    pub fn is_package_revoked(&self, scope: &str, name: &str, version: PackageVersion) -> bool {
        let key = PackageKey {
            scope: scope.to_string(),
            name: name.to_string(),
            version,
        };
        match self.packages.get(&key) {
            None => false,
            Some(pkg) => {
                // Direct package revocation.
                if pkg.revoked {
                    return true;
                }
                // Transitive: publisher revoked.
                !self.is_publisher_active(&pkg.manifest.publisher_id)
            }
        }
    }

    /// Collect all packages affected by a publisher revocation.
    pub fn packages_affected_by_publisher_revocation(
        &self,
        publisher_id: &EngineObjectId,
    ) -> Vec<&SignedPackage> {
        self.packages
            .values()
            .filter(|pkg| pkg.manifest.publisher_id == *publisher_id)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Audit helpers
    // -----------------------------------------------------------------------

    /// Export the audit log as a JSON-lines-compatible vector.
    pub fn export_audit_log(&self) -> &[RegistryEvent] {
        &self.events
    }

    /// Count of audit events.
    pub fn audit_event_count(&self) -> usize {
        self.events.len()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn emit_event(
        &mut self,
        event_type: RegistryEventType,
        outcome: EventOutcome,
        publisher_id: Option<EngineObjectId>,
        package_id: Option<EngineObjectId>,
        scope: Option<String>,
        name: Option<String>,
        version: Option<PackageVersion>,
        error_code: Option<String>,
    ) {
        self.events.push(RegistryEvent {
            event_type,
            component: "extension_registry",
            outcome,
            publisher_id,
            package_id,
            scope,
            name,
            version,
            error_code,
            timestamp: self.current_tick,
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::SigningKey;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_signing_key() -> SigningKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        SigningKey(bytes)
    }

    fn test_verification_key_from(sk: &SigningKey) -> VerificationKey {
        VerificationKey(sk.public_key_bytes())
    }

    fn second_signing_key() -> SigningKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(17);
        }
        SigningKey(bytes)
    }

    fn test_build_descriptor() -> BuildDescriptor {
        BuildDescriptor {
            toolchain_hash: ContentHash::compute(b"rustc-1.77"),
            toolchain_version: "1.77.0".to_string(),
            source_hash: ContentHash::compute(b"source-tree"),
            build_flags: vec!["--release".to_string()],
            dependency_hashes: {
                let mut m = BTreeMap::new();
                m.insert("serde".to_string(), ContentHash::compute(b"serde-1.0"));
                m
            },
            reproducible: true,
        }
    }

    fn test_artifact() -> ArtifactEntry {
        ArtifactEntry {
            path: "main.fir".to_string(),
            content_hash: ContentHash::compute(b"compiled-extension-code"),
            size_bytes: 4096,
            mime_type: Some("application/octet-stream".to_string()),
        }
    }

    fn test_capability() -> CapabilityDeclaration {
        CapabilityDeclaration {
            name: "net:outbound".to_string(),
            justification: "Needs to fetch weather data".to_string(),
            optional: false,
        }
    }

    fn build_manifest(
        scope: &str,
        name: &str,
        version: PackageVersion,
        publisher_id: EngineObjectId,
        publisher_key: VerificationKey,
    ) -> ExtensionManifest {
        let artifacts = vec![test_artifact()];
        let mut buf = Vec::new();
        for art in &artifacts {
            buf.extend_from_slice(art.path.as_bytes());
            buf.push(0);
            buf.extend_from_slice(art.content_hash.as_bytes());
            buf.extend_from_slice(&art.size_bytes.to_le_bytes());
        }
        let artifacts_root_hash = ContentHash::compute(&buf);

        ExtensionManifest {
            scope: scope.to_string(),
            name: name.to_string(),
            version,
            publisher_id,
            publisher_key,
            capabilities: vec![test_capability()],
            artifacts,
            build: test_build_descriptor(),
            artifacts_root_hash,
            description: "A test extension".to_string(),
            license: Some("MIT".to_string()),
            dependencies: BTreeMap::new(),
        }
    }

    fn setup_registry_with_publisher() -> (
        ExtensionRegistry,
        EngineObjectId,
        SigningKey,
        VerificationKey,
    ) {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(100));
        let sk = test_signing_key();
        let vk = test_verification_key_from(&sk);
        let pub_id = reg.register_publisher("TestOrg", vk).unwrap();
        reg.claim_scope(pub_id, "testorg").unwrap();
        (reg, pub_id, sk, vk)
    }

    fn sign_and_publish(
        reg: &mut ExtensionRegistry,
        manifest: &ExtensionManifest,
        sk: &SigningKey,
    ) -> Result<EngineObjectId, RegistryError> {
        let unsigned = manifest.unsigned_bytes();
        let sig = sign_preimage(sk, &unsigned);
        reg.publish(manifest.clone(), sig)
    }

    // -----------------------------------------------------------------------
    // Publisher tests
    // -----------------------------------------------------------------------

    #[test]
    fn register_publisher_succeeds() {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
        let sk = test_signing_key();
        let vk = test_verification_key_from(&sk);
        let result = reg.register_publisher("MyPublisher", vk);
        assert!(result.is_ok());
        let pub_id = result.unwrap();
        assert!(reg.is_publisher_active(&pub_id));
        assert_eq!(reg.publisher_count(), 1);
    }

    #[test]
    fn revoke_publisher_marks_inactive() {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
        let sk = test_signing_key();
        let vk = test_verification_key_from(&sk);
        let pub_id = reg.register_publisher("Org", vk).unwrap();
        assert!(reg.is_publisher_active(&pub_id));

        reg.advance_tick(DeterministicTimestamp(10));
        reg.revoke_publisher(pub_id, "compromised key").unwrap();
        assert!(!reg.is_publisher_active(&pub_id));

        let p = reg.get_publisher(&pub_id).unwrap();
        assert!(p.revoked);
        assert_eq!(p.revoked_at, Some(DeterministicTimestamp(10)));
        assert_eq!(p.revocation_reason.as_deref(), Some("compromised key"));
    }

    #[test]
    fn revoke_unknown_publisher_fails() {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
        let fake_id = EngineObjectId([42; 32]);
        let result = reg.revoke_publisher(fake_id, "test");
        assert!(matches!(
            result,
            Err(RegistryError::PublisherNotFound { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Scope tests
    // -----------------------------------------------------------------------

    #[test]
    fn claim_scope_succeeds() {
        let (mut reg, pub_id, _, _) = setup_registry_with_publisher();
        // Already claimed "testorg" in setup — idempotent re-claim.
        assert!(reg.claim_scope(pub_id, "testorg").is_ok());
        assert!(reg.publisher_owns_scope(&pub_id, "testorg"));
    }

    #[test]
    fn claim_scope_by_different_publisher_fails() {
        let (mut reg, _pub_id, _, _) = setup_registry_with_publisher();
        let sk2 = second_signing_key();
        let vk2 = test_verification_key_from(&sk2);
        let pub_id2 = reg.register_publisher("OtherOrg", vk2).unwrap();
        let result = reg.claim_scope(pub_id2, "testorg");
        assert!(matches!(result, Err(RegistryError::ScopeNotOwned { .. })));
    }

    #[test]
    fn claim_scope_invalid_name_fails() {
        let (mut reg, pub_id, _, _) = setup_registry_with_publisher();
        assert!(matches!(
            reg.claim_scope(pub_id, ""),
            Err(RegistryError::InvalidScope { .. })
        ));
        assert!(matches!(
            reg.claim_scope(pub_id, "has spaces"),
            Err(RegistryError::InvalidScope { .. })
        ));
    }

    #[test]
    fn claim_scope_revoked_publisher_fails() {
        let (mut reg, pub_id, _, _) = setup_registry_with_publisher();
        reg.revoke_publisher(pub_id, "test").unwrap();
        let result = reg.claim_scope(pub_id, "newscope");
        assert!(matches!(
            result,
            Err(RegistryError::PublisherRevoked { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Publish tests
    // -----------------------------------------------------------------------

    #[test]
    fn publish_valid_package_succeeds() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let version = PackageVersion::new(1, 0, 0);
        let manifest = build_manifest("testorg", "weather-ext", version, pub_id, vk);
        let pkg_id = sign_and_publish(&mut reg, &manifest, &sk).unwrap();
        assert_eq!(reg.package_count(), 1);
        let pkg = reg.get_package("testorg", "weather-ext", version).unwrap();
        assert_eq!(pkg.package_id, pkg_id);
        assert!(!pkg.revoked);
    }

    #[test]
    fn publish_duplicate_fails() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let version = PackageVersion::new(1, 0, 0);
        let manifest = build_manifest("testorg", "weather-ext", version, pub_id, vk);
        sign_and_publish(&mut reg, &manifest, &sk).unwrap();
        let result = sign_and_publish(&mut reg, &manifest, &sk);
        assert!(matches!(
            result,
            Err(RegistryError::PackageAlreadyExists { .. })
        ));
    }

    #[test]
    fn publish_wrong_scope_fails() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let version = PackageVersion::new(1, 0, 0);
        let manifest = build_manifest("otherscope", "ext", version, pub_id, vk);
        let result = sign_and_publish(&mut reg, &manifest, &sk);
        assert!(matches!(result, Err(RegistryError::ScopeNotOwned { .. })));
    }

    #[test]
    fn publish_revoked_publisher_fails() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        reg.revoke_publisher(pub_id, "compromised").unwrap();
        let version = PackageVersion::new(1, 0, 0);
        let manifest = build_manifest("testorg", "ext", version, pub_id, vk);
        let result = sign_and_publish(&mut reg, &manifest, &sk);
        assert!(matches!(
            result,
            Err(RegistryError::PublisherRevoked { .. })
        ));
    }

    #[test]
    fn publish_invalid_signature_fails() {
        let (mut reg, pub_id, _sk, vk) = setup_registry_with_publisher();
        let bad_sk = second_signing_key();
        let version = PackageVersion::new(1, 0, 0);
        let manifest = build_manifest("testorg", "ext", version, pub_id, vk);
        let result = sign_and_publish(&mut reg, &manifest, &bad_sk);
        assert!(matches!(
            result,
            Err(RegistryError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn publish_too_many_capabilities_fails() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let version = PackageVersion::new(1, 0, 0);
        let mut manifest = build_manifest("testorg", "ext", version, pub_id, vk);
        manifest.capabilities = (0..=MAX_CAPABILITIES)
            .map(|i| CapabilityDeclaration {
                name: format!("cap:{i}"),
                justification: "test".to_string(),
                optional: false,
            })
            .collect();
        let result = sign_and_publish(&mut reg, &manifest, &sk);
        assert!(matches!(
            result,
            Err(RegistryError::TooManyCapabilities { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Query tests
    // -----------------------------------------------------------------------

    #[test]
    fn get_package_returns_published() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v1 = PackageVersion::new(1, 0, 0);
        let v2 = PackageVersion::new(1, 1, 0);
        let m1 = build_manifest("testorg", "ext", v1, pub_id, vk);
        let m2 = build_manifest("testorg", "ext", v2, pub_id, vk);
        sign_and_publish(&mut reg, &m1, &sk).unwrap();
        sign_and_publish(&mut reg, &m2, &sk).unwrap();

        assert!(reg.get_package("testorg", "ext", v1).is_some());
        assert!(reg.get_package("testorg", "ext", v2).is_some());
        assert!(
            reg.get_package("testorg", "ext", PackageVersion::new(2, 0, 0))
                .is_none()
        );
    }

    #[test]
    fn search_filters_correctly() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v1 = PackageVersion::new(1, 0, 0);
        let m1 = build_manifest("testorg", "ext-a", v1, pub_id, vk);
        let m2 = build_manifest("testorg", "ext-b", v1, pub_id, vk);
        sign_and_publish(&mut reg, &m1, &sk).unwrap();
        sign_and_publish(&mut reg, &m2, &sk).unwrap();

        // Filter by scope.
        let results = reg.search(&PackageQuery {
            scope: Some("testorg".to_string()),
            ..PackageQuery::default()
        });
        assert_eq!(results.len(), 2);

        // Filter by name.
        let results = reg.search(&PackageQuery {
            name: Some("ext-a".to_string()),
            ..PackageQuery::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].manifest.name, "ext-a");

        // Filter by non-existent scope.
        let results = reg.search(&PackageQuery {
            scope: Some("nope".to_string()),
            ..PackageQuery::default()
        });
        assert!(results.is_empty());
    }

    #[test]
    fn search_excludes_revoked_by_default() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v1 = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v1, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();
        reg.revoke_package("testorg", "ext", v1, "bad").unwrap();

        let results = reg.search(&PackageQuery::default());
        assert!(results.is_empty());

        let results = reg.search(&PackageQuery {
            include_revoked: true,
            ..PackageQuery::default()
        });
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn list_versions_returns_all() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        for patch in 0..3 {
            let v = PackageVersion::new(1, 0, patch);
            let m = build_manifest("testorg", "ext", v, pub_id, vk);
            sign_and_publish(&mut reg, &m, &sk).unwrap();
        }
        let versions = reg.list_versions("testorg", "ext");
        assert_eq!(versions.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Verify tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_valid_package_passes() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();

        let result = reg.verify_package("testorg", "ext", v).unwrap();
        assert!(result.valid);
        assert!(result.signature_valid);
        assert!(result.structure_valid);
        assert!(result.artifacts_root_valid);
        assert!(result.publisher_active);
        assert!(result.package_active);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn verify_revoked_package_reports_inactive() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();
        reg.revoke_package("testorg", "ext", v, "vuln").unwrap();

        let result = reg.verify_package("testorg", "ext", v).unwrap();
        assert!(!result.valid);
        assert!(!result.package_active);
        assert!(result.signature_valid); // Signature is still valid.
    }

    #[test]
    fn verify_publisher_revoked_reports_inactive() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();
        reg.revoke_publisher(pub_id, "compromised").unwrap();

        let result = reg.verify_package("testorg", "ext", v).unwrap();
        assert!(!result.valid);
        assert!(!result.publisher_active);
    }

    #[test]
    fn verify_nonexistent_package_errors() {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
        let v = PackageVersion::new(1, 0, 0);
        let result = reg.verify_package("x", "y", v);
        assert!(matches!(result, Err(RegistryError::PackageNotFound { .. })));
    }

    // -----------------------------------------------------------------------
    // Revoke tests
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_package_marks_revoked() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();

        reg.advance_tick(DeterministicTimestamp(200));
        reg.revoke_package("testorg", "ext", v, "supply chain compromise")
            .unwrap();

        assert!(reg.is_package_revoked("testorg", "ext", v));
        let pkg = reg.get_package("testorg", "ext", v).unwrap();
        assert!(pkg.revoked);
        assert_eq!(pkg.revoked_at, Some(DeterministicTimestamp(200)));
    }

    #[test]
    fn revoke_nonexistent_package_fails() {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
        let v = PackageVersion::new(1, 0, 0);
        let result = reg.revoke_package("x", "y", v, "test");
        assert!(matches!(result, Err(RegistryError::PackageNotFound { .. })));
    }

    #[test]
    fn revoke_package_by_id_works() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        let pkg_id = sign_and_publish(&mut reg, &m, &sk).unwrap();

        reg.revoke_package_by_id(pkg_id, "bad").unwrap();
        assert!(reg.is_package_revoked("testorg", "ext", v));
    }

    #[test]
    fn revoke_unknown_id_fails() {
        let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
        let fake_id = EngineObjectId([99; 32]);
        let result = reg.revoke_package_by_id(fake_id, "test");
        assert!(matches!(
            result,
            Err(RegistryError::RevocationTargetUnknown { .. })
        ));
    }

    #[test]
    fn transitive_revocation_via_publisher() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();

        // Package not directly revoked, but publisher is revoked.
        assert!(!reg.is_package_revoked("testorg", "ext", v));
        reg.revoke_publisher(pub_id, "key compromise").unwrap();
        assert!(reg.is_package_revoked("testorg", "ext", v));
    }

    #[test]
    fn packages_affected_by_publisher_revocation_lists_all() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        for i in 0..3 {
            let v = PackageVersion::new(1, 0, i);
            let m = build_manifest("testorg", "ext", v, pub_id, vk);
            sign_and_publish(&mut reg, &m, &sk).unwrap();
        }
        let affected = reg.packages_affected_by_publisher_revocation(&pub_id);
        assert_eq!(affected.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Audit event tests
    // -----------------------------------------------------------------------

    #[test]
    fn events_are_emitted_for_all_operations() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let initial_events = reg.audit_event_count();

        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();
        reg.verify_package("testorg", "ext", v).unwrap();
        reg.revoke_package("testorg", "ext", v, "test").unwrap();

        // Should have events for: register_publisher, claim_scope, publish,
        // verify, revoke = at least 5.
        assert!(reg.audit_event_count() >= initial_events + 3);

        let events = reg.export_audit_log();
        let types: BTreeSet<RegistryEventType> = events.iter().map(|e| e.event_type).collect();
        assert!(types.contains(&RegistryEventType::PublisherRegistered));
        assert!(types.contains(&RegistryEventType::ScopeClaimed));
        assert!(types.contains(&RegistryEventType::PackagePublished));
        assert!(types.contains(&RegistryEventType::PackageVerified));
        assert!(types.contains(&RegistryEventType::PackageRevoked));
    }

    #[test]
    fn failed_publish_emits_verification_failed_event() {
        let (mut reg, pub_id, _sk, vk) = setup_registry_with_publisher();
        let bad_sk = second_signing_key();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        let _ = sign_and_publish(&mut reg, &m, &bad_sk);

        let events = reg.export_audit_log();
        let has_failed = events
            .iter()
            .any(|e| e.event_type == RegistryEventType::VerificationFailed);
        assert!(has_failed);
    }

    // -----------------------------------------------------------------------
    // Validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn validate_scope_rejects_empty() {
        assert!(matches!(
            validate_scope(""),
            Err(RegistryError::InvalidScope { .. })
        ));
    }

    #[test]
    fn validate_scope_rejects_special_chars() {
        assert!(matches!(
            validate_scope("my scope!"),
            Err(RegistryError::InvalidScope { .. })
        ));
    }

    #[test]
    fn validate_scope_accepts_valid() {
        assert!(validate_scope("my-org").is_ok());
        assert!(validate_scope("org_123").is_ok());
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert!(matches!(
            validate_name(""),
            Err(RegistryError::InvalidName { .. })
        ));
    }

    #[test]
    fn validate_name_accepts_hyphen_underscore() {
        assert!(validate_name("my-ext").is_ok());
        assert!(validate_name("ext_v2").is_ok());
    }

    #[test]
    fn build_descriptor_validates_toolchain_version() {
        let mut bd = test_build_descriptor();
        bd.toolchain_version = String::new();
        assert!(matches!(
            bd.validate(),
            Err(RegistryError::BuildDescriptorIncomplete { .. })
        ));
    }

    #[test]
    fn manifest_artifacts_root_mismatch_caught() {
        let (_, pub_id, _, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let mut m = build_manifest("testorg", "ext", v, pub_id, vk);
        // Corrupt the artifacts root hash.
        m.artifacts_root_hash = ContentHash::compute(b"wrong");
        let result = m.validate_structure();
        assert!(matches!(
            result,
            Err(RegistryError::ContentHashMismatch { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn package_version_display() {
        let v = PackageVersion::new(2, 3, 1);
        assert_eq!(format!("{v}"), "2.3.1");
    }

    #[test]
    fn package_version_ordering() {
        let v1 = PackageVersion::new(1, 0, 0);
        let v2 = PackageVersion::new(1, 1, 0);
        let v3 = PackageVersion::new(2, 0, 0);
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn registry_serde_roundtrip() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();

        let json = serde_json::to_string(&reg).unwrap();
        let restored: ExtensionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.package_count(), 1);
        assert_eq!(restored.publisher_count(), 1);
    }

    #[test]
    fn signed_package_serde_roundtrip() {
        let (mut reg, pub_id, sk, vk) = setup_registry_with_publisher();
        let v = PackageVersion::new(1, 0, 0);
        let m = build_manifest("testorg", "ext", v, pub_id, vk);
        sign_and_publish(&mut reg, &m, &sk).unwrap();
        let pkg = reg.get_package("testorg", "ext", v).unwrap();

        let json = serde_json::to_string(pkg).unwrap();
        let restored: SignedPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.package_id, pkg.package_id);
    }

    // -----------------------------------------------------------------------
    // Display trait coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_coverage() {
        let errs: Vec<RegistryError> = vec![
            RegistryError::PublisherNotFound {
                publisher_id: EngineObjectId([0; 32]),
            },
            RegistryError::PublisherRevoked {
                publisher_id: EngineObjectId([0; 32]),
            },
            RegistryError::PackageAlreadyExists {
                scope: "s".to_string(),
                name: "n".to_string(),
                version: PackageVersion::new(1, 0, 0),
            },
            RegistryError::PackageNotFound {
                scope: "s".to_string(),
                name: "n".to_string(),
                version: PackageVersion::new(1, 0, 0),
            },
            RegistryError::PackageRevoked {
                package_id: EngineObjectId([0; 32]),
            },
            RegistryError::SignatureInvalid {
                reason: "bad".to_string(),
            },
            RegistryError::ContentHashMismatch {
                artifact_name: "a".to_string(),
                expected: ContentHash::compute(b"x"),
                actual: ContentHash::compute(b"y"),
            },
            RegistryError::ScopeNotOwned {
                scope: "s".to_string(),
                publisher_id: EngineObjectId([0; 32]),
            },
            RegistryError::TooManyCapabilities {
                count: 300,
                max: 256,
            },
            RegistryError::TooManyArtifacts {
                count: 2000,
                max: 1024,
            },
            RegistryError::InvalidScope {
                scope: "".to_string(),
                reason: "empty".to_string(),
            },
            RegistryError::InvalidName {
                name: "".to_string(),
                reason: "empty".to_string(),
            },
            RegistryError::RevocationTargetUnknown {
                target_id: EngineObjectId([0; 32]),
            },
            RegistryError::BuildDescriptorIncomplete {
                missing_field: "version".to_string(),
            },
        ];
        for err in &errs {
            let s = format!("{err}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn event_type_display_coverage() {
        let types = [
            RegistryEventType::PublisherRegistered,
            RegistryEventType::PublisherRevoked,
            RegistryEventType::ScopeClaimed,
            RegistryEventType::PackagePublished,
            RegistryEventType::PackageQueried,
            RegistryEventType::PackageVerified,
            RegistryEventType::PackageRevoked,
            RegistryEventType::VerificationFailed,
            RegistryEventType::RevocationPropagated,
        ];
        for t in &types {
            assert!(!format!("{t}").is_empty());
        }
    }

    #[test]
    fn event_outcome_display_coverage() {
        assert_eq!(format!("{}", EventOutcome::Success), "success");
        assert_eq!(format!("{}", EventOutcome::Denied), "denied");
        assert_eq!(format!("{}", EventOutcome::Error), "error");
    }

    #[test]
    fn package_key_display() {
        let k = PackageKey {
            scope: "org".to_string(),
            name: "ext".to_string(),
            version: PackageVersion::new(1, 2, 3),
        };
        assert_eq!(format!("{k}"), "@org/ext@1.2.3");
    }
}
