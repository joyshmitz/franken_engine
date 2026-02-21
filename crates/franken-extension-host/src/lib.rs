pub fn placeholder_extension_host_symbol() {}

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Extension capability identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Capability(pub String);

impl Capability {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Extension manifest from the engine's perspective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    pub capabilities: BTreeSet<Capability>,
}

/// Manifest validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestValidationError {
    pub message: String,
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "manifest validation error: {}", self.message)
    }
}

impl std::error::Error for ManifestValidationError {}

/// Validate an extension manifest.
pub fn validate_manifest(manifest: &ExtensionManifest) -> Result<(), ManifestValidationError> {
    if manifest.name.is_empty() {
        return Err(ManifestValidationError {
            message: "name must not be empty".to_string(),
        });
    }
    if manifest.entrypoint.is_empty() {
        return Err(ManifestValidationError {
            message: "entrypoint must not be empty".to_string(),
        });
    }
    Ok(())
}
