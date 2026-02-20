#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    NetworkEgress,
    ProcessSpawn,
    EnvRead,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetworkEgress => "network_egress",
            Self::ProcessSpawn => "process_spawn",
            Self::EnvRead => "env_read",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestValidationError {
    MissingName,
    MissingVersion,
    MissingEntrypoint,
    MissingCapabilities,
    DuplicateCapability(Capability),
}

impl Display for ManifestValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingName => write!(f, "extension manifest is missing name"),
            Self::MissingVersion => write!(f, "extension manifest is missing version"),
            Self::MissingEntrypoint => write!(f, "extension manifest is missing entrypoint"),
            Self::MissingCapabilities => {
                write!(f, "extension manifest must declare at least one capability")
            }
            Self::DuplicateCapability(capability) => write!(
                f,
                "extension manifest declares duplicate capability: {}",
                capability.as_str()
            ),
        }
    }
}

impl Error for ManifestValidationError {}

impl ExtensionManifest {
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        validate_manifest(self)
    }
}

pub fn validate_manifest(manifest: &ExtensionManifest) -> Result<(), ManifestValidationError> {
    if manifest.name.trim().is_empty() {
        return Err(ManifestValidationError::MissingName);
    }
    if manifest.version.trim().is_empty() {
        return Err(ManifestValidationError::MissingVersion);
    }
    if manifest.entrypoint.trim().is_empty() {
        return Err(ManifestValidationError::MissingEntrypoint);
    }
    if manifest.capabilities.is_empty() {
        return Err(ManifestValidationError::MissingCapabilities);
    }

    let mut seen = BTreeSet::new();
    for capability in &manifest.capabilities {
        if !seen.insert(*capability) {
            return Err(ManifestValidationError::DuplicateCapability(*capability));
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionHostSnapshot {
    pub source_project: String,
    pub snapshot_root: String,
    pub notes: String,
}

pub fn snapshot_metadata() -> ExtensionHostSnapshot {
    ExtensionHostSnapshot {
        source_project: "pi_agent_rust".to_string(),
        snapshot_root: "/dp/franken_node/transplant/pi_agent_rust".to_string(),
        notes:
            "Raw extension-host transplant retained in franken_node and consumed by franken_engine integration workflows".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> ExtensionManifest {
        ExtensionManifest {
            name: "weather-ext".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "dist/main.js".to_string(),
            capabilities: vec![Capability::FsRead, Capability::NetworkEgress],
        }
    }

    #[test]
    fn valid_manifest_passes_validation() {
        let manifest = valid_manifest();
        assert_eq!(manifest.validate(), Ok(()));
    }

    #[test]
    fn manifest_requires_name() {
        let mut manifest = valid_manifest();
        manifest.name = "   ".to_string();

        let err = manifest.validate().expect_err("missing name should fail");
        assert_eq!(err, ManifestValidationError::MissingName);
        assert_eq!(err.to_string(), "extension manifest is missing name");
    }

    #[test]
    fn manifest_requires_capability_declarations() {
        let mut manifest = valid_manifest();
        manifest.capabilities.clear();

        let err = manifest
            .validate()
            .expect_err("missing capabilities should fail");
        assert_eq!(err, ManifestValidationError::MissingCapabilities);
        assert_eq!(
            err.to_string(),
            "extension manifest must declare at least one capability"
        );
    }

    #[test]
    fn manifest_rejects_duplicate_capabilities() {
        let mut manifest = valid_manifest();
        manifest.capabilities.push(Capability::FsRead);

        let err = manifest
            .validate()
            .expect_err("duplicate capability should fail");
        assert_eq!(
            err,
            ManifestValidationError::DuplicateCapability(Capability::FsRead)
        );
        assert_eq!(
            err.to_string(),
            "extension manifest declares duplicate capability: fs_read"
        );
    }
}
