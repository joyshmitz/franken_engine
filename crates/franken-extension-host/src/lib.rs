#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

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
