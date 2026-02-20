//! Trust-zone taxonomy with deterministic capability ceilings and inheritance.
//!
//! Trust zones partition runtime authority into explicit domains:
//! `Owner`, `Private`, `Team`, and `Community`.
//!
//! Each zone has:
//! - a deterministic `zone_id` (`EngineObjectId`)
//! - a declared ceiling (`CapabilitySet`)
//! - an effective ceiling (intersection of parent effective + declared)
//!
//! Plan references: Section 10.10 item 20, 9E.8.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Weak};

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, IdError, ObjectDomain, SchemaId, derive_id};

use super::RuntimeCapability;

const ZONE_SCHEMA: &[u8] = b"frankenengine.trust-zone.v1";
const FE_ZONE_CEILING_EXCEEDED: &str = "FE-6001";
const FE_ZONE_POLICY_GATE_DENIED: &str = "FE-6002";
const FE_ZONE_AUTHORITY_LEAK_DENIED: &str = "FE-6003";
const FE_ZONE_PROVENANCE_NOT_PERMITTED: &str = "FE-6004";

/// Canonical trust-zone classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustZoneClass {
    Owner,
    Private,
    Team,
    Community,
}

impl TrustZoneClass {
    pub const ORDERED: [Self; 4] = [Self::Owner, Self::Private, Self::Team, Self::Community];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Private => "private",
            Self::Team => "team",
            Self::Community => "community",
        }
    }

    pub fn default_ceiling(self) -> BTreeSet<RuntimeCapability> {
        use RuntimeCapability::*;

        match self {
            Self::Owner => super::CapabilityProfile::full().capabilities,
            Self::Private => BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                PolicyRead,
                PolicyWrite,
                EvidenceEmit,
                DecisionInvoke,
                NetworkEgress,
                LeaseManagement,
                IdempotencyDerive,
                ExtensionLifecycle,
                HeapAllocate,
                FsRead,
            ]),
            Self::Team => BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                EvidenceEmit,
                DecisionInvoke,
                ExtensionLifecycle,
                HeapAllocate,
                FsRead,
            ]),
            Self::Community => BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                ExtensionLifecycle,
                HeapAllocate,
            ]),
        }
    }
}

impl fmt::Display for TrustZoneClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persisted trust-zone metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustZone {
    pub zone_id: EngineObjectId,
    pub zone_name: String,
    pub class: TrustZoneClass,
    pub parent_zone: Option<EngineObjectId>,
    pub policy_version: u64,
    pub created_by: String,
    pub declared_ceiling: BTreeSet<RuntimeCapability>,
    pub effective_ceiling: BTreeSet<RuntimeCapability>,
}

impl TrustZone {
    fn from_request(
        request: ZoneCreateRequest,
        parent: Option<&TrustZone>,
    ) -> Result<Self, TrustZoneError> {
        let ZoneCreateRequest {
            zone_name,
            class,
            parent_zone_name: _,
            declared_ceiling,
            policy_version,
            created_by,
        } = request;

        let resolved_declared = declared_ceiling.unwrap_or_else(|| class.default_ceiling());
        let (parent_zone, parent_effective) = match parent {
            Some(parent_zone) => (
                Some(parent_zone.zone_id.clone()),
                parent_zone.effective_ceiling.clone(),
            ),
            None => (None, BTreeSet::new()),
        };

        let effective_ceiling = if parent.is_some() {
            resolved_declared
                .intersection(&parent_effective)
                .copied()
                .collect()
        } else {
            resolved_declared.clone()
        };

        if parent.is_some() && !effective_ceiling.is_subset(&parent_effective) {
            let exceeded = effective_ceiling
                .difference(&parent_effective)
                .copied()
                .collect();
            return Err(TrustZoneError::CeilingExceedsParent {
                zone_name,
                exceeded,
            });
        }

        let zone_id = derive_zone_id(&zone_name, class, parent_zone.as_ref(), policy_version)?;

        Ok(Self {
            zone_id,
            zone_name,
            class,
            parent_zone,
            policy_version,
            created_by,
            declared_ceiling: resolved_declared,
            effective_ceiling,
        })
    }

    pub fn allows(&self, requested: &BTreeSet<RuntimeCapability>) -> bool {
        requested.is_subset(&self.effective_ceiling)
    }
}

/// Request bundle for creating a trust zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneCreateRequest {
    pub zone_name: String,
    pub class: TrustZoneClass,
    pub parent_zone_name: Option<String>,
    pub declared_ceiling: Option<BTreeSet<RuntimeCapability>>,
    pub policy_version: u64,
    pub created_by: String,
}

impl ZoneCreateRequest {
    pub fn new(
        zone_name: impl Into<String>,
        class: TrustZoneClass,
        policy_version: u64,
        created_by: impl Into<String>,
    ) -> Self {
        Self {
            zone_name: zone_name.into(),
            class,
            parent_zone_name: None,
            declared_ceiling: None,
            policy_version,
            created_by: created_by.into(),
        }
    }

    pub fn with_parent(mut self, parent_zone_name: impl Into<String>) -> Self {
        self.parent_zone_name = Some(parent_zone_name.into());
        self
    }

    pub fn with_declared_ceiling(mut self, declared_ceiling: BTreeSet<RuntimeCapability>) -> Self {
        self.declared_ceiling = Some(declared_ceiling);
        self
    }
}

/// Structured event kind for trust-zone operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneEventType {
    Assignment,
    CeilingCheck,
    ZoneTransition,
    CrossZoneReference,
}

/// Structured event outcome for trust-zone operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneEventOutcome {
    Pass,
    Allowed,
    Assigned,
    Migrated,
    CeilingExceeded,
    Denied,
}

/// Structured trust-zone event with stable observability keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: ZoneEventType,
    pub outcome: ZoneEventOutcome,
    pub error_code: Option<String>,
    pub entity_id: Option<String>,
    pub zone_name: Option<String>,
    pub from_zone: Option<String>,
    pub to_zone: Option<String>,
}

impl ZoneEvent {
    fn base(trace_id: &str, event: ZoneEventType, outcome: ZoneEventOutcome) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            decision_id: None,
            policy_id: None,
            component: "trust_zone".to_string(),
            event,
            outcome,
            error_code: None,
            entity_id: None,
            zone_name: None,
            from_zone: None,
            to_zone: None,
        }
    }
}

/// Reference categories that can cross trust-zone boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    Provenance,
    Authority,
}

/// Cross-zone reference check request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneReferenceRequest {
    pub source_zone: String,
    pub target_zone: String,
    pub reference_type: ReferenceType,
    pub trace_id: String,
    pub policy_id: Option<String>,
    pub decision_id: Option<String>,
}

impl CrossZoneReferenceRequest {
    pub fn new(
        source_zone: impl Into<String>,
        target_zone: impl Into<String>,
        reference_type: ReferenceType,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            source_zone: source_zone.into(),
            target_zone: target_zone.into(),
            reference_type,
            trace_id: trace_id.into(),
            policy_id: None,
            decision_id: None,
        }
    }

    pub fn with_policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    pub fn with_decision_id(mut self, decision_id: impl Into<String>) -> Self {
        self.decision_id = Some(decision_id.into());
        self
    }
}

/// Provenance-only cross-zone reference.
///
/// Holds only a weak pointer so provenance references do not keep foreign-zone
/// objects alive.
///
/// ```compile_fail
/// use std::sync::Arc;
/// use frankenengine_engine::capability::trust_zone::ProvenanceRef;
/// use frankenengine_engine::engine_object_id::EngineObjectId;
///
/// let arc = Arc::new(String::from("payload"));
/// let p = ProvenanceRef::new("team", "community", EngineObjectId([0; 32]), &arc);
/// let _ = p.get();
/// ```
#[derive(Debug, Clone)]
pub struct ProvenanceRef<T> {
    source_zone: String,
    target_zone: String,
    object_id: EngineObjectId,
    weak: Weak<T>,
}

impl<T> ProvenanceRef<T> {
    pub fn new(
        source_zone: impl Into<String>,
        target_zone: impl Into<String>,
        object_id: EngineObjectId,
        value: &Arc<T>,
    ) -> Self {
        Self {
            source_zone: source_zone.into(),
            target_zone: target_zone.into(),
            object_id,
            weak: Arc::downgrade(value),
        }
    }

    pub fn source_zone(&self) -> &str {
        &self.source_zone
    }

    pub fn target_zone(&self) -> &str {
        &self.target_zone
    }

    pub fn object_id(&self) -> &EngineObjectId {
        &self.object_id
    }

    pub fn is_alive(&self) -> bool {
        self.weak.strong_count() > 0
    }
}

/// Full-authority reference.
#[derive(Debug, Clone)]
pub struct AuthorityRef<T> {
    source_zone: String,
    target_zone: String,
    value: Arc<T>,
}

impl<T> AuthorityRef<T> {
    pub fn new(
        source_zone: impl Into<String>,
        target_zone: impl Into<String>,
        value: Arc<T>,
    ) -> Self {
        Self {
            source_zone: source_zone.into(),
            target_zone: target_zone.into(),
            value,
        }
    }

    pub fn source_zone(&self) -> &str {
        &self.source_zone
    }

    pub fn target_zone(&self) -> &str {
        &self.target_zone
    }

    pub fn value(&self) -> &Arc<T> {
        &self.value
    }
}

/// Runtime checker for cross-zone provenance/authority references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneReferenceChecker {
    provenance_allowlist: BTreeSet<(String, String)>,
    events: Vec<ZoneEvent>,
}

impl CrossZoneReferenceChecker {
    pub fn new() -> Self {
        Self {
            provenance_allowlist: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    pub fn allow_provenance(
        &mut self,
        source_zone: impl Into<String>,
        target_zone: impl Into<String>,
    ) {
        self.provenance_allowlist
            .insert((source_zone.into(), target_zone.into()));
    }

    pub fn is_provenance_allowed(&self, source_zone: &str, target_zone: &str) -> bool {
        source_zone == target_zone
            || self
                .provenance_allowlist
                .contains(&(source_zone.to_string(), target_zone.to_string()))
    }

    pub fn validate(&mut self, request: CrossZoneReferenceRequest) -> Result<(), TrustZoneError> {
        let CrossZoneReferenceRequest {
            source_zone,
            target_zone,
            reference_type,
            trace_id,
            policy_id,
            decision_id,
        } = request;

        let mut event = ZoneEvent::base(
            &trace_id,
            ZoneEventType::CrossZoneReference,
            ZoneEventOutcome::Pass,
        );
        event.policy_id = policy_id.clone();
        event.decision_id = decision_id.clone();
        event.from_zone = Some(source_zone.clone());
        event.to_zone = Some(target_zone.clone());

        if source_zone == target_zone {
            self.events.push(event);
            return Ok(());
        }

        match reference_type {
            ReferenceType::Authority => {
                event.outcome = ZoneEventOutcome::Denied;
                event.error_code = Some(FE_ZONE_AUTHORITY_LEAK_DENIED.to_string());
                self.events.push(event);
                Err(TrustZoneError::CrossZoneAuthorityLeak {
                    source_zone,
                    target_zone,
                })
            }
            ReferenceType::Provenance => {
                if self.is_provenance_allowed(&source_zone, &target_zone) {
                    event.outcome = ZoneEventOutcome::Allowed;
                    self.events.push(event);
                    return Ok(());
                }

                event.outcome = ZoneEventOutcome::Denied;
                event.error_code = Some(FE_ZONE_PROVENANCE_NOT_PERMITTED.to_string());
                self.events.push(event);
                Err(TrustZoneError::CrossZoneProvenanceNotPermitted {
                    source_zone,
                    target_zone,
                })
            }
        }
    }

    pub fn events(&self) -> &[ZoneEvent] {
        &self.events
    }

    pub fn drain_events(&mut self) -> Vec<ZoneEvent> {
        std::mem::take(&mut self.events)
    }
}

impl Default for CrossZoneReferenceChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Zone transition request with explicit policy gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneTransitionRequest {
    pub entity_id: String,
    pub to_zone_name: String,
    pub trace_id: String,
    pub policy_id: String,
    pub decision_id: String,
    pub policy_gate_approved: bool,
}

impl ZoneTransitionRequest {
    pub fn new(
        entity_id: impl Into<String>,
        to_zone_name: impl Into<String>,
        trace_id: impl Into<String>,
        policy_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_gate_approved: bool,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            to_zone_name: to_zone_name.into(),
            trace_id: trace_id.into(),
            policy_id: policy_id.into(),
            decision_id: decision_id.into(),
            policy_gate_approved,
        }
    }
}

/// Errors from trust-zone operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustZoneError {
    ZoneAlreadyExists {
        zone_name: String,
    },
    ParentZoneMissing {
        zone_name: String,
        parent_zone: String,
    },
    ZoneMissing {
        zone_name: String,
    },
    CeilingExceedsParent {
        zone_name: String,
        exceeded: BTreeSet<RuntimeCapability>,
    },
    CapabilityCeilingExceeded {
        zone_name: String,
        requested: BTreeSet<RuntimeCapability>,
        ceiling: BTreeSet<RuntimeCapability>,
    },
    PolicyGateDenied {
        entity_id: String,
        from_zone: String,
        to_zone: String,
    },
    CrossZoneAuthorityLeak {
        source_zone: String,
        target_zone: String,
    },
    CrossZoneProvenanceNotPermitted {
        source_zone: String,
        target_zone: String,
    },
    IdDerivation(IdError),
}

impl fmt::Display for TrustZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZoneAlreadyExists { zone_name } => {
                write!(f, "zone already exists: {zone_name}")
            }
            Self::ParentZoneMissing {
                zone_name,
                parent_zone,
            } => write!(
                f,
                "cannot create zone '{zone_name}': missing parent zone '{parent_zone}'"
            ),
            Self::ZoneMissing { zone_name } => write!(f, "unknown zone: {zone_name}"),
            Self::CeilingExceedsParent {
                zone_name,
                exceeded,
            } => write!(
                f,
                "zone '{zone_name}' declared capabilities not permitted by parent: {:?}",
                exceeded
            ),
            Self::CapabilityCeilingExceeded {
                zone_name,
                requested,
                ceiling,
            } => write!(
                f,
                "zone '{zone_name}' capability ceiling exceeded: requested={:?}, ceiling={:?}",
                requested, ceiling
            ),
            Self::PolicyGateDenied {
                entity_id,
                from_zone,
                to_zone,
            } => write!(
                f,
                "policy gate denied transition for '{entity_id}' from '{from_zone}' to '{to_zone}'"
            ),
            Self::CrossZoneAuthorityLeak {
                source_zone,
                target_zone,
            } => write!(
                f,
                "cross-zone authority leak denied from '{source_zone}' to '{target_zone}'"
            ),
            Self::CrossZoneProvenanceNotPermitted {
                source_zone,
                target_zone,
            } => write!(
                f,
                "cross-zone provenance not explicitly permitted from '{source_zone}' to '{target_zone}'"
            ),
            Self::IdDerivation(err) => write!(f, "zone id derivation failed: {err}"),
        }
    }
}

impl std::error::Error for TrustZoneError {}

impl From<IdError> for TrustZoneError {
    fn from(value: IdError) -> Self {
        Self::IdDerivation(value)
    }
}

/// Mutable trust-zone hierarchy and assignment registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneHierarchy {
    zones: BTreeMap<String, TrustZone>,
    assignments: BTreeMap<String, String>,
    default_zone: String,
    events: Vec<ZoneEvent>,
}

impl ZoneHierarchy {
    pub fn new(default_zone: impl Into<String>) -> Self {
        Self {
            zones: BTreeMap::new(),
            assignments: BTreeMap::new(),
            default_zone: default_zone.into(),
            events: Vec::new(),
        }
    }

    pub fn standard(created_by: &str, policy_version: u64) -> Result<Self, TrustZoneError> {
        let mut hierarchy = Self::new("community");
        hierarchy.add_zone(ZoneCreateRequest::new(
            "owner",
            TrustZoneClass::Owner,
            policy_version,
            created_by,
        ))?;
        hierarchy.add_zone(
            ZoneCreateRequest::new(
                "private",
                TrustZoneClass::Private,
                policy_version,
                created_by,
            )
            .with_parent("owner"),
        )?;
        hierarchy.add_zone(
            ZoneCreateRequest::new("team", TrustZoneClass::Team, policy_version, created_by)
                .with_parent("private"),
        )?;
        hierarchy.add_zone(
            ZoneCreateRequest::new(
                "community",
                TrustZoneClass::Community,
                policy_version,
                created_by,
            )
            .with_parent("team"),
        )?;
        Ok(hierarchy)
    }

    pub fn add_zone(
        &mut self,
        request: ZoneCreateRequest,
    ) -> Result<EngineObjectId, TrustZoneError> {
        if self.zones.contains_key(&request.zone_name) {
            return Err(TrustZoneError::ZoneAlreadyExists {
                zone_name: request.zone_name,
            });
        }

        let parent = match request.parent_zone_name.as_ref() {
            Some(parent_zone_name) => Some(self.zones.get(parent_zone_name).ok_or_else(|| {
                TrustZoneError::ParentZoneMissing {
                    zone_name: request.zone_name.clone(),
                    parent_zone: parent_zone_name.clone(),
                }
            })?),
            None => None,
        };

        let zone_name = request.zone_name.clone();
        let zone = TrustZone::from_request(request, parent)?;
        let zone_id = zone.zone_id.clone();
        self.zones.insert(zone_name, zone);
        Ok(zone_id)
    }

    pub fn zone(&self, zone_name: &str) -> Option<&TrustZone> {
        self.zones.get(zone_name)
    }

    pub fn zone_for_entity(&self, entity_id: &str) -> Result<&TrustZone, TrustZoneError> {
        let zone_name = self
            .assignments
            .get(entity_id)
            .map_or(self.default_zone.as_str(), String::as_str);
        self.zone(zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })
    }

    pub fn assign_entity(
        &mut self,
        entity_id: impl Into<String>,
        zone_name: &str,
        trace_id: &str,
    ) -> Result<(), TrustZoneError> {
        self.zone(zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })?;
        let entity_id = entity_id.into();
        self.assignments
            .insert(entity_id.clone(), zone_name.to_string());

        let mut event = ZoneEvent::base(
            trace_id,
            ZoneEventType::Assignment,
            ZoneEventOutcome::Assigned,
        );
        event.entity_id = Some(entity_id);
        event.zone_name = Some(zone_name.to_string());
        self.events.push(event);
        Ok(())
    }

    pub fn enforce_ceiling(
        &mut self,
        zone_name: &str,
        requested: &BTreeSet<RuntimeCapability>,
        trace_id: &str,
    ) -> Result<(), TrustZoneError> {
        let zone = self
            .zone(zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })?;

        if zone.allows(requested) {
            let mut event = ZoneEvent::base(
                trace_id,
                ZoneEventType::CeilingCheck,
                ZoneEventOutcome::Pass,
            );
            event.zone_name = Some(zone_name.to_string());
            self.events.push(event);
            return Ok(());
        }

        let mut event = ZoneEvent::base(
            trace_id,
            ZoneEventType::CeilingCheck,
            ZoneEventOutcome::CeilingExceeded,
        );
        event.zone_name = Some(zone_name.to_string());
        event.error_code = Some(FE_ZONE_CEILING_EXCEEDED.to_string());
        let ceiling = zone.effective_ceiling.clone();
        self.events.push(event);

        Err(TrustZoneError::CapabilityCeilingExceeded {
            zone_name: zone_name.to_string(),
            requested: requested.clone(),
            ceiling,
        })
    }

    pub fn transition_entity(
        &mut self,
        request: ZoneTransitionRequest,
    ) -> Result<(), TrustZoneError> {
        self.zone(&request.to_zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: request.to_zone_name.clone(),
            })?;

        let from_zone_name = self.zone_for_entity(&request.entity_id)?.zone_name.clone();
        if !request.policy_gate_approved {
            let mut event = ZoneEvent::base(
                &request.trace_id,
                ZoneEventType::ZoneTransition,
                ZoneEventOutcome::Denied,
            );
            event.policy_id = Some(request.policy_id);
            event.decision_id = Some(request.decision_id);
            event.entity_id = Some(request.entity_id.clone());
            event.from_zone = Some(from_zone_name.clone());
            event.to_zone = Some(request.to_zone_name.clone());
            event.error_code = Some(FE_ZONE_POLICY_GATE_DENIED.to_string());
            self.events.push(event);

            return Err(TrustZoneError::PolicyGateDenied {
                entity_id: request.entity_id,
                from_zone: from_zone_name,
                to_zone: request.to_zone_name,
            });
        }

        self.assignments
            .insert(request.entity_id.clone(), request.to_zone_name.clone());

        let mut event = ZoneEvent::base(
            &request.trace_id,
            ZoneEventType::ZoneTransition,
            ZoneEventOutcome::Migrated,
        );
        event.policy_id = Some(request.policy_id);
        event.decision_id = Some(request.decision_id);
        event.entity_id = Some(request.entity_id);
        event.from_zone = Some(from_zone_name);
        event.to_zone = Some(request.to_zone_name);
        self.events.push(event);
        Ok(())
    }

    pub fn compute_effective_ceiling(
        &self,
        zone_name: &str,
    ) -> Result<BTreeSet<RuntimeCapability>, TrustZoneError> {
        self.zone(zone_name)
            .map(|zone| zone.effective_ceiling.clone())
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })
    }

    pub fn validate_cross_zone_reference(
        &self,
        checker: &mut CrossZoneReferenceChecker,
        request: CrossZoneReferenceRequest,
    ) -> Result<(), TrustZoneError> {
        self.zone(&request.source_zone)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: request.source_zone.clone(),
            })?;
        self.zone(&request.target_zone)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: request.target_zone.clone(),
            })?;
        checker.validate(request)
    }

    pub fn events(&self) -> &[ZoneEvent] {
        &self.events
    }

    pub fn drain_events(&mut self) -> Vec<ZoneEvent> {
        std::mem::take(&mut self.events)
    }
}

/// Derive any object id scoped to a specific trust zone.
pub fn derive_zone_scoped_object_id(
    zone: &TrustZone,
    domain: ObjectDomain,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Result<EngineObjectId, IdError> {
    derive_id(domain, &zone.zone_name, schema_id, canonical_bytes)
}

fn derive_zone_id(
    zone_name: &str,
    class: TrustZoneClass,
    parent_zone: Option<&EngineObjectId>,
    policy_version: u64,
) -> Result<EngineObjectId, IdError> {
    let schema = SchemaId::from_definition(ZONE_SCHEMA);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(class.as_str().as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&policy_version.to_be_bytes());
    canonical.push(0);
    canonical.extend_from_slice(zone_name.as_bytes());
    if let Some(parent) = parent_zone {
        canonical.extend_from_slice(parent.as_bytes());
    }
    derive_id(ObjectDomain::PolicyObject, zone_name, &schema, &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::ObjectDomain;
    use std::sync::Arc;

    fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
        caps.iter().copied().collect()
    }

    fn mask_to_capset(basis: &[RuntimeCapability], mask: u16) -> BTreeSet<RuntimeCapability> {
        basis
            .iter()
            .enumerate()
            .filter_map(|(idx, cap)| ((mask & (1 << idx)) != 0).then_some(*cap))
            .collect()
    }

    #[test]
    fn standard_hierarchy_has_expected_order_and_defaults() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        for class in TrustZoneClass::ORDERED {
            let zone_name = class.as_str();
            assert!(
                hierarchy.zone(zone_name).is_some(),
                "missing zone {zone_name}"
            );
        }
        assert_eq!(
            hierarchy
                .zone_for_entity("unknown-entity")
                .expect("default zone")
                .zone_name,
            "community"
        );
    }

    #[test]
    fn child_effective_ceiling_uses_intersection_with_parent() {
        let mut hierarchy = ZoneHierarchy::new("community");
        hierarchy
            .add_zone(ZoneCreateRequest::new(
                "owner",
                TrustZoneClass::Owner,
                7,
                "root",
            ))
            .expect("owner");
        hierarchy
            .add_zone(
                ZoneCreateRequest::new("private", TrustZoneClass::Private, 7, "root")
                    .with_parent("owner")
                    .with_declared_ceiling(capset(&[
                        RuntimeCapability::VmDispatch,
                        RuntimeCapability::NetworkEgress,
                    ])),
            )
            .expect("private");
        hierarchy
            .add_zone(
                ZoneCreateRequest::new("team", TrustZoneClass::Team, 7, "root")
                    .with_parent("private")
                    .with_declared_ceiling(capset(&[
                        RuntimeCapability::VmDispatch,
                        RuntimeCapability::FsWrite,
                    ])),
            )
            .expect("team");

        let team = hierarchy.zone("team").expect("team");
        assert_eq!(
            team.effective_ceiling,
            capset(&[RuntimeCapability::VmDispatch]),
        );
    }

    #[test]
    fn effective_ceiling_is_subset_of_parent_in_standard_hierarchy() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 9).expect("build hierarchy");
        let private = hierarchy.zone("private").expect("private");
        let team = hierarchy.zone("team").expect("team");
        let community = hierarchy.zone("community").expect("community");
        assert!(
            private
                .effective_ceiling
                .is_subset(&hierarchy.zone("owner").expect("owner").effective_ceiling)
        );
        assert!(team.effective_ceiling.is_subset(&private.effective_ceiling));
        assert!(
            community
                .effective_ceiling
                .is_subset(&team.effective_ceiling)
        );
    }

    #[test]
    fn exhaustive_intersection_invariant_keeps_child_within_parent() {
        let basis = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::FsWrite,
        ];

        for parent_mask in 0u16..(1u16 << basis.len()) {
            let parent = mask_to_capset(&basis, parent_mask);
            for child_mask in 0u16..(1u16 << basis.len()) {
                let child_declared = mask_to_capset(&basis, child_mask);
                let effective: BTreeSet<RuntimeCapability> =
                    child_declared.intersection(&parent).copied().collect();
                assert!(effective.is_subset(&parent));
            }
        }
    }

    #[test]
    fn add_zone_rejects_missing_parent() {
        let mut hierarchy = ZoneHierarchy::new("community");
        let err = hierarchy
            .add_zone(
                ZoneCreateRequest::new("team", TrustZoneClass::Team, 1, "root")
                    .with_parent("private"),
            )
            .expect_err("missing parent");
        assert!(matches!(err, TrustZoneError::ParentZoneMissing { .. }));
    }

    #[test]
    fn enforce_ceiling_rejects_requested_capability_outside_zone_ceiling() {
        let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        let requested = capset(&[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ]);

        let err = hierarchy
            .enforce_ceiling("community", &requested, "trace-zone-1")
            .expect_err("should reject network capability in community zone");

        match err {
            TrustZoneError::CapabilityCeilingExceeded { zone_name, .. } => {
                assert_eq!(zone_name, "community");
            }
            other => panic!("unexpected error: {other}"),
        }

        let event = hierarchy.events().last().expect("zone event");
        assert_eq!(event.error_code.as_deref(), Some(FE_ZONE_CEILING_EXCEEDED));
        assert_eq!(event.event, ZoneEventType::CeilingCheck);
        assert_eq!(event.outcome, ZoneEventOutcome::CeilingExceeded);
    }

    #[test]
    fn transition_requires_policy_gate() {
        let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        hierarchy
            .assign_entity("ext-alpha", "community", "trace-a")
            .expect("assign");

        let err = hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-alpha",
                "team",
                "trace-transition",
                "policy-zone",
                "decision-zone",
                false,
            ))
            .expect_err("must deny without policy gate");

        assert!(matches!(err, TrustZoneError::PolicyGateDenied { .. }));
        let event = hierarchy.events().last().expect("event");
        assert_eq!(event.event, ZoneEventType::ZoneTransition);
        assert_eq!(event.outcome, ZoneEventOutcome::Denied);
        assert_eq!(
            event.error_code.as_deref(),
            Some(FE_ZONE_POLICY_GATE_DENIED)
        );
    }

    #[test]
    fn transition_updates_assignment_when_policy_gate_is_approved() {
        let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        hierarchy
            .assign_entity("ext-beta", "community", "trace-a")
            .expect("assign");

        hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-beta",
                "team",
                "trace-transition",
                "policy-zone",
                "decision-zone",
                true,
            ))
            .expect("transition");

        let zone = hierarchy.zone_for_entity("ext-beta").expect("zone");
        assert_eq!(zone.zone_name, "team");
        let event = hierarchy.events().last().expect("event");
        assert_eq!(event.outcome, ZoneEventOutcome::Migrated);
    }

    #[test]
    fn provenance_reference_is_allowed_when_explicitly_permitted() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        let mut checker = CrossZoneReferenceChecker::new();
        checker.allow_provenance("community", "team");

        hierarchy
            .validate_cross_zone_reference(
                &mut checker,
                CrossZoneReferenceRequest::new(
                    "community",
                    "team",
                    ReferenceType::Provenance,
                    "trace-cross-zone-allow",
                )
                .with_policy_id("policy-cross-zone")
                .with_decision_id("decision-cross-zone"),
            )
            .expect("explicit provenance edge should pass");

        let event = checker.events().last().expect("event");
        assert_eq!(event.event, ZoneEventType::CrossZoneReference);
        assert_eq!(event.outcome, ZoneEventOutcome::Allowed);
        assert_eq!(event.error_code, None);
    }

    #[test]
    fn authority_reference_is_denied_across_zones() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        let mut checker = CrossZoneReferenceChecker::new();

        let err = hierarchy
            .validate_cross_zone_reference(
                &mut checker,
                CrossZoneReferenceRequest::new(
                    "community",
                    "team",
                    ReferenceType::Authority,
                    "trace-cross-zone-deny",
                ),
            )
            .expect_err("authority reference must be denied");

        assert!(matches!(err, TrustZoneError::CrossZoneAuthorityLeak { .. }));
        let event = checker.events().last().expect("event");
        assert_eq!(event.event, ZoneEventType::CrossZoneReference);
        assert_eq!(event.outcome, ZoneEventOutcome::Denied);
        assert_eq!(
            event.error_code.as_deref(),
            Some(FE_ZONE_AUTHORITY_LEAK_DENIED)
        );
    }

    #[test]
    fn provenance_reference_is_weak_and_does_not_prevent_gc() {
        let value = Arc::new("audit-record".to_string());
        let prov_ref = ProvenanceRef::new("team", "community", EngineObjectId([3; 32]), &value);

        assert!(prov_ref.is_alive());
        assert_eq!(prov_ref.source_zone(), "team");
        assert_eq!(prov_ref.target_zone(), "community");
        assert_eq!(prov_ref.object_id(), &EngineObjectId([3; 32]));

        drop(value);
        assert!(!prov_ref.is_alive());
    }

    #[test]
    fn provenance_edges_are_not_transitive_without_explicit_allow() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        let mut checker = CrossZoneReferenceChecker::new();
        checker.allow_provenance("community", "team");
        checker.allow_provenance("team", "private");

        let err = hierarchy
            .validate_cross_zone_reference(
                &mut checker,
                CrossZoneReferenceRequest::new(
                    "community",
                    "private",
                    ReferenceType::Provenance,
                    "trace-community-private",
                ),
            )
            .expect_err("community->private should require explicit allowlist entry");

        assert!(matches!(
            err,
            TrustZoneError::CrossZoneProvenanceNotPermitted { .. }
        ));
        let event = checker.events().last().expect("event");
        assert_eq!(
            event.error_code.as_deref(),
            Some(FE_ZONE_PROVENANCE_NOT_PERMITTED)
        );
        assert_eq!(event.outcome, ZoneEventOutcome::Denied);
    }

    #[test]
    fn zone_scoped_object_id_changes_with_zone() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 3).expect("build hierarchy");
        let team = hierarchy.zone("team").expect("team");
        let community = hierarchy.zone("community").expect("community");
        let schema = SchemaId::from_definition(b"zone-scoped-object-v1");
        let canonical_bytes = b"same-object";

        let team_id = derive_zone_scoped_object_id(
            team,
            ObjectDomain::EvidenceRecord,
            &schema,
            canonical_bytes,
        )
        .expect("team id");
        let community_id = derive_zone_scoped_object_id(
            community,
            ObjectDomain::EvidenceRecord,
            &schema,
            canonical_bytes,
        )
        .expect("community id");

        assert_ne!(team_id, community_id);
    }

    #[test]
    fn hierarchy_serialization_is_deterministic_for_same_inputs() {
        let a = ZoneHierarchy::standard("maintainer", 5).expect("hierarchy A");
        let b = ZoneHierarchy::standard("maintainer", 5).expect("hierarchy B");
        let json_a = serde_json::to_string(&a).expect("serialize A");
        let json_b = serde_json::to_string(&b).expect("serialize B");
        assert_eq!(json_a, json_b);
    }
}
