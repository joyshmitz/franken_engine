//! Canonical runtime capability profiles.
//!
//! Defines five authority partitions enforced at API boundaries:
//! `FullCaps`, `EngineCoreCaps`, `PolicyCaps`, `RemoteCaps`,
//! `ComputeOnlyCaps`.  Each profile grants a specific subset of
//! runtime capabilities, preventing ambient authority leaks.
//!
//! Plan references: Section 10.11 item 1, 9G.1 (capability-context-first
//! runtime), Top-10 #2 (Guardplane), #7 (capability lattice), #8 (budgets).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

pub mod trust_zone;

// ---------------------------------------------------------------------------
// RuntimeCapability — the atomic permission unit
// ---------------------------------------------------------------------------

/// Atomic capabilities that can be granted to subsystems.
///
/// Each capability represents a single, indivisible permission.
/// Profiles compose subsets of these capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuntimeCapability {
    /// Execute VM dispatch (interpreter, IR lowering).
    VmDispatch,
    /// Invoke garbage collector.
    GcInvoke,
    /// Perform IR lowering passes.
    IrLowering,
    /// Read policy configuration.
    PolicyRead,
    /// Write/mutate policy configuration.
    PolicyWrite,
    /// Emit evidence entries to the evidence ledger.
    EvidenceEmit,
    /// Invoke decision contracts.
    DecisionInvoke,
    /// Perform network egress operations.
    NetworkEgress,
    /// Manage remote leases.
    LeaseManagement,
    /// Derive idempotency keys for remote operations.
    IdempotencyDerive,
    /// Manage extension lifecycle (load, start, suspend, terminate).
    ExtensionLifecycle,
    /// Allocate from extension heaps.
    HeapAllocate,
    /// Read environment variables.
    EnvRead,
    /// Spawn external processes.
    ProcessSpawn,
    /// Perform filesystem reads.
    FsRead,
    /// Perform filesystem writes.
    FsWrite,
}

impl fmt::Display for RuntimeCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::VmDispatch => "vm_dispatch",
            Self::GcInvoke => "gc_invoke",
            Self::IrLowering => "ir_lowering",
            Self::PolicyRead => "policy_read",
            Self::PolicyWrite => "policy_write",
            Self::EvidenceEmit => "evidence_emit",
            Self::DecisionInvoke => "decision_invoke",
            Self::NetworkEgress => "network_egress",
            Self::LeaseManagement => "lease_management",
            Self::IdempotencyDerive => "idempotency_derive",
            Self::ExtensionLifecycle => "extension_lifecycle",
            Self::HeapAllocate => "heap_allocate",
            Self::EnvRead => "env_read",
            Self::ProcessSpawn => "process_spawn",
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// CapabilityProfile — named profiles with their capability sets
// ---------------------------------------------------------------------------

/// Named capability profile identifying a standard authority partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProfileKind {
    /// Union of all capabilities — orchestrator and test harness only.
    Full,
    /// VM dispatch, GC, IR lowering, heap allocation — no network, no policy mutation.
    EngineCore,
    /// Policy read/write, evidence emission, decision contracts — no VM, no network.
    Policy,
    /// Network egress, lease management, idempotency — no policy mutation, no VM.
    Remote,
    /// Pure computation, zero side effects — no I/O, no network, no policy.
    ComputeOnly,
}

impl fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Full => "FullCaps",
            Self::EngineCore => "EngineCoreCaps",
            Self::Policy => "PolicyCaps",
            Self::Remote => "RemoteCaps",
            Self::ComputeOnly => "ComputeOnlyCaps",
        };
        f.write_str(name)
    }
}

/// A concrete capability profile: a named set of granted capabilities.
///
/// Uses `BTreeSet` for deterministic serialization and iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub kind: ProfileKind,
    pub capabilities: BTreeSet<RuntimeCapability>,
}

impl CapabilityProfile {
    /// Create the `FullCaps` profile (all capabilities).
    pub fn full() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::Full,
            capabilities: BTreeSet::from([
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
                EnvRead,
                ProcessSpawn,
                FsRead,
                FsWrite,
            ]),
        }
    }

    /// Create the `EngineCoreCaps` profile.
    pub fn engine_core() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::EngineCore,
            capabilities: BTreeSet::from([VmDispatch, GcInvoke, IrLowering, HeapAllocate]),
        }
    }

    /// Create the `PolicyCaps` profile.
    pub fn policy() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::Policy,
            capabilities: BTreeSet::from([PolicyRead, PolicyWrite, EvidenceEmit, DecisionInvoke]),
        }
    }

    /// Create the `RemoteCaps` profile.
    pub fn remote() -> Self {
        use RuntimeCapability::*;
        Self {
            kind: ProfileKind::Remote,
            capabilities: BTreeSet::from([NetworkEgress, LeaseManagement, IdempotencyDerive]),
        }
    }

    /// Create the `ComputeOnlyCaps` profile (zero side effects).
    pub fn compute_only() -> Self {
        Self {
            kind: ProfileKind::ComputeOnly,
            capabilities: BTreeSet::new(),
        }
    }

    /// Check whether this profile grants a specific capability.
    pub fn has(&self, cap: RuntimeCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Check whether this profile is a superset of another.
    pub fn subsumes(&self, other: &CapabilityProfile) -> bool {
        other.capabilities.is_subset(&self.capabilities)
    }

    /// Intersect two profiles (narrowing — always safe).
    ///
    /// The result contains only capabilities present in both profiles.
    /// The resulting kind is `ComputeOnly` since intersection produces
    /// a non-standard profile.
    pub fn intersect(&self, other: &CapabilityProfile) -> CapabilityProfile {
        let caps: BTreeSet<RuntimeCapability> = self
            .capabilities
            .intersection(&other.capabilities)
            .copied()
            .collect();
        CapabilityProfile {
            kind: ProfileKind::ComputeOnly,
            capabilities: caps,
        }
    }

    /// Number of capabilities in this profile.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

impl fmt::Display for CapabilityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.kind, self.capabilities.len())
    }
}

// ---------------------------------------------------------------------------
// CapabilityCheck — runtime capability enforcement
// ---------------------------------------------------------------------------

/// Error returned when a required capability is not held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDenied {
    /// The capability that was required.
    pub required: RuntimeCapability,
    /// The profile that was held.
    pub held_profile: ProfileKind,
    /// The component that attempted the operation.
    pub component: String,
}

impl fmt::Display for CapabilityDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "capability denied: '{}' requires '{}' but held profile '{}' does not grant it",
            self.component, self.required, self.held_profile
        )
    }
}

impl std::error::Error for CapabilityDenied {}

/// Check that a profile grants a required capability.
///
/// Returns `Ok(())` if granted, `Err(CapabilityDenied)` if not.
pub fn require_capability(
    profile: &CapabilityProfile,
    required: RuntimeCapability,
    component: &str,
) -> Result<(), CapabilityDenied> {
    if profile.has(required) {
        Ok(())
    } else {
        Err(CapabilityDenied {
            required,
            held_profile: profile.kind,
            component: component.to_string(),
        })
    }
}

/// Check that a profile grants all required capabilities.
///
/// Returns all denials (not fail-fast) for structured error reporting.
pub fn require_all(
    profile: &CapabilityProfile,
    required: &[RuntimeCapability],
    component: &str,
) -> Result<(), Vec<CapabilityDenied>> {
    let denials: Vec<CapabilityDenied> = required
        .iter()
        .filter(|cap| !profile.has(**cap))
        .map(|cap| CapabilityDenied {
            required: *cap,
            held_profile: profile.kind,
            component: component.to_string(),
        })
        .collect();

    if denials.is_empty() {
        Ok(())
    } else {
        Err(denials)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Profile contents --

    #[test]
    fn full_caps_contains_all_capabilities() {
        let full = CapabilityProfile::full();
        assert_eq!(full.len(), 16);
        assert!(full.has(RuntimeCapability::VmDispatch));
        assert!(full.has(RuntimeCapability::PolicyWrite));
        assert!(full.has(RuntimeCapability::NetworkEgress));
        assert!(full.has(RuntimeCapability::FsWrite));
    }

    #[test]
    fn engine_core_caps_contains_only_vm_gc_ir_heap() {
        let ec = CapabilityProfile::engine_core();
        assert_eq!(ec.len(), 4);
        assert!(ec.has(RuntimeCapability::VmDispatch));
        assert!(ec.has(RuntimeCapability::GcInvoke));
        assert!(ec.has(RuntimeCapability::IrLowering));
        assert!(ec.has(RuntimeCapability::HeapAllocate));
        // Must NOT have policy, network, or lifecycle.
        assert!(!ec.has(RuntimeCapability::PolicyWrite));
        assert!(!ec.has(RuntimeCapability::NetworkEgress));
        assert!(!ec.has(RuntimeCapability::ExtensionLifecycle));
    }

    #[test]
    fn policy_caps_contains_only_policy_evidence_decision() {
        let pol = CapabilityProfile::policy();
        assert_eq!(pol.len(), 4);
        assert!(pol.has(RuntimeCapability::PolicyRead));
        assert!(pol.has(RuntimeCapability::PolicyWrite));
        assert!(pol.has(RuntimeCapability::EvidenceEmit));
        assert!(pol.has(RuntimeCapability::DecisionInvoke));
        // Must NOT have VM or network.
        assert!(!pol.has(RuntimeCapability::VmDispatch));
        assert!(!pol.has(RuntimeCapability::NetworkEgress));
    }

    #[test]
    fn remote_caps_contains_only_network_lease_idempotency() {
        let rem = CapabilityProfile::remote();
        assert_eq!(rem.len(), 3);
        assert!(rem.has(RuntimeCapability::NetworkEgress));
        assert!(rem.has(RuntimeCapability::LeaseManagement));
        assert!(rem.has(RuntimeCapability::IdempotencyDerive));
        // Must NOT have policy or VM.
        assert!(!rem.has(RuntimeCapability::PolicyWrite));
        assert!(!rem.has(RuntimeCapability::VmDispatch));
    }

    #[test]
    fn compute_only_caps_is_empty() {
        let co = CapabilityProfile::compute_only();
        assert!(co.is_empty());
        assert_eq!(co.len(), 0);
        assert!(!co.has(RuntimeCapability::VmDispatch));
    }

    // -- Profiles are disjoint (except Full) --

    #[test]
    fn standard_profiles_are_pairwise_disjoint() {
        let ec = CapabilityProfile::engine_core();
        let pol = CapabilityProfile::policy();
        let rem = CapabilityProfile::remote();

        assert!(ec.intersect(&pol).is_empty());
        assert!(ec.intersect(&rem).is_empty());
        assert!(pol.intersect(&rem).is_empty());
    }

    // -- Subsumption --

    #[test]
    fn full_subsumes_all_profiles() {
        let full = CapabilityProfile::full();
        assert!(full.subsumes(&CapabilityProfile::engine_core()));
        assert!(full.subsumes(&CapabilityProfile::policy()));
        assert!(full.subsumes(&CapabilityProfile::remote()));
        assert!(full.subsumes(&CapabilityProfile::compute_only()));
    }

    #[test]
    fn narrow_profile_does_not_subsume_broader() {
        let ec = CapabilityProfile::engine_core();
        let full = CapabilityProfile::full();
        assert!(!ec.subsumes(&full));
    }

    #[test]
    fn profile_subsumes_itself() {
        let ec = CapabilityProfile::engine_core();
        assert!(ec.subsumes(&ec));
    }

    // -- Intersection --

    #[test]
    fn intersection_produces_common_caps() {
        let mut custom_a = CapabilityProfile::engine_core();
        custom_a.capabilities.insert(RuntimeCapability::PolicyRead);

        let pol = CapabilityProfile::policy();
        let inter = custom_a.intersect(&pol);
        assert_eq!(inter.len(), 1);
        assert!(inter.has(RuntimeCapability::PolicyRead));
    }

    #[test]
    fn intersection_is_monotonic_narrowing() {
        let full = CapabilityProfile::full();
        let ec = CapabilityProfile::engine_core();
        let inter = full.intersect(&ec);
        assert_eq!(inter.capabilities, ec.capabilities);
    }

    // -- Capability checks --

    #[test]
    fn require_capability_succeeds_when_granted() {
        let ec = CapabilityProfile::engine_core();
        assert!(require_capability(&ec, RuntimeCapability::VmDispatch, "test-vm").is_ok());
    }

    #[test]
    fn require_capability_fails_when_denied() {
        let ec = CapabilityProfile::engine_core();
        let err =
            require_capability(&ec, RuntimeCapability::NetworkEgress, "test-net").unwrap_err();
        assert_eq!(err.required, RuntimeCapability::NetworkEgress);
        assert_eq!(err.held_profile, ProfileKind::EngineCore);
        assert_eq!(err.component, "test-net");
    }

    #[test]
    fn require_all_succeeds_when_all_granted() {
        let full = CapabilityProfile::full();
        assert!(
            require_all(
                &full,
                &[
                    RuntimeCapability::VmDispatch,
                    RuntimeCapability::PolicyWrite
                ],
                "test"
            )
            .is_ok()
        );
    }

    #[test]
    fn require_all_collects_all_denials() {
        let co = CapabilityProfile::compute_only();
        let denials = require_all(
            &co,
            &[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::NetworkEgress,
                RuntimeCapability::PolicyWrite,
            ],
            "test-multi",
        )
        .unwrap_err();
        assert_eq!(denials.len(), 3);
    }

    // -- Display --

    #[test]
    fn profile_kind_display() {
        assert_eq!(ProfileKind::Full.to_string(), "FullCaps");
        assert_eq!(ProfileKind::EngineCore.to_string(), "EngineCoreCaps");
        assert_eq!(ProfileKind::Policy.to_string(), "PolicyCaps");
        assert_eq!(ProfileKind::Remote.to_string(), "RemoteCaps");
        assert_eq!(ProfileKind::ComputeOnly.to_string(), "ComputeOnlyCaps");
    }

    #[test]
    fn capability_display() {
        assert_eq!(RuntimeCapability::VmDispatch.to_string(), "vm_dispatch");
        assert_eq!(RuntimeCapability::PolicyWrite.to_string(), "policy_write");
        assert_eq!(
            RuntimeCapability::NetworkEgress.to_string(),
            "network_egress"
        );
    }

    #[test]
    fn capability_denied_display() {
        let err = CapabilityDenied {
            required: RuntimeCapability::NetworkEgress,
            held_profile: ProfileKind::EngineCore,
            component: "remote-sender".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "capability denied: 'remote-sender' requires 'network_egress' but held profile 'EngineCoreCaps' does not grant it"
        );
    }

    #[test]
    fn capability_profile_display() {
        let ec = CapabilityProfile::engine_core();
        assert_eq!(ec.to_string(), "EngineCoreCaps[4]");
    }

    // -- Serialization --

    #[test]
    fn capability_profile_serialization_round_trip() {
        let full = CapabilityProfile::full();
        let json = serde_json::to_string(&full).expect("serialize");
        let restored: CapabilityProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(full, restored);
    }

    #[test]
    fn all_profiles_serialize_deterministically() {
        let profiles = [
            CapabilityProfile::full(),
            CapabilityProfile::engine_core(),
            CapabilityProfile::policy(),
            CapabilityProfile::remote(),
            CapabilityProfile::compute_only(),
        ];
        for profile in &profiles {
            let json1 = serde_json::to_string(profile).expect("serialize");
            let json2 = serde_json::to_string(profile).expect("serialize");
            assert_eq!(
                json1, json2,
                "non-deterministic serialization for {}",
                profile.kind
            );
        }
    }

    // -- Enrichment: serde, ordering, std::error --

    #[test]
    fn runtime_capability_serde_all_variants() {
        let all = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        for cap in &all {
            let json = serde_json::to_string(cap).expect("serialize");
            let restored: RuntimeCapability = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*cap, restored);
        }
    }

    #[test]
    fn profile_kind_serde_all_variants() {
        let all = [
            ProfileKind::Full,
            ProfileKind::EngineCore,
            ProfileKind::Policy,
            ProfileKind::Remote,
            ProfileKind::ComputeOnly,
        ];
        for kind in &all {
            let json = serde_json::to_string(kind).expect("serialize");
            let restored: ProfileKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, restored);
        }
    }

    #[test]
    fn runtime_capability_ordering() {
        assert!(RuntimeCapability::VmDispatch < RuntimeCapability::GcInvoke);
        assert!(RuntimeCapability::GcInvoke < RuntimeCapability::IrLowering);
        assert!(RuntimeCapability::IrLowering < RuntimeCapability::PolicyRead);
        assert!(RuntimeCapability::FsRead < RuntimeCapability::FsWrite);
    }

    #[test]
    fn profile_kind_ordering() {
        assert!(ProfileKind::Full < ProfileKind::EngineCore);
        assert!(ProfileKind::EngineCore < ProfileKind::Policy);
        assert!(ProfileKind::Policy < ProfileKind::Remote);
        assert!(ProfileKind::Remote < ProfileKind::ComputeOnly);
    }

    #[test]
    fn capability_denied_implements_std_error() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::PolicyWrite,
            held_profile: ProfileKind::EngineCore,
            component: "test".to_string(),
        };
        let err: &dyn std::error::Error = &denied;
        assert!(!format!("{err}").is_empty());
        assert!(err.source().is_none());
    }

    #[test]
    fn capability_denied_serialization_round_trip() {
        let denied = CapabilityDenied {
            required: RuntimeCapability::PolicyWrite,
            held_profile: ProfileKind::EngineCore,
            component: "test".to_string(),
        };
        let json = serde_json::to_string(&denied).expect("serialize");
        let restored: CapabilityDenied = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(denied, restored);
    }
}
