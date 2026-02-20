//! Allocation domain taxonomy and lifetime class hierarchy.
//!
//! Defines how memory is organized, tracked, and reclaimed across the
//! FrankenEngine runtime.  Each allocation belongs to exactly one domain
//! and lifetime class, enabling per-extension budget enforcement, domain
//! isolation (security), and deterministic allocation patterns (replay).
//!
//! Plan references: Section 10.3 item 1, 9A.8 (per-extension budgets),
//! 9B.1 (arena allocation for IR nodes), 9B.4 (allocator strategy).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AllocationDomain — where memory lives
// ---------------------------------------------------------------------------

/// Identifies a logical memory region with isolation guarantees.
///
/// Domain isolation ensures that one extension's allocations cannot corrupt
/// another's — a hard security requirement for untrusted code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AllocationDomain {
    /// Per-extension managed heap — isolated per extension/session.
    ExtensionHeap,
    /// Shared runtime heap — used by engine internals.
    RuntimeHeap,
    /// IR compilation arena — used during parse/lower/optimize passes.
    IrArena,
    /// Evidence and witness arena — stores decision/replay artifacts.
    EvidenceArena,
    /// Temporary scratch buffers — short-lived, reusable.
    ScratchBuffer,
}

impl fmt::Display for AllocationDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ExtensionHeap => "extension-heap",
            Self::RuntimeHeap => "runtime-heap",
            Self::IrArena => "ir-arena",
            Self::EvidenceArena => "evidence-arena",
            Self::ScratchBuffer => "scratch-buffer",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// LifetimeClass — how long memory lives
// ---------------------------------------------------------------------------

/// Describes the expected duration of an allocation, informing GC strategy
/// and resource accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LifetimeClass {
    /// Single hostcall or operation — freed when the call returns.
    RequestScoped,
    /// Extension session — freed when the extension/session terminates.
    SessionScoped,
    /// Runtime lifetime — freed only at engine shutdown.
    Global,
    /// Compilation unit — freed when the compilation arena is dropped.
    Arena,
}

impl fmt::Display for LifetimeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::RequestScoped => "request-scoped",
            Self::SessionScoped => "session-scoped",
            Self::Global => "global",
            Self::Arena => "arena",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// DomainBudget — size limits per domain
// ---------------------------------------------------------------------------

/// Configurable size limits for an allocation domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainBudget {
    /// Maximum bytes permitted in this domain.
    pub max_bytes: u64,
    /// Current bytes allocated.
    pub used_bytes: u64,
}

impl DomainBudget {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
        }
    }

    /// Remaining bytes available.
    pub fn remaining(&self) -> u64 {
        self.max_bytes.saturating_sub(self.used_bytes)
    }

    /// Try to reserve `bytes`.  Returns `Ok(())` if budget allows,
    /// `Err` if it would exceed the limit.
    pub fn try_reserve(&mut self, bytes: u64) -> Result<(), AllocDomainError> {
        let new_used = self
            .used_bytes
            .checked_add(bytes)
            .ok_or(AllocDomainError::BudgetOverflow)?;
        if new_used > self.max_bytes {
            return Err(AllocDomainError::BudgetExceeded {
                requested: bytes,
                remaining: self.remaining(),
                domain: None,
            });
        }
        self.used_bytes = new_used;
        Ok(())
    }

    /// Release `bytes` back to the budget.
    pub fn release(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }

    /// Utilization ratio (0.0–1.0).
    pub fn utilization(&self) -> f64 {
        if self.max_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.max_bytes as f64
    }
}

// ---------------------------------------------------------------------------
// DomainConfig — per-domain configuration
// ---------------------------------------------------------------------------

/// Configuration for a single allocation domain instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainConfig {
    pub domain: AllocationDomain,
    pub lifetime: LifetimeClass,
    pub budget: DomainBudget,
}

// ---------------------------------------------------------------------------
// AllocDomainError — typed error contract
// ---------------------------------------------------------------------------

/// Errors from allocation domain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocDomainError {
    /// Allocation would exceed domain budget.
    BudgetExceeded {
        requested: u64,
        remaining: u64,
        domain: Option<AllocationDomain>,
    },
    /// Arithmetic overflow in budget tracking.
    BudgetOverflow,
    /// Domain not found in registry.
    DomainNotFound { domain: AllocationDomain },
    /// Duplicate domain registration.
    DuplicateDomain { domain: AllocationDomain },
}

impl fmt::Display for AllocDomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExceeded {
                requested,
                remaining,
                domain,
            } => {
                if let Some(d) = domain {
                    write!(
                        f,
                        "budget exceeded in {}: requested {} bytes, {} remaining",
                        d, requested, remaining
                    )
                } else {
                    write!(
                        f,
                        "budget exceeded: requested {} bytes, {} remaining",
                        requested, remaining
                    )
                }
            }
            Self::BudgetOverflow => write!(f, "budget arithmetic overflow"),
            Self::DomainNotFound { domain } => write!(f, "domain '{}' not registered", domain),
            Self::DuplicateDomain { domain } => {
                write!(f, "domain '{}' already registered", domain)
            }
        }
    }
}

impl std::error::Error for AllocDomainError {}

// ---------------------------------------------------------------------------
// DomainRegistry — tracks all allocation domains
// ---------------------------------------------------------------------------

/// Registry of allocation domains with budget tracking.
///
/// Uses `BTreeMap` for deterministic iteration order (replay requirement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistry {
    domains: BTreeMap<AllocationDomain, DomainConfig>,
    /// Total allocation events tracked (for determinism auditing).
    allocation_sequence: u64,
}

impl DomainRegistry {
    pub fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
            allocation_sequence: 0,
        }
    }

    /// Register a new allocation domain with its lifetime class and budget.
    pub fn register(
        &mut self,
        domain: AllocationDomain,
        lifetime: LifetimeClass,
        max_bytes: u64,
    ) -> Result<(), AllocDomainError> {
        if self.domains.contains_key(&domain) {
            return Err(AllocDomainError::DuplicateDomain { domain });
        }
        self.domains.insert(
            domain,
            DomainConfig {
                domain,
                lifetime,
                budget: DomainBudget::new(max_bytes),
            },
        );
        Ok(())
    }

    /// Try to allocate `bytes` from the specified domain.
    pub fn allocate(
        &mut self,
        domain: AllocationDomain,
        bytes: u64,
    ) -> Result<u64, AllocDomainError> {
        let config = self
            .domains
            .get_mut(&domain)
            .ok_or(AllocDomainError::DomainNotFound { domain })?;
        config.budget.try_reserve(bytes).map_err(|e| match e {
            AllocDomainError::BudgetExceeded {
                requested,
                remaining,
                ..
            } => AllocDomainError::BudgetExceeded {
                requested,
                remaining,
                domain: Some(domain),
            },
            other => other,
        })?;
        self.allocation_sequence += 1;
        Ok(self.allocation_sequence)
    }

    /// Release `bytes` back to the specified domain.
    pub fn release(
        &mut self,
        domain: AllocationDomain,
        bytes: u64,
    ) -> Result<(), AllocDomainError> {
        let config = self
            .domains
            .get_mut(&domain)
            .ok_or(AllocDomainError::DomainNotFound { domain })?;
        config.budget.release(bytes);
        Ok(())
    }

    /// Get the current configuration and budget state for a domain.
    pub fn get(&self, domain: &AllocationDomain) -> Option<&DomainConfig> {
        self.domains.get(domain)
    }

    /// Iterate domains in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&AllocationDomain, &DomainConfig)> {
        self.domains.iter()
    }

    /// Total bytes used across all domains.
    pub fn total_used(&self) -> u64 {
        self.domains.values().map(|c| c.budget.used_bytes).sum()
    }

    /// Total budget capacity across all domains.
    pub fn total_capacity(&self) -> u64 {
        self.domains.values().map(|c| c.budget.max_bytes).sum()
    }

    /// Number of registered domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Current allocation sequence number (for determinism auditing).
    pub fn allocation_sequence(&self) -> u64 {
        self.allocation_sequence
    }

    /// Reset a domain's used bytes to zero (for lifetime-class transitions).
    pub fn reset_domain(&mut self, domain: AllocationDomain) -> Result<(), AllocDomainError> {
        let config = self
            .domains
            .get_mut(&domain)
            .ok_or(AllocDomainError::DomainNotFound { domain })?;
        config.budget.used_bytes = 0;
        Ok(())
    }

    /// Create a standard runtime domain set with configurable budgets.
    pub fn with_standard_domains(extension_heap_bytes: u64) -> Self {
        let mut reg = Self::new();
        // These are safe to unwrap because we know there are no duplicates.
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            extension_heap_bytes,
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::RuntimeHeap,
            LifetimeClass::Global,
            u64::MAX, // runtime heap is bounded externally
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::IrArena,
            LifetimeClass::Arena,
            512 * 1024 * 1024, // 512 MB default for IR arena
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::EvidenceArena,
            LifetimeClass::SessionScoped,
            128 * 1024 * 1024, // 128 MB default for evidence
        )
        .expect("no duplicate");
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            64 * 1024 * 1024, // 64 MB default for scratch
        )
        .expect("no duplicate");
        reg
    }
}

impl Default for DomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DomainBudget --

    #[test]
    fn budget_reserves_within_limit() {
        let mut budget = DomainBudget::new(1024);
        assert!(budget.try_reserve(512).is_ok());
        assert_eq!(budget.used_bytes, 512);
        assert_eq!(budget.remaining(), 512);
    }

    #[test]
    fn budget_rejects_over_limit() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(60).unwrap();
        assert!(matches!(
            budget.try_reserve(50),
            Err(AllocDomainError::BudgetExceeded { .. })
        ));
        // Used bytes unchanged on failure.
        assert_eq!(budget.used_bytes, 60);
    }

    #[test]
    fn budget_release_frees_space() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(80).unwrap();
        budget.release(30);
        assert_eq!(budget.used_bytes, 50);
        assert_eq!(budget.remaining(), 50);
    }

    #[test]
    fn budget_release_saturates_at_zero() {
        let mut budget = DomainBudget::new(100);
        budget.try_reserve(10).unwrap();
        budget.release(100); // release more than used
        assert_eq!(budget.used_bytes, 0);
    }

    #[test]
    fn budget_utilization_calculation() {
        let mut budget = DomainBudget::new(200);
        assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
        budget.try_reserve(100).unwrap();
        assert!((budget.utilization() - 0.5).abs() < f64::EPSILON);
        budget.try_reserve(100).unwrap();
        assert!((budget.utilization() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_zero_capacity_utilization() {
        let budget = DomainBudget::new(0);
        assert!((budget.utilization() - 0.0).abs() < f64::EPSILON);
    }

    // -- DomainRegistry --

    #[test]
    fn register_and_allocate() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            1024,
        )
        .unwrap();
        let seq = reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();
        assert_eq!(seq, 1);
        let config = reg.get(&AllocationDomain::ExtensionHeap).unwrap();
        assert_eq!(config.budget.used_bytes, 256);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = DomainRegistry::new();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1024)
            .unwrap();
        assert!(matches!(
            reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 2048),
            Err(AllocDomainError::DuplicateDomain { .. })
        ));
    }

    #[test]
    fn allocate_from_unregistered_domain_fails() {
        let mut reg = DomainRegistry::new();
        assert!(matches!(
            reg.allocate(AllocationDomain::ScratchBuffer, 10),
            Err(AllocDomainError::DomainNotFound { .. })
        ));
    }

    #[test]
    fn budget_enforcement_across_allocations() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 60).unwrap();
        reg.allocate(AllocationDomain::ExtensionHeap, 30).unwrap();
        // Next allocation would exceed
        assert!(matches!(
            reg.allocate(AllocationDomain::ExtensionHeap, 20),
            Err(AllocDomainError::BudgetExceeded {
                domain: Some(AllocationDomain::ExtensionHeap),
                ..
            })
        ));
    }

    #[test]
    fn release_and_reallocate() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            100,
        )
        .unwrap();
        reg.allocate(AllocationDomain::ScratchBuffer, 80).unwrap();
        reg.release(AllocationDomain::ScratchBuffer, 80).unwrap();
        // Should be able to allocate again.
        reg.allocate(AllocationDomain::ScratchBuffer, 90).unwrap();
        assert_eq!(
            reg.get(&AllocationDomain::ScratchBuffer)
                .unwrap()
                .budget
                .used_bytes,
            90
        );
    }

    #[test]
    fn reset_domain_clears_usage() {
        let mut reg = DomainRegistry::new();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 1024)
            .unwrap();
        reg.allocate(AllocationDomain::IrArena, 500).unwrap();
        reg.reset_domain(AllocationDomain::IrArena).unwrap();
        assert_eq!(
            reg.get(&AllocationDomain::IrArena)
                .unwrap()
                .budget
                .used_bytes,
            0
        );
    }

    #[test]
    fn allocation_sequence_increments_deterministically() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            10000,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 10000)
            .unwrap();

        let s1 = reg.allocate(AllocationDomain::ExtensionHeap, 10).unwrap();
        let s2 = reg.allocate(AllocationDomain::IrArena, 20).unwrap();
        let s3 = reg.allocate(AllocationDomain::ExtensionHeap, 30).unwrap();

        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
        assert_eq!(reg.allocation_sequence(), 3);
    }

    #[test]
    fn domains_iterate_in_deterministic_order() {
        let mut reg = DomainRegistry::new();
        // Register in non-sorted order.
        reg.register(
            AllocationDomain::ScratchBuffer,
            LifetimeClass::RequestScoped,
            100,
        )
        .unwrap();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
            .unwrap();

        let domains: Vec<AllocationDomain> = reg.iter().map(|(d, _)| *d).collect();
        // BTreeMap sorts by enum discriminant order.
        assert_eq!(
            domains,
            vec![
                AllocationDomain::ExtensionHeap,
                AllocationDomain::RuntimeHeap, // not registered, won't appear
                AllocationDomain::IrArena,
                AllocationDomain::ScratchBuffer,
            ]
            .into_iter()
            .filter(|d| reg.get(d).is_some())
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn standard_domains_creates_five_domains() {
        let reg = DomainRegistry::with_standard_domains(128 * 1024 * 1024);
        assert_eq!(reg.len(), 5);
        assert!(reg.get(&AllocationDomain::ExtensionHeap).is_some());
        assert!(reg.get(&AllocationDomain::RuntimeHeap).is_some());
        assert!(reg.get(&AllocationDomain::IrArena).is_some());
        assert!(reg.get(&AllocationDomain::EvidenceArena).is_some());
        assert!(reg.get(&AllocationDomain::ScratchBuffer).is_some());
    }

    #[test]
    fn domain_isolation_separate_budgets() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 100)
            .unwrap();

        // Fill extension heap to capacity.
        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();

        // IR arena should still be fully available.
        reg.allocate(AllocationDomain::IrArena, 100).unwrap();

        assert_eq!(reg.total_used(), 200);
        assert_eq!(reg.total_capacity(), 200);
    }

    #[test]
    fn total_used_and_capacity() {
        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            LifetimeClass::SessionScoped,
            500,
        )
        .unwrap();
        reg.register(AllocationDomain::IrArena, LifetimeClass::Arena, 300)
            .unwrap();

        reg.allocate(AllocationDomain::ExtensionHeap, 100).unwrap();
        reg.allocate(AllocationDomain::IrArena, 50).unwrap();

        assert_eq!(reg.total_used(), 150);
        assert_eq!(reg.total_capacity(), 800);
    }

    // -- Serialization --

    #[test]
    fn domain_registry_serialization_round_trip() {
        let mut reg = DomainRegistry::with_standard_domains(1024);
        reg.allocate(AllocationDomain::ExtensionHeap, 256).unwrap();

        let json = serde_json::to_string(&reg).expect("serialize");
        let roundtrip: DomainRegistry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(reg.len(), roundtrip.len());
        assert_eq!(reg.allocation_sequence(), roundtrip.allocation_sequence());
        assert_eq!(
            reg.get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            roundtrip
                .get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes
        );
    }
}
