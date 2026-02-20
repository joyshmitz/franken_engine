//! Privacy-preserving fleet learning contract for calibration data governance.
//!
//! Defines the canonical contract schema that governs how fleet-wide
//! calibration data is collected, aggregated, and consumed without
//! centralising raw tenant-sensitive traces.  Every privacy guarantee
//! is machine-readable, versioned, and auditable.
//!
//! Key contract components:
//! - **Feature schema** — typed fields for local model updates with
//!   versioning and backward-compatibility rules.
//! - **Update policy** — frequency, sample minimums, submission windows.
//! - **Clipping strategy** — per-feature sensitivity bounding before
//!   noise addition.
//! - **DP budget semantics** — epsilon/delta, composition accounting,
//!   hard fail-closed on exhaustion.
//! - **Secure aggregation requirements** — minimum participant threshold,
//!   dropout tolerance, coordinator trust model.
//!
//! Design invariants:
//! - Learning state is *stochastic*; decision state is *deterministic*.
//!   Live decision paths consume only signed snapshot artifacts, never
//!   raw learning state.
//! - Contract changes require signed governance approval and propagation
//!   to all fleet participants.
//! - Budget exhaustion is *fail-closed*: no silent degradation.
//!
//! Plan references: Section 10.15 (Delta Moonshots), subsection 9I.2
//! (Privacy-Preserving Fleet Learning Layer), item 1 of 4.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

const CONTRACT_SCHEMA_DEF: &[u8] = b"FrankenEngine.PrivacyLearningContract.v1";

pub fn contract_schema() -> SchemaHash {
    SchemaHash::from_definition(CONTRACT_SCHEMA_DEF)
}

pub fn contract_schema_id() -> SchemaId {
    SchemaId::from_definition(CONTRACT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// Feature field types
// ---------------------------------------------------------------------------

/// Supported data types for feature schema fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FeatureFieldType {
    /// Fixed-point millionths (i64 where 1_000_000 = 1.0).
    FixedPoint,
    /// Unsigned 64-bit integer counter.
    Counter,
    /// Boolean flag.
    Boolean,
    /// Categorical index (bounded enum ordinal).
    Categorical,
}

impl fmt::Display for FeatureFieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedPoint => write!(f, "fixed_point"),
            Self::Counter => write!(f, "counter"),
            Self::Boolean => write!(f, "boolean"),
            Self::Categorical => write!(f, "categorical"),
        }
    }
}

/// A single field in the feature schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FeatureField {
    /// Machine-readable field name (snake_case, unique within schema).
    pub name: String,
    /// Data type of this field.
    pub field_type: FeatureFieldType,
    /// Human-readable description of what this field captures.
    pub description: String,
    /// Whether this field was present in the previous schema version.
    /// New fields must be marked `false` for backward compatibility.
    pub existed_in_prior_version: bool,
}

/// Typed definition of local model update / summary statistic fields.
///
/// Each version is immutable once published.  Adding fields is the only
/// permitted change; removing or retyping fields requires a new major
/// version with explicit migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureSchema {
    /// Schema version (monotonically increasing).
    pub version: u32,
    /// Fields in deterministic order (sorted by name).
    pub fields: BTreeMap<String, FeatureField>,
    /// Optional reference to the prior schema version for migration.
    pub prior_version: Option<u32>,
}

impl FeatureSchema {
    /// Validate the schema for internal consistency.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.fields.is_empty() {
            return Err(ContractError::EmptyFeatureSchema);
        }
        if self.version == 0 {
            return Err(ContractError::InvalidVersion {
                detail: "schema version must be > 0".to_string(),
            });
        }
        // Ensure field names match their map keys.
        for (key, field) in &self.fields {
            if key != &field.name {
                return Err(ContractError::FieldNameMismatch {
                    key: key.clone(),
                    field_name: field.name.clone(),
                });
            }
        }
        // If prior_version exists, new fields must be marked accordingly.
        if self.prior_version.is_some() {
            let has_new_fields = self.fields.values().any(|f| !f.existed_in_prior_version);
            let has_old_fields = self.fields.values().any(|f| f.existed_in_prior_version);
            if !has_old_fields {
                return Err(ContractError::BackwardCompatibilityViolation {
                    detail: "schema with prior_version must retain at least one prior field"
                        .to_string(),
                });
            }
            // Version must be strictly greater than prior.
            if let Some(prior) = self.prior_version
                && self.version <= prior
            {
                return Err(ContractError::InvalidVersion {
                    detail: format!("version {} must be > prior_version {}", self.version, prior),
                });
            }
            let _ = has_new_fields; // lint: used for documentation, not logic gate
        }
        Ok(())
    }

    /// Check backward compatibility: all fields from `prior` must exist
    /// in `self` with the same type.
    pub fn is_backward_compatible_with(&self, prior: &FeatureSchema) -> bool {
        for (name, prior_field) in &prior.fields {
            match self.fields.get(name) {
                Some(current_field) => {
                    if current_field.field_type != prior_field.field_type {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Update policy
// ---------------------------------------------------------------------------

/// Rules governing when and how local updates are computed and submitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    /// Minimum number of local samples before an update may be submitted.
    pub min_local_samples: u64,
    /// Maximum submission frequency: minimum interval between submissions
    /// (in deterministic timestamp units).
    pub min_submission_interval: u64,
    /// Maximum age of local data included in a submission (staleness bound).
    pub max_data_age: u64,
    /// Whether participants may skip a submission round without penalty.
    pub allow_skip: bool,
    /// Maximum number of consecutive skips before the participant is
    /// considered dropped from the current aggregation epoch.
    pub max_consecutive_skips: u32,
}

impl UpdatePolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.min_local_samples == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "min_local_samples must be > 0".to_string(),
            });
        }
        if self.min_submission_interval == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "min_submission_interval must be > 0".to_string(),
            });
        }
        if self.max_data_age == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "max_data_age must be > 0".to_string(),
            });
        }
        if self.allow_skip && self.max_consecutive_skips == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "max_consecutive_skips must be > 0 when skips are allowed".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Clipping strategy
// ---------------------------------------------------------------------------

/// Method for bounding the sensitivity of a feature field before noise
/// addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClippingMethod {
    /// L2 norm clipping: scale the entire update vector if its L2 norm
    /// exceeds the bound.
    L2Norm,
    /// Per-coordinate clipping: independently clip each field to its bound.
    PerCoordinate,
    /// Adaptive clipping: adjust the bound based on observed quantiles
    /// (requires additional DP budget for the quantile estimation).
    Adaptive,
}

impl fmt::Display for ClippingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L2Norm => write!(f, "l2_norm"),
            Self::PerCoordinate => write!(f, "per_coordinate"),
            Self::Adaptive => write!(f, "adaptive"),
        }
    }
}

/// Per-feature clipping bounds to control sensitivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClippingStrategy {
    /// Global clipping method applied to the update vector.
    pub method: ClippingMethod,
    /// Global clipping bound (fixed-point millionths).
    /// For L2Norm: the maximum L2 norm of the update vector.
    /// For PerCoordinate: the default per-field bound.
    pub global_bound_millionths: i64,
    /// Optional per-field overrides (field name -> bound in millionths).
    /// Only valid when method is PerCoordinate.
    pub per_field_bounds: BTreeMap<String, i64>,
}

impl ClippingStrategy {
    pub fn validate(&self, feature_schema: &FeatureSchema) -> Result<(), ContractError> {
        if self.global_bound_millionths <= 0 {
            return Err(ContractError::InvalidClippingStrategy {
                detail: "global_bound_millionths must be > 0".to_string(),
            });
        }
        // Per-field bounds only valid with PerCoordinate.
        if self.method != ClippingMethod::PerCoordinate && !self.per_field_bounds.is_empty() {
            return Err(ContractError::InvalidClippingStrategy {
                detail: "per_field_bounds only valid with PerCoordinate clipping".to_string(),
            });
        }
        // All per-field bound keys must exist in the feature schema.
        for field_name in self.per_field_bounds.keys() {
            if !feature_schema.fields.contains_key(field_name) {
                return Err(ContractError::InvalidClippingStrategy {
                    detail: format!("per_field_bound references unknown field: {field_name}"),
                });
            }
        }
        // All per-field bounds must be positive.
        for (name, bound) in &self.per_field_bounds {
            if *bound <= 0 {
                return Err(ContractError::InvalidClippingStrategy {
                    detail: format!("per_field_bound for '{name}' must be > 0"),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DP budget semantics
// ---------------------------------------------------------------------------

/// Composition accounting method for differential privacy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CompositionMethod {
    /// Basic (linear) composition: epsilon sums linearly.
    Basic,
    /// Advanced composition theorem (Dwork et al. 2010).
    Advanced,
    /// Renyi Differential Privacy (Mironov 2017).
    Renyi,
    /// Zero-Concentrated DP (Bun & Steinke 2016).
    ZeroCdp,
}

impl fmt::Display for CompositionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Advanced => write!(f, "advanced"),
            Self::Renyi => write!(f, "renyi"),
            Self::ZeroCdp => write!(f, "zcdp"),
        }
    }
}

/// Differential privacy budget semantics with hard fail-closed enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpBudgetSemantics {
    /// Privacy loss parameter per epoch (fixed-point millionths).
    pub epsilon_per_epoch_millionths: i64,
    /// Failure probability per epoch (fixed-point millionths).
    pub delta_per_epoch_millionths: i64,
    /// Composition method for multi-epoch accounting.
    pub composition_method: CompositionMethod,
    /// Total lifetime budget for epsilon (fixed-point millionths).
    /// Once exhausted, the system MUST fail closed.
    pub lifetime_epsilon_budget_millionths: i64,
    /// Total lifetime budget for delta (fixed-point millionths).
    pub lifetime_delta_budget_millionths: i64,
    /// Whether budget exhaustion triggers immediate hard stop.
    /// MUST be true per contract invariants.
    pub fail_closed_on_exhaustion: bool,
}

impl DpBudgetSemantics {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.epsilon_per_epoch_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "epsilon_per_epoch must be > 0".to_string(),
            });
        }
        if self.delta_per_epoch_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "delta_per_epoch must be > 0".to_string(),
            });
        }
        if self.lifetime_epsilon_budget_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "lifetime_epsilon_budget must be > 0".to_string(),
            });
        }
        if self.lifetime_delta_budget_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "lifetime_delta_budget must be > 0".to_string(),
            });
        }
        if !self.fail_closed_on_exhaustion {
            return Err(ContractError::InvalidDpBudget {
                detail: "fail_closed_on_exhaustion must be true".to_string(),
            });
        }
        // Per-epoch budget must not exceed lifetime budget.
        if self.epsilon_per_epoch_millionths > self.lifetime_epsilon_budget_millionths {
            return Err(ContractError::InvalidDpBudget {
                detail: "epsilon_per_epoch exceeds lifetime budget".to_string(),
            });
        }
        if self.delta_per_epoch_millionths > self.lifetime_delta_budget_millionths {
            return Err(ContractError::InvalidDpBudget {
                detail: "delta_per_epoch exceeds lifetime budget".to_string(),
            });
        }
        Ok(())
    }

    /// Compute the maximum number of epochs before budget exhaustion
    /// under the given composition method.
    pub fn max_epochs(&self) -> u64 {
        match self.composition_method {
            CompositionMethod::Basic => {
                // Linear composition: total = k * epsilon_per_epoch.
                (self.lifetime_epsilon_budget_millionths / self.epsilon_per_epoch_millionths) as u64
            }
            CompositionMethod::Advanced | CompositionMethod::Renyi | CompositionMethod::ZeroCdp => {
                // For advanced/Renyi/zCDP, epsilon grows as O(sqrt(k)).
                // max_k such that epsilon_per_epoch * sqrt(k) <= lifetime.
                // k <= (lifetime / epsilon_per_epoch)^2.
                let ratio =
                    self.lifetime_epsilon_budget_millionths / self.epsilon_per_epoch_millionths;
                (ratio * ratio) as u64
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Secure aggregation requirements
// ---------------------------------------------------------------------------

/// Trust model for the aggregation coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoordinatorTrustModel {
    /// Coordinator sees only aggregated results, never individual updates.
    HonestButCurious,
    /// Coordinator may behave arbitrarily; protocol is secure against
    /// malicious coordinator (requires heavier crypto).
    Malicious,
}

impl fmt::Display for CoordinatorTrustModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HonestButCurious => write!(f, "honest_but_curious"),
            Self::Malicious => write!(f, "malicious"),
        }
    }
}

/// Cryptographic protocol for secret sharing in secure aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecretSharingScheme {
    /// Additive secret sharing (lightweight, sufficient for honest-but-curious).
    Additive,
    /// Shamir secret sharing (threshold-based, stronger guarantees).
    Shamir,
}

impl fmt::Display for SecretSharingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Additive => write!(f, "additive"),
            Self::Shamir => write!(f, "shamir"),
        }
    }
}

/// Requirements for secure aggregation of local updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureAggregationRequirements {
    /// Minimum number of participants for aggregation to proceed.
    pub min_participants: u32,
    /// Maximum fraction of participants that may drop out (millionths).
    /// E.g., 200_000 = 20% dropout tolerance.
    pub dropout_tolerance_millionths: i64,
    /// Cryptographic protocol for secret sharing.
    pub secret_sharing_scheme: SecretSharingScheme,
    /// Threshold for Shamir sharing (k-of-n).  Only relevant when
    /// scheme is `Shamir`.
    pub sharing_threshold: Option<u32>,
    /// Trust model for the coordinator.
    pub coordinator_trust_model: CoordinatorTrustModel,
}

impl SecureAggregationRequirements {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.min_participants < 2 {
            return Err(ContractError::InvalidAggregation {
                detail: "min_participants must be >= 2".to_string(),
            });
        }
        if self.dropout_tolerance_millionths < 0 || self.dropout_tolerance_millionths >= 1_000_000 {
            return Err(ContractError::InvalidAggregation {
                detail: "dropout_tolerance must be in [0, 1_000_000)".to_string(),
            });
        }
        // Shamir requires a threshold.
        if self.secret_sharing_scheme == SecretSharingScheme::Shamir {
            match self.sharing_threshold {
                None => {
                    return Err(ContractError::InvalidAggregation {
                        detail: "Shamir scheme requires sharing_threshold".to_string(),
                    });
                }
                Some(t) if t < 2 => {
                    return Err(ContractError::InvalidAggregation {
                        detail: "sharing_threshold must be >= 2".to_string(),
                    });
                }
                Some(t) if t > self.min_participants => {
                    return Err(ContractError::InvalidAggregation {
                        detail: "sharing_threshold must be <= min_participants".to_string(),
                    });
                }
                _ => {}
            }
        }
        // Additive should not have threshold.
        if self.secret_sharing_scheme == SecretSharingScheme::Additive
            && self.sharing_threshold.is_some()
        {
            return Err(ContractError::InvalidAggregation {
                detail: "Additive scheme must not specify sharing_threshold".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Data retention
// ---------------------------------------------------------------------------

/// Data retention and deletion semantics for intermediate aggregation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRetentionPolicy {
    /// Maximum retention period for intermediate aggregation state
    /// (in deterministic timestamp units).
    pub max_intermediate_retention: u64,
    /// Maximum retention period for signed snapshot artifacts.
    pub max_snapshot_retention: u64,
    /// Whether local raw updates must be deleted after submission.
    pub delete_local_after_submission: bool,
    /// Whether intermediate shares must be deleted after aggregation completes.
    pub delete_shares_after_aggregation: bool,
}

impl DataRetentionPolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.max_intermediate_retention == 0 {
            return Err(ContractError::InvalidRetention {
                detail: "max_intermediate_retention must be > 0".to_string(),
            });
        }
        if self.max_snapshot_retention == 0 {
            return Err(ContractError::InvalidRetention {
                detail: "max_snapshot_retention must be > 0".to_string(),
            });
        }
        // Snapshot retention should be >= intermediate retention.
        if self.max_snapshot_retention < self.max_intermediate_retention {
            return Err(ContractError::InvalidRetention {
                detail: "max_snapshot_retention must be >= max_intermediate_retention".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The contract itself
// ---------------------------------------------------------------------------

/// A versioned, governance-signed privacy-learning contract.
///
/// Defines all privacy guarantees for fleet-wide calibration.
/// Live decision paths consume only signed snapshots from this contract,
/// never raw learning state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyLearningContract {
    /// Unique contract identity derived from canonical content.
    pub contract_id: EngineObjectId,
    /// The epoch in which this contract is effective.
    pub epoch: SecurityEpoch,
    /// Zone this contract governs.
    pub zone: String,
    /// Feature schema defining the local update fields.
    pub feature_schema: FeatureSchema,
    /// Rules governing update computation and submission.
    pub update_policy: UpdatePolicy,
    /// Sensitivity bounding strategy.
    pub clipping_strategy: ClippingStrategy,
    /// Differential privacy budget semantics.
    pub dp_budget: DpBudgetSemantics,
    /// Secure aggregation requirements.
    pub aggregation: SecureAggregationRequirements,
    /// Data retention and deletion policy.
    pub retention: DataRetentionPolicy,
    /// Governance signature over all fields (sentinel during signing).
    pub governance_signature: Signature,
    /// Set of participant node IDs authorized for this contract.
    pub authorized_participants: BTreeSet<EngineObjectId>,
}

impl PrivacyLearningContract {
    /// Derive the contract ID from canonical content.
    fn derive_contract_id(
        epoch: SecurityEpoch,
        zone: &str,
        schema_version: u32,
    ) -> Result<EngineObjectId, engine_object_id::IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&epoch.as_u64().to_be_bytes());
        canonical.extend_from_slice(zone.as_bytes());
        canonical.extend_from_slice(&schema_version.to_be_bytes());
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            zone,
            &contract_schema_id(),
            &canonical,
        )
    }

    /// Create and sign a new privacy-learning contract.
    pub fn create_signed(
        governance_key: &SigningKey,
        input: CreateContractInput<'_>,
    ) -> Result<Self, ContractError> {
        // Validate all sub-components.
        input.feature_schema.validate()?;
        input.update_policy.validate()?;
        input.clipping_strategy.validate(&input.feature_schema)?;
        input.dp_budget.validate()?;
        input.aggregation.validate()?;
        input.retention.validate()?;

        if input.authorized_participants.is_empty() {
            return Err(ContractError::NoAuthorizedParticipants);
        }

        let contract_id =
            Self::derive_contract_id(input.epoch, input.zone, input.feature_schema.version)
                .map_err(|e| ContractError::IdDerivationFailed {
                    detail: e.to_string(),
                })?;

        let mut contract = Self {
            contract_id,
            epoch: input.epoch,
            zone: input.zone.to_string(),
            feature_schema: input.feature_schema,
            update_policy: input.update_policy,
            clipping_strategy: input.clipping_strategy,
            dp_budget: input.dp_budget,
            aggregation: input.aggregation,
            retention: input.retention,
            governance_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
            authorized_participants: input.authorized_participants,
        };

        let preimage = contract.preimage_bytes();
        let sig = sign_preimage(governance_key, &preimage).map_err(|e| {
            ContractError::SignatureFailed {
                detail: e.to_string(),
            }
        })?;
        contract.governance_signature = sig;

        Ok(contract)
    }

    /// Verify the governance signature on this contract.
    pub fn verify_governance_signature(
        &self,
        governance_vk: &VerificationKey,
    ) -> Result<(), ContractError> {
        let preimage = self.preimage_bytes();
        verify_signature(governance_vk, &preimage, &self.governance_signature).map_err(|e| {
            ContractError::SignatureInvalid {
                detail: e.to_string(),
            }
        })
    }

    /// Check whether a participant is authorized under this contract.
    pub fn is_authorized(&self, participant: &EngineObjectId) -> bool {
        self.authorized_participants.contains(participant)
    }

    /// Build the unsigned view for signature computation.
    fn build_unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "aggregation_min_participants".to_string(),
            CanonicalValue::U64(self.aggregation.min_participants as u64),
        );
        map.insert(
            "clipping_method".to_string(),
            CanonicalValue::String(self.clipping_strategy.method.to_string()),
        );
        map.insert(
            "contract_id".to_string(),
            CanonicalValue::Bytes(self.contract_id.as_bytes().to_vec()),
        );
        map.insert(
            "dp_composition".to_string(),
            CanonicalValue::String(self.dp_budget.composition_method.to_string()),
        );
        map.insert(
            "dp_epsilon_per_epoch".to_string(),
            CanonicalValue::I64(self.dp_budget.epsilon_per_epoch_millionths),
        );
        map.insert(
            "dp_lifetime_epsilon".to_string(),
            CanonicalValue::I64(self.dp_budget.lifetime_epsilon_budget_millionths),
        );
        map.insert(
            "epoch".to_string(),
            CanonicalValue::U64(self.epoch.as_u64()),
        );
        map.insert(
            "feature_schema_version".to_string(),
            CanonicalValue::U64(self.feature_schema.version as u64),
        );
        map.insert(
            "governance_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

/// Input parameters for creating a signed privacy-learning contract.
#[derive(Debug, Clone)]
pub struct CreateContractInput<'a> {
    pub epoch: SecurityEpoch,
    pub zone: &'a str,
    pub feature_schema: FeatureSchema,
    pub update_policy: UpdatePolicy,
    pub clipping_strategy: ClippingStrategy,
    pub dp_budget: DpBudgetSemantics,
    pub aggregation: SecureAggregationRequirements,
    pub retention: DataRetentionPolicy,
    pub authorized_participants: BTreeSet<EngineObjectId>,
}

impl SignaturePreimage for PrivacyLearningContract {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &SchemaHash {
        unreachable!("use preimage_bytes directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        self.build_unsigned_view()
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let domain_tag = self.signature_domain().tag();
        let schema = contract_schema();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

impl fmt::Display for PrivacyLearningContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivacyLearningContract(id={}, epoch={}, zone={}, schema_v={}, dp={}/{})",
            self.contract_id,
            self.epoch,
            self.zone,
            self.feature_schema.version,
            self.dp_budget.composition_method,
            self.dp_budget.epsilon_per_epoch_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// Contract registry — manages active contracts per zone
// ---------------------------------------------------------------------------

/// Manages privacy-learning contracts with epoch-based versioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRegistry {
    /// Active contracts indexed by contract ID.
    contracts: BTreeMap<EngineObjectId, PrivacyLearningContract>,
    /// Per-zone active contract: zone -> contract ID.
    zone_active: BTreeMap<String, EngineObjectId>,
    /// Audit events.
    audit_events: Vec<ContractEvent>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self {
            contracts: BTreeMap::new(),
            zone_active: BTreeMap::new(),
            audit_events: Vec::new(),
        }
    }

    /// Register a new contract after full verification.
    pub fn register(
        &mut self,
        contract: PrivacyLearningContract,
        governance_vk: &VerificationKey,
        trace_id: &str,
    ) -> Result<EngineObjectId, ContractError> {
        // Verify governance signature.
        contract.verify_governance_signature(governance_vk)?;

        // Check for duplicate.
        if self.contracts.contains_key(&contract.contract_id) {
            return Err(ContractError::DuplicateContract {
                contract_id: contract.contract_id.clone(),
            });
        }

        // If a contract exists for this zone, the new one must have a
        // higher epoch.
        if let Some(existing_id) = self.zone_active.get(&contract.zone)
            && let Some(existing) = self.contracts.get(existing_id)
            && existing.epoch.as_u64() >= contract.epoch.as_u64()
        {
            return Err(ContractError::EpochNotAdvanced {
                zone: contract.zone.clone(),
                existing_epoch: existing.epoch,
                new_epoch: contract.epoch,
            });
        }

        let contract_id = contract.contract_id.clone();
        let zone = contract.zone.clone();
        let epoch = contract.epoch;

        self.zone_active.insert(zone.clone(), contract_id.clone());
        self.contracts.insert(contract_id.clone(), contract);

        self.emit_event(
            ContractEventType::Registered {
                contract_id: contract_id.clone(),
                zone: zone.clone(),
                epoch,
            },
            trace_id,
        );

        Ok(contract_id)
    }

    /// Look up a contract by ID.
    pub fn get(&self, contract_id: &EngineObjectId) -> Option<&PrivacyLearningContract> {
        self.contracts.get(contract_id)
    }

    /// Get the active contract for a zone.
    pub fn active_for_zone(&self, zone: &str) -> Option<&PrivacyLearningContract> {
        self.zone_active
            .get(zone)
            .and_then(|id| self.contracts.get(id))
    }

    /// Revoke a contract.
    pub fn revoke(
        &mut self,
        contract_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<(), ContractError> {
        let contract =
            self.contracts
                .remove(contract_id)
                .ok_or_else(|| ContractError::NotFound {
                    contract_id: contract_id.clone(),
                })?;

        // Remove from zone active if it was the active contract.
        if let Some(active_id) = self.zone_active.get(&contract.zone)
            && active_id == contract_id
        {
            self.zone_active.remove(&contract.zone);
        }

        self.emit_event(
            ContractEventType::Revoked {
                contract_id: contract_id.clone(),
                zone: contract.zone.clone(),
            },
            trace_id,
        );

        Ok(())
    }

    /// Total number of contracts.
    pub fn total_count(&self) -> usize {
        self.contracts.len()
    }

    /// Number of zones with active contracts.
    pub fn zone_count(&self) -> usize {
        self.zone_active.len()
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.audit_events)
    }

    fn emit_event(&mut self, event_type: ContractEventType, trace_id: &str) {
        self.audit_events.push(ContractEvent {
            event_type,
            trace_id: trace_id.to_string(),
        });
    }
}

impl Default for ContractRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from privacy-learning contract operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractError {
    EmptyFeatureSchema,
    InvalidVersion {
        detail: String,
    },
    FieldNameMismatch {
        key: String,
        field_name: String,
    },
    BackwardCompatibilityViolation {
        detail: String,
    },
    InvalidUpdatePolicy {
        detail: String,
    },
    InvalidClippingStrategy {
        detail: String,
    },
    InvalidDpBudget {
        detail: String,
    },
    InvalidAggregation {
        detail: String,
    },
    InvalidRetention {
        detail: String,
    },
    NoAuthorizedParticipants,
    IdDerivationFailed {
        detail: String,
    },
    SignatureFailed {
        detail: String,
    },
    SignatureInvalid {
        detail: String,
    },
    DuplicateContract {
        contract_id: EngineObjectId,
    },
    NotFound {
        contract_id: EngineObjectId,
    },
    EpochNotAdvanced {
        zone: String,
        existing_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFeatureSchema => write!(f, "feature schema has no fields"),
            Self::InvalidVersion { detail } => write!(f, "invalid version: {detail}"),
            Self::FieldNameMismatch { key, field_name } => {
                write!(f, "field name mismatch: key={key}, field.name={field_name}")
            }
            Self::BackwardCompatibilityViolation { detail } => {
                write!(f, "backward compatibility violation: {detail}")
            }
            Self::InvalidUpdatePolicy { detail } => {
                write!(f, "invalid update policy: {detail}")
            }
            Self::InvalidClippingStrategy { detail } => {
                write!(f, "invalid clipping strategy: {detail}")
            }
            Self::InvalidDpBudget { detail } => write!(f, "invalid DP budget: {detail}"),
            Self::InvalidAggregation { detail } => {
                write!(f, "invalid aggregation: {detail}")
            }
            Self::InvalidRetention { detail } => write!(f, "invalid retention: {detail}"),
            Self::NoAuthorizedParticipants => write!(f, "no authorized participants"),
            Self::IdDerivationFailed { detail } => write!(f, "id derivation failed: {detail}"),
            Self::SignatureFailed { detail } => write!(f, "signature failed: {detail}"),
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::DuplicateContract { contract_id } => {
                write!(f, "duplicate contract: {contract_id}")
            }
            Self::NotFound { contract_id } => write!(f, "contract not found: {contract_id}"),
            Self::EpochNotAdvanced {
                zone,
                existing_epoch,
                new_epoch,
            } => write!(
                f,
                "epoch not advanced for zone {zone}: existing={existing_epoch}, new={new_epoch}"
            ),
        }
    }
}

impl std::error::Error for ContractError {}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractEventType {
    Registered {
        contract_id: EngineObjectId,
        zone: String,
        epoch: SecurityEpoch,
    },
    Revoked {
        contract_id: EngineObjectId,
        zone: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    pub event_type: ContractEventType,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ZONE: &str = "test-zone";

    fn governance_signing_key() -> SigningKey {
        SigningKey::from_bytes([0x01; 32])
    }

    fn governance_vk() -> VerificationKey {
        governance_signing_key().verification_key()
    }

    fn test_participant_ids() -> BTreeSet<EngineObjectId> {
        let mut set = BTreeSet::new();
        set.insert(EngineObjectId([0xAA; 32]));
        set.insert(EngineObjectId([0xBB; 32]));
        set.insert(EngineObjectId([0xCC; 32]));
        set
    }

    fn test_feature_schema() -> FeatureSchema {
        let mut fields = BTreeMap::new();
        fields.insert(
            "calibration_residual".to_string(),
            FeatureField {
                name: "calibration_residual".to_string(),
                field_type: FeatureFieldType::FixedPoint,
                description: "Residual from local calibration model".to_string(),
                existed_in_prior_version: false,
            },
        );
        fields.insert(
            "drift_indicator".to_string(),
            FeatureField {
                name: "drift_indicator".to_string(),
                field_type: FeatureFieldType::FixedPoint,
                description: "Distribution drift signal".to_string(),
                existed_in_prior_version: false,
            },
        );
        fields.insert(
            "false_positive_count".to_string(),
            FeatureField {
                name: "false_positive_count".to_string(),
                field_type: FeatureFieldType::Counter,
                description: "Number of false positive detections".to_string(),
                existed_in_prior_version: false,
            },
        );
        FeatureSchema {
            version: 1,
            fields,
            prior_version: None,
        }
    }

    fn test_update_policy() -> UpdatePolicy {
        UpdatePolicy {
            min_local_samples: 100,
            min_submission_interval: 3600,
            max_data_age: 86400,
            allow_skip: true,
            max_consecutive_skips: 3,
        }
    }

    fn test_clipping_strategy() -> ClippingStrategy {
        ClippingStrategy {
            method: ClippingMethod::L2Norm,
            global_bound_millionths: 1_000_000, // 1.0
            per_field_bounds: BTreeMap::new(),
        }
    }

    fn test_dp_budget() -> DpBudgetSemantics {
        DpBudgetSemantics {
            epsilon_per_epoch_millionths: 100_000, // 0.1
            delta_per_epoch_millionths: 1_000,     // 0.000001
            composition_method: CompositionMethod::Renyi,
            lifetime_epsilon_budget_millionths: 10_000_000, // 10.0
            lifetime_delta_budget_millionths: 100_000,      // 0.0001
            fail_closed_on_exhaustion: true,
        }
    }

    fn test_aggregation() -> SecureAggregationRequirements {
        SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000, // 20%
            secret_sharing_scheme: SecretSharingScheme::Additive,
            sharing_threshold: None,
            coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
        }
    }

    fn test_retention() -> DataRetentionPolicy {
        DataRetentionPolicy {
            max_intermediate_retention: 86400,
            max_snapshot_retention: 604800,
            delete_local_after_submission: true,
            delete_shares_after_aggregation: true,
        }
    }

    fn test_contract_input() -> CreateContractInput<'static> {
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
            feature_schema: test_feature_schema(),
            update_policy: test_update_policy(),
            clipping_strategy: test_clipping_strategy(),
            dp_budget: test_dp_budget(),
            aggregation: test_aggregation(),
            retention: test_retention(),
            authorized_participants: test_participant_ids(),
        }
    }

    fn create_test_contract() -> PrivacyLearningContract {
        PrivacyLearningContract::create_signed(&governance_signing_key(), test_contract_input())
            .expect("create test contract")
    }

    // -------------------------------------------------------------------
    // Feature schema tests
    // -------------------------------------------------------------------

    #[test]
    fn feature_schema_valid() {
        let schema = test_feature_schema();
        schema.validate().expect("valid schema");
    }

    #[test]
    fn feature_schema_empty_rejected() {
        let schema = FeatureSchema {
            version: 1,
            fields: BTreeMap::new(),
            prior_version: None,
        };
        assert!(matches!(
            schema.validate(),
            Err(ContractError::EmptyFeatureSchema)
        ));
    }

    #[test]
    fn feature_schema_version_zero_rejected() {
        let mut schema = test_feature_schema();
        schema.version = 0;
        assert!(matches!(
            schema.validate(),
            Err(ContractError::InvalidVersion { .. })
        ));
    }

    #[test]
    fn feature_schema_name_mismatch_rejected() {
        let mut schema = test_feature_schema();
        schema.fields.insert(
            "wrong_key".to_string(),
            FeatureField {
                name: "actual_name".to_string(),
                field_type: FeatureFieldType::Counter,
                description: "test".to_string(),
                existed_in_prior_version: false,
            },
        );
        assert!(matches!(
            schema.validate(),
            Err(ContractError::FieldNameMismatch { .. })
        ));
    }

    #[test]
    fn feature_schema_backward_compatible() {
        let v1 = test_feature_schema();
        let mut v2_fields = v1.fields.clone();
        for field in v2_fields.values_mut() {
            field.existed_in_prior_version = true;
        }
        v2_fields.insert(
            "new_field".to_string(),
            FeatureField {
                name: "new_field".to_string(),
                field_type: FeatureFieldType::Boolean,
                description: "New feature flag".to_string(),
                existed_in_prior_version: false,
            },
        );
        let v2 = FeatureSchema {
            version: 2,
            fields: v2_fields,
            prior_version: Some(1),
        };
        v2.validate().expect("valid v2");
        assert!(v2.is_backward_compatible_with(&v1));
    }

    #[test]
    fn feature_schema_not_backward_compatible_type_change() {
        let v1 = test_feature_schema();
        let mut v2_fields = v1.fields.clone();
        // Change type of an existing field.
        if let Some(field) = v2_fields.get_mut("calibration_residual") {
            field.field_type = FeatureFieldType::Counter; // was FixedPoint
            field.existed_in_prior_version = true;
        }
        let v2 = FeatureSchema {
            version: 2,
            fields: v2_fields,
            prior_version: Some(1),
        };
        assert!(!v2.is_backward_compatible_with(&v1));
    }

    #[test]
    fn feature_schema_not_backward_compatible_field_removed() {
        let v1 = test_feature_schema();
        let mut v2_fields = BTreeMap::new();
        // Only keep one field from v1.
        if let Some(field) = v1.fields.get("calibration_residual") {
            let mut f = field.clone();
            f.existed_in_prior_version = true;
            v2_fields.insert(f.name.clone(), f);
        }
        let v2 = FeatureSchema {
            version: 2,
            fields: v2_fields,
            prior_version: Some(1),
        };
        assert!(!v2.is_backward_compatible_with(&v1));
    }

    #[test]
    fn feature_schema_prior_version_must_retain_fields() {
        let mut schema = test_feature_schema();
        schema.version = 2;
        schema.prior_version = Some(1);
        // All fields marked as new (not prior) — violates rule.
        assert!(matches!(
            schema.validate(),
            Err(ContractError::BackwardCompatibilityViolation { .. })
        ));
    }

    #[test]
    fn feature_schema_version_must_exceed_prior() {
        let mut schema = test_feature_schema();
        schema.prior_version = Some(1); // same as version
        for field in schema.fields.values_mut() {
            field.existed_in_prior_version = true;
        }
        assert!(matches!(
            schema.validate(),
            Err(ContractError::InvalidVersion { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Update policy tests
    // -------------------------------------------------------------------

    #[test]
    fn update_policy_valid() {
        test_update_policy().validate().expect("valid");
    }

    #[test]
    fn update_policy_zero_samples_rejected() {
        let mut policy = test_update_policy();
        policy.min_local_samples = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_zero_interval_rejected() {
        let mut policy = test_update_policy();
        policy.min_submission_interval = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_zero_age_rejected() {
        let mut policy = test_update_policy();
        policy.max_data_age = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_skip_without_limit_rejected() {
        let mut policy = test_update_policy();
        policy.allow_skip = true;
        policy.max_consecutive_skips = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_no_skip_zero_limit_ok() {
        let mut policy = test_update_policy();
        policy.allow_skip = false;
        policy.max_consecutive_skips = 0;
        policy.validate().expect("valid when skips disabled");
    }

    // -------------------------------------------------------------------
    // Clipping strategy tests
    // -------------------------------------------------------------------

    #[test]
    fn clipping_strategy_l2_valid() {
        test_clipping_strategy()
            .validate(&test_feature_schema())
            .expect("valid");
    }

    #[test]
    fn clipping_strategy_zero_bound_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.global_bound_millionths = 0;
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_negative_bound_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.global_bound_millionths = -1;
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_per_field_with_l2_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::L2Norm;
        clipping
            .per_field_bounds
            .insert("calibration_residual".to_string(), 500_000);
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_per_coordinate_valid() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::PerCoordinate;
        clipping
            .per_field_bounds
            .insert("calibration_residual".to_string(), 500_000);
        clipping.validate(&test_feature_schema()).expect("valid");
    }

    #[test]
    fn clipping_strategy_unknown_field_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::PerCoordinate;
        clipping
            .per_field_bounds
            .insert("nonexistent_field".to_string(), 500_000);
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_per_field_negative_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::PerCoordinate;
        clipping
            .per_field_bounds
            .insert("calibration_residual".to_string(), -1);
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    // -------------------------------------------------------------------
    // DP budget tests
    // -------------------------------------------------------------------

    #[test]
    fn dp_budget_valid() {
        test_dp_budget().validate().expect("valid");
    }

    #[test]
    fn dp_budget_zero_epsilon_rejected() {
        let mut budget = test_dp_budget();
        budget.epsilon_per_epoch_millionths = 0;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_negative_delta_rejected() {
        let mut budget = test_dp_budget();
        budget.delta_per_epoch_millionths = -1;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_fail_open_rejected() {
        let mut budget = test_dp_budget();
        budget.fail_closed_on_exhaustion = false;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_epoch_exceeds_lifetime_rejected() {
        let mut budget = test_dp_budget();
        budget.epsilon_per_epoch_millionths = budget.lifetime_epsilon_budget_millionths + 1;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_max_epochs_basic() {
        let mut budget = test_dp_budget();
        budget.composition_method = CompositionMethod::Basic;
        budget.epsilon_per_epoch_millionths = 1_000_000; // 1.0
        budget.lifetime_epsilon_budget_millionths = 10_000_000; // 10.0
        assert_eq!(budget.max_epochs(), 10);
    }

    #[test]
    fn dp_budget_max_epochs_renyi() {
        let mut budget = test_dp_budget();
        budget.composition_method = CompositionMethod::Renyi;
        budget.epsilon_per_epoch_millionths = 1_000_000; // 1.0
        budget.lifetime_epsilon_budget_millionths = 10_000_000; // 10.0
        // sqrt composition: (10/1)^2 = 100
        assert_eq!(budget.max_epochs(), 100);
    }

    #[test]
    fn dp_budget_max_epochs_zcdp() {
        let mut budget = test_dp_budget();
        budget.composition_method = CompositionMethod::ZeroCdp;
        budget.epsilon_per_epoch_millionths = 500_000; // 0.5
        budget.lifetime_epsilon_budget_millionths = 5_000_000; // 5.0
        // (5_000_000 / 500_000)^2 = 100
        assert_eq!(budget.max_epochs(), 100);
    }

    // -------------------------------------------------------------------
    // Aggregation tests
    // -------------------------------------------------------------------

    #[test]
    fn aggregation_valid() {
        test_aggregation().validate().expect("valid");
    }

    #[test]
    fn aggregation_one_participant_rejected() {
        let mut agg = test_aggregation();
        agg.min_participants = 1;
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_negative_dropout_rejected() {
        let mut agg = test_aggregation();
        agg.dropout_tolerance_millionths = -1;
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_full_dropout_rejected() {
        let mut agg = test_aggregation();
        agg.dropout_tolerance_millionths = 1_000_000; // 100%
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_shamir_valid() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: Some(7),
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        agg.validate().expect("valid shamir");
    }

    #[test]
    fn aggregation_shamir_no_threshold_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: None,
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_shamir_low_threshold_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: Some(1),
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_shamir_threshold_exceeds_participants_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 5,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: Some(6),
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_additive_with_threshold_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Additive,
            sharing_threshold: Some(5),
            coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Retention tests
    // -------------------------------------------------------------------

    #[test]
    fn retention_valid() {
        test_retention().validate().expect("valid");
    }

    #[test]
    fn retention_zero_intermediate_rejected() {
        let mut ret = test_retention();
        ret.max_intermediate_retention = 0;
        assert!(matches!(
            ret.validate(),
            Err(ContractError::InvalidRetention { .. })
        ));
    }

    #[test]
    fn retention_snapshot_less_than_intermediate_rejected() {
        let mut ret = test_retention();
        ret.max_intermediate_retention = 1000;
        ret.max_snapshot_retention = 500;
        assert!(matches!(
            ret.validate(),
            Err(ContractError::InvalidRetention { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Contract creation tests
    // -------------------------------------------------------------------

    #[test]
    fn create_contract_succeeds() {
        let contract = create_test_contract();
        assert_eq!(contract.zone, TEST_ZONE);
        assert_eq!(contract.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(contract.feature_schema.version, 1);
        assert_eq!(contract.authorized_participants.len(), 3);
    }

    #[test]
    fn create_contract_deterministic() {
        let c1 = create_test_contract();
        let c2 = create_test_contract();
        assert_eq!(c1.contract_id, c2.contract_id);
        assert_eq!(c1.governance_signature, c2.governance_signature);
    }

    #[test]
    fn create_contract_no_participants_rejected() {
        let mut input = test_contract_input();
        input.authorized_participants = BTreeSet::new();
        let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
        assert!(matches!(
            result,
            Err(ContractError::NoAuthorizedParticipants)
        ));
    }

    #[test]
    fn create_contract_invalid_schema_rejected() {
        let mut input = test_contract_input();
        input.feature_schema.version = 0;
        let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
        assert!(matches!(result, Err(ContractError::InvalidVersion { .. })));
    }

    #[test]
    fn create_contract_invalid_dp_budget_rejected() {
        let mut input = test_contract_input();
        input.dp_budget.fail_closed_on_exhaustion = false;
        let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
        assert!(matches!(result, Err(ContractError::InvalidDpBudget { .. })));
    }

    // -------------------------------------------------------------------
    // Signature verification
    // -------------------------------------------------------------------

    #[test]
    fn verify_governance_signature_succeeds() {
        let contract = create_test_contract();
        contract
            .verify_governance_signature(&governance_vk())
            .expect("valid");
    }

    #[test]
    fn verify_governance_signature_wrong_key_fails() {
        let contract = create_test_contract();
        let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
        let wrong_vk = wrong_sk.verification_key();
        let result = contract.verify_governance_signature(&wrong_vk);
        assert!(matches!(
            result,
            Err(ContractError::SignatureInvalid { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Contract registry tests
    // -------------------------------------------------------------------

    #[test]
    fn registry_register_succeeds() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let id = registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        assert_eq!(registry.total_count(), 1);
        assert!(registry.get(&id).is_some());
    }

    #[test]
    fn registry_active_for_zone() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        let active = registry.active_for_zone(TEST_ZONE);
        assert!(active.is_some());
        assert_eq!(active.unwrap().zone, TEST_ZONE);
    }

    #[test]
    fn registry_duplicate_rejected() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        registry
            .register(contract.clone(), &governance_vk(), "t-1")
            .expect("first");
        let result = registry.register(contract, &governance_vk(), "t-2");
        assert!(matches!(
            result,
            Err(ContractError::DuplicateContract { .. })
        ));
    }

    #[test]
    fn registry_epoch_advance_required() {
        let mut registry = ContractRegistry::new();
        let contract1 = create_test_contract();
        registry
            .register(contract1, &governance_vk(), "t-1")
            .expect("first");

        // Same epoch contract should be rejected.
        let mut input = test_contract_input();
        input.feature_schema.version = 2;
        let contract2 =
            PrivacyLearningContract::create_signed(&governance_signing_key(), input).unwrap();
        let result = registry.register(contract2, &governance_vk(), "t-2");
        assert!(matches!(
            result,
            Err(ContractError::EpochNotAdvanced { .. })
        ));
    }

    #[test]
    fn registry_epoch_upgrade_succeeds() {
        let mut registry = ContractRegistry::new();
        let contract1 = create_test_contract();
        registry
            .register(contract1, &governance_vk(), "t-1")
            .expect("first");

        let mut input = test_contract_input();
        input.epoch = SecurityEpoch::from_raw(2);
        let contract2 =
            PrivacyLearningContract::create_signed(&governance_signing_key(), input).unwrap();
        let id2 = registry
            .register(contract2, &governance_vk(), "t-2")
            .expect("upgrade");

        let active = registry.active_for_zone(TEST_ZONE).unwrap();
        assert_eq!(active.contract_id, id2);
        assert_eq!(active.epoch, SecurityEpoch::from_raw(2));
    }

    #[test]
    fn registry_revoke_succeeds() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let id = registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        registry.revoke(&id, "t-revoke").expect("revoke");
        assert_eq!(registry.total_count(), 0);
        assert!(registry.active_for_zone(TEST_ZONE).is_none());
    }

    #[test]
    fn registry_revoke_not_found() {
        let mut registry = ContractRegistry::new();
        let fake_id = EngineObjectId([0xFF; 32]);
        let result = registry.revoke(&fake_id, "t-revoke");
        assert!(matches!(result, Err(ContractError::NotFound { .. })));
    }

    #[test]
    fn registry_wrong_signature_rejected() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
        let wrong_vk = wrong_sk.verification_key();
        let result = registry.register(contract, &wrong_vk, "t-sig");
        assert!(matches!(
            result,
            Err(ContractError::SignatureInvalid { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Audit event tests
    // -------------------------------------------------------------------

    #[test]
    fn events_on_register() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        let events = registry.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            ContractEventType::Registered { .. }
        ));
    }

    #[test]
    fn events_on_revoke() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let id = registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        registry.drain_events();
        registry.revoke(&id, "t-revoke").expect("revoke");
        let events = registry.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            ContractEventType::Revoked { .. }
        ));
    }

    // -------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------

    #[test]
    fn contract_serde_round_trip() {
        let contract = create_test_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let restored: PrivacyLearningContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, restored);
    }

    #[test]
    fn feature_schema_serde_round_trip() {
        let schema = test_feature_schema();
        let json = serde_json::to_string(&schema).expect("serialize");
        let restored: FeatureSchema = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, restored);
    }

    #[test]
    fn dp_budget_serde_round_trip() {
        let budget = test_dp_budget();
        let json = serde_json::to_string(&budget).expect("serialize");
        let restored: DpBudgetSemantics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(budget, restored);
    }

    #[test]
    fn error_serde_round_trip() {
        let errors: Vec<ContractError> = vec![
            ContractError::EmptyFeatureSchema,
            ContractError::InvalidDpBudget {
                detail: "test".to_string(),
            },
            ContractError::NoAuthorizedParticipants,
            ContractError::EpochNotAdvanced {
                zone: "z".to_string(),
                existing_epoch: SecurityEpoch::from_raw(1),
                new_epoch: SecurityEpoch::from_raw(1),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ContractError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -------------------------------------------------------------------
    // Display tests
    // -------------------------------------------------------------------

    #[test]
    fn contract_display() {
        let contract = create_test_contract();
        let display = contract.to_string();
        assert!(display.contains("PrivacyLearningContract"));
        assert!(display.contains(TEST_ZONE));
    }

    #[test]
    fn error_display() {
        let err = ContractError::EmptyFeatureSchema;
        assert_eq!(err.to_string(), "feature schema has no fields");

        let err = ContractError::NoAuthorizedParticipants;
        assert_eq!(err.to_string(), "no authorized participants");
    }

    #[test]
    fn clipping_method_display() {
        assert_eq!(ClippingMethod::L2Norm.to_string(), "l2_norm");
        assert_eq!(ClippingMethod::PerCoordinate.to_string(), "per_coordinate");
        assert_eq!(ClippingMethod::Adaptive.to_string(), "adaptive");
    }

    #[test]
    fn composition_method_display() {
        assert_eq!(CompositionMethod::Basic.to_string(), "basic");
        assert_eq!(CompositionMethod::Renyi.to_string(), "renyi");
        assert_eq!(CompositionMethod::ZeroCdp.to_string(), "zcdp");
    }

    // -------------------------------------------------------------------
    // Authorization tests
    // -------------------------------------------------------------------

    #[test]
    fn contract_is_authorized() {
        let contract = create_test_contract();
        assert!(contract.is_authorized(&EngineObjectId([0xAA; 32])));
        assert!(contract.is_authorized(&EngineObjectId([0xBB; 32])));
        assert!(!contract.is_authorized(&EngineObjectId([0xFF; 32])));
    }

    // -------------------------------------------------------------------
    // Schema determinism
    // -------------------------------------------------------------------

    #[test]
    fn schema_determinism() {
        let s1 = contract_schema();
        let s2 = contract_schema();
        assert_eq!(s1, s2);
    }

    #[test]
    fn schema_id_determinism() {
        let s1 = contract_schema_id();
        let s2 = contract_schema_id();
        assert_eq!(s1, s2);
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn empty_registry_queries() {
        let registry = ContractRegistry::new();
        assert_eq!(registry.total_count(), 0);
        assert_eq!(registry.zone_count(), 0);
        assert!(registry.active_for_zone(TEST_ZONE).is_none());
    }

    #[test]
    fn multi_zone_contracts() {
        let mut registry = ContractRegistry::new();

        let contract1 = create_test_contract();
        registry
            .register(contract1, &governance_vk(), "t-1")
            .expect("zone1");

        let mut input2 = test_contract_input();
        input2.zone = "other-zone";
        let contract2 =
            PrivacyLearningContract::create_signed(&governance_signing_key(), input2).unwrap();
        registry
            .register(contract2, &governance_vk(), "t-2")
            .expect("zone2");

        assert_eq!(registry.total_count(), 2);
        assert_eq!(registry.zone_count(), 2);
        assert!(registry.active_for_zone(TEST_ZONE).is_some());
        assert!(registry.active_for_zone("other-zone").is_some());
        assert!(registry.active_for_zone("nonexistent").is_none());
    }

    #[test]
    fn field_type_display() {
        assert_eq!(FeatureFieldType::FixedPoint.to_string(), "fixed_point");
        assert_eq!(FeatureFieldType::Counter.to_string(), "counter");
        assert_eq!(FeatureFieldType::Boolean.to_string(), "boolean");
        assert_eq!(FeatureFieldType::Categorical.to_string(), "categorical");
    }

    #[test]
    fn coordinator_trust_model_display() {
        assert_eq!(
            CoordinatorTrustModel::HonestButCurious.to_string(),
            "honest_but_curious"
        );
        assert_eq!(CoordinatorTrustModel::Malicious.to_string(), "malicious");
    }

    #[test]
    fn secret_sharing_scheme_display() {
        assert_eq!(SecretSharingScheme::Additive.to_string(), "additive");
        assert_eq!(SecretSharingScheme::Shamir.to_string(), "shamir");
    }
}
