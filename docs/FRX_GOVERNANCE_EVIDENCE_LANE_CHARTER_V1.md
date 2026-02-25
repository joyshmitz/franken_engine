# FRX Governance/Evidence Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.7
Lane id: FRX-10.7
Program constitution reference: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`
Machine-readable contract: `docs/frx_governance_evidence_lane_contract_v1.json`

## Charter Scope

This lane is the final authority for policy-as-data integrity,
evidence-ledger correctness, and operator explainability surfaces that govern
FRX promotion and fallback decisions.

## Decision Rights

The lane has unilateral authority to:

1. Approve or reject decision/evidence schema version migrations.
2. Approve or reject policy artifact signing and verification rules.
3. Block promotion when evidence completeness or provenance integrity is
   insufficient.
4. Force conservative deterministic mode when integrity checks fail.

## Responsibilities

1. Own decision/evidence schema governance and migration safety rules.
2. Own policy artifact signing/verification enforcement and key-rotation
   safety constraints.
3. Own explainability surfaces that bind operator guidance to machine-readable
   evidence IDs.
4. Own incident artifact requirements for integrity and policy-verification
   failures.

## Inputs

- Runtime, compiler, and verification event streams plus lane-level block
  advisories.
- Security/adversarial findings and incident artifacts.
- Promotion gate requirements, waiver metadata, and governance policy updates.

## Outputs

- Versioned decision/evidence schemas with migration compatibility
  attestations.
- Signed policy artifacts with verification, expiry, and rollback metadata.
- Queryable evidence ledgers linking actions to `trace_id`, `decision_id`,
  `policy_id`, and `evidence_id`.
- Operator incident triage guidance tied to stable evidence IDs and replay
  commands.

## Policy-as-Data Integrity and Signing

1. Policies are immutable artifacts with explicit schema version and digest.
2. Verification is fail-closed: unsigned, expired, or digest-mismatched policy
   artifacts are rejected.
3. Key rotation requires overlap windows and deterministic rollback posture.
4. Every policy decision must emit a machine-readable evidence ID; free-form
   logs alone are insufficient.

## Evidence Ledger and Explainability Surfaces

1. Evidence ledgers are append-only and queryable by `trace_id`,
   `decision_id`, `policy_id`, and `evidence_id`.
2. Explainability views must reference evidence IDs, decision-path metadata,
   and replay commands.
3. Lane, fallback, and optimization actions require deterministic provenance
   linkage.
4. Missing evidence linkage is treated as policy failure and blocks promotion.

## Failure and Deterministic Safe Mode Policy

1. On integrity or policy-verification failure, disable adaptive behavior.
2. Enforce conservative deterministic mode until remediation evidence is
   accepted.
3. Emit incident artifacts with explicit failure class, trigger evidence ID,
   and recovery command.
4. Promotion remains blocked until fail-closed checks rerun cleanly with
   signed artifacts.

## Interface Contracts

1. Runtime, compiler, and verification lanes emit machine-readable events
   consumed by governance ledger schemas.
2. Toolchain lane consumes governance explainability artifacts for
   operator-facing diagnostics.
3. Adoption/release lane consumes policy conformance reports and integrity
   attestations for cut decisions.
4. Governance lane publishes deterministic block/allow decisions and required
   remediation classes.
