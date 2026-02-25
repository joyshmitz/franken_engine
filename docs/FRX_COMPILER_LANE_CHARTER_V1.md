# FRX Compiler/FRIR Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.2
Lane id: FRX-10.2
Machine-readable contract: `docs/frx_compiler_lane_contract_v1.json`

## Charter Scope

This lane is the final authority for source-to-FRIR semantics preservation and
pass-level artifact integrity in the FrankenReact sidecar pipeline.

## Decision Rights

The lane has unilateral authority to:

1. Approve or reject parser normalization and backend parity changes that
   affect FRIR production.
2. Approve or reject FRIR schema version changes and compatibility posture.
3. Block compile promotion when required pass witnesses are missing, stale, or
   invalid.
4. Force deterministic fallback lowering mode when compile-time proof
   obligations cannot be satisfied.

## Responsibilities

1. Own parser normalization boundaries and SWC/OXC parity obligations.
2. Own analysis graph correctness invariants and FRIR schema evolution policy.
3. Own transformation witness generation, including hash linkage and budget
   compliance metadata.
4. Publish deterministic diagnostics contracts consumed by toolchain and
   runtime lanes.

## Inputs

- Semantics lane contracts, compatibility constitution, and capability
  boundaries.
- Optimization lane policy budgets and rewrite safety gates.
- Cross-track handoff packets and verification lane obligations for active
  promotion windows.

## Outputs

- Deterministic FRIR artifacts for JS and WASM runtime lanes.
- Pass witness bundles with replay-compatible linkage metadata.
- Compiler diagnostics envelopes with stable, machine-checkable fields.

## FRIR Schema Governance

1. FRIR artifacts must declare a schema version and compatibility mode.
2. Additive schema change is allowed only with deterministic downgrade/upgrade
   notes.
3. Breaking schema change requires explicit fail-closed promotion behavior.
4. Runtime and toolchain consumers must be able to reject incompatible artifacts
   deterministically.

## Pass Witness Obligations

Every compile pass must emit a witness entry containing:

- pass identifier
- input artifact hash
- output artifact hash
- invariant checks run and outcomes
- budget consumption summary
- replay linkage metadata

Missing or malformed witness metadata blocks activation.

## Failure and Fallback Policy

1. Any failed witness validation or schema incompatibility is fail-closed.
2. Fail-closed outcome must produce deterministic diagnostics and evidence
   linkage.
3. If configured fallback lowering is available, the lane may emit a
   deterministic fallback artifact set.
4. If fallback lowering cannot satisfy constitutional invariants, compilation is
   rejected with no promotion.

## Interface Contracts

1. Runtime lane consumes FRIR schema/version and pass witness bundles.
2. Toolchain lane consumes compiler diagnostics contract and witness metadata.
3. Verification lane consumes witness hashes, invariant outcomes, and replay
   linkages.
4. Governance lane consumes compile/fallback decisions plus rationale events.

