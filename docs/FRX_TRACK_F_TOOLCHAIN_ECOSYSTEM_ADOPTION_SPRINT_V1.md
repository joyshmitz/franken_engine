# FRX Track F Toolchain/Ecosystem/Adoption Sprint Charter v1

Status: active
Primary bead: bd-mjh3.7.1
Track id: FRX-07.1
Machine-readable contract: `docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json`

## Charter Scope

Track F validates practical adoption outcomes while Track B (compiler/FRIR)
and Track C (runtime lane) mature. It owns integration readiness signals for
bundlers, source maps, ecosystem compatibility, and rollout safety.

## Decision Rights

This track can:

1. Approve or reject bundler adapter readiness and source-map fidelity grades.
2. Publish compatibility regression classes and migration diagnostics.
3. Approve or reject pilot/canary progression to broader rollout.
4. Force fallback routing and block promotion when adoption risk exceeds policy.

## Responsibilities

1. Maintain bundler adapters with deterministic source-map fidelity checks.
2. Maintain ecosystem compatibility matrix expansion and regression triage.
3. Maintain migration diagnostics with remediation identifiers.
4. Maintain pilot and canary evidence bundles for cut-line review.
5. Maintain fallback routing advisories for unstable integration classes.

## Inputs

- Track B compiler/FRIR outputs and compatibility contracts.
- Track C runtime lane outputs and failover/fallback signals.
- Lane charter authority from `FRX-10.6` toolchain ownership surfaces.
- Verification and governance lane evidence policy requirements.

## Outputs

- Integration readiness dashboard (bundlers, frameworks, routing/tooling cases).
- Source-map fidelity and diagnostics integrity evidence.
- Ecosystem compatibility regression classification and remediation routing.
- Pilot/canary rollout evidence bundle for release decisioning.
- Promotion-block recommendations with deterministic fallback guidance.

## Bundler and Source-Map Fidelity Contract

1. Bundler adapters must emit deterministic integration profile identifiers.
2. Source-map fidelity checks must report stable error classes and repro hints.
3. Adapter regressions are fail-closed for promotion decisions.
4. Missing source-map evidence blocks promotion by policy.

## Ecosystem Compatibility and Migration Diagnostics Contract

1. Compatibility matrix updates must be machine-readable and versioned.
2. Every compatibility regression must map to a remediation identifier.
3. Migration diagnostics must include compatibility class and fallback route.
4. Untriaged compatibility regressions block rollout progression.

## Pilot/Canary Evidence Contract

1. Pilot/canary runs emit deterministic trace linkage (`trace_id`, `decision_id`,
   `policy_id`).
2. Rollout evidence bundles include scenario outcomes and fallback reasons.
3. Canary regressions automatically open remediation routing paths.
4. Promotion cannot proceed without pilot/canary evidence coverage.

## Fallback Routing and Promotion-Block Policy

1. Default policy mode is fail-closed with conservative fallback routing.
2. Repeated incompatibility in the same class escalates to promotion block.
3. Promotion blocks require explicit remediation + replay evidence to clear.
4. Track F recommendations are consumable by FRX cut-line gates.

## Interface Contracts

1. Track C supplies runtime lane replay and failover artifacts consumed by Track F.
2. Track F supplies compatibility and rollout evidence consumed by Track 12 cut lines.
3. Governance and verification lanes consume Track F classification outputs.
4. Adoption/release workflows consume Track F fallback and promotion-block signals.
