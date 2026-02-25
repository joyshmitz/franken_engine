# FRX Adoption/Release Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.8
Lane id: FRX-10.8
Program constitution reference: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`
Machine-readable contract: `docs/frx_adoption_release_lane_contract_v1.json`

## Charter Scope

This lane is the final authority for pilot rollout strategy, stage-gate
discipline, and claim publication integrity for FRX promotions.

## Decision Rights

The lane has unilateral authority to:

1. Approve or reject pilot rollout scope and cohort progression.
2. Approve or reject alpha, beta, and GA promotions based on stage-gate
   artifacts.
3. Halt promotions when rollback or oncall readiness criteria are not met.
4. Block public claim publication when claim-to-artifact linkage is incomplete.

## Responsibilities

1. Own pilot app portfolio governance and A/B rollout policy.
2. Own alpha, beta, and GA readiness checks with explicit artifact
   prerequisites.
3. Own rollback drills, oncall readiness validation, and operational handoff
   quality.
4. Own claim publication registry quality and reproducibility bundle
   completeness checks.

## Inputs

- Milestone cut-line gate outputs and risk advisories from all lanes.
- Production telemetry, pilot incident reports, and rollout health signals.
- Governance attestations, toolchain compatibility grades, and verification
  confidence reports.

## Outputs

- Release decisions with explicit supporting evidence bundles.
- Rollout plans, canary scopes, and rollback readiness artifacts.
- Oncall readiness attestations with drill timestamps and owner coverage maps.
- Public claim registry entries mapped to reproducibility packs.

## Stage-Gate and Artifact Prerequisites

This lane enforces stage-gate discipline through explicit artifact contracts.

1. Each promotion stage must declare mandatory artifact prerequisites.
2. Stage-gate decisions are invalid without explicit evidence IDs and owner
   sign-off.
3. A/B rollout progression requires threshold definitions and halt conditions.
4. Missing prerequisites force fail-closed promotion outcomes.

## Rollback and Oncall Readiness

1. Rollback drills are mandatory before beta and GA promotion attempts.
2. Oncall readiness requires escalation contacts, coverage windows, and
   recovery runbooks.
3. Release decision bundles must include rollback command surfaces and expected
   recovery SLOs.
4. If rollback drills fail, halt promotion and enforce remediation before
   re-attempt.

## Claim Publication Integrity

1. Public claim publication requires complete reproducibility bundles.
2. Every claim must map to stable evidence IDs and replay commands.
3. Claim registry entries must include stage-gate decision linkage and
   publication timestamp.
4. Claims without reproducibility artifacts are blocked from publication.

## Failure and Promotion Halt Policy

1. If stage gates fail, halt promotion and require remediation artifacts.
2. If rollback readiness checks fail, halt promotion until successful rerun.
3. If claim-to-artifact linkage is incomplete, block publication and emit
   operator diagnostics.
4. Re-promotion is allowed only after deterministic rerun evidence passes.

## Interface Contracts

1. Governance lane provides policy/evidence attestations consumed by release
   decisions.
2. Toolchain lane provides compatibility-grade and rollout-surface health
   signals.
3. Runtime and verification lanes provide incident/risk advisories used for
   stage gating.
4. Adoption/release lane publishes promotion decisions and claim registry
   updates with deterministic evidence linkage.
