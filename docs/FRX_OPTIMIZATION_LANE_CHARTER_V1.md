# FRX Optimization/Performance Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.5
Lane id: FRX-10.5
Program constitution reference: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`
Machine-readable contract: `docs/frx_optimization_lane_contract_v1.json`

## Charter Scope

This lane owns profile-driven performance improvement under strict
behavior-isomorphism guarantees.

## Decision Rights

The lane has unilateral authority to:

1. Approve or reject optimization campaigns based on profile evidence and risk
   posture.
2. Approve or reject one-lever changes entering promotion windows.
3. Block optimization merges when isomorphism proof obligations are missing.
4. Trigger rollback to baseline paths when regression gate limits are exceeded.

## Responsibilities

1. Own baseline/profile/opportunity-matrix machinery across compiler and
   runtime paths.
2. Enforce one-lever optimization discipline and rollback preparedness.
3. Own tail-latency, memory-footprint, and responsiveness regression gate
   policy.
4. Publish deterministic before/after evidence bundles and risk advisories.

## Inputs

- Hotspot evidence (top-5 CPU, allocation, and tail contributors).
- Verification lane non-regression contracts and golden outputs.
- Runtime telemetry snapshots and release gate budget policies.

## Outputs

- Ranked optimization campaigns with EV/relevance/risk scoring.
- Isomorphism proof notes and before/after artifact bundles.
- Performance risk advisories consumed by release gates.

## Profile-First Evidence Discipline

Every optimization decision must include:

- baseline profile snapshot
- candidate profile snapshot
- opportunity matrix row with expected value and confidence
- explicit bottleneck attribution

Profile-free optimizations are rejected by policy.

## One-Lever and Isomorphism Proof Discipline

1. One optimization lever per merge candidate.
2. Each candidate must include an isomorphism proof note tied to verification
   lane contracts.
3. Any behavior drift without approved waiver is a hard rejection.

## Regression and Rollback Gates

Optimization candidates must pass all of:

- tail-latency budget gate
- memory-footprint gate
- responsiveness gate
- deterministic rollback readiness check

If any gate fails, the candidate is blocked and a rollback plan is required.

## Failure and Fallback Policy

1. Any unproven optimization is blocked from merge and promotion.
2. Failed gate checks route execution to conservative baseline path.
3. Regression incidents require deterministic rollback artifact publication
   before reconsideration.

## Interface Contracts

1. Verification lane supplies golden outputs and non-regression obligations.
2. Runtime lane supplies hotspot telemetry and responsiveness traces.
3. Compiler lane supplies pass-level performance witness metadata.
4. Governance/release lanes consume risk advisories, gate outcomes, and
   rollback readiness evidence.
