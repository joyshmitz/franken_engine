# FRX Toolchain/Ecosystem Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.6
Lane id: FRX-10.6
Machine-readable contract: `docs/frx_toolchain_lane_contract_v1.json`
Program constitution reference: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`

## Charter Scope

This lane is the final authority for real-world integration stability,
compatibility ergonomics, and migration safety for sidecar adoption.

## Decision Rights

The lane has unilateral authority to:

1. Approve or reject supported integration profiles and confidence grades.
2. Publish compatibility-class diagnostics and remediation guidance.
3. Approve or reject rollout-control defaults for incremental adoption.
4. Force conservative compatibility mode when integration instability is
   detected.

## Responsibilities

1. Own build-tool adapters plus source-map and diagnostics fidelity
   expectations.
2. Own ecosystem compatibility matrix updates and incremental-adoption controls.
3. Own migration UX guardrails for teams rolling out sidecar mode gradually.
4. Emit deterministic fallback policy and actionable diagnostics when
   instability appears.

## Inputs

- Compiler/runtime artifact contracts and fallback policy surfaces.
- Pilot feedback and ecosystem breakage telemetry.
- Verification-lane risk advisories and promotion gate requirements.

## Outputs

- Supported integration profiles with confidence grades.
- Migration diagnostics and remediation guidance tied to compatibility classes.
- Rollout toggles (`file`, `component`, `route`, `policy`) with safe defaults.
- Conservative compatibility mode advisories with evidence linkage.

## Supported Integration Profiles

Every profile must declare:

- integration class (bundler, framework, router, test harness)
- confidence grade (`green`, `yellow`, `red`)
- known compatibility classes and remediation pointers
- fallback posture when stability degrades

## Migration and Rollout Controls

1. Rollout controls must be explicit and deterministic.
2. Controls must support staged progression: file -> component -> route ->
   policy.
3. Default posture is fail-safe (conservative compatibility mode enabled for
   unstable classes).
4. Rollout decisions must be consumable by release gates and evidence ledgers.

## Failure and Fallback Policy

1. On integration instability, auto-route to conservative compatibility mode.
2. Emit actionable diagnostics with compatibility class + remediation id.
3. If instability persists above policy thresholds, block promotion and require
   remediation beads.
4. All fallback routing decisions require deterministic trace/evidence linkage.

## Interface Contracts

1. Compiler lane provides artifact/schema compatibility signals.
2. Runtime lane consumes rollout controls and compatibility-mode directives.
3. Verification lane consumes integration-failure traces and confidence deltas.
4. Governance/release lanes consume confidence-grade transitions and promotion
   block recommendations.
