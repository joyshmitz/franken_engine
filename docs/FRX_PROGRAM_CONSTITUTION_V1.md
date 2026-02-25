# FRX Program Constitution v1

Status: active
Primary bead: bd-mjh3.1
Constitution version: `frx.program.constitution.v1`
Machine-readable objective contract: `docs/frx_objective_function_v1.json`

## Purpose

This constitution defines the global optimization target and non-negotiable
safety envelope for FrankenReact (FRX) workstreams. Downstream lanes may
optimize aggressively, but only inside this boundary.

## Objective Function

Optimize for:

1. Drop-in compatibility for declared React behavior contracts.
2. Deterministic reliability under normal and degraded operation.
3. Measurable speed improvements with auditable evidence.

Subject to hard constraints:

- no constitutional invariant violations
- fail-closed behavior on missing/invalid proofs
- deterministic safe-mode fallback when confidence is insufficient

## Compatibility Scope and Non-Goals

Compatibility scope:

- User-visible semantics defined in `docs/FRX_COMPATIBILITY_CONSTITUTION_V1.md`
- Compiler/runtime behaviors that are explicitly declared as equivalent

Non-goals:

1. Preserving undocumented donor quirks that conflict with deterministic replay.
2. Silent semantic drift in the name of benchmark gains.
3. Unsafe optimization that cannot emit replay-stable evidence linkage.

## Testable Constitutional Invariants

Each invariant is test-addressable and must map to deterministic fixtures and
structured logs.

1. `FRX-CI-001` Compatibility preservation:
   no forbidden regression IDs may appear for promoted changes.
2. `FRX-CI-002` Deterministic replay:
   high-impact decisions must replay with identical outcome and rationale.
3. `FRX-CI-003` Safe-mode guarantee:
   insufficient confidence or invalid policy inputs must demote to deterministic
   safe mode.
4. `FRX-CI-004` Evidence completeness:
   promotion/containment/fallback decisions must emit traceable evidence and
   policy identifiers.
5. `FRX-CI-005` Fail-closed governance:
   missing or stale required artifacts blocks promotion.

## Loss Matrix, Calibration, and Fallback Linkage

Runtime decision surfaces implementing this constitution:

- Loss-matrix and expected-action selection:
  `crates/franken-engine/src/expected_loss_selector.rs`
- Runtime decision policy and deterministic fallback hooks:
  `crates/franken-engine/src/runtime_decision_theory.rs`
- Safe-mode activation and recovery contract:
  `crates/franken-engine/src/safe_mode_fallback.rs`
- Program scorecard and objective metrics:
  `crates/franken-engine/src/northstar_scorecard.rs`

If calibration or loss data is missing/incompatible, execution must fail closed
or demote to deterministic safe mode according to policy.

## Program Metrics (North-Star + Guardrails)

North-star metrics include both speed and reliability dimensions:

1. Compatibility conformance rate (must not regress).
2. Deterministic replay success rate (must remain at policy target).
3. Performance uplift vs baseline lane (tracked with evidence bundles).

Guardrail metrics:

1. Safe-mode fallback frequency and recovery latency.
2. Regression count against forbidden compatibility IDs.
3. Missing/stale evidence artifact incidents.

## Downstream Workstream Contract

All downstream FRX workstreams must reference this constitution and include:

1. constitution version (`frx.program.constitution.v1`)
2. objective contract version (`frx.objective_function.v1`)
3. explicit mapping from lane-local decisions to constitutional invariants

This includes semantics, compiler, runtime, verification, governance, and gate
automation tracks.

## Program-Wide Test Gate

Every child bead must define:

1. comprehensive unit-test scope with edge/adversarial coverage
2. deterministic end-to-end scenarios with replay-ready fixtures
3. structured logs (`trace_id`, `decision_id`, `policy_id`, `component`,
   `event`, `outcome`, `error_code`)

Missing or stale test/logging evidence blocks milestone promotion and release.

## Change Control

A constitution update requires:

1. version bump
2. invariant diff and migration notes
3. updated objective contract and freeze-manifest linkage
4. downstream lane acknowledgement in charter/contract artifacts
