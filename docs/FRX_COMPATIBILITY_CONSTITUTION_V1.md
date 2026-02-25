# FRX Compatibility Constitution v1

Status: active
Owner lane: FRX-10.1 (Semantics/Compatibility)
Primary bead: bd-mjh3.1.1
Parent constitution: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`

## Purpose

This constitution defines the non-negotiable, user-visible behavior envelope for the FrankenReact sidecar. Any optimization, lowering, or routing decision that violates this document is invalid and must fall back deterministically.

## Versioning Contract

- Constitution version: `frx.compat.constitution.v1`
- Forbidden regression registry: `docs/frx_forbidden_regressions_v1.json`
- Compile-vs-fallback table: `docs/frx_compile_vs_fallback_v1.json`
- C0 freeze manifest linkage: `docs/FRX_C0_FREEZE_MANIFEST_V1.json`

## Compatibility Invariants (Test-Addressable)

Each invariant is mandatory and must have fixture coverage via a stable `fixture_ref` namespace.

1. `CI-RENDER-001`: Render-equivalent DOM snapshot semantics.
   Fixture ref: `compat.render.*`
2. `CI-HOOK-001`: Hook ordering and cardinality are stable across re-renders.
   Fixture ref: `compat.hooks.order.*`
3. `CI-EFFECT-001`: Effect scheduling and cleanup ordering remain contract-equivalent.
   Fixture ref: `compat.effects.lifecycle.*`
4. `CI-ERROR-001`: Error-boundary capture and recovery semantics are preserved.
   Fixture ref: `compat.errors.boundary.*`
5. `CI-SUSPENSE-001`: Suspense fallback/reveal transition behavior is preserved.
   Fixture ref: `compat.suspense.transitions.*`
6. `CI-HYDRATE-001`: Hydration reconciliation and mismatch handling are deterministic.
   Fixture ref: `compat.hydration.*`
7. `CI-STATE-001`: State update visibility and batching semantics remain equivalent.
   Fixture ref: `compat.state.batching.*`
8. `CI-EVENT-001`: Event dispatch ordering and propagation contracts are preserved.
   Fixture ref: `compat.events.dispatch.*`

## Constitutional Safety Rules

1. If a transform cannot prove preservation of all applicable invariants, it must not execute.
2. If confidence/calibration evidence is below threshold for an adaptive path, demote to deterministic safe mode.
3. Unsupported constructs must not silently degrade behavior. They must take explicit deterministic fallback routes.
4. All fallback decisions must emit evidence records and replay-stable traces.

## Enforcement

- Hard fail on any forbidden regression ID listed in `frx_forbidden_regressions_v1.json`.
- Gate compile path decisions through `frx_compile_vs_fallback_v1.json`.
- Require provenance and policy IDs in evidence ledger events for all fallback and demotion decisions.

## Change Control

A constitution update requires:

1. New version tag.
2. Diff against prior invariant set.
3. Added/updated fixture references.
4. Explicit migration note for downstream gates.
