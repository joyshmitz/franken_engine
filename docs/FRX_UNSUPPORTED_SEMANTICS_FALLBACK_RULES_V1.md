# FRX Unsupported Semantics and Deterministic Fallback Rules V1

`FRX-02.3` defines how unsupported or ambiguous hook/effect semantics are
rejected from compile path and routed through deterministic compatibility lanes.

## Scope

- precise compile-path rejection triggers
- deterministic fallback route mapping
- structured diagnostics with stable error codes
- compatibility-preserving execution route guarantees
- incremental hardening guidance for unsupported cases

## Trigger Taxonomy

- `HookTopologyDrift`
- `DependencyShapeDrift`
- `OutOfRenderHookExecution`
- `SchedulerOrderingAmbiguity`
- `UnsupportedHookPrimitive`
- `TransformationProofMissing`

Each trigger has a stable error code (`FE-HOOK-UNSUPPORTED-0001`..`0006`) and
must set `compile_path_rejected=true`.

## Deterministic Fallback Mapping

- `HookTopologyDrift` / `DependencyShapeDrift` / `UnsupportedHookPrimitive`
  -> `CompatibilityRuntimeLane`
- `TransformationProofMissing`
  -> `BaselineInterpreterLane`
- `OutOfRenderHookExecution` / `SchedulerOrderingAmbiguity`
  -> `DeterministicSafeModeLane`

No trigger may resolve to multiple routes for the same input tuple.

## Diagnostic Contract

Diagnostics must include:

- `schema_version`
- `component_name`
- `trigger`
- `fallback_route`
- `compile_path_rejected`
- `reason`
- `hardening_guidance`
- `error_code`
- `trace_id`
- `decision_id`
- `policy_id`

## Replay and Gate Commands

Primary replay wrapper:

```bash
./scripts/e2e/frx_unsupported_semantics_fallback_rules_replay.sh ci
```

Runner modes:

- `check`
- `test`
- `clippy`
- `replay`
- `ci`

All heavy cargo steps are executed through `rch` only.

## Evidence Pack

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

under:

`artifacts/frx_unsupported_semantics_fallback_rules/<UTC_TIMESTAMP>/`

## Operator Verification

1. Run replay wrapper in `ci` mode.
2. Verify `run_manifest.json` reports `outcome=pass`.
3. Verify parser log schema validation passes for emitted `events.jsonl`.
4. Confirm diagnostics include stable error codes and hardening guidance.
