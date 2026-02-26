# FRX SSR/Hydration/RSC Compatibility Strategy V1

Status: active
Primary bead: bd-mjh3.7.2
Track id: FRX-07.2
Machine-readable contract: `docs/frx_ssr_hydration_rsc_compatibility_strategy_v1.json`

## Scope

FRX-07.2 defines deterministic compatibility strategy for server rendering,
hydration boundary equivalence, and React Server Component (RSC) interaction
handling.

This lane is fail-closed: when lane guarantees cannot be upheld, routing must go
to deterministic fallback surfaces rather than best-effort behavior.

## SSR Render Contract

SSR strategy requires deterministic rendering and handoff semantics:

1. stream chunk ordering is deterministic and replay-stable,
2. suspense streaming handoff into hydration preserves boundary semantics,
3. server-side output always emits operator-visible decision paths.

## Hydration Boundary Equivalence Rules

Hydration compatibility must enforce server/client boundary checks and
predictable recovery behavior:

1. markup mismatch detection is explicit and structured,
2. deterministic recovery route (`recover_client_render`) is required,
3. boundary decisions are replayable with stable seed/trace metadata.

## RSC Interaction Routing and Fallback Policy

RSC interactions must be handled explicitly:

1. supported RSC interactions continue under native strategy,
2. unsupported or unsafe server-component interactions fail closed,
3. deterministic safe-mode fallback is mandatory for unsupported RSC boundary
   behavior.

## Known Divergences and Mitigation Plan

Known divergence classes are tracked in the JSON contract and must include:

1. deterministic fallback route,
2. mitigation plan and owning lane,
3. stable error code and blocking issue linkage.

## Deterministic Logging and Evidence Contract

Every gate/replay run must emit structured logs with stable fields:

- `schema_version`
- `scenario_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `decision_path`
- `seed`
- `timing_us`
- `outcome`
- `error_code`

Artifacts are written under:

`artifacts/frx_ssr_hydration_rsc_compatibility_strategy/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

## Operator Verification

```bash
./scripts/run_frx_ssr_hydration_rsc_compatibility_strategy_suite.sh ci
./scripts/e2e/frx_ssr_hydration_rsc_compatibility_strategy_replay.sh ci
jq empty docs/frx_ssr_hydration_rsc_compatibility_strategy_v1.json
```
