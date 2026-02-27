# FRX FrankenBrowser Integration Blueprint V1

Status: active
Primary bead: bd-mjh3.9.3
Track id: FRX-09.3
Machine-readable contract: `docs/frx_frankenbrowser_integration_blueprint_v1.json`

## Scope

FRX-09.3 defines a phased blueprint for integrating FrankenReact sidecar execution
surfaces into FrankenBrowser while preserving deterministic replay, explicit
policy boundaries, and fail-closed fallback behavior.

This lane does not permit implicit privilege expansion. Every integration bridge
must declare:

1. host-side boundary ownership,
2. sidecar execution boundary ownership,
3. deterministic fallback route when policy or scheduler contracts are violated.

## Embedding Boundaries

Embedding boundaries must make sidecar interactions auditable and constrained:

1. browser host <-> sidecar runtime bridge is capability-gated,
2. scheduler bridge is explicit and replay-stable,
3. policy enforcement bridge denies unsafe capabilities and routes to safe mode.

## Scheduler and Runtime Interaction Contract

Scheduler integration must remain deterministic:

1. host and sidecar schedulers coordinate through deterministic turn-based
   arbitration,
2. queue ordering is replay-stable,
3. preemption and handoff receipts are explicit and structured.

## Security and Policy Boundaries

Security boundaries must be explicit and fail closed:

1. deny-by-default policy for undeclared cross-boundary operations,
2. explicit fallback route for policy denials,
3. mandatory evidence linkage for boundary decisions.

## Migration Path (Optional Sidecar -> First-Class Browser Subsystem)

Migration phases must be concrete and reversible:

1. `P0_optional_sidecar` establishes optional sidecar embedding,
2. `P1_shadow_mode` adds observe-only shadow integration with mismatch telemetry,
3. `P2_guarded_active` enables policy-guarded active routing,
4. `P3_first_class_subsystem` promotes to first-class subsystem only after gate
   evidence completeness.

Each phase includes entry criteria, exit criteria, promotion blockers, and
deterministic rollback actions.

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

`artifacts/frx_frankenbrowser_integration_blueprint/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

## Dependencies and Prerequisites

Blueprint promotion references these prerequisite beads:

- `bd-mjh3.7.2` (SSR/Hydration/RSC compatibility baseline),
- `bd-mjh3.9.2` (release gatebook/publication workflow integration).

## Operator Verification

```bash
./scripts/run_frx_frankenbrowser_integration_blueprint_suite.sh ci
./scripts/e2e/frx_frankenbrowser_integration_blueprint_replay.sh ci
jq empty docs/frx_frankenbrowser_integration_blueprint_v1.json
```
