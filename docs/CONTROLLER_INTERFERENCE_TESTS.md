# Controller Interference Tests (`bd-2py0`)

Deterministic multi-controller interference validation for Section 10.13 item 14.

## Scope

This suite validates shared-metric behavior when multiple controllers read/write the
same metrics with explicit timescale-separation statements.

## Required Controller Registration Fields

Each controller registration must include:

- `controller_id`
- `read_metrics`
- `write_metrics`
- `timescale.observation_interval_millionths`
- `timescale.write_interval_millionths`
- `timescale.statement`

Missing or invalid timescale declarations fail closed.

## Interference Behaviors Covered

- concurrent reads on shared metrics return consistent snapshots
- concurrent writes on shared metrics either:
  - are rejected (`conflict_resolution_mode=reject`), or
  - are deterministically serialized (`conflict_resolution_mode=serialize`)
- read-while-write preserves snapshot isolation
- subscriber update streams remain isolated and deterministic
- long-duration soak checks (10,000 iterations) detect drift/corruption

## Structured Log Fields

Interference guard emits stable fields for every event:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Core events:

- `read_snapshot`
- `timescale_conflict`
- `write_conflict_serialized`
- `interference_summary`

## Suite Runner

```bash
./scripts/run_controller_interference_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci`

Runner uses `rch` when available and falls back to local cargo execution where
`rch` is unavailable (for example, hosted CI runners).

## Reproducibility Artifacts

Each run writes:

- `artifacts/controller_interference/<timestamp>/commands.txt`
- `artifacts/controller_interference/<timestamp>/events.jsonl`
- `artifacts/controller_interference/<timestamp>/run_manifest.json`

`run_manifest.json` includes operator verification commands.
