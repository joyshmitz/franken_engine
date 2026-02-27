# FRX Flake Detection, Reproducer, and Quarantine Workflow v1

Status: active  
Primary bead: `bd-mjh3.20.5`  
Track id: `FRX-20.5`  
Machine-readable contract: `docs/frx_flake_quarantine_workflow_v1.json`

## Scope

FRX-20.5 adds a deterministic reliability layer for intermittent test failures.

The workflow is fail-closed and requires:

- deterministic flake classification with stable severity bands,
- deterministic reproducer bundle generation with CI and local replay commands,
- owner-bound quarantines with explicit expiry,
- gate-confidence metrics with trendlines,
- scenario linkage to impacted unit suites and root-cause hypothesis artifacts.

## Deterministic Flake Classification Contract

Flake classes are keyed by `(suite_kind, scenario_id)` and computed from repeated
runs under fixed seeds.

Classification rules:

1. a class is flaky only when both pass and fail outcomes are observed,
2. `flake_rate_millionths = min(pass_count, fail_count) * 1_000_000 / total_runs`,
3. classes below warning threshold are ignored,
4. classes at or above high threshold are marked `high` and trigger immediate quarantine action.

## Deterministic Reproducer Bundle Contract

Every classified flake emits a reproducer bundle containing:

- stable `bundle_id`,
- `replay_command_ci`,
- `replay_command_local`,
- `artifact_bundle_ids`,
- `run_ids`.

The bundle is deterministic for identical inputs and can be re-run in CI and on
local developer machines.

## Quarantine Workflow Contract

High-severity flakes produce quarantine records that are:

- owner-bound (explicit accountable owner),
- time-bounded (expiry epoch required),
- linked to the reproducer bundle id.

Missing owner binding or non-expiring quarantine records are fail-closed
violations.

## Gate Confidence and Trendline Contract

Gate confidence reports must include:

- latest flake burden millionths,
- high-severity flake count,
- per-epoch burden points,
- trend direction (`improving`, `stable`, `degrading`),
- promotion decision (`promote` or `hold`),
- blocker list with deterministic identifiers.

## Scenario-to-Unit and Root-Cause Linkage Contract

Each flaky e2e scenario must include:

- impacted unit suite links,
- root-cause hypothesis artifact links.

These links are required in both classification records and structured events.

## Structured Event Contract

Workflow events use schema `frx.flake-quarantine-workflow.event.v1` and include
stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `suite_kind`
- `scenario_id`
- `replay_command_ci`
- `replay_command_local`

## Operator Verification

```bash
./scripts/run_frx_flake_quarantine_workflow_suite.sh ci
./scripts/e2e/frx_flake_quarantine_workflow_replay.sh ci
jq empty docs/frx_flake_quarantine_workflow_v1.json
```

Expected artifacts:

- `artifacts/frx_flake_quarantine_workflow/<UTC_TIMESTAMP>/run_manifest.json`
- `artifacts/frx_flake_quarantine_workflow/<UTC_TIMESTAMP>/events.jsonl`
- `artifacts/frx_flake_quarantine_workflow/<UTC_TIMESTAMP>/commands.txt`
