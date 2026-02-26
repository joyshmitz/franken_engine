# FRX Local Semantic Atlas v1

Status: active
Primary bead: bd-mjh3.14.1
Track id: FRX-14.1
Machine-readable contract: `docs/frx_local_semantic_atlas_v1.json`

## Scope

FRX-14.1 defines a deterministic local semantic atlas for component, hook, and
effect contracts. The atlas is the local source of truth consumed by global
coherence (`FRX-14.2`) and obstruction checks.

## Local Atlas Entry Contract

Each local entry must contain:

1. Component identity and module ownership.
2. Hook signature in stable slot order.
3. Effect signature with capability requirements and deterministic metadata.
4. Context requirements and explicit local assumptions.
5. Canonical hash for replay and diff-safe promotion checks.

## Fixture and Trace Linkage

Each local contract entry must link directly to compatibility fixtures and
deterministic observable traces:

- `fixture_refs`: compatibility fixture IDs proving expected local behavior.
- `trace_refs`: trace IDs for deterministic replay and triage.

Missing fixture/trace linkage is not advisory; it is blocking quality debt.

## Blocking Quality Debt Policy

FRX-14.1 fails closed on local semantic contract gaps. Blocking debt includes:

1. Missing compatibility fixture linkage.
2. Missing deterministic trace linkage.
3. Missing context assumptions for consumed contexts.
4. Empty local hook/effect contract surfaces.

All debt records must include stable debt codes and component ownership.

## Deterministic Replay

Primary replay entrypoint:

```bash
./scripts/e2e/frx_local_semantic_atlas_replay.sh ci
```

Supported modes:

- `check`
- `test`
- `clippy`
- `ci`

All heavy cargo work in the gate runner is executed via `rch`.

## Evidence Pack

Every run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

Under:

`artifacts/frx_local_semantic_atlas/<UTC_TIMESTAMP>/`

## Operator Verification

1. Run the replay command in `ci` mode.
2. Inspect manifest/events/commands artifacts.
3. Confirm `outcome=pass` and `gate_completed` event.
4. Confirm zero blocking quality debt for promoted entries.
