# FRX Hook/Effect Semantics Contract V1

`FRX-02.2` defines a machine-readable hook/effect contract for deterministic runtime behavior.

## Scope

- Hook slot indexing and ordering invariants.
- Effect timing semantics (`insertion`, `layout`, `passive`).
- Typestate-safe render lifecycle transitions.
- Legal transformation set and transformation receipt evidence.
- Deterministic structured scenario logs for replay and failure triage.

## Contracted Invariants

1. Hook indices are consecutive and stable across renders.
2. Hook kinds are stable by slot across renders.
3. Dependency-array semantics are explicit and validated.
4. Render phase transitions are fail-closed and typestate-constrained.
5. Effect scheduler drains in deterministic global order:
   - `insertion` cleanups then creates
   - `layout` cleanups then creates
   - `passive` cleanups then creates

## Structured Scenario Log Schema

Integration scenarios emit deterministic JSON events with:

- `schema_version`
- `scenario_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `seed`
- `timing`
- `decision_path`
- `outcome`
- `error_code`
- `replay_command`

## Deterministic Replay

Primary replay entrypoint:

```bash
./scripts/e2e/frx_hook_effect_semantics_contract_replay.sh ci
```

Supported modes:

- `check`
- `test`
- `clippy`
- `replay`
- `ci`

All heavy cargo operations in the gate runner are executed through `rch`.

## Evidence Pack

Every run publishes:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

Under:

`artifacts/frx_hook_effect_semantics_contract/<UTC_TIMESTAMP>/`

## Operator Verification

1. Run replay command in `ci` mode.
2. Inspect emitted manifest/events/commands artifacts.
3. Confirm manifest `outcome=pass` and `gate_completed` event.
