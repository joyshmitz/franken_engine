# FRX Unit-Test Taxonomy and Fixture Registry V1

`FRX-20.1` defines a unified unit-test taxonomy, deterministic fixture registry contract, and lane ownership map for FrankenEngine.

## Scope

- Canonical unit-test classes across compiler/runtime/router/governance/parser/scheduler/evidence/security surfaces.
- Versioned fixture registry schema with provenance, seed, and integrity requirements.
- Determinism contract covering seed/time/environment controls and replay obligations.
- Lane ownership map linking test surfaces to charter beads.
- Explicit mapping from unit-test classes to end-to-end scenario families with coverage rationale.

## Unit-Test Taxonomy

Canonical classes:

1. `core`
2. `edge`
3. `adversarial`
4. `regression`
5. `fault_injection`

Each class is bound to deterministic fixture constraints in `crates/franken-engine/src/test_taxonomy.rs`.

## Fixture Registry Schema

Registry schema version: `0.1.0`

Required fixture fields:

- `fixture_id`
- `description`
- `test_class`
- `surfaces`
- `provenance`
- `seed`
- `content_hash`
- `format_version`
- `origin_ref`
- `tags`

Provenance levels:

- `authored`
- `generated`
- `captured`
- `synthesized`

## Determinism and Replay Contract

Determinism contract requirements include:

- class-bound seed policy (`adversarial` and `fault_injection` require explicit seeds)
- virtual-clock and deterministic-RNG requirements for high-risk classes
- fixed environment controls (`timezone`, `locale`, `toolchain`, `seed transcript`, `env fingerprint`)
- replay command obligations for CI and operator reruns

Primary replay entrypoint:

```bash
./scripts/e2e/frx_unit_test_taxonomy_contract_replay.sh ci
```

## Lane Ownership Map

Each test surface is bound to a lane charter owner:

- `compiler` -> `bd-mjh3.10.2`
- `runtime` -> `bd-mjh3.10.3`
- `router` -> `bd-mjh3.10.3`
- `governance` -> `bd-mjh3.10.7`
- `parser` -> `bd-mjh3.10.3`
- `scheduler` -> `bd-mjh3.10.3`
- `evidence` -> `bd-mjh3.10.7`
- `security` -> `bd-mjh3.10.4`

All ownership entries require the full class set (`core`, `edge`, `adversarial`, `regression`, `fault_injection`).

## Unit-to-E2E Coverage Mapping

`FRX-20.1` explicitly maps each unit-test class to e2e scenario families:

- `core` -> normal behavior and deterministic baseline replay
- `edge` -> boundary conditions and parser/runtime edge transitions
- `adversarial` -> malformed input and exploit-pattern containment drills
- `regression` -> pinned regressions and compatibility backstop scenarios
- `fault_injection` -> timeout/cancellation/resource-failure/rollback recovery flows

Each mapping carries explicit coverage rationale in `docs/frx_unit_test_taxonomy_v1.json`.

## Logging and Artifact Retention Hooks

Required structured logging fields:

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

Required artifact retention hooks:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- fixture registry snapshot linkage
- determinism contract snapshot linkage

## CI Gate and Failure Policy

Gate runner:

```bash
./scripts/run_frx_unit_test_taxonomy_contract_suite.sh ci
```

Failure policy:

- mode: `fail_closed`
- error code: `FE-FRX-20-1-TAXONOMY-0001`
- block on schema drift, missing ownership map coverage, missing unit-to-e2e mapping, or logging/artifact contract gaps

All heavy Cargo operations are executed via `rch` in the gate runner.

## Operator Verification

1. Run replay command in `ci` mode.
2. Inspect emitted `run_manifest.json`, `events.jsonl`, and `commands.txt`.
3. Confirm `outcome=pass` and `gate_completed` event with `error_code=null`.
