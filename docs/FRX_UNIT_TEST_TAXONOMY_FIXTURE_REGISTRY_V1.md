# FRX Unit-Test Taxonomy and Fixture Registry v1

This document defines the FRX-20.1 contract for deterministic unit-test
classification, fixture ownership, and replay-safe debugging artifacts.

## Scope

- Bead: `bd-mjh3.20.1`
- Machine-readable contract:
  - `docs/frx_unit_test_taxonomy_fixture_registry_v1.json`
- Runtime validation module:
  - `crates/franken-engine/src/unit_test_taxonomy.rs`
- Focused gate tests:
  - `crates/franken-engine/tests/frx_unit_test_taxonomy.rs`
- Hermetic gate runner:
  - `scripts/run_frx_unit_test_taxonomy_fixture_registry_gate.sh`

## Unit-Test Taxonomy

Canonical classes:

1. `core`
2. `edge`
3. `adversarial`
4. `regression`
5. `fault_injection`

Each lane declares required classes and must not ship without class-complete
coverage.

## Fixture Registry Contract

Every fixture registry entry must include:

1. `fixture_id` (unique, deterministic)
2. `fixture_path`
3. optional `trace_path`
4. `provenance`
5. `owner_lane`
6. non-empty `required_classes`
7. `e2e_family`
8. deterministic `seed_strategy`
9. full structured log field requirements
10. `artifact_retention` policy

Registry and taxonomy versions are fail-closed gate inputs.

## Determinism Contract

Deterministic execution requirements:

1. schema version `frx.test-determinism-contract.v1`
2. explicit seed and seed transcript checksum requirements
3. fixed environment controls: `TZ=UTC`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`
4. toolchain fingerprint requirement
5. replay command requirement in artifacts

## Lane Ownership and Coverage Mapping

Lane ownership map is explicit and versioned for:

- compiler
- js runtime
- wasm runtime
- hybrid router
- verification
- toolchain
- governance evidence
- adoption/release

Each lane maps unit classes to e2e scenario families with a coverage rationale.

## Structured Logging and Artifact Retention

Required structured log fields for every fixture-driven unit/e2e run:

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

Artifact retention hooks must include manifest/events/commands and fixture
lineage references for deterministic debugging.

## Operator Verification

```bash
./scripts/run_frx_unit_test_taxonomy_fixture_registry_gate.sh ci
./scripts/e2e/frx_unit_test_taxonomy_fixture_registry_replay.sh test
cat artifacts/frx_unit_test_taxonomy_fixture_registry/<timestamp>/run_manifest.json
cat artifacts/frx_unit_test_taxonomy_fixture_registry/<timestamp>/events.jsonl
cat artifacts/frx_unit_test_taxonomy_fixture_registry/<timestamp>/commands.txt
```

Gate runs are invalid when taxonomy/registry schema drifts, lane coverage is
incomplete, or required structured log fields are missing.
