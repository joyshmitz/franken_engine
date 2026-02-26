# FRX End-to-End Scenario Matrix V1

Status: active
Primary bead: bd-mjh3.20.3
Track id: FRX-20.3
Machine-readable contract: `docs/frx_end_to_end_scenario_matrix_v1.json`

## Scope

FRX-20.3 defines deterministic end-to-end scenario coverage for core user
journeys and degraded/adversarial operating modes.

The gate is fail-closed: missing baseline linkage, missing chaos profile,
missing unit anchors, or missing invariant references blocks promotion.

## Scenario Classes and Coverage

The matrix must include at minimum:

- baseline user journeys (`render`, `update`, `hydration`, `navigation`, `error_recovery`)
- differential checks against declared baseline scenarios
- chaos lanes for deterministic latency spikes, partial failures, policy demotion,
  and failover exercises

Each scenario must declare:

- stable `scenario_id`
- scenario class
- deterministic seed
- decision path
- expected outcome
- companion unit-test anchors
- invariant references

## Differential Lane Contract

Differential lanes compare observed behavior to a declared baseline contract:

1. every differential scenario references a valid baseline scenario id,
2. behavior drift thresholds are versioned and machine-readable,
3. unexplained drift fails closed.

## Chaos Lane Contract

Chaos lanes are deterministic and replayable:

1. each chaos scenario references an explicit chaos profile,
2. chaos profiles pin deterministic fault injectors and seed offsets,
3. expected policy actions are declared (`challenge`, `sandbox`, `demote`, `fallback`) and audited.

## Unit-Anchor and Invariant Linkage Contract

Every scenario must declare at least one companion unit-test anchor and one
invariant reference.

Anchors and invariants are required for:

- scenario triage routing,
- deterministic root-cause replay,
- fail-closed promotion evidence.

## Structured Logging and Correlation Contract

Scenario execution and gate results must emit structured logs containing:

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

Correlation ids (`trace_id`, `decision_id`, `policy_id`) are mandatory for
deterministic replay and artifact linkage.

## Promotion Gate Evidence Contract

Promotion consumers must require FRX-20.3 evidence artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `scenario_matrix_summary.json`
- `scenario_matrix_summary.md`

Artifacts are emitted under:

`artifacts/frx_end_to_end_scenario_matrix/<UTC_TIMESTAMP>/`

## Operator Verification

```bash
./scripts/run_frx_end_to_end_scenario_matrix_suite.sh ci
./scripts/e2e/frx_end_to_end_scenario_matrix_replay.sh ci
jq empty docs/frx_end_to_end_scenario_matrix_v1.json
```
