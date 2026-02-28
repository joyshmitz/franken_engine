# RGC Verification Coverage Matrix V1

Status: active  
Primary bead: `bd-1lsy.11.1`  
Track id: `RGC-051`  
Machine-readable contract: `docs/rgc_verification_coverage_matrix_v1.json`

## Purpose

`RGC-051` defines a canonical verification mapping from open `bd-1lsy*` beads to
unit, integration, and e2e validation rows.

The contract is fail-closed:

- every open RGC bead must match at least one row,
- critical-behavior beads must match `unit` + `integration` + `e2e`,
- every row must declare deterministic seed policy, required log fields, and
  artifact triad paths,
- operator replay commands are first-class contract fields.

## Matrix Model

Each coverage row includes:

- `row_id`
- `bead_selectors`
- `requirement_id`
- `test_kind` (`unit` | `integration` | `e2e`)
- `harness_entrypoint`
- `deterministic_seed_policy`
- `required_log_fields`
- `artifact_paths`
- `gate_owner`
- `pass_fail_interpretation`

Selector semantics are deterministic:

- exact selector: `bd-1lsy.4.1` matches only that bead
- wildcard selector: `bd-1lsy.4.*` matches `bd-1lsy.4` and all descendants

## Coverage Guarantees

The v1 contract guarantees:

- `100%` mapping for the open `bd-1lsy*` snapshot in `scope.open_bead_ids`.
- `unit` + `integration` + `e2e` coverage for all `critical_behavior_bead_ids`.
- required root logging fields:
  - `trace_id`
  - `decision_id`
  - `runtime_lane`
  - `seed`
  - `result`
  - `error_code`
- artifact triad requirements for each row:
  - `run_manifest.json`
  - `events.jsonl`
  - `commands.txt`

## Gate Runner

Use the deterministic gate runner:

```bash
./scripts/run_rgc_verification_coverage_matrix.sh check
./scripts/run_rgc_verification_coverage_matrix.sh ci
```

Replay wrapper:

```bash
./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci
```

## Operator Verification

```bash
jq empty docs/rgc_verification_coverage_matrix_v1.json
./scripts/run_rgc_verification_coverage_matrix.sh check
./scripts/run_rgc_verification_coverage_matrix.sh ci
./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci
```
