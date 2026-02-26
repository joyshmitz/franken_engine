# FRX Ecosystem Compatibility Matrix V1

Status: active
Primary bead: bd-mjh3.7.3
Track id: FRX-07.3
Machine-readable contract: `docs/frx_ecosystem_compatibility_matrix_v1.json`

## Scope

FRX-07.3 defines the versioned compatibility matrix for high-impact React
libraries and legacy APIs used by the toolchain/adoption lane. The matrix is
fail-closed for release promotion and must always expose fallback routing plus
roadmap status for known gaps.

## Coverage Dimensions

- State libraries: Redux Toolkit, Zustand, Recoil
- Routing libraries: React Router
- Forms libraries: React Hook Form, Formik
- Data libraries: TanStack Query, Apollo Client
- Legacy API surfaces: class components, portals/refs, context/error boundaries

## High-Impact Stack Coverage

Each matrix entry must include:

1. stable `stack_id` + `surface`
2. `compatibility_status`
3. deterministic `integration_test_id`
4. `evidence_bundle_ref`
5. `fallback_route` and `roadmap_status`

## Legacy API Surface Coverage

Legacy compatibility is explicit and tracked as first-class matrix entries for:

- class lifecycle/update behavior
- portals/ref timing and event retargeting
- context propagation and error-boundary recovery behavior

## Known Gaps and Fallback/Roadmap Status

Known gaps are required to declare all of the following:

1. deterministic fallback route (`compatibility_fallback` or `deterministic_safe_mode`)
2. roadmap status (`investigating`, `targeted_patch`, `planned`, `released`)
3. owning lane + target milestone + blocking bead reference
4. stable `error_code`

## Deterministic Logging and Evidence Contract

All validation and replay runs must emit structured logs with these required
fields:

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

Artifacts are emitted under:

`artifacts/frx_ecosystem_compatibility_matrix/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

## Operator Verification

```bash
./scripts/run_frx_ecosystem_compatibility_matrix_suite.sh ci
./scripts/e2e/frx_ecosystem_compatibility_matrix_replay.sh ci
jq empty docs/frx_ecosystem_compatibility_matrix_v1.json
```
