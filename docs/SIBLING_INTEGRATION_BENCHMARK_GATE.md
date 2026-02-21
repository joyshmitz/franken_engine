# Sibling Integration Benchmark Gate (`bd-1coe`)

Deterministic release gate for Section 10.14 item 13:

- verify sibling integrations do not regress control-plane p95/p99 SLOs
- enforce bounded integration overhead vs no-integration control runs
- keep control-plane integration costs isolated from VM hot-path concerns

## Covered Integrations

- `frankentui`
- `frankensqlite`
- `sqlmodel_rust`
- `fastapi_rust`

All four integrations must be present in both baseline and candidate snapshots.

## Covered Control-Plane Operations

- `evidence_write`
- `policy_query`
- `telemetry_ingestion`
- `tui_data_update`

Each operation requires benchmark samples from:

- `without_integrations_ns` (control run)
- `with_integrations_ns` (integrated run)

## Thresholds (Default)

| Operation | p95 max | p99 max | Max regression vs baseline | Max integration overhead |
| --- | ---: | ---: | ---: | ---: |
| `evidence_write` | 5 ms | 10 ms | 15% | 20% |
| `policy_query` | 3 ms | 6 ms | 15% | 20% |
| `telemetry_ingestion` | 4 ms | 8 ms | 15% | 20% |
| `tui_data_update` | 7 ms | 12 ms | 15% | 20% |

## Gate Decision Rules

Candidate passes only if all checks pass:

1. Required integrations are present in baseline and candidate.
2. Every covered operation has non-empty baseline/candidate samples.
3. Candidate `with_integrations` p95/p99 are within operation SLO.
4. Candidate regression ratio vs baseline p95/p99 stays within threshold.
5. Candidate integration overhead (`with` vs `without`) stays within threshold.

Failing decisions set `rollback_required=true`.

## Failure Codes

- `missing_required_integration`
- `missing_operation_samples`
- `empty_samples`
- `slo_threshold_exceeded`
- `regression_threshold_exceeded`
- `integration_overhead_exceeded`

## Structured Log Fields

Each decision emits structured log events with stable fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `operation` (for per-operation checks)

## Baseline Tracking

`BaselineLedger` tracks snapshots over monotonically increasing epochs:

- rejects non-monotonic epochs
- rejects duplicate snapshot hashes
- exposes `latest()` for next-gate comparison

## RCH-Only Operator Commands

```bash
./scripts/run_sibling_integration_benchmark_gate_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci`

`ci` runs the deterministic gate-critical checks (`check` + integration test).
`clippy` is available as an explicit mode.

All heavy Rust commands are run via `rch exec`.

## Reproducibility Artifacts

Each script run writes:

- `artifacts/sibling_integration_benchmark_gate/<timestamp>/commands.txt`
- `artifacts/sibling_integration_benchmark_gate/<timestamp>/run_manifest.json`

Operator verification steps are embedded in `run_manifest.json`.
