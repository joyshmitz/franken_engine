# Tail-Latency and Memory Hardening Regression Gate (`bd-mjh3.6.4`)

This contract defines deterministic tail-latency and memory-tail regression gating
for FRX optimization campaigns, with explicit fail-closed behavior for mean-only
improvements that degrade tail-risk posture.

## Scope

This lane is implemented by:

- `docs/TAIL_LATENCY_MEMORY_HARDENING_REGRESSION_GATE.md`
- `crates/franken-engine/tests/fixtures/tail_latency_memory_hardening_regression_gate_v1.json`
- `crates/franken-engine/tests/tail_latency_memory_hardening_regression_gate.rs`
- `scripts/run_tail_latency_memory_hardening_regression_gate.sh`
- `scripts/e2e/tail_latency_memory_hardening_regression_gate_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.tail-latency-memory-hardening-regression-gate.v1`
- `campaign_version`: `1.0.0`
- `metric_schema_version`: `franken-engine.tail-memory-telemetry.v1`

## Tail Decomposition Ledger Contract

Every campaign run must include a deterministic decomposition ledger with
non-negative terms:

- queueing
- service
- synchronization
- retries
- gc/allocator
- ABI-boundary

The ledger is part of evidence; missing terms are fail-closed.

## Tail-Risk and Memory Objectives

Each campaign must evaluate:

- latency tails: `p95`, `p99`, `p999`
- conditional tail loss: `cvar`
- memory tails: `peak_heap_bytes`, `live_allocations_tail`
- central metrics: `mean_latency`, `throughput`

Gating enforces tail and memory objectives, not averages only.

## Fail-Closed Decision Policy

A campaign outcome is `hold` when any of the following are true:

1. tail/memory budget breach (`p95/p99/p999/cvar/peak_heap/live_allocations_tail`)
2. central metric improvement (`mean_latency` or `throughput`) with any tail/memory regression
3. compatibility invariant violation

`promote` is allowed only when none of the above triggers.

## One-Lever Attribution Discipline

Each campaign run must map changed paths to exactly one lever family:

- queueing
- service
- synchronization
- retries
- gc_allocator
- abi_boundary

Multi-family path changes are rejected by policy.

## EV Scoring Contract

EV formula:

```text
ev_score = (impact * confidence * reuse) / (effort * friction)
```

Integer execution contract:

- represent EV as millionths (`ev_score_millionths`)
- compute as:
  - numerator = `impact * confidence * reuse * 1_000_000`
  - denominator = `effort * friction`
  - result = `numerator / denominator` (integer floor)

## Structured Log Contract

Required keys for emitted events:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Contract

Fixture-driven replay scenarios must include canonical wrapper commands under
`./scripts/e2e/`.

Canonical replay wrapper:

```bash
./scripts/e2e/tail_latency_memory_hardening_regression_gate_replay.sh
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane must run through `rch`.

Canonical gate command:

```bash
./scripts/run_tail_latency_memory_hardening_regression_gate.sh ci
```

Modes:

- `check`: compile focused gate test target
- `test`: execute focused gate tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run emits:

- `artifacts/tail_latency_memory_hardening_regression_gate/<timestamp>/run_manifest.json`
- `artifacts/tail_latency_memory_hardening_regression_gate/<timestamp>/events.jsonl`
- `artifacts/tail_latency_memory_hardening_regression_gate/<timestamp>/commands.txt`

The manifest must include replay command, deterministic run metadata, command
transcript, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_tail_latency_memory_hardening_regression_gate.sh ci
cat artifacts/tail_latency_memory_hardening_regression_gate/<timestamp>/run_manifest.json
cat artifacts/tail_latency_memory_hardening_regression_gate/<timestamp>/events.jsonl
cat artifacts/tail_latency_memory_hardening_regression_gate/<timestamp>/commands.txt
./scripts/e2e/tail_latency_memory_hardening_regression_gate_replay.sh
```
