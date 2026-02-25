# Parser Benchmark Protocol (`bd-2mds.1.6.1`)

This document defines the canonical parser benchmark protocol and corpus tiers
for parser-frontier performance claims.

## Scope

Protocol artifacts are owned by:

- `docs/PARSER_BENCHMARK_PROTOCOL.md`
- `crates/franken-engine/tests/fixtures/parser_benchmark_protocol_v1.json`
- `crates/franken-engine/tests/parser_benchmark_protocol.rs`
- `scripts/run_parser_benchmark_protocol.sh`

This protocol is binding for parser-frontier benchmark publication and for
downstream parser performance beads (`PSRP-06.*`, `PSRP-07.*`, `PSRP-08.*`).

## Contract Version

- `schema_version`: `franken-engine.parser-benchmark-protocol.v1`
- `protocol_version`: `1.0.0`
- deterministic environment contract: `franken-engine.parser-frontier.env-contract.v1`

## Corpus Tier Model (Normative)

All parser benchmark suites must classify workloads into the following tiers:

| Tier | Purpose | Typical Scale | Gate Usage |
|---|---|---|---|
| `smoke` | Fast sanity/perf drift check on every PR | 8-25 fixtures | required |
| `core` | Representative steady-state parser corpus | 50-250 fixtures | required |
| `stress` | High-complexity parser throughput/latency envelope | 100-500 fixtures | required for release |
| `adversarial` | Worst-case and parser-defense pressure cases | 25-150 fixtures | required for release |

Tier IDs are part of artifact schema and must not be renamed in-place. Breaking
changes require a schema version bump.

## Workload Contract

Each benchmark case must provide:

- `case_id` (stable identifier)
- `tier_id` (`smoke|core|stress|adversarial`)
- `family_id` (semantic family label)
- `goal` (`script|module`)
- `source` (deterministic fixture source)
- `expected_semantic_class` (human-readable expected behavior class)

## Measurement Window Contract

Default protocol measurement window:

- warmup iterations: `5`
- measurement iterations: `30`
- replicates: `5`
- max relative stdev: `100000` millionths (`10%`)

Per-tier overrides are allowed only through versioned protocol fixture updates.

## Required Metric Families

Every benchmark run must emit:

- `throughput_sources_per_second`
- `latency_ns_p50`
- `latency_ns_p95`
- `latency_ns_p99`
- `bytes_per_source_avg`
- `tokens_per_source_avg`
- `semantic_hash_stability_rate`

## Structured Event Contract

Parser benchmark events must include the parser logging base keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Recommended benchmark context fields:

- `tier_id`
- `case_id`
- `replicate_index`
- `throughput_sources_per_second`
- `latency_ns_p95`
- `replay_command`

## Deterministic Execution Contract

All heavy Rust benchmark protocol checks/tests must run through `rch` wrappers.

Canonical command:

```bash
./scripts/run_parser_benchmark_protocol.sh ci
```

Modes:

- `check`: compile focused parser benchmark protocol test target
- `test`: execute focused parser benchmark protocol tests
- `clippy`: lint focused parser benchmark protocol target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run must publish:

- `artifacts/parser_benchmark_protocol/<timestamp>/run_manifest.json`
- `artifacts/parser_benchmark_protocol/<timestamp>/events.jsonl`
- `artifacts/parser_benchmark_protocol/<timestamp>/commands.txt`

`run_manifest.json` must include:

- schema/version identifiers
- mode/toolchain/target-dir
- git commit and dirty-worktree state
- exact executed command list
- operator verification replay steps

## Operator Verification

```bash
./scripts/run_parser_benchmark_protocol.sh ci
cat artifacts/parser_benchmark_protocol/<timestamp>/run_manifest.json
cat artifacts/parser_benchmark_protocol/<timestamp>/events.jsonl
cat artifacts/parser_benchmark_protocol/<timestamp>/commands.txt
```

The run is invalid if required artifact files or required structured event keys
are missing.
