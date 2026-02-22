# Benchmark Denominator Validation Artifacts

`bd-2n9` emits deterministic validation artifacts under:

- `artifacts/benchmark_denominator/<timestamp>/run_manifest.json`
- `artifacts/benchmark_denominator/<timestamp>/benchmark_denominator_events.jsonl`
- `artifacts/benchmark_denominator/<timestamp>/commands.txt`

## Run Modes

All heavy Rust commands are offloaded through `rch` by the suite script.

```bash
./scripts/run_benchmark_denominator_suite.sh ci
./scripts/run_benchmark_denominator_suite.sh check
./scripts/run_benchmark_denominator_suite.sh test
./scripts/run_benchmark_denominator_suite.sh clippy
```

## Operator Verification

```bash
cat artifacts/benchmark_denominator/<timestamp>/run_manifest.json
cat artifacts/benchmark_denominator/<timestamp>/benchmark_denominator_events.jsonl
cat artifacts/benchmark_denominator/<timestamp>/commands.txt
```
