# Constrained Ambient Benchmark Lane Artifacts

`bd-3qv` emits deterministic validation artifacts under:

- `artifacts/constrained_ambient_benchmark_lane/<timestamp>/run_manifest.json`
- `artifacts/constrained_ambient_benchmark_lane/<timestamp>/constrained_ambient_benchmark_lane_events.jsonl`
- `artifacts/constrained_ambient_benchmark_lane/<timestamp>/commands.txt`

## Run Modes

All heavy Rust commands are offloaded through `rch` by the suite script.

```bash
./scripts/run_constrained_ambient_benchmark_lane_suite.sh ci
./scripts/run_constrained_ambient_benchmark_lane_suite.sh check
./scripts/run_constrained_ambient_benchmark_lane_suite.sh test
./scripts/run_constrained_ambient_benchmark_lane_suite.sh clippy
```

## Operator Verification

```bash
cat artifacts/constrained_ambient_benchmark_lane/<timestamp>/run_manifest.json
cat artifacts/constrained_ambient_benchmark_lane/<timestamp>/constrained_ambient_benchmark_lane_events.jsonl
cat artifacts/constrained_ambient_benchmark_lane/<timestamp>/commands.txt
```
