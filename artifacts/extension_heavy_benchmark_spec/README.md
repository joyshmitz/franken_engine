# Extension-Heavy Benchmark Spec Validation Artifacts

`bd-19l0` emits deterministic validation artifacts under:

- `artifacts/extension_heavy_benchmark_spec/<timestamp>/run_manifest.json`
- `artifacts/extension_heavy_benchmark_spec/<timestamp>/extension_heavy_benchmark_spec_events.jsonl`
- `artifacts/extension_heavy_benchmark_spec/<timestamp>/commands.txt`

## Run Modes

All heavy Rust commands are offloaded through `rch` by the suite script.

```bash
./scripts/run_extension_heavy_benchmark_spec_suite.sh ci
./scripts/run_extension_heavy_benchmark_spec_suite.sh check
./scripts/run_extension_heavy_benchmark_spec_suite.sh test
./scripts/run_extension_heavy_benchmark_spec_suite.sh clippy
```

## Operator Verification

```bash
cat artifacts/extension_heavy_benchmark_spec/<timestamp>/run_manifest.json
cat artifacts/extension_heavy_benchmark_spec/<timestamp>/extension_heavy_benchmark_spec_events.jsonl
cat artifacts/extension_heavy_benchmark_spec/<timestamp>/commands.txt
```
