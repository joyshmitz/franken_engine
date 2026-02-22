# Extension-Heavy Benchmark Suite Contract Validation Artifacts

`bd-2ql` emits deterministic validation artifacts under:

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

The script validates:
- `docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md`
- `docs/extension_heavy_workload_matrix_v1.json`
- `docs/extension_heavy_golden_outputs_v1.json`
- `crates/franken-engine/tests/extension_heavy_benchmark_spec.rs`
- `crates/franken-engine/tests/extension_heavy_benchmark_matrix.rs`

## Operator Verification

```bash
cat artifacts/extension_heavy_benchmark_spec/<timestamp>/run_manifest.json
cat artifacts/extension_heavy_benchmark_spec/<timestamp>/extension_heavy_benchmark_spec_events.jsonl
cat artifacts/extension_heavy_benchmark_spec/<timestamp>/commands.txt
```
