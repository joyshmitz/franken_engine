# Flamegraph Pipeline Validation Artifacts

`bd-1nn` emits deterministic validation artifacts under:

- `artifacts/flamegraph_pipeline/<timestamp>/run_manifest.json`
- `artifacts/flamegraph_pipeline/<timestamp>/flamegraph_pipeline_events.jsonl`
- `artifacts/flamegraph_pipeline/<timestamp>/commands.txt`
- `artifacts/flamegraph_pipeline/<timestamp>/logs/`

## Run Modes

All heavy Rust commands are offloaded through `rch` by the suite script.

```bash
./scripts/run_flamegraph_pipeline_suite.sh ci
./scripts/run_flamegraph_pipeline_suite.sh check
./scripts/run_flamegraph_pipeline_suite.sh test
./scripts/run_flamegraph_pipeline_suite.sh clippy
```

## Operator Verification

```bash
cat artifacts/flamegraph_pipeline/<timestamp>/run_manifest.json
cat artifacts/flamegraph_pipeline/<timestamp>/flamegraph_pipeline_events.jsonl
cat artifacts/flamegraph_pipeline/<timestamp>/commands.txt
```

