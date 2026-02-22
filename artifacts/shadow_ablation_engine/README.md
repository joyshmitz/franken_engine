# Shadow Ablation Engine Reproducibility Artifacts

`bd-1kdc` writes deterministic validation artifacts under:

- `artifacts/shadow_ablation_engine/<timestamp>/run_manifest.json`
- `artifacts/shadow_ablation_engine/<timestamp>/shadow_ablation_engine_events.jsonl`
- `artifacts/shadow_ablation_engine/<timestamp>/commands.txt`

## Run Modes

All heavy Rust commands are offloaded through `rch` by the suite runner.

```bash
./scripts/run_shadow_ablation_engine_suite.sh check
./scripts/run_shadow_ablation_engine_suite.sh test
./scripts/run_shadow_ablation_engine_suite.sh clippy
./scripts/run_shadow_ablation_engine_suite.sh ci
```

## Operator Verification

1. Execute `./scripts/run_shadow_ablation_engine_suite.sh ci`.
2. Inspect the generated `run_manifest.json` for command list, commit, and outcome.
3. Inspect `shadow_ablation_engine_events.jsonl` for structured suite completion event.
4. Replay commands from `commands.txt` to independently reproduce the run.
