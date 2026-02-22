# Replacement Lineage Log Reproducibility Artifacts

`bd-1a5z.1` writes deterministic suite artifacts under:

- `artifacts/replacement_lineage_log/<timestamp>/run_manifest.json`
- `artifacts/replacement_lineage_log/<timestamp>/replacement_lineage_log_events.jsonl`
- `artifacts/replacement_lineage_log/<timestamp>/commands.txt`

## How To Run

All CPU-heavy cargo commands are offloaded through `rch` by the runner script.

```bash
./scripts/run_replacement_lineage_log_suite.sh ci
```

Mode options:

```bash
./scripts/run_replacement_lineage_log_suite.sh check
./scripts/run_replacement_lineage_log_suite.sh test
./scripts/run_replacement_lineage_log_suite.sh clippy
```

## Operator Verification

After a run:

```bash
cat artifacts/replacement_lineage_log/<timestamp>/run_manifest.json
cat artifacts/replacement_lineage_log/<timestamp>/replacement_lineage_log_events.jsonl
cat artifacts/replacement_lineage_log/<timestamp>/commands.txt
```

Verifier expectations:

- `outcome` is `pass`.
- `mode_completed` is `true`.
- `commands_executed` matches the command count in `commands`.
- `replacement_lineage_log_events.jsonl` contains a `suite_completed` event with stable fields:
  - `trace_id`
  - `decision_id`
  - `policy_id`
  - `component`
  - `event`
  - `outcome`
  - `error_code`
