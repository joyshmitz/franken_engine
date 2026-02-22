# Capability Witness Publication Reproducibility Artifacts

`bd-2w2g` writes deterministic suite artifacts under:

- `artifacts/capability_witness_publication/<timestamp>/run_manifest.json`
- `artifacts/capability_witness_publication/<timestamp>/capability_witness_publication_events.jsonl`
- `artifacts/capability_witness_publication/<timestamp>/commands.txt`

## How To Run

All CPU-heavy cargo commands are offloaded through `rch` by the runner script.

```bash
./scripts/run_capability_witness_publication_suite.sh ci
```

Mode options:

```bash
./scripts/run_capability_witness_publication_suite.sh check
./scripts/run_capability_witness_publication_suite.sh test
./scripts/run_capability_witness_publication_suite.sh clippy
```

## Operator Verification

After a run:

```bash
cat artifacts/capability_witness_publication/<timestamp>/run_manifest.json
cat artifacts/capability_witness_publication/<timestamp>/capability_witness_publication_events.jsonl
cat artifacts/capability_witness_publication/<timestamp>/commands.txt
```

Verifier expectations:

- `outcome` is `pass`.
- `mode_completed` is `true`.
- `commands_executed` matches the command count in `commands`.
- `capability_witness_publication_events.jsonl` contains a `suite_completed` event with stable fields:
  - `trace_id`
  - `decision_id`
  - `policy_id`
  - `component`
  - `event`
  - `outcome`
  - `error_code`
