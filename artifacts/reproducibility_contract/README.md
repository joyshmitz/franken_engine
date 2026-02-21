# Reproducibility Contract Validation Artifacts

`bd-2u0` emits deterministic suite artifacts under:

- `artifacts/reproducibility_contract/<timestamp>/run_manifest.json`
- `artifacts/reproducibility_contract/<timestamp>/reproducibility_contract_events.jsonl`
- `artifacts/reproducibility_contract/<timestamp>/commands.txt`

## How to Run

All heavy Rust commands are offloaded through `rch` by the runner script.

```bash
./scripts/run_reproducibility_contract_suite.sh ci
```

Mode options:

```bash
./scripts/run_reproducibility_contract_suite.sh check
./scripts/run_reproducibility_contract_suite.sh test
./scripts/run_reproducibility_contract_suite.sh clippy
```

## Operator Verification

After a run:

```bash
cat artifacts/reproducibility_contract/<timestamp>/run_manifest.json
cat artifacts/reproducibility_contract/<timestamp>/reproducibility_contract_events.jsonl
cat artifacts/reproducibility_contract/<timestamp>/commands.txt
```
