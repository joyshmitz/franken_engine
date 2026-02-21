# Shadow Evaluation Gate Reproducibility Artifacts

This directory stores deterministic run manifests for the shadow-promotion gate bead.

Run:

`./scripts/run_shadow_evaluation_gate_suite.sh ci`

Each run writes:
- `commands.txt`: exact `rch`-wrapped commands executed.
- `run_manifest.json`: mode, seed, git commit, command list, outcome, and operator verification commands.

## Operator Verification

1. Execute `./scripts/run_shadow_evaluation_gate_suite.sh ci`.
2. Inspect the latest `artifacts/shadow_evaluation_gate/<timestamp>/run_manifest.json`.
3. Confirm `component`, `git_commit`, `commands`, and `outcome`.
4. Replay commands from `commands.txt` to independently reproduce results.
