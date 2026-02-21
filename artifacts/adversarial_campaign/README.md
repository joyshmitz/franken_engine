# Adversarial Campaign Generator Reproducibility Artifacts

This directory stores deterministic run manifests for `bd-2onl` (continuous adversarial campaign generator).

Run:

`./scripts/run_adversarial_campaign_suite.sh ci`

Each run writes:
- `commands.txt`: exact `rch`-wrapped commands executed.
- `run_manifest.json`: mode, seed, git commit, command list, outcome, and verification commands.

## Operator Verification

1. Execute `./scripts/run_adversarial_campaign_suite.sh ci`.
2. Inspect the latest `artifacts/adversarial_campaign/<timestamp>/run_manifest.json`.
3. Confirm `component`, `git_commit`, `commands`, and `outcome`.
4. Replay commands from `commands.txt` to independently reproduce results.
