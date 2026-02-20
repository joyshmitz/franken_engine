# Governance Audit Ledger Reproducibility Artifacts

This directory stores deterministic run manifests produced by:

`scripts/run_governance_audit_ledger_suite.sh`

Each run writes:
- `commands.txt`: exact `rch`-wrapped commands executed.
- `run_manifest.json`: component metadata, git commit, command list, outcome, and verification instructions.

## Operator Verification

1. Run `./scripts/run_governance_audit_ledger_suite.sh ci`.
2. Open the latest manifest under `artifacts/governance_audit_ledger/<timestamp>/run_manifest.json`.
3. Confirm `component`, `git_commit`, `commands`, and `outcome` fields.
4. Replay command sequence from `commands.txt` if independent verification is required.
