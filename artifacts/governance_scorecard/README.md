# Governance Scorecard Artifacts

This directory stores reproducibility artifacts for `bd-12n5`.

The governance scorecard publication covers four dimensions:

- attested-receipt coverage,
- privacy-budget health,
- moonshot-governor decision behavior,
- cross-repo conformance stability.

Each publication is deterministic, signed, and appended to the governance audit ledger.

## Runner

Use:

```bash
./scripts/run_governance_scorecard_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci` (all of the above)

## Required Execution Path

The suite runs heavy cargo commands via `rch`.

Environment controls:

- `RUSTUP_TOOLCHAIN` (default: `nightly`)
- `RCH_EXEC_TIMEOUT_SECONDS` (default: `900`)
- `CARGO_TARGET_DIR` (default: timestamped `/tmp/rch_target_franken_engine_governance_scorecard_*`)
- `GOVERNANCE_SCORECARD_BEAD_ID` (default: `bd-12n5`)
- `GOVERNANCE_SCORECARD_ARTIFACT_ROOT` (default: `artifacts/governance_scorecard`)

## Output Contract

Each run writes `artifacts/governance_scorecard/<timestamp>/`:

- `run_manifest.json`
- `governance_scorecard_events.jsonl`
- `commands.txt`
- `logs/step_XX.log`

Manifest fields include:

- schema/component metadata (`schema_version`, `component`, `bead_id`, `mode`, `generated_at_utc`)
- reproducibility context (`toolchain`, `cargo_target_dir`, `git_commit`, `dirty_worktree`)
- outcome (`outcome`, `mode_completed`, `commands_executed`, `failed_command`, `failed_log`)
- artifact pointers and operator verification commands

## Current Blocker Note

If this suite fails on unrelated compile errors outside `governance_scorecard` scope, keep the failing manifest as evidence and coordinate with the owning lane before rerun.
