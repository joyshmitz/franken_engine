# PLAS Burn-In Gate Artifacts

This directory stores reproducibility artifacts for `bd-24ie`.

The burn-in gate enforces promotion criteria before `auto_enforcement`:

- shadow success-rate threshold,
- false-deny envelope threshold,
- rollback proof artifact completeness.

## Runner

Use:

```bash
./scripts/run_plas_burn_in_gate_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci` (all of the above)

## Required Execution Path

The suite executes heavy cargo commands via `rch`.

Environment controls:

- `RUSTUP_TOOLCHAIN` (default: `nightly`)
- `RCH_EXEC_TIMEOUT_SECONDS` (default: `900`)
- `CARGO_TARGET_DIR` (default: timestamped `/tmp/rch_target_franken_engine_plas_burn_in_gate_*`)
- `PLAS_BURN_IN_GATE_BEAD_ID` (default: `bd-24ie`)
- `PLAS_BURN_IN_GATE_ARTIFACT_ROOT` (default: `artifacts/plas_burn_in_gate`)

## Output Contract

Each run writes `artifacts/plas_burn_in_gate/<timestamp>/`:

- `run_manifest.json`
- `plas_burn_in_gate_events.jsonl`
- `commands.txt`
- `logs/step_XX.log`

Manifest fields include:

- schema/component metadata (`schema_version`, `component`, `bead_id`, `mode`, `generated_at_utc`)
- reproducibility context (`toolchain`, `cargo_target_dir`, `git_commit`, `dirty_worktree`)
- outcome (`outcome`, `mode_completed`, `commands_executed`, `failed_command`, `failed_log`)
- artifact pointers and operator verification commands

## Burn-In Lifecycle Coverage

`crates/franken-engine/src/plas_burn_in_gate.rs` and
`crates/franken-engine/tests/plas_burn_in_gate_integration.rs` cover:

- `shadow_start` -> `shadow_evaluation` -> `promotion_gate` -> terminal state,
- `auto_enforcement` on all criteria pass,
- `rejection` on threshold/rollback failures,
- early termination on false-deny envelope breach with diagnostic artifact.
