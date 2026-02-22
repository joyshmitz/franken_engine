# PLAS Lockstep Suite Artifacts

This directory stores reproducibility artifacts for `bd-32d3` lockstep checks that validate synthesized minimal policies against:

- FrankenEngine full-manifest behavior,
- FrankenEngine minimal-policy behavior,
- Node/Bun reference lanes.

## Runner

Use `scripts/run_plas_lockstep_suite.sh`:

```bash
./scripts/run_plas_lockstep_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci` (all of the above in sequence)

## Required Execution Path

Heavy cargo operations are executed through `rch` by the suite runner.

Useful environment controls:

- `RUSTUP_TOOLCHAIN` (default: `nightly`)
- `RCH_EXEC_TIMEOUT_SECONDS` (default: `900`)
- `CARGO_TARGET_DIR` (default: timestamped `/tmp/rch_target_franken_engine_plas_lockstep_*`)
- `PLAS_LOCKSTEP_BEAD_ID` (default: `bd-32d3`)
- `PLAS_LOCKSTEP_ARTIFACT_ROOT` (default: `artifacts/plas_lockstep`)

## Output Contract

Each run writes `artifacts/plas_lockstep/<timestamp>/`:

- `run_manifest.json`
- `plas_lockstep_events.jsonl`
- `commands.txt`
- `logs/step_XX.log`

Manifest records:

- `schema_version`, `component`, `bead_id`, `mode`, `generated_at_utc`
- `toolchain`, `cargo_target_dir`, `git_commit`, `dirty_worktree`
- `outcome`, `mode_completed`, `commands_executed`
- `failed_command` (if any), `failed_log`, `command_logs`
- artifact pointers and operator verification commands

## Failure Classes (Tested)

`crates/franken-engine/src/plas_lockstep.rs` emits deterministic failure classification:

- `correctness_regression`
- `capability_gap`
- `platform_divergence`
