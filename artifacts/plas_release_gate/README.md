# PLAS Release Gate Artifacts

This directory stores reproducibility artifacts for `bd-2n3`.

The release gate validates prioritized extension cohorts for PLAS activation with:

- active (non-shadow) cohort coverage,
- signed `capability_witness` verification against trust anchors,
- deterministic escrow replay parity for grant decisions,
- revocation round-trip evidence (`revoke` escrow receipts + signed revocation witness),
- ambient-authority rejection (all active permissions traceable to witness evidence).

## Runner

Use:

```bash
./scripts/run_plas_release_gate_suite.sh ci
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
- `CARGO_TARGET_DIR` (default: timestamped `/tmp/rch_target_franken_engine_plas_release_gate_*`)
- `PLAS_RELEASE_GATE_BEAD_ID` (default: `bd-2n3`)
- `PLAS_RELEASE_GATE_ARTIFACT_ROOT` (default: `artifacts/plas_release_gate`)

## Output Contract

Each run writes `artifacts/plas_release_gate/<timestamp>/`:

- `run_manifest.json`
- `plas_release_gate_events.jsonl`
- `commands.txt`
- `logs/step_XX.log`

Manifest fields include:

- schema/component metadata (`schema_version`, `component`, `bead_id`, `mode`, `generated_at_utc`)
- reproducibility context (`toolchain`, `cargo_target_dir`, `git_commit`, `dirty_worktree`)
- outcome (`outcome`, `mode_completed`, `commands_executed`, `failed_command`, `failed_log`)
- artifact pointers and operator verification commands

## Gate Module Coverage

`crates/franken-engine/src/plas_release_gate.rs` and
`crates/franken-engine/tests/plas_release_gate_integration.rs` cover:

- cohort activation checks for PLAS non-shadow enforcement,
- capability witness signing/transparency verification,
- escrow replay parity validation,
- revocation round-trip witness/receipt coupling,
- ambient-authority traceability scan,
- deterministic decision artifact hashing and stable structured logs.
