# Capability Escrow Suite Artifacts

This directory stores deterministic run bundles for beads `bd-3kks` and `bd-17v2`.

## What This Validates

- Out-of-envelope capabilities never receive ambient grants.
- Default runtime escrow routing (`challenge` / `sandbox`) is enforced at hostcall boundaries.
- Emergency grants are signed, bounded by expiry and invocation count, and require post-review tracking.
- Escrow decisions emit deterministic receipt/event evidence with stable keys.
- Every escrow/deny/emergency-grant decision has receipt + replay linkage and completeness checks.

## Runner

Use the dedicated `rch`-wrapped runner:

```bash
./scripts/run_capability_escrow_suite.sh [check|test|clippy|ci]
```

Default mode is `ci` (`check` + `test` + `clippy`).

Optional timeout tuning:

```bash
RCH_EXEC_TIMEOUT_SECONDS=300 ./scripts/run_capability_escrow_suite.sh ci
```

Optional bead metadata override:

```bash
CAPABILITY_ESCROW_BEAD_ID=bd-17v2 ./scripts/run_capability_escrow_suite.sh ci
```

If `rch` artifact retrieval stalls after a remote `exit=0`, the runner recovers and records
the step log in the run manifest.

## Output Layout

Each run creates a UTC timestamped folder:

```text
artifacts/capability_escrow_suite/<timestamp>/
  run_manifest.json
  capability_escrow_events.jsonl
  commands.txt
  logs/step_00.log
  logs/step_01.log
  logs/step_02.log
  ...
```

`run_manifest.json` includes:

- bead id and mode
- toolchain and target dir
- git commit + dirty-worktree state
- executed commands
- artifact pointers

`capability_escrow_events.jsonl` uses stable fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Operator Verification

For a given run directory `<run_dir>`:

```bash
cat <run_dir>/run_manifest.json
cat <run_dir>/capability_escrow_events.jsonl
cat <run_dir>/commands.txt
```

To reproduce:

```bash
./scripts/run_capability_escrow_suite.sh ci
```

## Test Surface

Primary integration coverage lives in:

- `crates/franken-extension-host/tests/capability_escrow_and_emergency_grants.rs`
- `crates/franken-extension-host/tests/capability_escrow_adversarial.rs`

It covers:

- escrow state transitions and approval/expiry behavior
- challenge vs sandbox default routing
- emergency grant issuance, bounded use, and post-review
- expired/emergency bypass rejection
- in-envelope zero-escrow fast path
- adversarial escalation campaigns (time-delayed escalation, flood spam, grant exhaustion, expiry-boundary race, indirect-hostcall attempts)
