# Parser Phase1 Arena Runbook

This runbook covers `bd-drjd` verification commands and artifact interpretation for the phase-1 parser arena lane.

## Deterministic Environment Contract

All parser phase1 scripts source:

- `scripts/e2e/parser_deterministic_env.sh`

The bootstrap pins:

- `TZ=UTC`
- `LANG=C.UTF-8`
- `LC_ALL=C.UTF-8`
- `SOURCE_DATE_EPOCH` (default `0`)
- toolchain and CPU fingerprints (`PARSER_FRONTIER_*`)

## E2E Commands

Run all commands from repository root.

```bash
./scripts/e2e/parser_phase1_arena_smoke.sh
./scripts/e2e/parser_phase1_arena_parity.sh
./scripts/e2e/parser_phase1_arena_budget_failures.sh
./scripts/e2e/parser_phase1_arena_replay.sh
./scripts/e2e/parser_phase1_arena_handle_audit.sh
./scripts/e2e/parser_phase1_arena_corruption_injection.sh
./scripts/e2e/parser_phase1_arena_rollback_rehearsal.sh
```

Each command routes heavy cargo work through `rch` in `scripts/run_parser_phase1_arena_suite.sh`.

## Scenario Mapping

- `smoke`: `arena_alloc_order_is_deterministic`
- `parity`: `semantic_roundtrip_preserves_hash`
- `budget_failures`: `budget_enforcement_is_deterministic`
- `replay`: smoke + parity replay checks
- `handle_audit`: `handle_audit_entries_are_deterministic` + `handle_audit_jsonl_is_parseable_and_stable`
- `corruption_injection`: `corruption_injection_guards_fail_closed_deterministically`
- `rollback_rehearsal`: pre/post replay parity drill using rollback token transition

## Artifacts

Artifacts are written under:

- `artifacts/parser_phase1_arena/<timestamp>/`

Core files:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

Log schema validator:

- `./scripts/validate_parser_log_schema.sh --events <events.jsonl>`
- schema contract: `docs/PARSER_LOGGING_SCHEMA_V1.md`

Key manifest and event fields:

- `schema_version`
- `trace_id`, `decision_id`, `policy_id`
- `allocator_epoch`
- `arena_fragmentation_ratio`
- `arena_fragmentation_threshold`
- `rollback_token`
- `replay_command`
- `error_code`
- deterministic environment fingerprints

## Failure Code Mapping

- `FE-PARSER-PHASE1-ARENA-0001`
  - Meaning: one or more suite commands failed.
  - Typical causes: test failure, compile failure, clippy failure, toolchain/environment mismatch.
  - Operator action:
    1. Open `run_manifest.json` and inspect `failed_command`.
    2. Open `events.jsonl` and inspect `outcome`, `error_code`, and `replay_command`.
    3. Re-run with the exact `replay_command` from the manifest/event.

- `FE-PARSER-PHASE1-ARENA-BUDGET-0001`
  - Meaning: deterministic budget-governance or budget-related scenario failed.

- `FE-PARSER-PHASE1-ARENA-HANDLE-0001`
  - Meaning: handle integrity checks (audit/corruption guard) failed.

- `FE-PARSER-PHASE1-ARENA-PARITY-0001`
  - Meaning: replay/parity scenario failed.

- `FE-PARSER-PHASE1-ARENA-FRAG-0001`
  - Meaning: `arena_fragmentation_ratio` exceeded `arena_fragmentation_threshold`.

## Handle Audit Integrity Check

The handle-audit scenario validates that:

- handle-audit entries are deterministic across identical runs
- `handle_audit_jsonl` is parseable and round-trips to structured entries

This is the phase-1 integrity gate for forensic inspection artifacts.
