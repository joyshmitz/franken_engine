# Parser Error Recovery Resync Adversarial E2E Contract (`bd-2mds.1.10.2`)

This contract defines deterministic adversarial recovery/resynchronization checks
for malformed parser inputs so diagnostics remain actionable without silent
semantic corruption.

## Scope

This lane is implemented by:

- `docs/PARSER_ERROR_RECOVERY_RESYNC_ADVERSARIAL_E2E.md`
- `crates/franken-engine/tests/fixtures/parser_error_recovery_adversarial_e2e_v1.json`
- `crates/franken-engine/tests/parser_error_recovery_integration.rs`
- `scripts/run_parser_error_recovery_adversarial_e2e.sh`
- `scripts/e2e/parser_error_recovery_adversarial_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-error-recovery-adversarial-e2e.v1`
- `contract_version`: `1.0.0`

## Targeted Malformed-Input Families

Fixture coverage is required for these malformed families:

- `delimiter.missing_semicolon`
- `block.truncated_close_brace`
- `garbled.tail_noise`
- `execution.high_confidence_recover`
- `execution.low_confidence_fail_closed`

Each fixture case must define:

- deterministic synthetic syntax-error evidence
- mode (`diagnostic` or `execution`)
- expected outcome/action/success behavior
- scenario-level replay command routing

## Success-Rate and Deterministic Fallback Policy

The gate computes a deterministic success rate over fixture-designated
counted cases.

- contract floor: `min_success_rate_millionths`
- required behavior: repeated runs over the same fixture must produce byte-stable
  decision ledgers

Execution-mode low-confidence cases must fail closed with deterministic
`fail-strict` actioning.

## Silent Semantic Corruption Guards

To prevent hidden corruption under malformed inputs:

- `fail-strict` cases must apply zero edits and publish no repair diff hash
- `partial-recover` cases may only emit `Skip` edits (resync only)
- `recover-continue` cases may only emit `Insert` edits from declared
  candidate token sets

Any deviation is a hard gate failure.

## Structured Log Contract

Required keys for each scenario log record:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Recommended keys:

- `scenario_id`
- `case_id`
- `family_id`
- `ledger_outcome`
- `selected_action`
- `replay_command`

## Deterministic Execution and Replay

All heavy checks/tests for this lane are run via `rch` wrappers.

Canonical gate command:

```bash
./scripts/run_parser_error_recovery_adversarial_e2e.sh ci
```

Scenario replay commands:

```bash
PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO=adversarial ./scripts/run_parser_error_recovery_adversarial_e2e.sh test
PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO=resync ./scripts/run_parser_error_recovery_adversarial_e2e.sh test
PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO=replay ./scripts/run_parser_error_recovery_adversarial_e2e.sh test
```

One-command deterministic replay wrapper:

```bash
./scripts/e2e/parser_error_recovery_adversarial_replay.sh
```

## Required Artifacts

Each run emits:

- `artifacts/parser_error_recovery_adversarial_e2e/<timestamp>/run_manifest.json`
- `artifacts/parser_error_recovery_adversarial_e2e/<timestamp>/events.jsonl`
- `artifacts/parser_error_recovery_adversarial_e2e/<timestamp>/commands.txt`

Run manifest must include mode/scenario, replay command, deterministic
environment metadata, command transcript, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_parser_error_recovery_adversarial_e2e.sh ci
cat artifacts/parser_error_recovery_adversarial_e2e/<timestamp>/run_manifest.json
cat artifacts/parser_error_recovery_adversarial_e2e/<timestamp>/events.jsonl
cat artifacts/parser_error_recovery_adversarial_e2e/<timestamp>/commands.txt
./scripts/e2e/parser_error_recovery_adversarial_replay.sh
```
