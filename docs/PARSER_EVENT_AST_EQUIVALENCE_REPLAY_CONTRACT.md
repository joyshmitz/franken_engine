# Parser Event->AST Equivalence and Deterministic Replay Contract (`bd-2mds.1.4.4.1`)

This contract defines the core equivalence harness between parser event-stream
semantics and materialized AST semantics, plus deterministic replay requirements
for failure classes consumed by downstream parser quality lanes.

## Scope

This lane is implemented by:

- `docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md`
- `crates/franken-engine/tests/fixtures/parser_event_ast_equivalence_v1.json`
- `crates/franken-engine/tests/parser_event_ast_equivalence.rs`
- `scripts/run_parser_event_ast_equivalence.sh`
- `scripts/e2e/parser_event_ast_equivalence_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-event-ast-equivalence.v1`
- `contract_version`: `1.0.0`

## Core Equivalence Contract

For every success case:

1. Parse with `parse_with_event_ir` to produce canonical parse result and Event IR.
2. Materialize AST from the Event IR via `materialize_from_source`.
3. Require deterministic parity:
   - materialized AST canonical hash equals parser AST canonical hash
   - materialized statement-node count equals expected statement count
4. Require witness stability across reruns:
   - Event IR canonical hash is stable for identical input/goal
   - materialized root node id and statement-node witnesses are stable

## Failure Contract and Taxonomy

Required deterministic failure classes in this core phase:

- parse failure with empty source: `empty_source`
- materialization failure from failed event stream: `parse_failed_event_stream`
- tamper-detection failure for statement payload hash: `statement_hash_mismatch`

Every failure path must produce a replayable command contract and stable error
classification.

## Structured Log Contract

Required event keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Contract

One-command replay wrapper:

```bash
./scripts/e2e/parser_event_ast_equivalence_replay.sh
```

Scenario-specific replay commands (all deterministic):

```bash
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=parity ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=malformed ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=tamper ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=replay ./scripts/run_parser_event_ast_equivalence.sh test
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane run via `rch`.

Canonical gate command:

```bash
./scripts/run_parser_event_ast_equivalence.sh ci
```

Modes:

- `check`: compile focused event->AST equivalence test target
- `test`: execute scenario-focused deterministic tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + scenario test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json`
- `artifacts/parser_event_ast_equivalence/<timestamp>/events.jsonl`
- `artifacts/parser_event_ast_equivalence/<timestamp>/commands.txt`

The manifest includes deterministic environment fingerprints, replay command,
scenario, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_parser_event_ast_equivalence.sh ci
cat artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json
cat artifacts/parser_event_ast_equivalence/<timestamp>/events.jsonl
cat artifacts/parser_event_ast_equivalence/<timestamp>/commands.txt
./scripts/e2e/parser_event_ast_equivalence_replay.sh
```
