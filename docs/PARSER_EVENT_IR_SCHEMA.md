# Parser Canonical Parse Event IR Schema (v2)

This document defines the versioned Parse Event IR contract introduced for `bd-2mds.1.4.1`.

## Contract Identifiers

- Contract version: `franken-engine.parser-event-ir.contract.v2`
- Schema version: `franken-engine.parser-event-ir.schema.v2`
- Canonical hash algorithm: `sha256`
- Canonical hash prefix: `sha256:`
- Producer policy id: `franken-engine.parser-event-producer.policy.v1`
- Producer component: `canonical_es2020_parser`

## Canonical Serialization Rules

Parse Event IR canonical bytes are produced via `deterministic_serde::encode_value` over the canonical map form returned by `ParseEventIr::canonical_value()`.

Rules:
- map fields are represented as deterministic key-value pairs,
- arrays preserve event order,
- optional fields are encoded as explicit `null` values when absent,
- event sequence values are monotonic and gap-free.

## Canonical Hash Formula

`parse_event_ir_hash = "sha256:" + hex(sha256(canonical_bytes))`

`ParseEventIr::canonical_hash()` is the source of truth for this formula.

## Event IR Envelope Shape

Canonical top-level map keys:
- `schema_version`: string
- `contract_version`: string
- `hash_algorithm`: string
- `hash_prefix`: string
- `parser_mode`: string
- `goal`: string
- `source_label`: string
- `event_count`: u64
- `events`: array of event maps

## Event Record Shape

Canonical per-event map keys:
- `sequence`: u64
- `kind`: string (`parse_started`, `statement_parsed`, `parse_completed`, `parse_failed`)
- `parser_mode`: string
- `goal`: string
- `source_label`: string
- `trace_id`: string
- `decision_id`: string
- `policy_id`: string
- `component`: string
- `outcome`: string
- `error_code`: string or null
- `statement_index`: u64 or null
- `span`: canonical source-span map or null
- `payload_kind`: string or null
- `payload_hash`: string or null

## Deterministic Event Materialization (Current v2)

Success-path producers (`ParseEventIr::from_syntax_tree(...)` and
`ParseEventIr::from_parse_source(...)`) emit:
1. `parse_started` at sequence `0`
2. one `statement_parsed` event for each statement in source order
3. `parse_completed` at the final sequence

Failure-path producer (`ParseEventIr::from_parse_error(...)`) emits:
1. `parse_started` at sequence `0`
2. `parse_failed` at sequence `1`

`CanonicalEs2020Parser::parse_with_event_ir(...)` always returns a Parse Event IR
value even when parsing fails, so callers can persist deterministic replay
artifacts for both success and failure runs.

`statement_parsed.payload_hash` is the canonical hash of the statement canonical value.
`parse_completed.payload_hash` is the canonical hash of the full syntax tree canonical value.
`parse_failed.payload_hash` is the canonical hash of normalized diagnostics.

## Compatibility Policy

Any semantic change to:
- required map keys,
- key meaning,
- event ordering,
- hash algorithm/prefix,
- sequence semantics,
- payload hash derivation,
- provenance-id derivation contract (`trace_id`, `decision_id`, `policy_id`, `component`),

requires a contract/schema version bump and new pinned hash vectors.

## Compatibility Checks

Primary contract tests:
- `crates/franken-engine/src/parser.rs` unit tests for contract constants and deterministic event generation.
- `crates/franken-engine/tests/parser_trait_ast.rs` hash-vector compatibility tests.

Replay command:

```bash
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_event_ir_contract \
  cargo test -p frankenengine-engine --test parser_trait_ast
```
