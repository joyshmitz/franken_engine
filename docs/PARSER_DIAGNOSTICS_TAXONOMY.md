# Parser Diagnostics Taxonomy + Normalization Contract (v1)

This document defines the deterministic parser diagnostics taxonomy and
normalized diagnostics envelope introduced for `bd-2mds.1.1.3`.

## Contract Identifiers

- taxonomy version: `franken-engine.parser-diagnostics.taxonomy.v1`
- normalized diagnostics schema version: `franken-engine.parser-diagnostics.schema.v1`
- canonical hash algorithm: `sha256`
- canonical hash prefix: `sha256:`

Source of truth constants live in
`crates/franken-engine/src/parser.rs`:
- `PARSER_DIAGNOSTIC_TAXONOMY_VERSION`
- `PARSER_DIAGNOSTIC_SCHEMA_VERSION`
- `PARSER_DIAGNOSTIC_HASH_ALGORITHM`
- `PARSER_DIAGNOSTIC_HASH_PREFIX`

## Taxonomy (v1)

`ParseDiagnosticTaxonomy::v1()` is generated from `ParseErrorCode::ALL` and
maps each parser error code to a stable diagnostic identity:

| ParseErrorCode | Stable Diagnostic Code | Category | Severity | Template (taxonomy row) |
|---|---|---|---|---|
| `EmptySource` | `FE-PARSER-DIAG-EMPTY-SOURCE-0001` | `input` | `error` | `source is empty after whitespace normalization` |
| `InvalidGoal` | `FE-PARSER-DIAG-INVALID-GOAL-0001` | `goal` | `error` | `declaration is invalid for selected parse goal` |
| `UnsupportedSyntax` | `FE-PARSER-DIAG-UNSUPPORTED-SYNTAX-0001` | `syntax` | `error` | `statement or expression is unsupported by parser scaffold` |
| `IoReadFailed` | `FE-PARSER-DIAG-IO-READ-FAILED-0001` | `system` | `fatal` | `parser input could not be read` |
| `InvalidUtf8` | `FE-PARSER-DIAG-INVALID-UTF8-0001` | `encoding` | `error` | `parser input is not valid UTF-8` |
| `SourceTooLarge` | `FE-PARSER-DIAG-SOURCE-TOO-LARGE-0001` | `resource` | `fatal` | `source length/offset exceeds supported limits` |
| `BudgetExceeded` | `FE-PARSER-DIAG-BUDGET-EXCEEDED-0001` | `resource` | `fatal` | `parser budget exceeded` |

## Normalization Rules

`normalize_parse_error(&ParseError)` (and
`ParseError::normalized_diagnostic()`) produces a
`ParseDiagnosticEnvelope` with deterministic fields.

Normalization behavior:

1. `diagnostic_code`, `category`, and `severity` are derived only from
   `ParseErrorCode`.
2. `message_template` is derived from
   `ParseErrorCode::diagnostic_message_template(budget_kind)` where
   `budget_kind` comes from `witness.budget_kind` (if present).
3. Raw human error text (`ParseError.message`) is intentionally excluded from
   canonical diagnostic bytes to prevent host/OS-specific message drift from
   breaking comparisons.
4. `witness` is included canonically when present:
   - `mode`
   - `budget_kind`
   - `source_bytes`
   - `token_count`
   - `max_recursion_observed`
   - `max_source_bytes`
   - `max_token_count`
   - `max_recursion_depth`

## Canonical Envelope Shape

Canonical top-level keys (via `ParseDiagnosticEnvelope::canonical_value()`):

- `schema_version`
- `taxonomy_version`
- `hash_algorithm`
- `hash_prefix`
- `parse_error_code` (snake_case string)
- `diagnostic_code`
- `category`
- `severity`
- `message_template`
- `source_label`
- `span` (canonical source span or `null`)
- `budget_kind` (`source_bytes | token_count | recursion_depth | null`)
- `witness` (canonical witness map or `null`)

## Canonical Hash Formula

`diagnostic_hash = "sha256:" + hex(sha256(canonical_bytes))`

`ParseDiagnosticEnvelope::canonical_hash()` is the source of truth.

## Compatibility Policy

Any semantic change to:

- taxonomy mappings,
- required canonical keys,
- key semantics,
- canonical hashing algorithm/prefix,
- budget/witness normalization rules,

requires:

1. taxonomy and/or schema version bump,
2. updated compatibility vectors,
3. updated documentation in this file and parser verification docs.

## Compatibility Tests and Replay

Primary checks:

- `crates/franken-engine/src/parser.rs`
  - taxonomy completeness/uniqueness checks
  - normalized envelope determinism and serde/hash tests
- `crates/franken-engine/tests/parser_trait_ast.rs`
  - contract metadata stability
  - pinned normalized diagnostics hash vectors

Replay command (via `rch`):

```bash
rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_diagnostics_contract \
  cargo test -p frankenengine-engine --test parser_trait_ast
```
