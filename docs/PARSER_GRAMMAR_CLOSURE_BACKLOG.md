# Parser Grammar Closure Backlog (PSRP-01.1)

This document defines the canonical, machine-checkable backlog for scalar-reference grammar closure tracking.

## Source Artifacts

- Backlog catalog: `crates/franken-engine/tests/fixtures/parser_grammar_closure_backlog.json`
- Deterministic fixture catalog: `crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json`
- Backlog verification tests: `crates/franken-engine/tests/parser_grammar_closure_backlog.rs`
- Matrix source of truth: `crates/franken-engine/src/parser.rs` (`GrammarCompletenessMatrix::scalar_reference_es2020`)

## Coverage Contract

- Target family count: **20/20** (exactly the matrix family set)
- Each family must include:
  - deterministic fixture bindings (`fixture_ids`)
  - at least one replay command (family-scoped)
  - unit/property/e2e linkage fields
  - evidence path expectations

## Verification Commands

All CPU-intensive Rust commands must run through `rch`.

```bash
# Verify backlog-matrix alignment + fixture/replay integrity
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_phase0_gate \
  cargo test -p frankenengine-engine --test parser_grammar_closure_backlog

# Replay only one grammar family deterministically
PARSER_GRAMMAR_FAMILY=statement.control_flow rch exec -- \
  env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_phase0_gate \
  cargo test -p frankenengine-engine --test parser_grammar_closure_backlog \
  parser_grammar_closure_backlog_fixtures_are_replayable_by_family -- --nocapture

# End-to-end parser phase0 gate (includes backlog test lane)
./scripts/run_parser_phase0_gate.sh ci
```

## Evidence Expectations

- `artifacts/parser_phase0_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_phase0_gate/<timestamp>/events.jsonl`
- `artifacts/parser_phase0/golden_checksums.txt`

Backlog closure evidence is valid only when deterministic fixture hashes, backlog verification tests, and phase0 gate artifacts all pass.
