# Parser Phase0 Proof Note

- claim_id: claim.parser.scalar_reference_deterministic
- demo_id: demo.parser.scalar_reference
- parser_mode: scalar_reference

## Grammar Completeness Snapshot

- family_count: 20
- supported_families: 8
- partially_supported_families: 5
- unsupported_families: 7
- completeness_millionths: 537500

## Determinism Evidence

- fixture_catalog: crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json
- fixture_count: 20
- canonical fixture hashes pinned in fixture catalog and verified in
  `crates/franken-engine/tests/parser_phase0_semantic_fixtures.rs`.

## Latency Snapshot (local reference only)

- p50_ns: 126997
- p95_ns: 254435
- p99_ns: 275584

## Isomorphism / Safety Notes

- Parser output remains canonicalized through `SyntaxTree::canonical_hash`.
- Budget failures emit `ParseErrorCode::BudgetExceeded` with deterministic witness payload.
- Script/Module goal restrictions for import/export remain explicit and deterministic.
