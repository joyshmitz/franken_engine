# Parser Merge Witness Hashing Contract

This document defines the PSRP-05.3 contract for deterministic source-order
merge and merge witness hashing in `crates/franken-engine/src/parallel_parser.rs`.

## Scope

- Merge chunk-local token streams into one canonical source-order stream.
- Compute deterministic merge witness hashes bound to merge inputs/metadata.
- Expose merge witness fields for interference-gate drift detection.
- Produce one-command reproducible verification artifacts.

## Merge Determinism Contract

`merge_chunks` must canonicalize all merged tokens by sorting on:

1. absolute token `start`
2. absolute token `end`
3. `chunk_index`
4. per-chunk `token_ordinal`

This prevents chunk iteration order from affecting the merged result while still
keeping tie-breaks deterministic for identical spans.

## Witness Hash Contract

`MergeWitness` contains:

- `merged_hash`: content hash over merged output tokens.
- `witness_hash`: content hash over merge provenance inputs.
- `chunk_count`: merged chunk count.
- `boundary_repairs`: count of boundary token repairs.
- `total_tokens`: merged token count.

`witness_hash` is computed from deterministic bytes including:

- `merged_hash`
- `boundary_repairs`
- `total_tokens`
- ordered chunk list (sorted by `chunk_index`)
- per-chunk witness hash covering `chunk_index`, byte span, token count, and
  each token `(kind,start,end)` tuple

Any change in merge provenance must change `witness_hash`.

## Interference Gate Expectations

`parallel_interference_gate::compare_witnesses` must compare and report diffs
for all merge witness fields, including `witness_hash`.

Expected drift detection classes:

- output drift (`merged_hash`)
- provenance drift (`witness_hash`)
- structural drift (`chunk_count`, `boundary_repairs`, `total_tokens`)

## Gate and Artifacts

Primary gate script:

```bash
./scripts/run_parser_merge_witness_gate.sh ci
```

Artifacts are emitted under:

- `artifacts/parser_merge_witness/<timestamp>/run_manifest.json`
- `artifacts/parser_merge_witness/<timestamp>/events.jsonl`
- `artifacts/parser_merge_witness/<timestamp>/commands.txt`

The manifest must include deterministic environment fields and replay command.
