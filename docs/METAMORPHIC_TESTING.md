# Metamorphic Testing (bd-2eu)

This document defines the metamorphic test framework for parser, IR, and execution invariants.

## Relation Catalog

Source of truth: `crates/franken-metamorphic/metamorphic_relations.toml`

Catalog coverage:
- parser: whitespace, comment, parenthesization, ASI-equivalence, unicode escape equivalence, source-position independence
- IR: lowering determinism, optimization idempotence, capability preservation, dead-code insertion invariance, constant-folding equivalence
- execution: evaluation-order determinism, GC-timing independence, stack-depth independence, prototype-chain equivalence, promise-resolution order stability

Each relation carries:
- `subsystem`
- `oracle`
- `budget_pairs` (default `1000`)
- `enabled`

## Runner

Use the suite wrapper (heavy cargo paths routed through `rch`):

```bash
./scripts/run_metamorphic_suite.sh check
./scripts/run_metamorphic_suite.sh test
./scripts/run_metamorphic_suite.sh ci
```

Environment overrides:
- `METAMORPHIC_PAIRS` (default `1000`, applied per enabled relation)
- `METAMORPHIC_SEED` (default `1`)
- `RUSTUP_TOOLCHAIN` (default `nightly`)
- `CARGO_TARGET_DIR` (default `/tmp/rch_target_franken_engine_metamorphic`)

## Failure Minimization

When a relation diverges, the framework applies deterministic ddmin reduction and writes:

- `metamorphic_failure_{relation}_{hash}.json`

Payload fields:
- `relation_id`
- `seed`
- `input_source`
- `variant_source`
- `expected_equivalence`
- `actual_divergence`
- `minimized`

## Artifacts

Each run writes deterministic metadata under:

- `artifacts/metamorphic/<timestamp>/run_manifest.json`
- `artifacts/metamorphic/<timestamp>/events.jsonl`
- `artifacts/metamorphic/<timestamp>/relation_events.jsonl`
- `artifacts/metamorphic/<timestamp>/metamorphic_evidence.jsonl`
- `artifacts/metamorphic/<timestamp>/failures/`
- `artifacts/metamorphic/<timestamp>/commands.txt`

Evidence rows include stable governance fields:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Plus relation metrics:
- `relation_id`
- `subsystem`
- `oracle`
- `pairs_tested`
- `violations_found`
- `min_failure_size`
- `duration_us`
- `relation_catalog_hash`
- `seed`
- `environment_fingerprint`

A `suite_summary` row is appended with aggregate totals.

## Meta-Tests

The crate includes infrastructure self-tests for:
- relation soundness on a curated deterministic seed set
- generator coverage >= 99%
- minimizer effectiveness (<= 20 AST-node metric)
- deterministic reruns for identical seeds
- strict budget enforcement

## Structured Failure Semantics

- Non-zero relation violations emit `FE-META-0001` and fail the suite.
- No suppression mechanism is implemented; CI remains zero-violation.

## Operator Verification

After a run:

```bash
cat artifacts/metamorphic/<timestamp>/run_manifest.json
cat artifacts/metamorphic/<timestamp>/events.jsonl
cat artifacts/metamorphic/<timestamp>/relation_events.jsonl
cat artifacts/metamorphic/<timestamp>/metamorphic_evidence.jsonl
ls artifacts/metamorphic/<timestamp>/failures
```
