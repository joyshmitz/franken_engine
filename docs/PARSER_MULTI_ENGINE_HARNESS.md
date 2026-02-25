# Parser Multi-Engine Harness (`bd-2mds.1.2.1`, `bd-2mds.1.2.2`, `bd-2mds.1.2.3`, `bd-2mds.1.2.4.1`)

Deterministic comparison harness for parser outputs across multiple engines under a controlled environment (`LC_ALL=C`, `TZ=UTC`) with reproducible manifests and one-command replay paths per fixture.

## Scope

The harness is implemented in:

- `crates/franken-engine/src/parser_multi_engine_harness.rs`
- `crates/franken-engine/src/bin/franken_parser_multi_engine_harness.rs`

It compares fixture outcomes across:

- `franken_canonical` (native scalar-reference parser)
- `fixture_expected_hash` (catalog baseline oracle)
- optional `external_command` engines (e.g., Boa/peer parser wrappers)

## Normalization Adapters (PSRP-02.2)

The harness now normalizes engine-specific outputs into canonical comparison
artifacts before drift comparison:

- AST/hash outcomes normalize through adapter
  `canonical_hash_passthrough_v1` into schema
  `franken-engine.parser-ast-normalization.v1`.
- Diagnostic/error outcomes normalize through adapter
  `parser_diagnostics_taxonomy_v1` into schema
  `franken-engine.parser-diagnostic-normalization.v1`.
- Known parser error aliases (`EmptySource`, `empty_source`, etc.) are mapped
  into canonical parser diagnostics taxonomy entries so cross-engine case/style
  differences do not create false divergences.
- Unknown external diagnostic codes are normalized deterministically under
  fallback taxonomy `external.engine-diagnostic.v1`.

Per-engine `first_run`/`second_run` rows include optional:

- `normalized_ast`
- `normalized_diagnostic`

Harness equivalence checks compare these normalized artifacts (not only raw
engine-returned strings), and deterministic checks assert both raw and
normalized consistency across repeated runs.

## Drift Classification (PSRP-02.3)

When engines diverge, the harness now emits deterministic drift classification
metadata on each fixture row (`drift_classification`) and summary rollups:

- Taxonomy version:
  `franken-engine.parser-multi-engine-drift-taxonomy.v1`
- Categories:
  - `semantic`
  - `diagnostics`
  - `harness`
  - `artifact`
- Severity mapping:
  - `diagnostics` -> `minor` (`comparator_decision=drift_minor`)
  - `semantic`, `harness`, `artifact` -> `critical`
    (`comparator_decision=drift_critical`)
- Deterministic owner hints:
  - `semantic` -> `parser-core`
  - `diagnostics` -> `parser-diagnostics-taxonomy`
  - `harness` -> `parser-multi-engine-harness`
  - `artifact` -> `parser-artifact-contract`

`summary` now includes:

- `drift_minor_fixtures`
- `drift_critical_fixtures`
- `drift_counts_by_category`

## Deterministic Minimizer + Repro Pack (PSRP-02.4.1)

Each divergent fixture now emits a deterministic repro-pack payload under
`fixture_results[].repro_pack` with schema:

- `franken-engine.parser-drift-repro-pack.v1`

Repro-pack fields include:

- fixture identity (`fixture_id`, `family_id`)
- original/minimized source hashes (`source_hash`, `minimized_source_hash`)
- minimized source text (`minimized_source`)
- drift classifier payload (`drift_classification`)
- one-command replay (`replay_command`)
- deterministic minimization stats (`minimization`)
- promotion hook targets (`promotion_hooks`)
- provenance digest (`provenance_hash`)

Minimization policy:

- deterministic line-based delta reduction
- fixed seed/env inherited from harness run
- candidate retained only if drift classification and per-engine outcome-kind
  signature are preserved
- bounded rounds/candidate evaluations to keep runs finite and replayable

## Engine Contract

`external_command` engines must read one JSON request from stdin and emit one JSON response on stdout.

Request payload:

```json
{
  "goal": "script|module",
  "source": "raw source string",
  "seed": 7,
  "trace_id": "trace-...",
  "decision_id": "decision-...",
  "policy_id": "policy-...",
  "engine_id": "boa_0_18"
}
```

Response payload:

- success: `{ "hash": "sha256:<64 lowercase hex>" }`
- parse/runtime failure: `{ "error_code": "ParseFailure" }`

Any other shape is treated as a protocol violation and fails closed for that run.

## CLI

```bash
cargo run -p frankenengine-engine --bin franken_parser_multi_engine_harness -- \
  --fixture-catalog crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json \
  --fixture-limit 8 \
  --seed 7 \
  --trace-id trace-parser-multi-engine-manual \
  --decision-id decision-parser-multi-engine-manual \
  --policy-id policy-parser-multi-engine-v1 \
  --locale C \
  --timezone UTC \
  --out artifacts/parser_multi_engine_harness/manual/report.json
```

Optional flags:

- `--fixture-id <id>`: run a single fixture
- `--fixture-limit <usize|none>`: cap fixture set
- `--engine-specs <path>`: load engine list from JSON (array or `{ "engines": [...] }`)
- `--fail-on-divergence`: exit `2` if any divergence/nondeterminism is observed

## Deterministic Runner (`rch`-backed)

Use the dedicated script for reproducible runs and artifact manifests:

```bash
./scripts/run_parser_multi_engine_harness.sh ci
```

Modes:

- `check`: compile harness surfaces
- `test`: focused harness unit/integration tests
- `clippy`: focused lint gate (`-D warnings`)
- `report`: produce harness report artifact
- `ci`: check + test + clippy + report

All CPU-intensive Rust operations are routed through `rch exec` when available.

## Artifacts

Each run writes:

- `artifacts/parser_multi_engine_harness/<timestamp>/run_manifest.json`
- `artifacts/parser_multi_engine_harness/<timestamp>/events.jsonl`
- `artifacts/parser_multi_engine_harness/<timestamp>/commands.txt`
- `artifacts/parser_multi_engine_harness/<timestamp>/report.json`
- `artifacts/parser_multi_engine_harness/<timestamp>/repro_packs/<fixture_id>.json`

The report includes per-fixture replay commands:

- `cargo run -p frankenengine-engine --bin franken_parser_multi_engine_harness -- ... --fixture-id <id>`

These replay commands are the source of truth for deterministic reruns of divergence cases.
