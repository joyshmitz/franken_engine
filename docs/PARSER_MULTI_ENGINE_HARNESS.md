# Parser Multi-Engine Harness (`bd-2mds.1.2.1`)

Deterministic comparison harness for parser outputs across multiple engines under a controlled environment (`LC_ALL=C`, `TZ=UTC`) with reproducible manifests and one-command replay paths per fixture.

## Scope

The harness is implemented in:

- `crates/franken-engine/src/parser_multi_engine_harness.rs`
- `crates/franken-engine/src/bin/franken_parser_multi_engine_harness.rs`

It compares fixture outcomes across:

- `franken_canonical` (native scalar-reference parser)
- `fixture_expected_hash` (catalog baseline oracle)
- optional `external_command` engines (e.g., Boa/peer parser wrappers)

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

The report includes per-fixture replay commands:

- `cargo run -p frankenengine-engine --bin franken_parser_multi_engine_harness -- ... --fixture-id <id>`

These replay commands are the source of truth for deterministic reruns of divergence cases.
