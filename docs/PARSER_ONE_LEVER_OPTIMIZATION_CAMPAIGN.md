# Parser One-Lever Optimization Campaign Contract (`bd-2mds.1.6.3`)

This contract defines deterministic one-lever optimization campaign semantics
for parser performance work with explicit EV scoring and per-lever attribution.

## Scope

This lane is implemented by:

- `docs/PARSER_ONE_LEVER_OPTIMIZATION_CAMPAIGN.md`
- `crates/franken-engine/tests/fixtures/parser_one_lever_optimization_campaign_v1.json`
- `crates/franken-engine/tests/parser_one_lever_optimization_campaign.rs`
- `scripts/run_parser_one_lever_optimization_campaign.sh`
- `scripts/e2e/parser_one_lever_optimization_campaign_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-one-lever-optimization-campaign.v1`
- `campaign_version`: `1.0.0`
- `metric_schema_version`: `franken-engine.parser-telemetry.v1`

## One-Lever Campaign Semantics

Each campaign run must represent exactly one optimization lever and include:

- lever identifier + category
- deterministic changed-path attribution note
- baseline and candidate metric vectors
- EV score inputs and expected deterministic EV output
- replay command and artifact pointers

Campaign output must include deterministic rankings for:

- EV score ranking
- gain-attribution ranking
- selected lever (top EV, deterministic tie-break by lever id)

## EV Scoring Contract

EV formula:

```text
ev_score = (impact * confidence * reuse) / (effort * friction)
```

Integer execution contract:

- represent EV as millionths (`ev_score_millionths`)
- compute as:
  - numerator = `impact * confidence * reuse * 1_000_000`
  - denominator = `effort * friction`
  - result = `numerator / denominator` (integer floor)

## Gain Attribution Contract

Composite gain for each lever is computed against baseline using deterministic
weighted deltas:

- throughput delta (higher is better): weight `400_000`
- latency p95 delta (lower is better): weight `300_000`
- ns/token delta (lower is better): weight `200_000`
- alloc/token delta (lower is better): weight `100_000`

Weights must sum to `1_000_000`.

## Structured Log Contract

Required keys for emitted events:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Contract

Fixture-driven cross-subsystem replay scenarios must provide:

- one-command replay invocation
- expected pass/fail outcome
- deterministic outcome classification

Canonical replay wrapper:

```bash
./scripts/e2e/parser_one_lever_optimization_campaign_replay.sh
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane must run through `rch`.

Canonical gate command:

```bash
./scripts/run_parser_one_lever_optimization_campaign.sh ci
```

Modes:

- `check`: compile focused campaign test target
- `test`: execute focused campaign tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_one_lever_optimization_campaign/<timestamp>/run_manifest.json`
- `artifacts/parser_one_lever_optimization_campaign/<timestamp>/events.jsonl`
- `artifacts/parser_one_lever_optimization_campaign/<timestamp>/commands.txt`

The manifest must include replay command, deterministic run metadata,
command transcript, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_parser_one_lever_optimization_campaign.sh ci
cat artifacts/parser_one_lever_optimization_campaign/<timestamp>/run_manifest.json
cat artifacts/parser_one_lever_optimization_campaign/<timestamp>/events.jsonl
cat artifacts/parser_one_lever_optimization_campaign/<timestamp>/commands.txt
./scripts/e2e/parser_one_lever_optimization_campaign_replay.sh
```
