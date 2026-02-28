# Runtime Hotspot Optimization Campaign Contract (`bd-mjh3.6.3`)

This contract defines deterministic one-lever optimization campaign semantics
for runtime-path hotspot work with explicit EV scoring, profile-first evidence,
and per-lever attribution.

## Scope

This lane is implemented by:

- `docs/RUNTIME_HOTSPOT_OPTIMIZATION_CAMPAIGN.md`
- `crates/franken-engine/tests/fixtures/runtime_hotspot_optimization_campaign_v1.json`
- `crates/franken-engine/tests/runtime_hotspot_optimization_campaign.rs`
- `scripts/run_runtime_hotspot_optimization_campaign.sh`
- `scripts/e2e/runtime_hotspot_optimization_campaign_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.runtime-hotspot-optimization-campaign.v1`
- `campaign_version`: `1.0.0`
- `metric_schema_version`: `franken-engine.runtime-hotspot-telemetry.v1`

## Runtime Hotspot Targets

Each campaign run must target exactly one hotspot lever:

- signal propagation scheduler,
- DOM op batching and commit path,
- lane router decision overhead,
- JS↔WASM boundary costs.

Every campaign entry must include:

- a single lever identifier/category,
- deterministic changed-path attribution,
- baseline and candidate metric vectors,
- hotspot profile evidence with baseline share attribution,
- semantic-preservation proof note tied to verification contracts,
- rollback reference and replay command.

## One-Lever Campaign Semantics

Campaign output must include deterministic rankings for:

- EV score ranking,
- gain-attribution ranking,
- selected campaign (top EV, deterministic tie-break by `campaign_id`).

One-lever discipline is fail-closed: multi-lever or profile-free candidates are
rejected from promotion.

## EV Scoring Contract

EV formula:

```text
ev_score = (impact * confidence * reuse) / (effort * friction)
```

Integer execution contract:

- represent EV as millionths (`ev_score_millionths`),
- compute as:
  - numerator = `impact * confidence * reuse * 1_000_000`,
  - denominator = `effort * friction`,
  - result = `numerator / denominator` (integer floor).

## Gain Attribution Contract

Composite gain for each campaign is computed against baseline using
deterministic weighted deltas:

- scheduler propagation latency delta (lower is better): weight `200_000`
- DOM commit batching latency delta (lower is better): weight `200_000`
- lane-router decision overhead delta (lower is better): weight `200_000`
- JS↔WASM boundary overhead delta (lower is better): weight `200_000`
- burst interaction p95 latency delta (lower is better): weight `200_000`

Weights must sum to `1_000_000`.

## Structured Log Contract

Required keys for emitted events:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Contract

Fixture-driven replay scenarios must include:

- normal campaign replay,
- adversarial fail-closed replay,
- recovery replay after rollback.

Canonical replay wrapper:

```bash
./scripts/e2e/runtime_hotspot_optimization_campaign_replay.sh
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane must run through `rch`.

Canonical gate command:

```bash
./scripts/run_runtime_hotspot_optimization_campaign.sh ci
```

Modes:

- `check`: compile focused campaign test target,
- `test`: execute focused campaign tests,
- `clippy`: lint focused target with `-D warnings`,
- `ci`: check + test + clippy.

## Required Artifacts

Each run emits:

- `artifacts/runtime_hotspot_optimization_campaign/<timestamp>/run_manifest.json`
- `artifacts/runtime_hotspot_optimization_campaign/<timestamp>/events.jsonl`
- `artifacts/runtime_hotspot_optimization_campaign/<timestamp>/commands.txt`

The manifest must include replay command, deterministic run metadata, command
transcript, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_runtime_hotspot_optimization_campaign.sh ci
cat artifacts/runtime_hotspot_optimization_campaign/<timestamp>/run_manifest.json
cat artifacts/runtime_hotspot_optimization_campaign/<timestamp>/events.jsonl
cat artifacts/runtime_hotspot_optimization_campaign/<timestamp>/commands.txt
./scripts/e2e/runtime_hotspot_optimization_campaign_replay.sh
```
