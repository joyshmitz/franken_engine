# FRX Canonical React Behavior Corpus v1

Status: active
Primary bead: bd-mjh3.2.1
Machine-readable contract: `docs/frx_canonical_react_behavior_corpus_v1.json`

## Scope

Define and gate the canonical React behavior corpus used by FRX semantics and
runtime lanes. The corpus captures observable behavior for high-risk semantics
that must remain stable under optimization and fallback transitions.

## Corpus Layout

- Fixture corpus: `crates/franken-engine/tests/conformance/frx_react_corpus/fixtures`
- Trace corpus: `crates/franken-engine/tests/conformance/frx_react_corpus/traces`
- Pairing rule: each `*.fixture.json` has exactly one matching `*.trace.json`
  by `fixture_ref` and `scenario_id`.

Required semantic classes in the corpus:
- hooks ordering and reducer/context transitions
- concurrent transitions and suspense reveal behavior
- hydration server/client mismatch handling
- error boundary capture and recovery
- portal/ref forwarding and event propagation/stop rules
- effect lifecycle cleanup semantics and state batching behavior

## Determinism and Replay Contract

1. Fixture schema version is `frx.react.fixture.v1`.
2. Trace schema version is `frx.react.observable.trace.v1`.
3. Every trace carries deterministic identifiers and replay seed.
4. Event sequence numbers are strictly increasing.
5. Event timing values are monotonic per trace.
6. Missing fixture/trace pairs are gate failures.

## Observable Trace Contract

Each trace includes stable governance and replay linkage fields:
- `trace_id`
- `decision_id`
- `policy_id`
- `scenario_id`
- `fixture_ref`
- `seed`
- per-event `phase`, `actor`, `event`, `decision_path`, `timing_us`, `outcome`

## CI Gate and Failure Policy

The FRX-02.1 corpus gate is fail-closed.

Gate command:
- `scripts/run_frx_canonical_react_behavior_corpus_suite.sh ci`

Failure conditions (non-exhaustive):
- schema drift from the declared fixture/trace schema versions
- missing or duplicated fixture references
- fixture/trace scenario mismatch
- non-monotonic event sequence or timing
- missing required semantic-focus coverage tags

Failure code:
- `FE-FRX-02-1-CORPUS-GATE-0001`

## Operator Verification

1. Run CI gate:
   - `./scripts/run_frx_canonical_react_behavior_corpus_suite.sh ci`
2. Replay test lane:
   - `./scripts/e2e/frx_canonical_react_behavior_corpus_replay.sh`
3. Inspect generated artifacts:
   - `artifacts/frx_canonical_react_behavior_corpus/<timestamp>/run_manifest.json`
   - `artifacts/frx_canonical_react_behavior_corpus/<timestamp>/events.jsonl`
   - `artifacts/frx_canonical_react_behavior_corpus/<timestamp>/commands.txt`
