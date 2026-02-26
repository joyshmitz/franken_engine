# Semantic Twin State Space Contract (`bd-mjh3.19.1`)

This document defines the FRX-19.1 semantic twin contract implemented in
`crates/franken-engine/src/semantic_twin.rs`.

## Scope

The semantic twin models lane/router decision effects with:

1. A deterministic state-space dictionary mapped to concrete runtime/FRIR signals.
2. A transition relation over those variables.
3. Causal adjustment strategy for key treatment→outcome effects.
4. Explicit identifiability assumptions with falsification monitors.

## Versioned Schemas

- State space: `franken-engine.semantic-twin.state-space.v1`
- Causal adjustment: `franken-engine.semantic-twin.causal-adjustment.v1`
- Log event: `franken-engine.semantic-twin.log-event.v1`

## Core Effects

The canonical effects tracked by this contract are:

- `effect_lane_choice_to_latency`
- `effect_lane_choice_to_correctness`

For each effect, the twin computes a backdoor adjustment set from the structural
causal model (`build_lane_decision_dag`) and stores the blocking strategy in the
specification.

## Telemetry Mapping

State variables are bound to deterministic signal namespaces:

- `frir`: workload profile metrics and witness linkage coverage.
- `runtime_decision_core`: risk posterior, lane choice, calibration metrics.
- `runtime_observability`: load/regime observability and outcome signals.
- `policy_controller`: loss matrix settings.
- `assumptions_ledger`: monitor/falsification state.

This mapping is validated at runtime (`SemanticTwinSpecification::validate`) and
fails fast if signal keys or units are missing.

## Identifiability Assumptions

The FRX-19.1 assumptions registry includes monitor contracts for:

- regime observability coverage,
- bounded environment-load drift,
- bounded risk-calibration error,
- FRIR witness linkage completeness.

Each assumption is compiled into `AssumptionLedger` entries +
`FalsificationMonitor`s. Violations produce deterministic demotion actions and
structured log events with stable fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Verification Commands (RCH-backed)

```bash
./scripts/run_semantic_twin_state_space_gate.sh ci
```

This gate executes semantic twin checks/tests/clippy through `rch`.
