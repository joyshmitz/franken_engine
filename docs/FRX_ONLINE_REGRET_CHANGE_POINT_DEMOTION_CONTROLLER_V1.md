# FRX Online Regret + Change-Point Demotion Controller v1

## Scope
This contract defines FRX-15.3 operational guarantees for continuously running
regret/change-point monitors that deterministically trigger conservative
fallback when the adaptive lane leaves its safety envelope.

## Inputs
The controller consumes per-round monitor outputs from existing runtime
surfaces:

- `regret_bounded_router`: realized regret, theoretical regret bound,
  exact-regret availability
- `hybrid_lane_router`: CUSUM change-point signal and demotion traces
- `runtime_decision_core`: calibration coverage and CVaR tail-risk evaluation

## Deterministic Threshold Policy
FRX-15.3 requires fixed, replay-stable thresholding:

1. Regret breach predicate:
   - exact-regret mode required
   - `realized_regret_millionths > min(theoretical_bound, policy_bound)`
2. Change-point breach predicate:
   - `cusum_stat_millionths > change_point_threshold_millionths`
3. Tail-risk breach predicate:
   - `cvar_us > max_cvar_us`
4. Calibration breach predicate:
   - `empirical_coverage_millionths < target_coverage_millionths`

No floating-point runtime decisions are allowed for breach predicates.

## Demotion Semantics
Demotion is fail-closed and deterministic:

- Regret/change-point breaches cause conservative demotion after policy-defined
  consecutive breach thresholds.
- Tail-risk (`CVaR`) and calibration undercoverage are immediate fail-closed
  demotion triggers.
- Demotion target lane is conservative/safe-mode compatible and replay-stable.

## Structured Event Contract
Every demotion decision must emit structured events with stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

FRX-15.3 also requires deterministic demotion reason metadata including regret,
change-point, calibration, and tail-risk terms used at decision time.

## Incident Artifact Requirements
Each gate run must emit replayable artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

These artifacts are authoritative for closeout and independent replay.

## Gate Commands
- `./scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh ci`
- `./scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh`

## Failure Policy
Fail-closed. Missing monitor artifacts, missing structured logs, or breached
thresholds without demotion evidence block promotion.
