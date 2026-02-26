# FRX Track D WASM Lane + Hybrid Router Sprint Charter v1

Status: active
Primary bead: bd-mjh3.11.4
Track id: FRX-11.4
Machine-readable contract: `docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json`

## Charter Scope

Track D owns the high-load WASM execution lane and hybrid router policy layer
that arbitrates lane selection under explicit safety controls.

This track defines deterministic execution and trace artifacts for WASM lane
runs, router calibration checkpoints, conservative override behavior, and
failover events required for replay/audit.

## Decision Rights

This track can:

1. Approve or reject WASM scheduler/ABI contract changes that affect runtime
   determinism.
2. Approve or reject hybrid router calibration updates and override thresholds.
3. Trigger conservative override when calibration or risk evidence is missing.
4. Block promotion until verification and governance signoff artifacts are
   present.

## Responsibilities

1. Keep wasm scheduler determinism stable under repeated seeded runs.
2. Enforce ABI overhead budget measurement and publication in gate artifacts.
3. Emit hybrid router calibration snapshots and decision-trace linkage.
4. Emit deterministic fallback events and replay linkage for demotions/failover.
5. Fail closed when required routing or signoff artifacts are missing.

## Inputs

- Track C semantic parity baseline and lane trace linkage schema.
- Runtime kernel ownership contract from FRX-10.3.
- Verification lane threshold policy and governance signoff requirements.
- Router calibration priors and ABI overhead budget policy.

## Outputs

- WASM lane execution artifact bundle with scheduler and ABI evidence.
- Router decision artifacts with calibration and conservative override data.
- Deterministic failover event stream with replay command linkage.
- Promotion signoff packet with verification and governance signoff artifacts.

## WASM Scheduler and ABI Contract

1. WASM scheduler ordering must be deterministic for identical seeded inputs.
2. ABI operations must carry stable per-cycle identifiers and trace linkage.
3. ABI overhead budget violations are hard blockers for promotion.
4. Queue/signal limits must degrade via explicit safe-mode behavior.

## Hybrid Router Calibration and Safety Override Contract

1. Hybrid router calibration must be recorded in deterministic snapshots.
2. Conservative override is mandatory when calibration confidence regresses.
3. Every router decision must emit lane choice, override reason, and policy
   linkage fields.
4. Router demotions must emit deterministic fallback events.

## Deterministic Replay and Failover Contract

1. Demotion and failover transitions must emit replay linkage fields.
2. Failover events must include deterministic cause classification.
3. Replay commands must be present in every blocking artifact bundle.
4. Missing replay linkage is a fail-closed promotion blocker.

## Promotion Signoff and Governance Artifacts

1. Promotion from this track requires verification and governance signoff
   artifacts.
2. Missing signoff artifacts force conservative mode and promotion rejection.
3. Signoff packet must include artifact IDs and rerun/replay commands.
4. Governance exceptions require explicit waiver IDs and expiration.

## Interface Contracts

1. Track E consumes router/failover artifacts for verification gate decisions.
2. Governance/evidence lanes consume signoff packet and failure rationale.
3. Toolchain/adoption lanes consume replay commands and ABI budget summaries.
4. Track D consumes Track C trace schema as the baseline integration contract.
