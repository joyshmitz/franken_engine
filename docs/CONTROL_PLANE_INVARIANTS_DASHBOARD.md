# Control-Plane Invariants Dashboard (`bd-36of`)

Operator-facing invariants dashboard model for Section 10.13 item 19.

## Scope

`ControlPlaneInvariantsDashboardView` in
`crates/franken-engine/src/frankentui_adapter.rs` provides the deterministic
projection consumed by operator surfaces.

The payload is emitted through:

- `AdapterStream::ControlPlaneInvariantsDashboard`
- `FrankentuiViewPayload::ControlPlaneInvariantsDashboard`

Because adapter envelopes are JSON-serializable, the same payload can be
consumed by TUI surfaces and browser clients without plugins.

## Required Panels

The dashboard model includes all required panel groups:

- Evidence stream: `evidence_stream`
- Decision outcomes: `decision_outcomes`
- Obligation status + drill-down rows: `obligation_status`, `obligation_rows`
- Region lifecycle + drill-down rows: `region_lifecycle`, `region_rows`
- Cancellation events: `cancellation_events`
- Replay health: `replay_health`
- Benchmark trends (with threshold lines): `benchmark_trends`
- Safe-mode activations: `safe_mode_activations`
- Schema version: `schema_version`

## Refresh and Real-Time Policy

Refresh cadence is encoded in `DashboardRefreshPolicy` and validated by
`ControlPlaneInvariantsDashboardView::meets_refresh_sla()`:

- evidence stream refresh budget: <= 5 seconds
- aggregate refresh budget: <= 60 seconds

## Filtering and Alerts

Filtering is deterministic via `ControlPlaneDashboardFilter`:

- `extension_id`
- `region_id`
- `severity`
- `start_unix_ms`
- `end_unix_ms`

Alerting is deterministic via `DashboardAlertRule` and
`ControlPlaneInvariantsDashboardView::triggered_alerts()`.

Structured event fields carried through dashboard evidence rows:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Validation Suite

Run the dashboard-focused suite (all heavy work offloaded with `rch`):

```bash
./scripts/run_control_plane_invariants_dashboard_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci` (`check` + `test` + `clippy`)

Optional (off by default because it compiles the full lib-test graph):

```bash
CONTROL_PLANE_INVARIANTS_DASHBOARD_RUN_LIB_VARIANT_TEST=1 \
  ./scripts/run_control_plane_invariants_dashboard_suite.sh test
```

## Reproducibility Artifacts

Each suite run writes:

- `artifacts/control_plane_invariants_dashboard/<timestamp>/commands.txt`
- `artifacts/control_plane_invariants_dashboard/<timestamp>/events.jsonl`
- `artifacts/control_plane_invariants_dashboard/<timestamp>/run_manifest.json`

`run_manifest.json` contains deterministic command history and operator
verification commands for replay.
