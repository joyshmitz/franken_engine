# ADR-0003: `/dp/frankentui` as Canonical Advanced Operator TUI Substrate

- Status: Accepted
- Date: 2026-02-20
- Owners: FrankenEngine maintainers + operator UX owners
- Plan references: 10.14 item 1, success criterion 13
- Related beads: `bd-2l0x`, `bd-1ad6`, `bd-1qgn`, `bd-yqg5`

## Context

FrankenEngine has a reuse-first sibling-repo policy and must avoid parallel local
replacements where a stronger substrate already exists. For advanced operator
terminal interfaces, that substrate is `/dp/frankentui`.

Without a binding scope decision, teams can ship multiple local TUI stacks with
inconsistent controls, fragmented UX, and duplicate maintenance burden.

## Decision

FrankenEngine declares `/dp/frankentui` as the canonical substrate for advanced
operator console/TUI surfaces. New advanced operator TUI features must integrate
through `/dp/frankentui` patterns/components unless an explicit exception is
approved.

## Scope

In scope (must use `/dp/frankentui`):

- Operator dashboards.
- Incident/replay viewers.
- Policy explanation cards and control panels.
- Interactive operational state explorers for security/runtime workflows.

Out of scope (does not require `/dp/frankentui`):

- Simple CLI output (tables, plain text, JSON, and non-interactive command output).
- Internal non-operator runtime components.

## Advanced TUI Boundary Definition

An interface is treated as an advanced operator console/TUI surface when it is:

1. Interactive beyond single-command output.
2. Used for operational decision-making, incident handling, or policy/runtime control.
3. Expected to provide consistent operator navigation and state presentation.

If all three are true, `/dp/frankentui` is required.

## Rationale

Centralizing advanced TUI surfaces on `/dp/frankentui` prevents framework
fragmentation, improves consistency across operator workflows, and keeps
cross-repo UX improvements reusable.

This aligns with AGENTS.md sibling reuse policy and `docs/REPO_SPLIT_CONTRACT.md`
reuse expectations.

## Exception Process

When `/dp/frankentui` cannot reasonably satisfy a required surface:

1. Open a tracking bead with explicit mismatch and alternatives.
2. Reference this ADR and describe exact surface scope.
3. Add an exception artifact at `docs/adr/exceptions/ADR-EXCEPTION-TUI-<id>.md`.
4. Exception artifact must include:
   - `Status: Approved`
   - one or more `Scope:` lines (`dependency:<crate>` and/or `module:<path-or-prefix*>`)
   - tracking bead, expiry date, and migration path back to canonical substrate.
5. Obtain maintainer approval before merge.
6. Keep exception time-bounded and reviewed in the next integration cycle.

## Consequences

- Positive: consistent operator experience and lower long-term maintenance cost.
- Positive: reusable improvements across Franken stack terminal surfaces.
- Cost: some feature delivery depends on `/dp/frankentui` compatibility cadence.

## Compliance Signals

- New advanced operator TUI PRs reference this ADR.
- CI/policy guard work (`bd-1qgn`) enforces no parallel local interactive TUI frameworks.
- Adapter boundary work (`bd-1ad6`) maps FrankenEngine needs into `/dp/frankentui`.
