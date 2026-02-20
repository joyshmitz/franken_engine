# ADR-0002: `/dp/fastapi_rust` Reuse Scope for FrankenEngine Service/API Surfaces

- Status: Accepted
- Date: 2026-02-20
- Owners: FrankenEngine maintainers + service/API integration owners
- Plan references: 10.14 item 10, success criterion 13
- Related beads: `bd-26qa`, `bd-3o95`, `bd-yqg5`

## Context

FrankenEngine reuses sibling repositories when they provide stronger substrate
contracts than local reimplementation. For service/API control surfaces, that
substrate is `/dp/fastapi_rust`.

Without an explicit scope boundary, endpoint work can drift between
incompatible conventions and ad-hoc implementations, which weakens operator
ergonomics, observability, and cross-repo integration.

## Decision

FrankenEngine adopts `/dp/fastapi_rust` conventions/components as the default
for runtime service/API control surfaces. Reuse is mandatory for the endpoint
classes listed below unless an explicit exception is approved.

## In-Scope Endpoint Classes

The following endpoint families must use `/dp/fastapi_rust` patterns/components:

| Endpoint class | Minimum reuse requirement |
| --- | --- |
| Health checks | Shared route shape, readiness/liveness semantics, and error envelope |
| Control actions (`start`/`stop`/`quarantine`) | Shared request/response contracts, auth middleware, and audit field conventions |
| Evidence export APIs | Shared pagination/filter patterns and deterministic error responses |
| Replay control APIs | Shared action routing conventions and structured failure payloads |
| Benchmark result APIs | Shared result transport conventions, metadata envelope, and status handling |

## Out-of-Scope Interfaces

The following are explicitly out of scope for this ADR:

- Internal RPC between engine components.
- VM hot-path communication or execution-lane internals.
- Local-only in-process call paths that are not exposed as service/API surfaces.

Out-of-scope paths must still obey FrankenEngine determinism, evidence, and
error-code contracts, but they are not required to adopt `/dp/fastapi_rust`
HTTP/service conventions.

## Required `fastapi_rust` Conventions and Components

For in-scope endpoints, reuse means alignment with the following categories:

1. Route and versioning conventions (stable path layout and method semantics).
2. Error response envelope and status-code mapping.
3. Authentication/authorization middleware patterns.
4. Request correlation and structured logging field conventions.
5. Shared pagination/filter/query conventions where applicable.

Implementation details can be adapted in Rust, but externally visible contracts
must preserve equivalent behavior.

## Exception Process

If `/dp/fastapi_rust` conventions do not fit a specific endpoint:

1. Open a local tracking bead with explicit mismatch rationale and alternatives.
2. Link this ADR and identify the exact endpoint scope.
3. Document proposed divergence, including compatibility and operator impact.
4. Define rollback/remediation path to return to canonical reuse posture.
5. Require maintainer approval before merge.

Exceptions are time-bounded and must be revisited in the next integration cycle.

## Review Gate

Every new or materially changed in-scope service endpoint must:

1. Reference this ADR in its PR/implementation notes.
2. State whether `/dp/fastapi_rust` reuse is direct or adapted.
3. If diverging, link an approved exception record.

Changes that skip this gate are non-compliant.

## Non-Goals

- Replacing FrankenEngine runtime internals with `/dp/fastapi_rust`.
- Forcing `/dp/fastapi_rust` conventions onto non-service in-process paths.

## Consequences

- Positive: unified service/API operator surface and lower integration drift.
- Positive: clearer review expectations for reuse versus reimplementation.
- Cost: endpoint work may wait on `/dp/fastapi_rust` compatibility updates.

## Compliance Signals

- Endpoint PRs reference this ADR and declare reuse/exception status.
- Service integration templates (`bd-3o95`) inherit this boundary by default.
- Release checklist includes explicit reuse-vs-reimplement justification (`bd-yqg5`).
