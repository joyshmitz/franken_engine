# ADR-0001: Control-Plane Primitive Adoption from `/dp/asupersync`

- Status: Accepted
- Date: 2026-02-20
- Owners: FrankenEngine maintainers + 10.11 primitive owners
- Plan references: 10.13 item 1, 10.11 ownership model
- Related beads: `bd-3vlb`, `bd-ypl4`, `bd-2fa1`

## Context

FrankenEngine must consume control-plane primitives from the canonical `/dp/asupersync`
crates and avoid local type forks. Without an explicit decision record, teams can
accidentally introduce duplicate local definitions that break determinism, evidence
linkage, and cross-repo integration.

## Decision

FrankenEngine adopts `/dp/asupersync` as the canonical source for control-plane
primitives. The listed types are imported from canonical crates and are never redefined
inside this repository.

## Canonical Imported Types

| Canonical type | Cargo package | Rust crate path | Canonical ownership track |
| --- | --- | --- | --- |
| `Cx` | `franken-kernel` | `franken_kernel` | 10.11 |
| `TraceId` | `franken-kernel` | `franken_kernel` | 10.11 |
| `Budget` | `franken-kernel` | `franken_kernel` | 10.11 |
| `DecisionId` | `franken-decision` | `franken_decision` | 10.11 |
| `PolicyId` | `franken-decision` | `franken_decision` | 10.11 |
| `SchemaVersion` | `franken-evidence` | `franken_evidence` | 10.11 |

`franken-kernel`/`franken_kernel`, `franken-decision`/`franken_decision`, and
`franken-evidence`/`franken_evidence` are both normative references.

## Version Policy

Version policy for `/dp/asupersync` imports is strict and explicit:

| Cargo package | Allowed range | Pinning policy | Upgrade gate |
| --- | --- | --- | --- |
| `franken-kernel` | `>=0.1.0, <0.2.0` | Lockfile pins exact release | 10.11 owner review + compatibility notes |
| `franken-decision` | `>=0.1.0, <0.2.0` | Lockfile pins exact release | 10.11 owner review + compatibility notes |
| `franken-evidence` | `>=0.1.0, <0.2.0` | Lockfile pins exact release | 10.11 owner review + compatibility notes |

For `0.x` crates, minor-version changes are treated as potentially breaking and require
explicit review before adoption.

## Naming Guidance

Cargo package names and Rust crate paths are both normative, but they are used in
different contexts:

| Context | Required form | Example |
| --- | --- | --- |
| `Cargo.toml` dependency keys and `package` values | Hyphenated package names | `franken-kernel`, `franken-decision`, `franken-evidence` |
| Rust source (`use`, `extern crate`) | Underscored crate paths | `franken_kernel`, `franken_decision`, `franken_evidence` |

Correct `Cargo.toml` examples:

```toml
[dependencies]
franken-kernel = "0.1"
franken-decision = "0.1"
franken-evidence = "0.1"
```

Correct Rust source examples:

```rust
use franken_kernel::Cx;
use franken_decision::{DecisionId, PolicyId};
use franken_evidence::SchemaVersion;
```

Common mistakes (forbidden):

- `Cargo.toml` dependency keys like `franken_kernel = "..."` (underscored package key).
- `package = "franken_kernel"` (underscored package value).
- Rust imports like `use franken-kernel::Cx;` (hyphen in Rust path).

A lint script is provided at `scripts/check_asupersync_naming.sh` and can be wired into
CI to enforce these rules.

## Escalation Path for Missing APIs

If a required primitive is missing upstream:

1. Open an upstream issue in `/dp/asupersync` with required type/contract details.
2. Open or update a local tracking bead that links the upstream issue.
3. Use only a narrow local adapter for call-shape compatibility when unavoidable.
4. Do not fork `/dp/asupersync` crates and do not create local shadow types for
   `Cx`, `TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`, or `Budget`.
5. Merge only after 10.11 primitive-owner sign-off.

## Dependency Policy: No Local Forks

FrankenEngine must not define local substitutes for canonical control-plane types:
`Cx`, `TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`, and `Budget`.

This policy treats all of the following as forbidden local forks:

- `struct` or `type` definitions that reuse those canonical names.
- Newtype wrappers intended to impersonate canonical primitives at integration boundaries.
- Local modules that re-export locally defined substitutes under canonical names.

Canonical crate ownership for these types remains:

- `franken_kernel`: `Cx`, `TraceId`, `Budget`
- `franken_decision`: `DecisionId`, `PolicyId`
- `franken_evidence`: `SchemaVersion`

Enforcement is provided by `scripts/check_no_local_control_plane_type_forks.sh`.
The script blocks new local definitions and supports an explicit baseline allowlist
until legacy names are migrated.

Remediation process for violations:

1. Replace local substitute types with canonical imports from `/dp/asupersync`.
2. Remove legacy allowlist entries when migration is complete.
3. Only keep allowlist entries that are explicitly tracked as migration debt.
4. Do not add new allowlist entries without an ADR amendment and linked bead.

## Non-Goals

- Re-implementing control-plane primitive semantics in `franken_engine`.
- Creating alternate local type systems for canonical control-plane identifiers.

## Consequences

- Positive: deterministic, single-source primitive vocabulary across repos.
- Positive: less drift and easier cross-repo verification for evidence and decisions.
- Cost: integration work may wait on upstream `/dp/asupersync` changes.

## Compliance Signals

- Dependency policy docs and CI checks should enforce no local forked primitive types.
- New integration code should reference this ADR and the companion naming/dependency beads.
