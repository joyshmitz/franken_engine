# FrankenEngine Release Checklist

This checklist is a release gate artifact. A release is blocked until every item
below is satisfied or an approved, linked exception is present.

## Core Validation Gate

- [ ] `rch exec -- ... cargo fmt --check`
- [ ] `rch exec -- ... cargo check --all-targets`
- [ ] `rch exec -- ... cargo test`
- [ ] `rch exec -- ... cargo clippy --all-targets -- -D warnings`
- [ ] Reproducibility artifacts recorded per `docs/REPRODUCIBILITY_CONTRACT.md`

## Reuse Vs Reimplement Decisions

Record every release-scope PR that introduces new infrastructure in one of the
tracked categories.

| PR/Change | Category | Canonical sibling repo | Decision (reuse/reimplement) | ADR / exception reference | Exception artifact link | Justification link |
| --- | --- | --- | --- | --- | --- | --- |
| | Operator TUI surface | `/dp/frankentui` | | `ADR-0003` | | |
| | SQLite persistence path | `/dp/frankensqlite` | | `ADR-0004` | | |
| | Service/API control surface | `/dp/fastapi_rust` | | `ADR-0002` | | |

### Validation Rules

1. If a release includes a new TUI, SQLite, or service/API infrastructure path,
the table above must include an entry for that change.
2. `Decision (reuse/reimplement)` is required for every entry.
3. Any `reimplement` entry must include:
   - an approved ADR exception reference
   - an exception artifact link
   - a written justification link
4. Release gate fails if any reimplement decision lacks exception or justification evidence.

## Sign-Off

- [ ] Release owner reviewed all reuse/reimplement entries.
- [ ] Governance reviewer confirmed ADR/exception traceability.
