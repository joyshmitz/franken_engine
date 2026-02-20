## Summary

Describe the change and why it is needed.

## Validation

- [ ] `rch exec -- ... cargo fmt --check`
- [ ] `rch exec -- ... cargo check --all-targets`
- [ ] `rch exec -- ... cargo test`
- [ ] `rch exec -- ... cargo clippy --all-targets -- -D warnings`

## Reuse Vs Reimplement

- [ ] Does this PR introduce new TUI/SQLite/service infrastructure?
- [ ] If yes, I documented the reuse vs reimplement decision and linked ADR/exception evidence.

Use this table when the answer is yes:

| Category | Canonical sibling repo | Decision (reuse/reimplement) | Required ADR | Exception artifact link | Justification link |
| --- | --- | --- | --- | --- | --- |
| Operator TUI surface | `/dp/frankentui` | | `ADR-0003` | | |
| SQLite persistence path | `/dp/frankensqlite` | | `ADR-0004` | | |
| Service/API control surface | `/dp/fastapi_rust` | | `ADR-0002` | | |

Rule:
- Any `reimplement` decision must include both an approved exception artifact link and a written justification link.
