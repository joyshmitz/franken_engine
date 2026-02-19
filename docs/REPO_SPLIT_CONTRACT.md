# Repo Split Contract: franken_engine <-> franken_node

## Objective

Keep engine innovation velocity independent from compatibility-product surface work.

- `/dp/franken_engine`: canonical engine internals and extension-host core.
- `/dp/franken_node`: Node/Bun compatibility surface and product packaging.

## Ownership

`franken_engine` owns:
- Execution semantics, policy semantics, decision/replay primitives.
- Engine crate public APIs and versioning.
- Engine-side benchmarks and core correctness proofs.

`franken_node` owns:
- Product CLI/runtime UX and compatibility entrypoints.
- Compatibility harnesses and migration ergonomics.
- Product distribution and integration tests.

## Dependency Direction

Allowed:
- `franken_node` -> `frankenengine-engine`
- `franken_node` -> `frankenengine-extension-host`

Forbidden:
- `franken_engine` -> `franken_node`
- Copy-paste forks of engine crates inside `franken_node`

## Release Cadence

- `franken_engine` may release faster than `franken_node`.
- `franken_node` pins engine versions and advances by explicit upgrade PRs.

## CI Matrix (required)

- Pinned matrix: `franken_node` against pinned engine revision.
- Head matrix: `franken_node` against latest `franken_engine` main.

Both must pass before product release.
