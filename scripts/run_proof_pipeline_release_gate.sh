#!/usr/bin/env bash
set -euo pipefail

# Deterministic release-gate validation for bd-2rx.
# All heavy commands are offloaded via rch.

TARGET_DIR="${TARGET_DIR:-/tmp/rch_target_franken_engine_proof_gate}"

echo "[bd-2rx] Checking rch availability..."
rch status >/dev/null

echo "[bd-2rx] Running proof-release-gate unit tests (offloaded)..."
rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" \
  cargo test -p frankenengine-engine --lib proof_release_gate::tests::

echo "[bd-2rx] Running crate check for compile-active gate module (offloaded)..."
rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" \
  cargo check -p frankenengine-engine --lib

echo "[bd-2rx] Proof pipeline release gate checks completed."
