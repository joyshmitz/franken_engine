#!/usr/bin/env bash
set -euo pipefail

# Development runner for bd-2rk security conformance scaffolding.
# Use --allow-small-corpus for the seed corpus until the production corpus
# reaches release minimums (>=200 benign, >=100 malicious).

rch exec -- \
  env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_security_conformance \
  cargo run -p frankenengine-engine --bin franken_security_conformance_runner -- \
  --allow-small-corpus \
  "$@"
