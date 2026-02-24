#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

PARSER_ORACLE_PARTITION="nightly" \
PARSER_ORACLE_GATE_MODE="fail_closed" \
PARSER_ORACLE_SEED="${PARSER_ORACLE_SEED:-7}" \
  ./scripts/run_parser_oracle_gate.sh ci

