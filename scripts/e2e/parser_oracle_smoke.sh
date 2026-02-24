#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

PARSER_ORACLE_PARTITION="smoke" \
PARSER_ORACLE_GATE_MODE="report_only" \
PARSER_ORACLE_SEED="${PARSER_ORACLE_SEED:-1}" \
  ./scripts/run_parser_oracle_gate.sh ci

