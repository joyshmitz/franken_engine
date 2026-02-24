#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

PARSER_PHASE1_ARENA_SCENARIO="budget_failures" \
  ./scripts/run_parser_phase1_arena_suite.sh test
