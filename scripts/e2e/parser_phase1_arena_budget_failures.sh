#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

PARSER_PHASE1_ARENA_SCENARIO="budget_failures" \
  ./scripts/run_parser_phase1_arena_suite.sh test
