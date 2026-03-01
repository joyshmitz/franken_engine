#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

bootstrap_script="${root_dir}/scripts/e2e/parser_oracle_env_bootstrap.sh"
# shellcheck source=/dev/null
source "$bootstrap_script"
parser_oracle_apply_deterministic_env

matrix_root="${PARSER_ORACLE_MATRIX_ARTIFACT_ROOT:-artifacts/parser_oracle_ci_matrix}"

declare -a matrix_lanes=(
  "smoke:report_only:1"
  "full:fail_closed:1"
  "nightly:fail_closed:7"
)

for lane in "${matrix_lanes[@]}"; do
  IFS=":" read -r partition gate_mode seed <<<"$lane"
  lane_root="${matrix_root}/${partition}_${gate_mode}_seed${seed}"
  echo "==> parser oracle matrix lane partition=${partition} gate_mode=${gate_mode} seed=${seed}"
  PARSER_ORACLE_PARTITION="${partition}" \
  PARSER_ORACLE_GATE_MODE="${gate_mode}" \
  PARSER_ORACLE_SEED="${seed}" \
  PARSER_ORACLE_ARTIFACT_ROOT="${lane_root}" \
    ./scripts/run_parser_oracle_gate.sh ci
done

echo "parser oracle ci matrix complete: ${matrix_root}"
