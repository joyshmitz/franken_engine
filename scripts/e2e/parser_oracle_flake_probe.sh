#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

bootstrap_script="${root_dir}/scripts/e2e/parser_oracle_env_bootstrap.sh"
# shellcheck source=/dev/null
source "$bootstrap_script"
parser_oracle_apply_deterministic_env

iterations="${PARSER_ORACLE_FLAKE_PROBE_RUNS:-3}"
seed="${PARSER_ORACLE_SEED:-1}"
probe_root="${PARSER_ORACLE_FLAKE_PROBE_ARTIFACT_ROOT:-artifacts/parser_oracle_flake_probe}"

if [[ "$iterations" -lt 2 ]]; then
  echo "PARSER_ORACLE_FLAKE_PROBE_RUNS must be >= 2" >&2
  exit 2
fi

reference_sha=""
for run_index in $(seq 1 "$iterations"); do
  run_root="${probe_root}/run_${run_index}"
  log_path="$(mktemp)"
  echo "==> parser oracle flake probe run=${run_index}/${iterations} seed=${seed}"
  if ! PARSER_ORACLE_PARTITION="smoke" \
    PARSER_ORACLE_GATE_MODE="report_only" \
    PARSER_ORACLE_SEED="${seed}" \
    PARSER_ORACLE_ARTIFACT_ROOT="${run_root}" \
    ./scripts/run_parser_oracle_gate.sh ci | tee "$log_path"; then
    rm -f "$log_path"
    echo "flake probe failed on run ${run_index}" >&2
    exit 1
  fi

  manifest_path="$(rg -o 'parser oracle gate manifest: .*' "$log_path" | tail -n1 | sed 's/^parser oracle gate manifest: //')"
  rm -f "$log_path"
  if [[ -z "$manifest_path" || ! -f "$manifest_path" ]]; then
    echo "unable to locate parser oracle manifest for run ${run_index}" >&2
    exit 1
  fi

  relation_report_path="$(jq -r '.artifacts.relation_report' "$manifest_path")"
  if [[ ! -f "$relation_report_path" ]]; then
    echo "relation report missing for run ${run_index}: ${relation_report_path}" >&2
    exit 1
  fi

  current_sha="$(sha256sum "$relation_report_path" | awk '{print $1}')"
  if [[ -z "$reference_sha" ]]; then
    reference_sha="$current_sha"
    continue
  fi
  if [[ "$current_sha" != "$reference_sha" ]]; then
    echo "nondeterministic relation report digest detected at run ${run_index}" >&2
    echo "expected=${reference_sha}" >&2
    echo "actual=${current_sha}" >&2
    exit 1
  fi
done

echo "parser oracle flake probe passed: digest=${reference_sha} runs=${iterations}"
