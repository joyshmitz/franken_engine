#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

fixture_id=""
previous_digest=""
next_digest=""
run_id=""
signer=""
signature=""
rationale=""
out_dir="crates/franken-engine/tests/artifacts/golden-updates"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture-id)
      fixture_id="${2:-}"
      shift 2
      ;;
    --previous-digest)
      previous_digest="${2:-}"
      shift 2
      ;;
    --next-digest)
      next_digest="${2:-}"
      shift 2
      ;;
    --run-id)
      run_id="${2:-}"
      shift 2
      ;;
    --signer)
      signer="${2:-}"
      shift 2
      ;;
    --signature)
      signature="${2:-}"
      shift 2
      ;;
    --rationale)
      rationale="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

for required in fixture_id previous_digest next_digest run_id signer signature rationale; do
  if [[ -z "${!required}" ]]; then
    echo "missing required value: $required" >&2
    exit 2
  fi
done

update_material="$fixture_id:$previous_digest:$next_digest:$signer:$signature:$rationale"
update_id="$(printf '%s' "$update_material" | sha256sum | awk '{print $1}')"

safe_fixture_id="$(printf '%s' "$fixture_id" | tr -c '[:alnum:]_-' '-')"
mkdir -p "$out_dir"
out_path="$out_dir/${safe_fixture_id}-${update_id}.json"

cat >"$out_path" <<JSON
{
  "update_id": "$update_id",
  "fixture_id": "$fixture_id",
  "previous_digest": "$previous_digest",
  "next_digest": "$next_digest",
  "source_run_id": "$run_id",
  "signer": "$signer",
  "signature": "$signature",
  "rationale": "$rationale"
}
JSON

echo "$out_path"

