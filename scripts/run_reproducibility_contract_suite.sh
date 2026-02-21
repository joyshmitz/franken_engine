#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-default}"
component="reproducibility_contract"
bead_id="bd-2u0"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="artifacts/reproducibility_contract/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/reproducibility_contract_events.jsonl"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- "$@"
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  if ! run_rch "$@"; then
    failed_command="$command_text"
    return 1
  fi
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test reproducibility_contract" \
    cargo check -p frankenengine-engine --test reproducibility_contract
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test reproducibility_contract" \
    cargo test -p frankenengine-engine --test reproducibility_contract
}

run_clippy() {
  run_step "cargo clippy -p frankenengine-engine --test reproducibility_contract -- -D warnings" \
    cargo clippy -p frankenengine-engine --test reproducibility_contract -- -D warnings
}

run_mode() {
  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    clippy)
      run_clippy
      ;;
    ci)
      run_check
      run_test
      run_clippy
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
  else
    outcome="fail"
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"${run_dir}/commands.txt"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.reproducibility-contract.run-manifest.v1",'
    echo "  \"component\": \"${component}\","
    echo "  \"bead_id\": \"${bead_id}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "artifacts": {'
    echo "    \"command_log\": \"${run_dir}/commands.txt\","
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo '    "bundle_contract": ['
    echo '      "docs/REPRODUCIBILITY_CONTRACT.md",'
    echo '      "docs/REPRODUCIBILITY_CONTRACT_TEMPLATE.md",'
    echo '      "docs/templates/env.json.template",'
    echo '      "docs/templates/manifest.json.template",'
    echo '      "docs/templates/repro.lock.template",'
    echo '      "crates/franken-engine/tests/reproducibility_contract.rs"'
    echo '    ]'
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"

  {
    echo "{\"trace_id\":\"trace-repro-contract-${timestamp}\",\"decision_id\":\"decision-repro-contract-${timestamp}\",\"policy_id\":\"policy-repro-contract-v1\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":$( [[ -n "$failed_command" ]] && echo '\"FE-REPRO-0006\"' || echo 'null' )}"
  } >"${events_path}"

  echo "reproducibility contract run manifest: ${manifest_path}"
  echo "reproducibility contract events: ${events_path}"
}

trap 'write_manifest $?' EXIT
run_mode
