#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_lockstep_runner_suite}"
artifact_root="${LOCKSTEP_RUNNER_ARTIFACT_ROOT:-artifacts/lockstep_runner}"
fixture_catalog="${LOCKSTEP_RUNNER_FIXTURE_CATALOG:-crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json}"
fixture_limit="${LOCKSTEP_RUNNER_FIXTURE_LIMIT:-8}"
fixture_id="${LOCKSTEP_RUNNER_FIXTURE_ID:-}"
seed="${LOCKSTEP_RUNNER_SEED:-7}"
fail_on_divergence="${LOCKSTEP_RUNNER_FAIL_ON_DIVERGENCE:-0}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.json"
repro_packs_dir="${run_dir}/repro_packs"

trace_id="trace-lockstep-runner-${timestamp}"
decision_id="decision-lockstep-runner-${timestamp}"
policy_id="policy-lockstep-runner-v1"
component="lockstep_runner_suite"

mkdir -p "$run_dir"

run_rch() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
  else
    echo "warning: rch not found; running locally" >&2
    env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
divergent_fixtures=0
nondeterministic_fixtures=0
repro_pack_fixtures=0

run_step() {
  local command_text="$1"
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"
  set +e
  run_rch "$@"
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi
}

run_report_step() {
  local report_stdout_path="${run_dir}/report.stdout"
  local -a command=(
    cargo run -p frankenengine-engine --bin franken_lockstep_runner -- \
      --fixture-catalog "$fixture_catalog" \
      --fixture-limit "$fixture_limit" \
      --seed "$seed" \
      --trace-id "$trace_id" \
      --decision-id "$decision_id" \
      --policy-id "$policy_id" \
      --locale C \
      --timezone UTC \
      --out "$report_path"
  )

  if [[ -n "$fixture_id" ]]; then
    command+=(--fixture-id "$fixture_id")
  fi
  if [[ "$fail_on_divergence" == "1" ]]; then
    command+=(--fail-on-divergence)
  fi

  local command_text
  command_text="$(printf '%q ' "${command[@]}")"
  command_text="${command_text% }"
  commands_run+=("$command_text")
  echo "==> $command_text"

  set +e
  run_rch "${command[@]}" | tee "$report_stdout_path"
  local rc=$?
  set -e

  if [[ ! -f "$report_path" && -s "$report_stdout_path" ]]; then
    if jq -e '.' "$report_stdout_path" >/dev/null 2>&1; then
      cp "$report_stdout_path" "$report_path"
    else
      local extracted_json_path="${run_dir}/report.stdout.extracted.json"
      awk '
        BEGIN { capture=0 }
        /^\{/ { capture=1 }
        capture { print }
      ' "$report_stdout_path" >"$extracted_json_path"
      if [[ -s "$extracted_json_path" ]] && jq -e '.' "$extracted_json_path" >/dev/null 2>&1; then
        cp "$extracted_json_path" "$report_path"
      fi
    fi
  fi

  if [[ -f "$report_path" ]]; then
    divergent_fixtures="$(jq -r '.summary.divergent_fixtures // 0' "$report_path")"
    nondeterministic_fixtures="$(jq -r '.summary.fixtures_with_nondeterminism // 0' "$report_path")"
    repro_pack_fixtures="$(jq -r '[.fixture_results[] | select(.repro_pack != null)] | length' "$report_path")"
    mkdir -p "$repro_packs_dir"
    jq -c '.fixture_results[] | select(.repro_pack != null) | .repro_pack' "$report_path" \
      | while IFS= read -r repro_json; do
          fixture_key="$(jq -r '.fixture_id' <<<"$repro_json")"
          jq '.' <<<"$repro_json" >"${repro_packs_dir}/${fixture_key}.json"
        done
  fi

  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli" \
        cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test franken_lockstep_runner_cli" \
        cargo test -p frankenengine-engine --test franken_lockstep_runner_cli \
        || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings \
        || return $?
      ;;
    report)
      run_report_step || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli" \
        cargo check -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli \
        || return $?
      run_step "cargo test -p frankenengine-engine --test franken_lockstep_runner_cli" \
        cargo test -p frankenengine-engine --test franken_lockstep_runner_cli \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_lockstep_runner --test franken_lockstep_runner_cli -- -D warnings \
        || return $?
      run_report_step || return $?
      ;;
    *)
      echo "usage: $0 [check|test|clippy|report|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-LOCKSTEP-RUNNER-SUITE-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"divergent_fixtures\":${divergent_fixtures},\"nondeterministic_fixtures\":${nondeterministic_fixtures}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.lockstep-runner-suite.run-manifest.v1",'
    echo '  "bead_id": "bd-2vu",'
    echo "  \"component\": \"${component}\","
    echo "  \"mode\": \"${mode}\","
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"fixture_catalog\": \"${fixture_catalog}\","
    echo "  \"fixture_limit\": \"${fixture_limit}\","
    echo "  \"fixture_id\": \"${fixture_id}\","
    echo "  \"seed\": ${seed},"
    echo "  \"fail_on_divergence\": ${fail_on_divergence},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    echo "  \"divergent_fixtures\": ${divergent_fixtures},"
    echo "  \"nondeterministic_fixtures\": ${nondeterministic_fixtures},"
    echo "  \"repro_pack_fixtures\": ${repro_pack_fixtures},"
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
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"report\": \"${report_path}\","
    echo "    \"repro_packs_dir\": \"${repro_packs_dir}\""
    echo "  },"
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${events_path}\","
    echo "    \"cat ${report_path}\","
    echo "    \"ls ${repro_packs_dir}\","
    echo "    \"${0} report\""
    echo "  ]"
    echo "}"
  } >"$manifest_path"

  echo "lockstep runner suite manifest: $manifest_path"
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
