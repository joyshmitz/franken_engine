#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_multi_engine_harness}"
artifact_root="${PARSER_MULTI_ENGINE_HARNESS_ARTIFACT_ROOT:-artifacts/parser_multi_engine_harness}"
fixture_catalog="${PARSER_MULTI_ENGINE_FIXTURE_CATALOG:-crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json}"
fixture_limit="${PARSER_MULTI_ENGINE_FIXTURE_LIMIT:-8}"
fixture_id="${PARSER_MULTI_ENGINE_FIXTURE_ID:-}"
seed="${PARSER_MULTI_ENGINE_SEED:-7}"
fail_on_divergence="${PARSER_MULTI_ENGINE_FAIL_ON_DIVERGENCE:-0}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.json"
repro_packs_dir="${run_dir}/repro_packs"

trace_id="trace-parser-multi-engine-harness-${timestamp}"
decision_id="decision-parser-multi-engine-harness-${timestamp}"
policy_id="policy-parser-multi-engine-harness-v1"
component="parser_multi_engine_harness"

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
  local report_stdout_clean_path="${run_dir}/report.stdout.clean"
  local -a command=(
    cargo run -p frankenengine-engine --bin franken_parser_multi_engine_harness -- \
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
  run_rch "${command[@]}" 2>&1 | tee "$report_stdout_path"
  local rc=$?
  set -e

  # Normalize ANSI/control sequences so JSON extraction works with colored rch output.
  sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$report_stdout_path" >"$report_stdout_clean_path"

  if [[ ! -f "$report_path" && -s "$report_stdout_path" ]]; then
    if jq -e '.' "$report_stdout_clean_path" >/dev/null 2>&1; then
      cp "$report_stdout_clean_path" "$report_path"
    else
      local extracted_json_path="${run_dir}/report.stdout.extracted.json"
      awk '
        BEGIN { capture=0 }
        /^[[:space:]]*\{/ { capture=1 }
        capture { print }
      ' "$report_stdout_clean_path" >"$extracted_json_path"
      if [[ -s "$extracted_json_path" ]] && jq -e '.' "$extracted_json_path" >/dev/null 2>&1; then
        cp "$extracted_json_path" "$report_path"
      fi
    fi
  fi

  if [[ "$rc" -ne 0 ]]; then
    failed_command="$command_text"
    return "$rc"
  fi

  if [[ ! -f "$report_path" ]]; then
    failed_command="${command_text} (report artifact missing)"
    return 4
  fi

  if ! jq -e '.summary and .parser_telemetry and .schema_version' "$report_path" >/dev/null 2>&1; then
    failed_command="${command_text} (report artifact invalid)"
    return 5
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
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration" \
        cargo check -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration \
        || return $?
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test parser_multi_engine_harness_integration" \
        cargo test -p frankenengine-engine --test parser_multi_engine_harness_integration \
        || return $?
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration -- -D warnings \
        || return $?
      ;;
    report)
      run_report_step || return $?
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration" \
        cargo check -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration \
        || return $?
      run_step "cargo test -p frankenengine-engine --test parser_multi_engine_harness_integration" \
        cargo test -p frankenengine-engine --test parser_multi_engine_harness_integration \
        || return $?
      run_step "cargo clippy -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_parser_multi_engine_harness --test parser_multi_engine_harness_integration -- -D warnings \
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
    error_code_json='"FE-PARSER-MULTI-ENGINE-HARNESS-0001"'
  fi

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"harness_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json},\"divergent_fixtures\":${divergent_fixtures},\"nondeterministic_fixtures\":${nondeterministic_fixtures}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-multi-engine-harness.run-manifest.v1",'
    echo '  "bead_id": "bd-2mds.1.2.4.1",'
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

  echo "parser multi-engine harness manifest: $manifest_path"
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
