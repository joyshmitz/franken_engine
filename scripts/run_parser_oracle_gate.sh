#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_parser_oracle_gate}"
artifact_root="${PARSER_ORACLE_ARTIFACT_ROOT:-artifacts/parser_oracle}"
partition="${PARSER_ORACLE_PARTITION:-smoke}"
gate_mode="${PARSER_ORACLE_GATE_MODE:-report_only}"
seed="${PARSER_ORACLE_SEED:-1}"
fixture_catalog="${PARSER_ORACLE_FIXTURE_CATALOG:-crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
baseline_path="${run_dir}/baseline.json"
relation_report_path="${run_dir}/relation_report.json"
relation_events_path="${run_dir}/relation_events.jsonl"
evidence_path="${run_dir}/metamorphic_evidence.jsonl"
failures_dir="${run_dir}/minimized_failures"
golden_checksums_path="${run_dir}/golden_checksums.txt"
proof_note_path="${run_dir}/proof_note.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"

trace_id="trace-parser-oracle-${timestamp}"
decision_id="decision-parser-oracle-${timestamp}"
policy_id="policy-parser-oracle-v1"

mkdir -p "$run_dir" "$failures_dir"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for parser oracle gate heavy commands" >&2
  exit 2
fi

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

rch_strip_ansi() {
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(
    rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true
  )"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: Project sync failed|running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \('; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

pairs_for_partition() {
  case "$1" in
    smoke) echo "64" ;;
    full) echo "256" ;;
    nightly) echo "1024" ;;
    *)
      echo "unsupported PARSER_ORACLE_PARTITION: $1" >&2
      return 2
      ;;
  esac
}

declare -a commands_run=()
failed_command=""
manifest_written=false

run_step() {
  local command_text="$1"
  local log_path remote_exit_code
  shift
  commands_run+=("$command_text")
  echo "==> $command_text"

  log_path="$(mktemp)"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    if rch_strip_ansi "$log_path" | rg -q "Remote command finished: exit=0"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    else
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi

  rm -f "$log_path"
}

write_placeholders() {
  [[ -f "$baseline_path" ]] || echo "{}" >"$baseline_path"
  [[ -f "$relation_report_path" ]] || echo "{\"status\":\"not_run\"}" >"$relation_report_path"
  [[ -f "$relation_events_path" ]] || : >"$relation_events_path"
  [[ -f "$evidence_path" ]] || : >"$evidence_path"
}

write_supporting_artifacts() {
  local git_commit kernel os_name arch cpu_model cores mem_kb mem_bytes rustc_version cargo_version
  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  kernel="$(uname -r)"
  os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //')"
  [[ -n "$cpu_model" ]] || cpu_model="unknown"
  cores="$(nproc 2>/dev/null || echo 0)"
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  mem_bytes="$((mem_kb * 1024))"
  rustc_version="$(rustc --version | sed 's/^rustc //')"
  cargo_version="$(cargo --version | sed 's/^cargo //')"

  jq -n \
    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg commit "$git_commit" \
    --arg os "$os_name" \
    --arg kernel "$kernel" \
    --arg arch "$arch" \
    --arg cpu_model "$cpu_model" \
    --argjson cores "$cores" \
    --argjson memory_bytes "$mem_bytes" \
    --arg rustc "$rustc_version" \
    --arg cargo "$cargo_version" \
    '{
      schema_version: "franken-engine.env.v1",
      captured_at_utc: $captured_at,
      project: { name: "franken_engine", commit: $commit, branch: "main" },
      host: {
        os: $os,
        kernel: $kernel,
        arch: $arch,
        cpu_model: $cpu_model,
        cpu_cores_logical: $cores,
        memory_bytes: $memory_bytes
      },
      toolchain: { rustc: $rustc, cargo: $cargo, target_dir: env.CARGO_TARGET_DIR },
      parser_oracle: {
        partition: env.PARSER_ORACLE_PARTITION,
        gate_mode: env.PARSER_ORACLE_GATE_MODE,
        fixture_catalog: env.PARSER_ORACLE_FIXTURE_CATALOG
      }
    }' >"$env_path"

  local equivalent minor critical action fallback
  equivalent="$(jq -r '.summary.equivalent_count // 0' "$relation_report_path")"
  minor="$(jq -r '.summary.minor_drift_count // 0' "$relation_report_path")"
  critical="$(jq -r '.summary.critical_drift_count // 0' "$relation_report_path")"
  action="$(jq -r '.decision.action // "unknown"' "$relation_report_path")"
  fallback="$(jq -r '.decision.fallback_reason // "none"' "$relation_report_path")"

  cat >"$proof_note_path" <<EOF_NOTE
# Parser Oracle Proof Note

- trace_id: ${trace_id}
- decision_id: ${decision_id}
- policy_id: ${policy_id}
- partition: ${partition}
- gate_mode: ${gate_mode}
- fixture_catalog: ${fixture_catalog}

## Drift Summary

- equivalent_count: ${equivalent}
- minor_drift_count: ${minor}
- critical_drift_count: ${critical}
- decision_action: ${action}
- fallback_reason: ${fallback}

## Replay

\`\`\`bash
cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- \
  --partition ${partition} \
  --gate-mode ${gate_mode} \
  --seed ${seed} \
  --trace-id ${trace_id} \
  --decision-id ${decision_id} \
  --policy-id ${policy_id} \
  --fixture-catalog ${fixture_catalog}
\`\`\`
EOF_NOTE

  local baseline_sha relation_sha relation_events_sha evidence_sha env_sha proof_sha
  baseline_sha="$(sha256sum "$baseline_path" | awk '{print $1}')"
  relation_sha="$(sha256sum "$relation_report_path" | awk '{print $1}')"
  relation_events_sha="$(sha256sum "$relation_events_path" | awk '{print $1}')"
  evidence_sha="$(sha256sum "$evidence_path" | awk '{print $1}')"
  env_sha="$(sha256sum "$env_path" | awk '{print $1}')"
  proof_sha="$(sha256sum "$proof_note_path" | awk '{print $1}')"

  cat >"$repro_lock_path" <<EOF_REPRO
{
  "schema_version": "franken-engine.repro-lock.v1",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lock_id": "parser-oracle-${timestamp}",
  "source_commit": "${git_commit}",
  "partition": "${partition}",
  "gate_mode": "${gate_mode}",
  "seed": ${seed},
  "commands_log": "${commands_path}",
  "inputs": [
    { "path": "${fixture_catalog}" }
  ],
  "outputs": [
    { "path": "${baseline_path}", "sha256": "sha256:${baseline_sha}" },
    { "path": "${relation_report_path}", "sha256": "sha256:${relation_sha}" },
    { "path": "${relation_events_path}", "sha256": "sha256:${relation_events_sha}" },
    { "path": "${evidence_path}", "sha256": "sha256:${evidence_sha}" }
  ]
}
EOF_REPRO

  cat >"$golden_checksums_path" <<EOF_SUM
${baseline_sha}  ${baseline_path}
${relation_sha}  ${relation_report_path}
${relation_events_sha}  ${relation_events_path}
${evidence_sha}  ${evidence_path}
${env_sha}  ${env_path}
${proof_sha}  ${proof_note_path}
$(sha256sum "$repro_lock_path" | awk '{print $1}')  ${repro_lock_path}
EOF_SUM
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
    error_code_json='"FE-PARSER-ORACLE-0001"'
  fi

  write_placeholders
  write_supporting_artifacts

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"parser_oracle_gate\",\"event\":\"gate_completed\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-oracle-gate.run-manifest.v1",'
    echo '  "bead_id": "bd-1b70",'
    echo '  "component": "parser_oracle_gate",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"partition\": \"${partition}\","
    echo "  \"gate_mode\": \"${gate_mode}\","
    echo "  \"seed\": ${seed},"
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"fixture_catalog\": \"${fixture_catalog}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
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
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"baseline\": \"${baseline_path}\","
    echo "    \"relation_report\": \"${relation_report_path}\","
    echo "    \"relation_events\": \"${relation_events_path}\","
    echo "    \"metamorphic_evidence\": \"${evidence_path}\","
    echo "    \"minimized_failures_dir\": \"${failures_dir}\","
    echo "    \"golden_checksums\": \"${golden_checksums_path}\","
    echo "    \"proof_note\": \"${proof_note_path}\","
    echo "    \"env\": \"${env_path}\","
    echo "    \"repro_lock\": \"${repro_lock_path}\""
    echo "  }"
    echo "}"
  } >"$manifest_path"

  echo "parser oracle gate manifest: $manifest_path"
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report" \
        cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test parser_oracle_gate" \
        cargo test -p frankenengine-engine --test parser_oracle_gate
      run_step "cargo test -p frankenengine-engine --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic" \
        cargo test -p frankenengine-engine --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report" \
        cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report
      run_step "cargo test -p frankenengine-engine --test parser_oracle_gate --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic" \
        cargo test -p frankenengine-engine --test parser_oracle_gate --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic

      run_step "cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- --partition ${partition} --gate-mode ${gate_mode} --seed ${seed} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --fixture-catalog ${fixture_catalog} --out ${relation_report_path}" \
        cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- \
          --partition "$partition" \
          --gate-mode "$gate_mode" \
          --seed "$seed" \
          --trace-id "$trace_id" \
          --decision-id "$decision_id" \
          --policy-id "$policy_id" \
          --fixture-catalog "$fixture_catalog" \
          --out "$relation_report_path"

      jq '{
          schema_version: "franken-engine.parser-oracle.baseline.v1",
          generated_at_utc,
          parser_mode,
          fixture_catalog_path,
          fixture_catalog_hash,
          partition,
          seed,
          equivalent_count: .summary.equivalent_count,
          minor_drift_count: .summary.minor_drift_count,
          critical_drift_count: .summary.critical_drift_count
        }' "$relation_report_path" >"$baseline_path"

      local pairs
      pairs="$(pairs_for_partition "$partition")"
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs ${pairs} --seed ${seed} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --evidence ${evidence_path} --events ${relation_events_path} --failures-dir ${failures_dir} --relation parser_whitespace_invariance --relation parser_comment_invariance --relation parser_parenthesization_invariance --relation parser_asi_equivalence --relation parser_unicode_escape_equivalence --relation parser_source_position_independence" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
          --pairs "$pairs" \
          --seed "$seed" \
          --trace-id "$trace_id" \
          --decision-id "$decision_id" \
          --policy-id "$policy_id" \
          --evidence "$evidence_path" \
          --events "$relation_events_path" \
          --failures-dir "$failures_dir" \
          --relation parser_whitespace_invariance \
          --relation parser_comment_invariance \
          --relation parser_parenthesization_invariance \
          --relation parser_asi_equivalence \
          --relation parser_unicode_escape_equivalence \
          --relation parser_source_position_independence
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
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
