#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_adversarial_gate}"
artifact_root="${ADVERSARIAL_GATE_ARTIFACT_ROOT:-artifacts/adversarial_campaign_gate}"
gate_input_fixture="${ADVERSARIAL_GATE_INPUT_FIXTURE:-crates/franken-engine/tests/fixtures/adversarial_campaign_gate_input_v1.json}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$artifact_root/$timestamp"
manifest_path="$run_dir/run_manifest.json"
gate_result_path="$run_dir/gate_result.json"

mkdir -p "$run_dir"

run_rch() {
  rch exec -- env CARGO_TARGET_DIR="$target_dir" "$@"
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

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate" \
        cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate
      run_step "cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator" \
        cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_" \
        cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli" \
        cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields" \
        cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields
      run_step "cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- --input ${gate_input_fixture} --out ${gate_result_path}" \
        cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- \
          --input "$gate_input_fixture" \
          --out "$gate_result_path"
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings" \
        cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate" \
        cargo check -p frankenengine-engine --bin franken_adversarial_campaign_gate
      run_step "cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator" \
        cargo check -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator
      run_step "cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_" \
        cargo test -p frankenengine-engine --lib adversarial_campaign::tests::suppression_gate_
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli" \
        cargo test -p frankenengine-engine --test adversarial_campaign_gate_cli
      run_step "cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields" \
        cargo test -p frankenengine-engine --test adversarial_campaign_generator suppression_gate_surface_exposes_required_structured_fields
      run_step "cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- --input ${gate_input_fixture} --out ${gate_result_path}" \
        cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- \
          --input "$gate_input_fixture" \
          --out "$gate_result_path"
      run_step "cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings" \
        cargo clippy -p frankenengine-engine --bin franken_adversarial_campaign_gate -- -D warnings
      run_step "cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings" \
        cargo clippy -p frankenengine-engine --test adversarial_campaign_gate_cli --test adversarial_campaign_generator -- -D warnings
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local git_commit dirty_worktree idx comma outcome
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

  printf '%s\n' "${commands_run[@]}" >"$run_dir/commands.txt"

  {
    echo "{"
    echo '  "component": "adversarial_campaign_suppression_gate",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"gate_input_fixture\": \"${gate_input_fixture}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "thresholds": {'
    echo '    "minimum_baseline_runtimes": 2,'
    echo '    "max_p_value_millionths": 50000,'
    echo '    "require_continuous_run": true,'
    echo '    "minimum_trend_points": 2,'
    echo '    "max_escalation_latency_seconds": 3600'
    echo '  },'
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
    echo "    \"gate_result\": \"${gate_result_path}\","
    echo "    \"manifest\": \"${manifest_path}\""
    echo '  },'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${run_dir}/commands.txt\","
    echo "    \"cat ${gate_result_path}\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"

  echo "Manifest written to: $manifest_path"
}

trap 'write_manifest $?' EXIT
run_mode
