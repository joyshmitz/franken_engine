use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use frankenengine_engine::runtime_hotspot_optimization_campaign::{
    RuntimeHotspotCampaignFixture, campaign_gain_millionths, classify_runtime_lever,
    compute_campaign_results, emit_structured_events, ev_score_millionths, rank_by_ev,
    rank_by_gain, selected_campaign,
};

fn load_fixture() -> RuntimeHotspotCampaignFixture {
    let path = Path::new("tests/fixtures/runtime_hotspot_optimization_campaign_v1.json");
    let bytes = fs::read(path).expect("read runtime hotspot fixture");
    serde_json::from_slice(&bytes).expect("deserialize runtime hotspot fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RUNTIME_HOTSPOT_OPTIMIZATION_CAMPAIGN.md");
    fs::read_to_string(path).expect("read runtime hotspot contract doc")
}

fn load_gate_script() -> String {
    let path = Path::new("../../scripts/run_runtime_hotspot_optimization_campaign.sh");
    fs::read_to_string(path).expect("read runtime hotspot gate script")
}

#[test]
fn runtime_hotspot_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Runtime Hotspot Optimization Campaign Contract (`bd-mjh3.6.3`)",
        "## Runtime Hotspot Targets",
        "## EV Scoring Contract",
        "## Gain Attribution Contract",
        "## Structured Log Contract",
        "./scripts/run_runtime_hotspot_optimization_campaign.sh ci",
        "./scripts/e2e/runtime_hotspot_optimization_campaign_replay.sh",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn runtime_hotspot_fixture_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.runtime-hotspot-optimization-campaign.v1"
    );
    assert_eq!(fixture.campaign_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.runtime-hotspot-telemetry.v1"
    );
    assert!(!fixture.campaign_runs.is_empty());
    assert_eq!(fixture.campaign_runs.len(), 4);

    let required_keys: BTreeSet<&str> = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(required_keys.contains(key), "missing required key `{key}`");
    }
}

#[test]
fn runtime_hotspot_campaigns_are_profile_justified_and_single_lever() {
    let fixture = load_fixture();

    for run in &fixture.campaign_runs {
        assert!(!run.campaign_id.trim().is_empty());
        assert!(!run.lever_id.trim().is_empty());
        assert!(!run.lever_category.trim().is_empty());
        assert!(!run.commit.trim().is_empty());
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.generated_at_utc.trim().is_empty());
        assert!(!run.attribution_note.trim().is_empty());
        assert!(!run.rollback_plan_ref.trim().is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_manifest.trim().is_empty());
        assert!(!run.artifact_report.trim().is_empty());
        assert!(run.hotspot.baseline_share_millionths > 0);
        assert!(run.hotspot.baseline_share_millionths <= 1_000_000);
        assert!(!run.hotspot.hotspot_id.trim().is_empty());
        assert!(!run.hotspot.phase.trim().is_empty());
        assert!(!run.hotspot.baseline_profile_ref.trim().is_empty());
        assert!(run.ev_inputs.effort > 0);
        assert!(run.ev_inputs.friction > 0);
        assert!(!run.semantic_proof.proof_method.trim().is_empty());
        assert!(
            !run.semantic_proof
                .verification_contract_ref
                .trim()
                .is_empty()
        );
        assert_eq!(run.semantic_proof.drift_status, "no_drift");

        let mut categories = BTreeSet::new();
        for path in &run.changed_paths {
            let category = classify_runtime_lever(path)
                .unwrap_or_else(|| panic!("unclassified runtime path `{path}`"));
            categories.insert(category);
        }
        assert_eq!(
            categories.len(),
            1,
            "campaign {} must remain single-lever",
            run.campaign_id
        );
    }
}

#[test]
fn runtime_hotspot_ev_and_gain_rankings_match_fixture() {
    let fixture = load_fixture();
    let results = compute_campaign_results(&fixture);
    assert_eq!(results.len(), fixture.campaign_runs.len());

    for run in &fixture.campaign_runs {
        let measured_ev = ev_score_millionths(&run.ev_inputs);
        assert_eq!(measured_ev, run.expected_ev_score_millionths);
        let measured_gain = campaign_gain_millionths(run);
        assert_eq!(measured_gain, run.expected_gain_millionths);
    }

    assert_eq!(rank_by_ev(&results), fixture.expected_ev_ranking);
    assert_eq!(rank_by_gain(&results), fixture.expected_gain_ranking);
    assert_eq!(
        selected_campaign(&results),
        fixture.expected_selected_campaign
    );
}

#[test]
fn runtime_hotspot_events_and_replay_contract_are_deterministic() {
    let fixture = load_fixture();
    let events = emit_structured_events(&compute_campaign_results(&fixture));
    assert_eq!(events.len(), fixture.campaign_runs.len());
    for event in events {
        let event = serde_json::to_value(event).expect("serialize runtime hotspot event");
        for key in [
            "schema_version",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
        ] {
            assert!(event.get(key).is_some(), "missing event key `{key}`");
        }
    }

    let scenario_kinds = fixture
        .cross_subsystem_replay_scenarios
        .iter()
        .map(|scenario| scenario.scenario_kind.as_str())
        .collect::<BTreeSet<_>>();
    assert!(scenario_kinds.contains("normal"));
    assert!(scenario_kinds.contains("adversarial"));
    assert!(scenario_kinds.contains("recovery"));
    for scenario in &fixture.cross_subsystem_replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.replay_command.trim().is_empty());
        assert!(!scenario.expected_outcome.trim().is_empty());
        if scenario.scenario_kind == "adversarial" {
            assert!(
                !scenario.expected_pass,
                "adversarial scenario should be fail-closed"
            );
        }
    }
}

#[test]
fn runtime_hotspot_gate_script_fail_closed_guards_are_present() {
    let script = load_gate_script();
    for marker in [
        "Remote toolchain failure, falling back to local",
        "running locally",
        "Dependency preflight blocked remote execution",
        "RCH-E326",
        "rch-local-fallback-detected",
        "rch_reject_artifact_retrieval_failure",
        "rch_has_recoverable_artifact_timeout",
        "rch-artifact-retrieval-failed",
    ] {
        assert!(
            script.contains(marker),
            "missing fail-closed marker `{marker}` in gate script"
        );
    }
}

#[test]
fn runtime_hotspot_gate_script_ci_mode_short_circuits_on_first_failure() {
    let script = load_gate_script();
    let ci_block = script
        .split("ci)")
        .nth(1)
        .and_then(|rest| rest.split(";;").next())
        .expect("ci mode block must exist");
    for command in [
        "cargo check -p frankenengine-engine --test runtime_hotspot_optimization_campaign",
        "cargo test -p frankenengine-engine --test runtime_hotspot_optimization_campaign",
        "cargo clippy -p frankenengine-engine --test runtime_hotspot_optimization_campaign -- -D warnings",
    ] {
        let required = format!("{command} || return 1");
        assert!(
            ci_block.contains(&required),
            "ci mode must short-circuit failed step `{command}`"
        );
    }
}

#[test]
fn runtime_hotspot_gate_script_emits_step_log_artifacts() {
    let script = load_gate_script();
    for marker in [
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "step_logs_index_path=\"${run_dir}/step_logs.txt\"",
        "printf '%s\\n' \"${step_logs[@]}\" >\"$step_logs_index_path\"",
        "\"step_logs_index\": \"${step_logs_index_path}\"",
        "\"step_logs_dir\": \"${step_logs_dir}\"",
        "\"cat ${step_logs_index_path}\"",
    ] {
        assert!(
            script.contains(marker),
            "missing step-log artifact marker `{marker}` in gate script"
        );
    }
}
