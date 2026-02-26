use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use frankenengine_engine::e2e_harness::{
    DeterministicRunner, HarnessEvent, RunReport, TestFixture,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AlarmPolicy {
    alarm_id: String,
    slo_id: String,
    metric_key: String,
    comparator: String,
    threshold_millionths: u32,
    severity: String,
    escalation_action: String,
    error_code: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricWindow {
    window_id: String,
    created_at_utc: String,
    metrics_millionths: BTreeMap<String, u32>,
    expected_alarm_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentSimulation {
    scenario_id: String,
    expected_pass: bool,
    replay_command: String,
    fixture: TestFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_blockers: Vec<String>,
    expected_psrp_10_4_status: String,
    expected_psrp_8_4_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct UserImpactRegressionAlarmsFixture {
    schema_version: String,
    pipeline_version: String,
    log_schema_version: String,
    required_log_keys: Vec<String>,
    alarm_policies: Vec<AlarmPolicy>,
    metric_windows: Vec<MetricWindow>,
    incident_simulations: Vec<IncidentSimulation>,
    expected_gate: ExpectedGate,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AlarmEvaluation {
    window_id: String,
    alarm_id: String,
    slo_id: String,
    severity: String,
    threshold_millionths: u32,
    observed_millionths: u32,
    breached: bool,
    escalation_action: String,
    replay_command: String,
    error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowEvaluation {
    window_id: String,
    alarms: Vec<AlarmEvaluation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardrailGate {
    outcome: String,
    blockers: Vec<String>,
    psrp_10_4_status: String,
    psrp_8_4_status: String,
}

fn load_fixture() -> UserImpactRegressionAlarmsFixture {
    let path = Path::new("tests/fixtures/parser_user_impact_regression_alarms_v1.json");
    let bytes = fs::read(path).expect("read parser user-impact regression alarms fixture");
    serde_json::from_slice(&bytes)
        .expect("deserialize parser user-impact regression alarms fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_USER_IMPACT_REGRESSION_ALARMS_SLO_GUARDRAILS.md");
    fs::read_to_string(path)
        .expect("read parser user-impact regression alarms and slo guardrails doc")
}

fn compare_millionths(policy: &AlarmPolicy, observed_millionths: u32) -> bool {
    match policy.comparator.as_str() {
        "min" => observed_millionths < policy.threshold_millionths,
        "max" => observed_millionths > policy.threshold_millionths,
        other => panic!("unsupported comparator `{other}`"),
    }
}

fn evaluate_windows(fixture: &UserImpactRegressionAlarmsFixture) -> Vec<WindowEvaluation> {
    let mut windows = Vec::new();
    for window in &fixture.metric_windows {
        let mut alarms = Vec::new();
        for policy in &fixture.alarm_policies {
            let observed_millionths = *window
                .metrics_millionths
                .get(policy.metric_key.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "window `{}` missing metric `{}`",
                        window.window_id, policy.metric_key
                    )
                });
            let breached = compare_millionths(policy, observed_millionths);
            alarms.push(AlarmEvaluation {
                window_id: window.window_id.clone(),
                alarm_id: policy.alarm_id.clone(),
                slo_id: policy.slo_id.clone(),
                severity: policy.severity.clone(),
                threshold_millionths: policy.threshold_millionths,
                observed_millionths,
                breached,
                escalation_action: policy.escalation_action.clone(),
                replay_command: policy.replay_command.clone(),
                error_code: policy.error_code.clone(),
            });
        }
        windows.push(WindowEvaluation {
            window_id: window.window_id.clone(),
            alarms,
        });
    }
    windows
}

fn evaluate_guardrail_gate(fixture: &UserImpactRegressionAlarmsFixture) -> GuardrailGate {
    let window_evaluations = evaluate_windows(fixture);
    let latest_window = fixture
        .metric_windows
        .last()
        .expect("metric windows must not be empty");
    let latest = window_evaluations
        .iter()
        .find(|window| window.window_id == latest_window.window_id)
        .expect("latest window evaluation must exist");

    let mut blockers = latest
        .alarms
        .iter()
        .filter(|alarm| alarm.breached)
        .filter(|alarm| alarm.severity == "critical" || alarm.severity == "high")
        .map(|alarm| format!("{}_alarm:{}", alarm.severity, alarm.alarm_id))
        .collect::<Vec<_>>();
    blockers.sort();
    blockers.dedup();

    let has_blockers = !blockers.is_empty();
    let outcome = if has_blockers { "hold" } else { "pass" };
    let downstream_status = if has_blockers { "blocked" } else { "ready" };

    GuardrailGate {
        outcome: outcome.to_string(),
        blockers,
        psrp_10_4_status: downstream_status.to_string(),
        psrp_8_4_status: downstream_status.to_string(),
    }
}

fn emit_structured_logs(fixture: &UserImpactRegressionAlarmsFixture) -> Vec<Value> {
    let mut events = Vec::new();
    for window in evaluate_windows(fixture) {
        for alarm in window.alarms {
            events.push(json!({
                "schema_version": fixture.log_schema_version,
                "trace_id": format!("trace-parser-user-impact-regression-alarms-{}-{}", window.window_id, alarm.alarm_id),
                "decision_id": format!("decision-parser-user-impact-regression-alarms-{}-{}", window.window_id, alarm.alarm_id),
                "policy_id": "policy-parser-user-impact-regression-alarms-v1",
                "component": "parser_user_impact_regression_alarm_pipeline",
                "event": "alarm_evaluated",
                "outcome": if alarm.breached { "breach" } else { "ok" },
                "error_code": if alarm.breached {
                    Some(alarm.error_code)
                } else {
                    Option::<String>::None
                },
                "replay_command": alarm.replay_command,
                "alarm_id": alarm.alarm_id,
                "slo_id": alarm.slo_id,
                "severity": alarm.severity,
                "window_id": alarm.window_id,
                "threshold_millionths": alarm.threshold_millionths,
                "observed_millionths": alarm.observed_millionths,
                "escalation_action": alarm.escalation_action
            }));
        }
    }

    let gate = evaluate_guardrail_gate(fixture);
    let replay_command = fixture
        .replay_scenarios
        .first()
        .expect("at least one replay scenario is required")
        .replay_command
        .clone();

    events.push(json!({
        "schema_version": fixture.log_schema_version,
        "trace_id": "trace-parser-user-impact-regression-alarms-gate",
        "decision_id": "decision-parser-user-impact-regression-alarms-gate",
        "policy_id": "policy-parser-user-impact-regression-alarms-v1",
        "component": "parser_user_impact_regression_alarm_pipeline",
        "event": "gate_decision",
        "outcome": gate.outcome,
        "error_code": if gate.blockers.is_empty() {
            Option::<String>::None
        } else {
            Some("FE-PARSER-USER-IMPACT-GATE-HOLD-0001".to_string())
        },
        "replay_command": replay_command,
        "alarm_id": "gate.summary",
        "slo_id": "gate.summary",
        "blockers": gate.blockers,
        "psrp_10_4_status": gate.psrp_10_4_status,
        "psrp_8_4_status": gate.psrp_8_4_status
    }));

    events
}

fn assert_required_log_keys(events: &[Value], required_keys: &[String], context_label: &str) {
    assert!(!events.is_empty(), "{context_label} emitted no events");

    for event in events {
        let obj = event
            .as_object()
            .expect("structured log event must be a json object");

        for key in required_keys {
            assert!(
                obj.contains_key(key),
                "{context_label} missing required key `{key}`"
            );
            if key == "error_code" {
                continue;
            }
            if let Some(value) = obj.get(key).and_then(Value::as_str) {
                assert!(
                    !value.trim().is_empty(),
                    "{context_label} required key `{key}` must not be empty"
                );
            }
        }
    }
}

fn assert_harness_keys(events: &[HarnessEvent], scenario_id: &str) {
    assert!(
        !events.is_empty(),
        "scenario `{scenario_id}` emitted no harness events"
    );
    for event in events {
        assert!(!event.trace_id.trim().is_empty());
        assert!(!event.decision_id.trim().is_empty());
        assert!(!event.policy_id.trim().is_empty());
        assert!(!event.component.trim().is_empty());
        assert!(!event.event.trim().is_empty());
        assert!(!event.outcome.trim().is_empty());
    }
}

#[test]
fn user_impact_regression_alarm_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser User-Impact Regression Alarms + SLO Guardrails (`bd-2mds.1.10.5.2`)",
        "## Alarm Policy Model",
        "## SLO Guardrail Semantics",
        "## Deterministic Incident Simulations",
        "## Structured Log Contract",
        "./scripts/run_parser_user_impact_regression_alarms.sh ci",
    ] {
        assert!(
            doc.contains(section),
            "required section missing from doc: {section}"
        );
    }
}

#[test]
fn user_impact_regression_alarm_fixture_contract_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-user-impact-regression-alarms.v1"
    );
    assert_eq!(fixture.pipeline_version, "1.0.0");
    assert_eq!(
        fixture.log_schema_version,
        "franken-engine.parser-log-event.v1"
    );

    assert!(!fixture.alarm_policies.is_empty());
    assert!(!fixture.metric_windows.is_empty());
    assert!(!fixture.incident_simulations.is_empty());
    assert!(!fixture.replay_scenarios.is_empty());

    let mut alarm_ids = BTreeSet::new();
    for policy in &fixture.alarm_policies {
        assert!(alarm_ids.insert(policy.alarm_id.clone()));
        assert!(policy.comparator == "min" || policy.comparator == "max");
        assert!(
            policy.severity == "warning"
                || policy.severity == "high"
                || policy.severity == "critical"
        );
        assert!(!policy.replay_command.trim().is_empty());
        assert!(!policy.error_code.trim().is_empty());
    }

    for window in &fixture.metric_windows {
        assert!(!window.created_at_utc.trim().is_empty());
        for policy in &fixture.alarm_policies {
            assert!(
                window
                    .metrics_millionths
                    .contains_key(policy.metric_key.as_str()),
                "window `{}` missing metric `{}`",
                window.window_id,
                policy.metric_key
            );
        }
    }

    for simulation in &fixture.incident_simulations {
        assert!(!simulation.replay_command.trim().is_empty());
        assert!(simulation.fixture.determinism_check);
    }
}

#[test]
fn user_impact_regression_alarm_pipeline_is_deterministic_and_gate_consumable() {
    let fixture = load_fixture();

    let first_windows = evaluate_windows(&fixture);
    let second_windows = evaluate_windows(&fixture);
    assert_eq!(
        first_windows, second_windows,
        "window evaluation must be deterministic"
    );

    for window in &first_windows {
        let mut observed_alarm_ids = window
            .alarms
            .iter()
            .filter(|alarm| alarm.breached)
            .map(|alarm| alarm.alarm_id.clone())
            .collect::<Vec<_>>();
        observed_alarm_ids.sort();

        let mut expected_alarm_ids = fixture
            .metric_windows
            .iter()
            .find(|candidate| candidate.window_id == window.window_id)
            .expect("window fixture entry must exist")
            .expected_alarm_ids
            .clone();
        expected_alarm_ids.sort();

        assert_eq!(
            observed_alarm_ids, expected_alarm_ids,
            "alarm mismatch for window `{}`",
            window.window_id
        );
    }

    let gate_left = evaluate_guardrail_gate(&fixture);
    let gate_right = evaluate_guardrail_gate(&fixture);
    assert_eq!(
        gate_left, gate_right,
        "guardrail gate must be deterministic"
    );
    assert_eq!(gate_left.outcome, fixture.expected_gate.expected_outcome);

    let mut expected_blockers = fixture.expected_gate.expected_blockers.clone();
    expected_blockers.sort();
    assert_eq!(gate_left.blockers, expected_blockers);
    assert_eq!(
        gate_left.psrp_10_4_status,
        fixture.expected_gate.expected_psrp_10_4_status
    );
    assert_eq!(
        gate_left.psrp_8_4_status,
        fixture.expected_gate.expected_psrp_8_4_status
    );
}

#[test]
fn user_impact_regression_alarm_incident_simulations_are_replayable() {
    let fixture = load_fixture();
    let runner = DeterministicRunner::default();

    for scenario in &fixture.incident_simulations {
        let first = runner
            .run_fixture(&scenario.fixture)
            .expect("first deterministic run");
        let second = runner
            .run_fixture(&scenario.fixture)
            .expect("second deterministic run");

        if scenario.fixture.determinism_check {
            assert_eq!(
                first.output_digest, second.output_digest,
                "output digest drift for scenario `{}`",
                scenario.scenario_id
            );
            assert_eq!(
                first.events, second.events,
                "event stream drift for scenario `{}`",
                scenario.scenario_id
            );
        }

        assert_harness_keys(&first.events, scenario.scenario_id.as_str());

        let report = RunReport::from_result(&first);
        assert_eq!(
            report.pass, scenario.expected_pass,
            "unexpected pass/fail for scenario `{}`",
            scenario.scenario_id
        );
        assert!(
            !scenario.replay_command.trim().is_empty(),
            "scenario `{}` replay command is required",
            scenario.scenario_id
        );
    }
}

#[test]
fn user_impact_regression_alarm_structured_logs_include_replay_commands() {
    let fixture = load_fixture();
    let events = emit_structured_logs(&fixture);

    assert_required_log_keys(
        &events,
        &fixture.required_log_keys,
        "parser-user-impact-regression-alarms",
    );

    let breach_count = events
        .iter()
        .filter(|event| event.get("outcome") == Some(&Value::String("breach".to_string())))
        .count();
    assert!(breach_count > 0, "expected at least one breach event");

    let has_gate_decision = events.iter().any(|event| {
        event.get("event") == Some(&Value::String("gate_decision".to_string()))
            && event.get("outcome") == Some(&Value::String("hold".to_string()))
    });
    assert!(has_gate_decision, "expected hold gate decision log event");

    for event in &events {
        let replay_command = event
            .get("replay_command")
            .and_then(Value::as_str)
            .expect("replay_command must be a string");
        assert!(
            !replay_command.trim().is_empty(),
            "replay_command must not be empty"
        );
    }
}
