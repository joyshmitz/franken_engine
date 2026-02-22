use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::controller_interference_guard::{
    ConflictResolutionMode, ControllerRegistration, InterferenceConfig, InterferenceFailureCode,
    InterferenceScenario, MetricReadRequest, MetricSubscription, MetricWriteRequest,
    TimescaleSeparationStatement, evaluate_controller_interference,
};

fn registration(
    id: &str,
    read_metrics: &[&str],
    write_metrics: &[&str],
    observation_interval_millionths: i64,
    write_interval_millionths: i64,
    statement: &str,
) -> ControllerRegistration {
    ControllerRegistration {
        controller_id: id.to_string(),
        read_metrics: read_metrics
            .iter()
            .map(|metric| (*metric).to_string())
            .collect::<BTreeSet<_>>(),
        write_metrics: write_metrics
            .iter()
            .map(|metric| (*metric).to_string())
            .collect::<BTreeSet<_>>(),
        timescale: TimescaleSeparationStatement {
            observation_interval_millionths,
            write_interval_millionths,
            statement: statement.to_string(),
        },
    }
}

fn initial_metrics() -> BTreeMap<String, i64> {
    BTreeMap::from([
        ("cpu".to_string(), 10),
        ("latency".to_string(), 100),
        ("throughput".to_string(), 1_000),
    ])
}

fn scenario<'a>(
    trace_id: &'a str,
    policy_id: &'a str,
    config: &'a InterferenceConfig,
    registrations: &'a [ControllerRegistration],
    metric_ops: (
        &'a [MetricReadRequest],
        &'a [MetricWriteRequest],
        &'a [MetricSubscription],
    ),
    initial_metrics: &'a BTreeMap<String, i64>,
) -> InterferenceScenario<'a> {
    let (read_requests, write_requests, subscriptions) = metric_ops;
    InterferenceScenario {
        trace_id,
        policy_id,
        config,
        registrations,
        read_requests,
        write_requests,
        subscriptions,
        initial_metrics,
    }
}

#[test]
fn conflicting_writers_are_rejected_with_structured_logs() {
    let registrations = vec![
        registration(
            "writer-a",
            &["throughput"],
            &["throughput"],
            100_000,
            100_000,
            "writes every 100ms",
        ),
        registration(
            "writer-b",
            &["throughput"],
            &["throughput"],
            120_000,
            120_000,
            "writes every 120ms",
        ),
    ];

    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Reject,
    };
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [
        MetricWriteRequest {
            controller_id: "writer-a".to_string(),
            metric: "throughput".to_string(),
            value: 700,
        },
        MetricWriteRequest {
            controller_id: "writer-b".to_string(),
            metric: "throughput".to_string(),
            value: 600,
        },
    ];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-interference-fail",
        "policy-interference-fail",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(!evaluation.pass);
    assert!(evaluation.rollback_required);
    assert_eq!(evaluation.rejected_writes.len(), 2);
    assert!(evaluation.findings.iter().any(|finding| {
        finding.code == InterferenceFailureCode::TimescaleConflict
            && finding.metric.as_deref() == Some("throughput")
    }));
    assert!(evaluation.logs.iter().any(|event| {
        event.event == "timescale_conflict"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("timescale_conflict")
    }));
}

#[test]
fn serialize_mode_preserves_deterministic_write_order_and_subscription_fanout() {
    let registrations = vec![
        registration(
            "writer-b",
            &["latency"],
            &["latency"],
            100_000,
            100_000,
            "writes every 100ms",
        ),
        registration(
            "writer-a",
            &["latency"],
            &["latency"],
            120_000,
            120_000,
            "writes every 120ms",
        ),
        registration(
            "subscriber",
            &["latency"],
            &[],
            500_000,
            2_000_000,
            "subscribes every 500ms",
        ),
    ];

    let config = InterferenceConfig {
        min_timescale_separation_millionths: 100_000,
        conflict_resolution_mode: ConflictResolutionMode::Serialize,
    };
    let read_requests = [MetricReadRequest {
        controller_id: "subscriber".to_string(),
        metric: "latency".to_string(),
    }];
    let write_requests = [
        MetricWriteRequest {
            controller_id: "writer-b".to_string(),
            metric: "latency".to_string(),
            value: 70,
        },
        MetricWriteRequest {
            controller_id: "writer-a".to_string(),
            metric: "latency".to_string(),
            value: 80,
        },
    ];
    let subscriptions = [MetricSubscription {
        controller_id: "subscriber".to_string(),
        metric: "latency".to_string(),
    }];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-interference-serialize",
        "policy-interference-serialize",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.pass);
    assert_eq!(evaluation.applied_writes.len(), 2);
    assert_eq!(evaluation.final_metrics.get("latency"), Some(&70));
    assert_eq!(evaluation.resolutions.len(), 1);
    assert!(
        evaluation
            .logs
            .iter()
            .any(|event| { event.event == "write_conflict_serialized" && event.outcome == "pass" })
    );
    assert_eq!(
        evaluation
            .subscription_streams
            .get("subscriber")
            .and_then(|updates| updates.first())
            .map(|update| update.value),
        Some(70)
    );
}

#[test]
fn long_duration_soak_preserves_metric_integrity_without_drift() {
    let registrations = vec![
        registration(
            "reader",
            &["cpu"],
            &[],
            250_000,
            2_000_000,
            "reads every 250ms",
        ),
        registration(
            "writer",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "writes every 1s",
        ),
    ];

    let mut metrics = initial_metrics();
    for iteration in 0..10_000i64 {
        let next_value = 10 + (iteration % 11);
        let config = InterferenceConfig::default();
        let read_requests = [MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "cpu".to_string(),
        }];
        let write_requests = [MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "cpu".to_string(),
            value: next_value,
        }];
        let subscriptions: [MetricSubscription; 0] = [];

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-interference-soak",
            "policy-interference-soak",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass, "soak iteration {iteration} failed");
        assert_eq!(
            evaluation.read_snapshots.get("reader:cpu"),
            metrics.get("cpu")
        );
        assert_eq!(evaluation.final_metrics.get("cpu"), Some(&next_value));
        metrics = evaluation.final_metrics;
    }

    assert!(matches!(metrics.get("cpu"), Some(value) if (10..=20).contains(value)));
}

#[test]
fn log_events_keep_required_stable_fields() {
    let registrations = vec![registration(
        "ctrl",
        &["cpu"],
        &["cpu"],
        1_000_000,
        1_000_000,
        "writes every 1s",
    )];

    let config = InterferenceConfig::default();
    let read_requests: [MetricReadRequest; 0] = [];
    let write_requests = [MetricWriteRequest {
        controller_id: "ctrl".to_string(),
        metric: "cpu".to_string(),
        value: 15,
    }];
    let subscriptions: [MetricSubscription; 0] = [];
    let metrics = initial_metrics();

    let evaluation = evaluate_controller_interference(&scenario(
        "trace-interference-log",
        "policy-interference-log",
        &config,
        &registrations,
        (&read_requests, &write_requests, &subscriptions),
        &metrics,
    ));

    assert!(evaluation.logs.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && !event.component.is_empty()
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
}
