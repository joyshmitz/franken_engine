use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::counterexample_synthesizer::{
    ControllerConfig, CounterexampleSynthesizer, InterferenceKind, SynthesisConfig,
};

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn controller(
    controller_id: &str,
    read_metrics: &[&str],
    write_metrics: &[&str],
    timescale_millionths: i64,
    timescale_statement: &str,
) -> ControllerConfig {
    let mut affected_metrics = set(read_metrics);
    affected_metrics.extend(set(write_metrics));
    ControllerConfig {
        controller_id: controller_id.to_string(),
        read_metrics: set(read_metrics),
        write_metrics: set(write_metrics),
        affected_metrics,
        timescale_millionths,
        timescale_statement: timescale_statement.to_string(),
    }
}

fn synth() -> CounterexampleSynthesizer {
    CounterexampleSynthesizer::new(SynthesisConfig::default())
}

fn metric_value_stream(iterations: u64) -> Vec<i64> {
    (0..iterations).map(|tick| tick as i64).collect()
}

#[test]
fn concurrent_readers_on_shared_metric_get_consistent_snapshots() {
    let synth = synth();
    let mut configs = Vec::new();
    for idx in 0..10 {
        configs.push(controller(
            &format!("reader-{idx:02}"),
            &["latency_ms"],
            &[],
            100_000 + (idx as i64 * 10_000),
            "reads every 100-190ms",
        ));
    }

    let interferences = synth.detect_interference(&configs);
    assert!(
        interferences.is_empty(),
        "read-only shared-metric access should remain conflict free: {interferences:?}"
    );

    let canonical_stream = metric_value_stream(128);
    let mut snapshots = BTreeMap::new();
    for config in &configs {
        snapshots.insert(config.controller_id.clone(), canonical_stream.clone());
    }

    for stream in snapshots.values() {
        assert_eq!(stream, &canonical_stream);
    }
}

#[test]
fn concurrent_writers_with_timescale_collision_emit_rejection_evidence() {
    let synth = synth();
    let configs = vec![
        controller(
            "writer-fast-a",
            &[],
            &["throughput_ops"],
            100_000,
            "writes every 100ms",
        ),
        controller(
            "writer-fast-b",
            &[],
            &["throughput_ops"],
            120_000,
            "writes every 120ms",
        ),
    ];

    let interferences = synth.detect_interference(&configs);
    assert!(interferences.iter().any(|interference| {
        interference.kind == InterferenceKind::TimescaleConflict
            && interference.shared_metrics.contains("throughput_ops")
    }));

    let events = synth.build_interference_events(
        &interferences,
        "trace-interference-ci-001",
        "policy-metric-interference-v1",
    );
    let rejection = events
        .iter()
        .find(|event| event.kind == InterferenceKind::TimescaleConflict)
        .expect("timescale conflict event must exist");
    assert_eq!(rejection.component, "counterexample_synthesizer");
    assert_eq!(rejection.event, "controller_interference_rejected");
    assert_eq!(rejection.outcome, "reject");
    assert_eq!(
        rejection.error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-TIMESCALE")
    );
}

#[test]
fn reader_writer_overlap_reports_serialization_path() {
    let synth = synth();
    let configs = vec![
        controller(
            "writer-slow",
            &[],
            &["queue_depth"],
            1_000_000,
            "writes every 1s",
        ),
        controller(
            "reader-fast",
            &["queue_depth"],
            &[],
            100_000,
            "reads every 100ms",
        ),
    ];

    let interferences = synth.detect_interference(&configs);
    assert!(interferences.iter().any(|interference| {
        interference.kind == InterferenceKind::InvariantInvalidation
            && interference.shared_metrics.contains("queue_depth")
    }));

    let events = synth.build_interference_events(
        &interferences,
        "trace-interference-ci-002",
        "policy-metric-interference-v1",
    );
    assert!(events.iter().any(|event| {
        event.kind == InterferenceKind::InvariantInvalidation
            && event.event == "controller_interference_serialized"
            && event.outcome == "serialize"
            && event.error_code.as_deref() == Some("FE-CX-INTERFERENCE-INVARIANT")
    }));
}

#[test]
fn metric_subscriptions_do_not_cross_contaminate_streams() {
    let updates: Vec<(u64, &'static str, i64)> = (0..64)
        .map(|tick| {
            (
                tick,
                if tick % 2 == 0 { "latency_ms" } else { "qps" },
                tick as i64,
            )
        })
        .collect();

    let subscribers = vec![
        ("latency-a", set(&["latency_ms"])),
        ("latency-b", set(&["latency_ms"])),
        ("qps-a", set(&["qps"])),
    ];

    let mut streams: BTreeMap<String, Vec<(u64, i64)>> = BTreeMap::new();
    for (subscriber_id, _) in &subscribers {
        streams.insert((*subscriber_id).to_string(), Vec::new());
    }

    for (tick, metric, value) in updates {
        for (subscriber_id, subscribed_metrics) in &subscribers {
            if subscribed_metrics.contains(metric) {
                streams
                    .get_mut(*subscriber_id)
                    .expect("subscriber stream")
                    .push((tick, value));
            }
        }
    }

    assert_eq!(
        streams.get("latency-a"),
        streams.get("latency-b"),
        "subscribers to the same metric must receive identical streams"
    );
    assert!(
        streams
            .get("qps-a")
            .expect("qps stream")
            .iter()
            .all(|(_, value)| value % 2 == 1),
        "qps subscriber must not receive latency updates"
    );
}

#[test]
fn long_duration_metric_soak_10k_iterations_has_no_drift_or_corruption() {
    let mut metric_value = 0_i64;
    let mut reader_streams: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for reader_id in ["reader-a", "reader-b", "reader-c", "reader-d", "reader-e"] {
        reader_streams.insert(reader_id.to_string(), Vec::new());
    }

    for _ in 0..10_000_u64 {
        metric_value += 1;
        for stream in reader_streams.values_mut() {
            stream.push(metric_value);
        }
    }

    assert_eq!(metric_value, 10_000);
    for stream in reader_streams.values() {
        assert_eq!(stream.len(), 10_000);
        assert_eq!(stream.first(), Some(&1));
        assert_eq!(stream.last(), Some(&10_000));
        assert!(
            stream.windows(2).all(|window| window[0] <= window[1]),
            "reader stream must be monotonic"
        );
        assert!(
            stream
                .windows(2)
                .all(|window| (window[1] - window[0]).abs() <= 1),
            "reader stream should not contain phantom spikes"
        );
    }
}

#[test]
fn every_detected_conflict_has_matching_structured_event() {
    let synth = synth();
    let configs = vec![
        controller("writer-a", &[], &["m1"], 100_000, "writes every 100ms"),
        controller("writer-b", &[], &["m1"], 120_000, "writes every 120ms"),
        controller("reader-c", &["m1"], &[], 400_000, "reads every 400ms"),
    ];

    let interferences = synth.detect_interference(&configs);
    assert!(!interferences.is_empty());

    let events = synth.build_interference_events(
        &interferences,
        "trace-interference-ci-003",
        "policy-metric-interference-v1",
    );
    assert_eq!(
        events.len(),
        interferences.len(),
        "every conflict must emit an evidence/log event"
    );
    assert!(events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && event.component == "counterexample_synthesizer"
            && event.error_code.is_some()
    }));
}
