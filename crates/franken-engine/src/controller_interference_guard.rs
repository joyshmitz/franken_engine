//! Deterministic interference guard for multi-controller metric access.
//!
//! Plan reference: Section 10.13 item 14 (`bd-2py0`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const CONTROLLER_INTERFERENCE_GUARD_DOMAIN: &[u8] = b"FrankenEngine.ControllerInterferenceGuard.v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolutionMode {
    Serialize,
    Reject,
}

impl fmt::Display for ConflictResolutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize => f.write_str("serialize"),
            Self::Reject => f.write_str("reject"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceConfig {
    pub min_timescale_separation_millionths: i64,
    pub conflict_resolution_mode: ConflictResolutionMode,
}

impl Default for InterferenceConfig {
    fn default() -> Self {
        Self {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Reject,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimescaleSeparationStatement {
    /// Observation cadence in millionths of one second.
    pub observation_interval_millionths: i64,
    /// Mutation cadence in millionths of one second.
    pub write_interval_millionths: i64,
    /// Human-readable declaration attached to registration.
    pub statement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerRegistration {
    pub controller_id: String,
    pub read_metrics: BTreeSet<String>,
    pub write_metrics: BTreeSet<String>,
    pub timescale: TimescaleSeparationStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricReadRequest {
    pub controller_id: String,
    pub metric: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricWriteRequest {
    pub controller_id: String,
    pub metric: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSubscription {
    pub controller_id: String,
    pub metric: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricUpdate {
    pub sequence: u64,
    pub metric: String,
    pub value: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InterferenceFailureCode {
    DuplicateController,
    MissingTimescaleStatement,
    InvalidTimescaleInterval,
    UnknownController,
    UnauthorizedRead,
    UnauthorizedWrite,
    TimescaleConflict,
}

impl fmt::Display for InterferenceFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateController => f.write_str("duplicate_controller"),
            Self::MissingTimescaleStatement => f.write_str("missing_timescale_statement"),
            Self::InvalidTimescaleInterval => f.write_str("invalid_timescale_interval"),
            Self::UnknownController => f.write_str("unknown_controller"),
            Self::UnauthorizedRead => f.write_str("unauthorized_read"),
            Self::UnauthorizedWrite => f.write_str("unauthorized_write"),
            Self::TimescaleConflict => f.write_str("timescale_conflict"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceFinding {
    pub code: InterferenceFailureCode,
    pub metric: Option<String>,
    pub controller_ids: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceResolution {
    pub metric: String,
    pub controller_ids: Vec<String>,
    pub mode: ConflictResolutionMode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub metric: Option<String>,
    pub controller_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceEvaluation {
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
    pub read_snapshots: BTreeMap<String, i64>,
    pub applied_writes: Vec<MetricWriteRequest>,
    pub rejected_writes: Vec<MetricWriteRequest>,
    pub resolutions: Vec<InterferenceResolution>,
    pub subscription_streams: BTreeMap<String, Vec<MetricUpdate>>,
    pub final_metrics: BTreeMap<String, i64>,
    pub findings: Vec<InterferenceFinding>,
    pub logs: Vec<InterferenceLogEvent>,
}

pub struct InterferenceScenario<'a> {
    pub trace_id: &'a str,
    pub policy_id: &'a str,
    pub config: &'a InterferenceConfig,
    pub registrations: &'a [ControllerRegistration],
    pub read_requests: &'a [MetricReadRequest],
    pub write_requests: &'a [MetricWriteRequest],
    pub subscriptions: &'a [MetricSubscription],
    pub initial_metrics: &'a BTreeMap<String, i64>,
}

fn evaluate_canonical_value(scenario: &InterferenceScenario<'_>) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(scenario.trace_id.to_string()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(scenario.policy_id.to_string()),
    );

    let mut config_map = BTreeMap::new();
    config_map.insert(
        "min_timescale_separation_millionths".to_string(),
        CanonicalValue::I64(scenario.config.min_timescale_separation_millionths),
    );
    config_map.insert(
        "conflict_resolution_mode".to_string(),
        CanonicalValue::String(scenario.config.conflict_resolution_mode.to_string()),
    );
    map.insert("config".to_string(), CanonicalValue::Map(config_map));

    map.insert(
        "initial_metrics".to_string(),
        CanonicalValue::Map(
            scenario
                .initial_metrics
                .iter()
                .map(|(metric, value)| (metric.clone(), CanonicalValue::I64(*value)))
                .collect(),
        ),
    );

    map.insert(
        "registrations".to_string(),
        CanonicalValue::Array(
            scenario
                .registrations
                .iter()
                .map(|registration| {
                    let mut registration_map = BTreeMap::new();
                    registration_map.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(registration.controller_id.clone()),
                    );
                    registration_map.insert(
                        "read_metrics".to_string(),
                        CanonicalValue::Array(
                            registration
                                .read_metrics
                                .iter()
                                .map(|metric| CanonicalValue::String(metric.clone()))
                                .collect(),
                        ),
                    );
                    registration_map.insert(
                        "write_metrics".to_string(),
                        CanonicalValue::Array(
                            registration
                                .write_metrics
                                .iter()
                                .map(|metric| CanonicalValue::String(metric.clone()))
                                .collect(),
                        ),
                    );
                    let mut timescale_map = BTreeMap::new();
                    timescale_map.insert(
                        "observation_interval_millionths".to_string(),
                        CanonicalValue::I64(registration.timescale.observation_interval_millionths),
                    );
                    timescale_map.insert(
                        "write_interval_millionths".to_string(),
                        CanonicalValue::I64(registration.timescale.write_interval_millionths),
                    );
                    timescale_map.insert(
                        "statement".to_string(),
                        CanonicalValue::String(registration.timescale.statement.clone()),
                    );
                    registration_map
                        .insert("timescale".to_string(), CanonicalValue::Map(timescale_map));
                    CanonicalValue::Map(registration_map)
                })
                .collect(),
        ),
    );

    map.insert(
        "read_requests".to_string(),
        CanonicalValue::Array(
            scenario
                .read_requests
                .iter()
                .map(|request| {
                    let mut req = BTreeMap::new();
                    req.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(request.controller_id.clone()),
                    );
                    req.insert(
                        "metric".to_string(),
                        CanonicalValue::String(request.metric.clone()),
                    );
                    CanonicalValue::Map(req)
                })
                .collect(),
        ),
    );

    map.insert(
        "write_requests".to_string(),
        CanonicalValue::Array(
            scenario
                .write_requests
                .iter()
                .map(|request| {
                    let mut req = BTreeMap::new();
                    req.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(request.controller_id.clone()),
                    );
                    req.insert(
                        "metric".to_string(),
                        CanonicalValue::String(request.metric.clone()),
                    );
                    req.insert("value".to_string(), CanonicalValue::I64(request.value));
                    CanonicalValue::Map(req)
                })
                .collect(),
        ),
    );

    map.insert(
        "subscriptions".to_string(),
        CanonicalValue::Array(
            scenario
                .subscriptions
                .iter()
                .map(|subscription| {
                    let mut s = BTreeMap::new();
                    s.insert(
                        "controller_id".to_string(),
                        CanonicalValue::String(subscription.controller_id.clone()),
                    );
                    s.insert(
                        "metric".to_string(),
                        CanonicalValue::String(subscription.metric.clone()),
                    );
                    CanonicalValue::Map(s)
                })
                .collect(),
        ),
    );

    CanonicalValue::Map(map)
}

fn lookup_registration<'a>(
    registrations: &'a BTreeMap<String, &'a ControllerRegistration>,
    controller_id: &str,
) -> Option<&'a ControllerRegistration> {
    registrations.get(controller_id).copied()
}

/// Evaluate shared metric access with deterministic conflict handling.
pub fn evaluate_controller_interference(
    scenario: &InterferenceScenario<'_>,
) -> InterferenceEvaluation {
    let input_hash = hash_bytes(&deterministic_serde::encode_value(&CanonicalValue::Array(
        vec![
            CanonicalValue::Bytes(CONTROLLER_INTERFERENCE_GUARD_DOMAIN.to_vec()),
            evaluate_canonical_value(scenario),
        ],
    )));
    let decision_id = format!("ctrl-interference-{}", to_hex(&input_hash[..16]));

    let mut logs = Vec::new();
    let mut findings = Vec::new();
    let mut final_metrics = scenario.initial_metrics.clone();
    let mut read_snapshots = BTreeMap::new();
    let mut applied_writes = Vec::new();
    let mut rejected_writes = Vec::new();
    let mut resolutions = Vec::new();
    let mut subscription_streams: BTreeMap<String, Vec<MetricUpdate>> = BTreeMap::new();

    let mut registration_index = BTreeMap::new();
    for registration in scenario.registrations {
        if registration_index
            .insert(registration.controller_id.clone(), registration)
            .is_some()
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::DuplicateController,
                metric: None,
                controller_ids: vec![registration.controller_id.clone()],
                detail: "duplicate controller registration".to_string(),
            });
            continue;
        }

        if registration.timescale.statement.trim().is_empty() {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::MissingTimescaleStatement,
                metric: None,
                controller_ids: vec![registration.controller_id.clone()],
                detail: "timescale statement must be present".to_string(),
            });
        }

        if registration.timescale.observation_interval_millionths <= 0
            || registration.timescale.write_interval_millionths <= 0
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::InvalidTimescaleInterval,
                metric: None,
                controller_ids: vec![registration.controller_id.clone()],
                detail: "timescale intervals must be positive".to_string(),
            });
        }
    }

    let mut writes_by_metric: BTreeMap<String, Vec<MetricWriteRequest>> = BTreeMap::new();
    for write in scenario.write_requests {
        let Some(registration) = lookup_registration(&registration_index, &write.controller_id)
        else {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnknownController,
                metric: Some(write.metric.clone()),
                controller_ids: vec![write.controller_id.clone()],
                detail: "write request references unknown controller".to_string(),
            });
            rejected_writes.push(write.clone());
            continue;
        };

        if !registration.write_metrics.contains(&write.metric) {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnauthorizedWrite,
                metric: Some(write.metric.clone()),
                controller_ids: vec![write.controller_id.clone()],
                detail: "controller not authorized to write metric".to_string(),
            });
            rejected_writes.push(write.clone());
            continue;
        }

        writes_by_metric
            .entry(write.metric.clone())
            .or_default()
            .push(write.clone());
    }

    for read in scenario.read_requests {
        let Some(registration) = lookup_registration(&registration_index, &read.controller_id)
        else {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnknownController,
                metric: Some(read.metric.clone()),
                controller_ids: vec![read.controller_id.clone()],
                detail: "read request references unknown controller".to_string(),
            });
            continue;
        };

        if !(registration.read_metrics.contains(&read.metric)
            || registration.write_metrics.contains(&read.metric))
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnauthorizedRead,
                metric: Some(read.metric.clone()),
                controller_ids: vec![read.controller_id.clone()],
                detail: "controller not authorized to read metric".to_string(),
            });
            continue;
        }

        let snapshot_key = format!("{}:{}", read.controller_id, read.metric);
        let snapshot_value = scenario
            .initial_metrics
            .get(&read.metric)
            .copied()
            .unwrap_or_default();
        read_snapshots.insert(snapshot_key, snapshot_value);

        logs.push(InterferenceLogEvent {
            trace_id: scenario.trace_id.to_string(),
            decision_id: decision_id.clone(),
            policy_id: scenario.policy_id.to_string(),
            component: "controller_interference_guard".to_string(),
            event: "read_snapshot".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            metric: Some(read.metric.clone()),
            controller_ids: vec![read.controller_id.clone()],
        });
    }

    for (metric, mut writes) in writes_by_metric {
        writes.sort_by(|left, right| left.controller_id.cmp(&right.controller_id));

        if writes.len() > 1 {
            let mut conflicting_pair: Option<(String, String, i64)> = None;
            for i in 0..writes.len() {
                for j in (i + 1)..writes.len() {
                    let left_reg =
                        lookup_registration(&registration_index, &writes[i].controller_id)
                            .expect("registration must exist");
                    let right_reg =
                        lookup_registration(&registration_index, &writes[j].controller_id)
                            .expect("registration must exist");
                    let separation = (left_reg.timescale.write_interval_millionths
                        - right_reg.timescale.write_interval_millionths)
                        .abs();
                    if separation < scenario.config.min_timescale_separation_millionths {
                        conflicting_pair = Some((
                            writes[i].controller_id.clone(),
                            writes[j].controller_id.clone(),
                            separation,
                        ));
                        break;
                    }
                }
                if conflicting_pair.is_some() {
                    break;
                }
            }

            if let Some((left_id, right_id, separation)) = conflicting_pair {
                match scenario.config.conflict_resolution_mode {
                    ConflictResolutionMode::Reject => {
                        findings.push(InterferenceFinding {
                            code: InterferenceFailureCode::TimescaleConflict,
                            metric: Some(metric.clone()),
                            controller_ids: vec![left_id.clone(), right_id.clone()],
                            detail: format!(
                                "write timescales are too close ({} ppm separation, min {} ppm)",
                                separation, scenario.config.min_timescale_separation_millionths
                            ),
                        });
                        rejected_writes.extend(writes.clone());
                        logs.push(InterferenceLogEvent {
                            trace_id: scenario.trace_id.to_string(),
                            decision_id: decision_id.clone(),
                            policy_id: scenario.policy_id.to_string(),
                            component: "controller_interference_guard".to_string(),
                            event: "timescale_conflict".to_string(),
                            outcome: "fail".to_string(),
                            error_code: Some(
                                InterferenceFailureCode::TimescaleConflict.to_string(),
                            ),
                            metric: Some(metric.clone()),
                            controller_ids: vec![left_id, right_id],
                        });
                        continue;
                    }
                    ConflictResolutionMode::Serialize => {
                        let controller_ids: Vec<String> = writes
                            .iter()
                            .map(|write| write.controller_id.clone())
                            .collect();
                        resolutions.push(InterferenceResolution {
                            metric: metric.clone(),
                            controller_ids: controller_ids.clone(),
                            mode: ConflictResolutionMode::Serialize,
                            detail: format!(
                                "serialized conflicting writes due to {} ppm separation",
                                separation
                            ),
                        });
                        logs.push(InterferenceLogEvent {
                            trace_id: scenario.trace_id.to_string(),
                            decision_id: decision_id.clone(),
                            policy_id: scenario.policy_id.to_string(),
                            component: "controller_interference_guard".to_string(),
                            event: "write_conflict_serialized".to_string(),
                            outcome: "pass".to_string(),
                            error_code: None,
                            metric: Some(metric.clone()),
                            controller_ids,
                        });
                    }
                }
            }
        }

        for write in writes {
            final_metrics.insert(metric.clone(), write.value);
            applied_writes.push(write);
        }
    }

    let mut update_sequence = 0u64;
    let mut sorted_subscriptions = scenario.subscriptions.to_vec();
    sorted_subscriptions.sort_by(|left, right| {
        left.controller_id
            .cmp(&right.controller_id)
            .then(left.metric.cmp(&right.metric))
    });
    for subscription in sorted_subscriptions {
        let Some(registration) =
            lookup_registration(&registration_index, &subscription.controller_id)
        else {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnknownController,
                metric: Some(subscription.metric.clone()),
                controller_ids: vec![subscription.controller_id.clone()],
                detail: "subscription references unknown controller".to_string(),
            });
            continue;
        };
        if !(registration.read_metrics.contains(&subscription.metric)
            || registration.write_metrics.contains(&subscription.metric))
        {
            findings.push(InterferenceFinding {
                code: InterferenceFailureCode::UnauthorizedRead,
                metric: Some(subscription.metric.clone()),
                controller_ids: vec![subscription.controller_id.clone()],
                detail: "subscription for unauthorized metric".to_string(),
            });
            continue;
        }

        if let Some(value) = final_metrics.get(&subscription.metric) {
            update_sequence = update_sequence.saturating_add(1);
            let update = MetricUpdate {
                sequence: update_sequence,
                metric: subscription.metric.clone(),
                value: *value,
            };
            subscription_streams
                .entry(subscription.controller_id.clone())
                .or_default()
                .push(update);
        }
    }

    let pass = findings.is_empty();
    logs.push(InterferenceLogEvent {
        trace_id: scenario.trace_id.to_string(),
        decision_id: decision_id.clone(),
        policy_id: scenario.policy_id.to_string(),
        component: "controller_interference_guard".to_string(),
        event: "interference_summary".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if pass {
            None
        } else {
            Some("controller_interference_failed".to_string())
        },
        metric: None,
        controller_ids: Vec::new(),
    });

    InterferenceEvaluation {
        decision_id,
        pass,
        rollback_required: !pass,
        read_snapshots,
        applied_writes,
        rejected_writes,
        resolutions,
        subscription_streams,
        final_metrics,
        findings,
        logs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                .collect(),
            write_metrics: write_metrics
                .iter()
                .map(|metric| (*metric).to_string())
                .collect(),
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
    fn concurrent_reads_observe_consistent_snapshots() {
        let registrations = vec![
            registration(
                "ctrl-a",
                &["cpu"],
                &[],
                1_000_000,
                2_000_000,
                "reads every 1s",
            ),
            registration(
                "ctrl-b",
                &["cpu"],
                &[],
                500_000,
                2_500_000,
                "reads every 500ms",
            ),
        ];

        let config = InterferenceConfig::default();
        let read_requests = [
            MetricReadRequest {
                controller_id: "ctrl-a".to_string(),
                metric: "cpu".to_string(),
            },
            MetricReadRequest {
                controller_id: "ctrl-b".to_string(),
                metric: "cpu".to_string(),
            },
        ];
        let write_requests: [MetricWriteRequest; 0] = [];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-read",
            "policy-read",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.read_snapshots.get("ctrl-a:cpu"), Some(&10));
        assert_eq!(evaluation.read_snapshots.get("ctrl-b:cpu"), Some(&10));
    }

    #[test]
    fn timescale_conflict_rejects_writes_when_policy_requires_reject() {
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
                value: 900,
            },
            MetricWriteRequest {
                controller_id: "writer-b".to_string(),
                metric: "throughput".to_string(),
                value: 700,
            },
        ];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-conflict",
            "policy-conflict",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(!evaluation.pass);
        assert!(evaluation.rollback_required);
        assert_eq!(evaluation.applied_writes.len(), 0);
        assert_eq!(evaluation.rejected_writes.len(), 2);
        assert!(evaluation.findings.iter().any(|finding| {
            finding.code == InterferenceFailureCode::TimescaleConflict
                && finding.metric.as_deref() == Some("throughput")
        }));
    }

    #[test]
    fn timescale_conflict_can_serialize_writes_when_policy_allows() {
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
        ];

        let config = InterferenceConfig {
            min_timescale_separation_millionths: 100_000,
            conflict_resolution_mode: ConflictResolutionMode::Serialize,
        };
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests = [
            MetricWriteRequest {
                controller_id: "writer-b".to_string(),
                metric: "latency".to_string(),
                value: 77,
            },
            MetricWriteRequest {
                controller_id: "writer-a".to_string(),
                metric: "latency".to_string(),
                value: 88,
            },
        ];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-serialize",
            "policy-serialize",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.rejected_writes.len(), 0);
        assert_eq!(evaluation.applied_writes.len(), 2);
        assert_eq!(evaluation.final_metrics.get("latency"), Some(&77));
        assert_eq!(evaluation.resolutions.len(), 1);
        assert_eq!(
            evaluation.resolutions[0].mode,
            ConflictResolutionMode::Serialize
        );
    }

    #[test]
    fn read_while_write_preserves_snapshot_isolation() {
        let registrations = vec![
            registration(
                "reader",
                &["cpu"],
                &[],
                200_000,
                2_000_000,
                "reads every 200ms",
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

        let config = InterferenceConfig::default();
        let read_requests = [MetricReadRequest {
            controller_id: "reader".to_string(),
            metric: "cpu".to_string(),
        }];
        let write_requests = [MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "cpu".to_string(),
            value: 42,
        }];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-rw",
            "policy-rw",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.read_snapshots.get("reader:cpu"), Some(&10));
        assert_eq!(evaluation.final_metrics.get("cpu"), Some(&42));
    }

    #[test]
    fn subscriptions_receive_isolated_deterministic_updates() {
        let registrations = vec![
            registration(
                "sub-a",
                &["throughput"],
                &[],
                250_000,
                2_000_000,
                "subscribes every 250ms",
            ),
            registration(
                "sub-b",
                &["throughput"],
                &[],
                500_000,
                2_000_000,
                "subscribes every 500ms",
            ),
            registration(
                "writer",
                &["throughput"],
                &["throughput"],
                1_000_000,
                1_000_000,
                "writes every 1s",
            ),
        ];

        let config = InterferenceConfig::default();
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests = [MetricWriteRequest {
            controller_id: "writer".to_string(),
            metric: "throughput".to_string(),
            value: 2_000,
        }];
        let subscriptions = [
            MetricSubscription {
                controller_id: "sub-b".to_string(),
                metric: "throughput".to_string(),
            },
            MetricSubscription {
                controller_id: "sub-a".to_string(),
                metric: "throughput".to_string(),
            },
        ];
        let metrics = initial_metrics();

        let evaluation = evaluate_controller_interference(&scenario(
            "trace-sub",
            "policy-sub",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(evaluation.pass);
        assert_eq!(evaluation.subscription_streams.len(), 2);
        assert_eq!(
            evaluation
                .subscription_streams
                .get("sub-a")
                .and_then(|updates| updates.first())
                .map(|update| update.value),
            Some(2_000)
        );
        assert_eq!(
            evaluation
                .subscription_streams
                .get("sub-b")
                .and_then(|updates| updates.first())
                .map(|update| update.value),
            Some(2_000)
        );
    }

    #[test]
    fn missing_timescale_statement_fails_closed() {
        let registrations = vec![registration(
            "ctrl-a",
            &["cpu"],
            &["cpu"],
            1_000_000,
            1_000_000,
            "   ",
        )];

        let config = InterferenceConfig::default();
        let read_requests: [MetricReadRequest; 0] = [];
        let write_requests: [MetricWriteRequest; 0] = [];
        let subscriptions: [MetricSubscription; 0] = [];
        let metrics = initial_metrics();
        let evaluation = evaluate_controller_interference(&scenario(
            "trace-invalid",
            "policy-invalid",
            &config,
            &registrations,
            (&read_requests, &write_requests, &subscriptions),
            &metrics,
        ));

        assert!(!evaluation.pass);
        assert!(evaluation.rollback_required);
        assert!(
            evaluation.findings.iter().any(|finding| {
                finding.code == InterferenceFailureCode::MissingTimescaleStatement
            })
        );
    }
}
