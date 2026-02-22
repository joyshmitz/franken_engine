#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::collections::BTreeSet;
use std::path::PathBuf;

use conformance_harness::{
    ConformanceLogEvent, ConformanceRunResult, ConformanceRunner, ConformanceWaiverSet,
};

const IFC_RELEASE_GATE_ERROR: &str = "FE-IFCR-1001";
const REQUIRED_FLOW_PATH_TYPES: [&str; 5] =
    ["direct", "indirect", "implicit", "temporal", "covert"];
const REQUIRED_EXFIL_VECTOR_DOMAINS: [&str; 6] = [
    "ifc_corpus/exfil/eval_function",
    "ifc_corpus/exfil/proxy_reflect",
    "ifc_corpus/exfil/native_addon_escape",
    "ifc_corpus/exfil/shared_array_buffer",
    "ifc_corpus/exfil/structured_clone",
    "ifc_corpus/exfil/prototype_chain",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfcReleaseGateMetrics {
    benign_total: usize,
    exfil_total: usize,
    declassify_total: usize,
    false_positive_count: usize,
    unauthorized_exfil_success_count: usize,
    direct_indirect_bypass_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfcReleaseGateDecision {
    blocked: bool,
    error_code: Option<String>,
    blockers: Vec<String>,
    metrics: IfcReleaseGateMetrics,
}

impl IfcReleaseGateDecision {
    fn allows_release(&self) -> bool {
        !self.blocked && self.error_code.is_none()
    }
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/ifc_corpus/ifc_conformance_assets.json")
}

fn run_ifc_corpus() -> ConformanceRunResult {
    ConformanceRunner::default()
        .run(manifest_path(), &ConformanceWaiverSet::default())
        .expect("ifc corpus should execute")
}

fn event_has_required_fields(event: &ConformanceLogEvent) -> bool {
    !event.trace_id.trim().is_empty()
        && !event.decision_id.trim().is_empty()
        && !event.policy_id.trim().is_empty()
        && !event.component.trim().is_empty()
        && !event.event.trim().is_empty()
        && !event.outcome.trim().is_empty()
}

fn evaluate_ifc_release_gate(run: &ConformanceRunResult) -> IfcReleaseGateDecision {
    let mut blockers = Vec::new();

    if let Err(err) = run.enforce_ci_gate() {
        blockers.push(format!("conformance ci gate rejected run: {err}"));
    }

    if run.summary.failed > 0 || run.summary.errored > 0 {
        blockers.push(format!(
            "run summary contains failures (failed={}, errored={})",
            run.summary.failed, run.summary.errored
        ));
    }

    let ifc_logs: Vec<&ConformanceLogEvent> = run
        .logs
        .iter()
        .filter(|event| event.category.is_some())
        .collect();
    if ifc_logs.is_empty() {
        blockers.push("manifest produced no IFC logs".to_string());
    }

    let mut benign_total = 0usize;
    let mut exfil_total = 0usize;
    let mut declassify_total = 0usize;
    let mut false_positive_count = 0usize;
    let mut unauthorized_exfil_success_count = 0usize;
    let mut direct_indirect_bypass_count = 0usize;
    let mut flow_path_coverage = BTreeSet::new();
    let mut vector_domain_coverage = BTreeSet::new();

    for event in &ifc_logs {
        if !event_has_required_fields(event) {
            blockers.push(format!(
                "asset `{}` missing required structured log fields",
                event.asset_id
            ));
        }

        if event.source_labels.is_empty() || event.sink_clearances.is_empty() {
            blockers.push(format!(
                "asset `{}` missing source/sink IFC labels in log",
                event.asset_id
            ));
        }

        if let Some(flow_path) = event.flow_path_type.as_deref() {
            flow_path_coverage.insert(flow_path.to_string());
        }

        for required_domain in REQUIRED_EXFIL_VECTOR_DOMAINS {
            if event.semantic_domain == required_domain {
                vector_domain_coverage.insert(required_domain.to_string());
            }
        }

        match event.category.as_deref() {
            Some("benign") => {
                benign_total += 1;
                if event.actual_outcome.as_deref() == Some("block") {
                    false_positive_count += 1;
                }
            }
            Some("exfil") => {
                exfil_total += 1;
                if event.actual_outcome.as_deref() != Some("block") {
                    unauthorized_exfil_success_count += 1;
                    if matches!(event.flow_path_type.as_deref(), Some("direct" | "indirect")) {
                        direct_indirect_bypass_count += 1;
                    }
                }
                if event.evidence_type.as_deref() != Some("flow_violation") {
                    blockers.push(format!(
                        "exfil asset `{}` missing flow_violation evidence type",
                        event.asset_id
                    ));
                }
                if event
                    .evidence_id
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    blockers.push(format!(
                        "exfil asset `{}` missing evidence_id receipt handle",
                        event.asset_id
                    ));
                }
            }
            Some("declassify") => {
                declassify_total += 1;
                if event.actual_outcome.as_deref() != Some("declassify") {
                    blockers.push(format!(
                        "declassify asset `{}` did not produce declassify outcome",
                        event.asset_id
                    ));
                }
                if event.evidence_type.as_deref() != Some("declassification_receipt") {
                    blockers.push(format!(
                        "declassify asset `{}` missing declassification receipt type",
                        event.asset_id
                    ));
                }
                if event
                    .evidence_id
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty() || !value.starts_with("dr-"))
                {
                    blockers.push(format!(
                        "declassify asset `{}` missing signed receipt handle",
                        event.asset_id
                    ));
                }
            }
            Some(other) => blockers.push(format!(
                "asset `{}` reported unsupported IFC category `{other}`",
                event.asset_id
            )),
            None => {}
        }
    }

    for required in REQUIRED_FLOW_PATH_TYPES {
        if !flow_path_coverage.contains(required) {
            blockers.push(format!("missing exfil flow-path coverage `{required}`"));
        }
    }

    for required in REQUIRED_EXFIL_VECTOR_DOMAINS {
        if !vector_domain_coverage.contains(required) {
            blockers.push(format!(
                "missing bypass-vector corpus coverage `{required}`"
            ));
        }
    }

    if false_positive_count > 0 {
        blockers.push(format!(
            "false positives detected for benign workloads: {false_positive_count}"
        ));
    }
    if unauthorized_exfil_success_count > 0 {
        blockers.push(format!(
            "unauthorized exfiltration succeeded in {} workload(s)",
            unauthorized_exfil_success_count
        ));
    }
    if direct_indirect_bypass_count > 0 {
        blockers.push(format!(
            "direct/indirect bypasses observed: {direct_indirect_bypass_count}"
        ));
    }

    if benign_total < 100 {
        blockers.push(format!("benign corpus too small: {benign_total} < 100"));
    }
    if exfil_total < 80 {
        blockers.push(format!("exfil corpus too small: {exfil_total} < 80"));
    }
    if declassify_total < 30 {
        blockers.push(format!(
            "declassify corpus too small: {declassify_total} < 30"
        ));
    }

    let blocked = !blockers.is_empty();
    let error_code = if blocked {
        Some(IFC_RELEASE_GATE_ERROR.to_string())
    } else {
        None
    };

    IfcReleaseGateDecision {
        blocked,
        error_code,
        blockers,
        metrics: IfcReleaseGateMetrics {
            benign_total,
            exfil_total,
            declassify_total,
            false_positive_count,
            unauthorized_exfil_success_count,
            direct_indirect_bypass_count,
        },
    }
}

#[test]
fn ifc_release_gate_accepts_published_corpus() {
    let run = run_ifc_corpus();
    let decision = evaluate_ifc_release_gate(&run);

    assert!(
        decision.allows_release(),
        "blockers: {:?}",
        decision.blockers
    );
    assert_eq!(decision.error_code, None);
    assert_eq!(decision.metrics.false_positive_count, 0);
    assert_eq!(decision.metrics.unauthorized_exfil_success_count, 0);
    assert_eq!(decision.metrics.direct_indirect_bypass_count, 0);
    assert!(decision.metrics.benign_total >= 100);
    assert!(decision.metrics.exfil_total >= 80);
    assert!(decision.metrics.declassify_total >= 30);
}

#[test]
fn ifc_release_gate_is_deterministic_for_identical_inputs() {
    let first = evaluate_ifc_release_gate(&run_ifc_corpus());
    let second = evaluate_ifc_release_gate(&run_ifc_corpus());

    assert_eq!(first, second);
    assert!(first.allows_release());
}

#[test]
fn ifc_release_gate_blocks_when_exfiltration_is_allowed() {
    let mut run = run_ifc_corpus();
    let exfil_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("exfil"))
        .expect("expected at least one exfil workload");

    exfil_event.actual_outcome = Some("allow".to_string());
    exfil_event.evidence_type = Some("none".to_string());
    exfil_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(IFC_RELEASE_GATE_ERROR));
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("unauthorized exfiltration succeeded"))
    );
}

#[test]
fn ifc_release_gate_blocks_when_declassification_receipt_is_missing() {
    let mut run = run_ifc_corpus();
    let declass_event = run
        .logs
        .iter_mut()
        .find(|event| event.category.as_deref() == Some("declassify"))
        .expect("expected at least one declassify workload");

    declass_event.evidence_id = None;

    let decision = evaluate_ifc_release_gate(&run);
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(IFC_RELEASE_GATE_ERROR));
    assert!(
        decision
            .blockers
            .iter()
            .any(|entry| entry.contains("missing signed receipt handle"))
    );
}
