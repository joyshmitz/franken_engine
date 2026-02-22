use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_registry::{
    AuthorityEnvelope, GaReleaseGuardConfig, GaReleaseGuardInput, GaReleaseGuardVerdict,
    GaSignedLineageArtifact, SlotCapability, SlotId, SlotKind, SlotRegistry,
};

fn test_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::EmitEvidence,
        ],
    }
}

fn narrower_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
    }
}

fn register_slot(registry: &mut SlotRegistry, id: &str, kind: SlotKind, digest: &str) -> SlotId {
    let slot_id = SlotId::new(id).expect("valid slot id");
    registry
        .register_delegate(
            slot_id.clone(),
            kind,
            test_authority(),
            digest.to_string(),
            "2026-02-21T00:00:00Z".to_string(),
        )
        .expect("register delegate");
    slot_id
}

fn promote_slot(registry: &mut SlotRegistry, slot_id: &SlotId, digest: &str) {
    registry
        .begin_candidacy(
            slot_id,
            format!("{digest}-candidate"),
            "2026-02-21T00:00:01Z".to_string(),
        )
        .expect("begin candidacy");
    registry
        .promote(
            slot_id,
            digest.to_string(),
            &narrower_authority(),
            format!("receipt-{digest}"),
            "2026-02-21T00:00:02Z".to_string(),
        )
        .expect("promote");
}

fn lineage_artifact(
    slot_id: &SlotId,
    former_delegate_digest: &str,
    replacement_component_digest: &str,
) -> GaSignedLineageArtifact {
    GaSignedLineageArtifact {
        slot_id: slot_id.clone(),
        former_delegate_digest: former_delegate_digest.to_string(),
        replacement_component_digest: replacement_component_digest.to_string(),
        replacement_author: "ga-release-operator".to_string(),
        replacement_timestamp: "2026-02-21T00:00:03Z".to_string(),
        lineage_signature: "sig:ga-lineage".to_string(),
        trust_anchor_ref: "trust-anchor://ga-lineage-v1".to_string(),
        signature_verified: true,
        equivalence_suite_ref: "suite://ga-core-equivalence-v1".to_string(),
        equivalence_passed: true,
        delegate_fallback_reachable: false,
    }
}

fn pipeline_input(
    core_slots: BTreeSet<SlotId>,
    non_core_limit: Option<usize>,
) -> GaReleaseGuardInput {
    let mut remediation_estimates = BTreeMap::new();
    remediation_estimates.insert(
        SlotId::new("parser").expect("valid parser id"),
        "4 engineering-days".to_string(),
    );
    remediation_estimates.insert(
        SlotId::new("builtins").expect("valid builtins id"),
        "2 engineering-days".to_string(),
    );

    GaReleaseGuardInput {
        trace_id: "trace-ga-pipeline-001".to_string(),
        decision_id: "decision-ga-pipeline-001".to_string(),
        policy_id: "policy-ga-release-readiness-v1".to_string(),
        current_epoch: SecurityEpoch::from_raw(100),
        config: GaReleaseGuardConfig {
            core_slots,
            non_core_delegate_limit: non_core_limit,
            lineage_dashboard_ref: "frankentui://replacement-lineage/ga-release".to_string(),
        },
        exemptions: Vec::new(),
        lineage_artifacts: Vec::new(),
        remediation_estimates,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn mock_release_pipeline_blocks_when_core_delegate_slot_exists() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let interpreter = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:delegate-interpreter",
    );
    let _builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );
    promote_slot(&mut registry, &interpreter, "sha256:native-interpreter");

    let core_slots = BTreeSet::from([parser.clone(), interpreter.clone()]);
    let mut input = pipeline_input(core_slots, Some(2));
    input.lineage_artifacts = vec![lineage_artifact(
        &interpreter,
        "sha256:delegate-interpreter",
        "sha256:native-interpreter",
    )];
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should evaluate");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
    assert_eq!(artifact.blocking_slots.len(), 1);
    assert_eq!(artifact.blocking_slots[0].slot_id, parser);
    assert_eq!(
        artifact.blocking_slots[0].estimated_remediation,
        "4 engineering-days"
    );
    assert!(artifact.events.iter().all(|event| {
        event.trace_id == "trace-ga-pipeline-001"
            && event.decision_id == "decision-ga-pipeline-001"
            && event.policy_id == "policy-ga-release-readiness-v1"
            && event.component == "ga_release_delegate_guard"
    }));
}

#[test]
fn mock_release_pipeline_passes_when_core_slots_are_native() {
    let mut registry = SlotRegistry::new();
    let parser = register_slot(
        &mut registry,
        "parser",
        SlotKind::Parser,
        "sha256:delegate-parser",
    );
    let interpreter = register_slot(
        &mut registry,
        "interpreter",
        SlotKind::Interpreter,
        "sha256:delegate-interpreter",
    );
    let _builtins = register_slot(
        &mut registry,
        "builtins",
        SlotKind::Builtins,
        "sha256:delegate-builtins",
    );

    promote_slot(&mut registry, &parser, "sha256:native-parser");
    promote_slot(&mut registry, &interpreter, "sha256:native-interpreter");

    let core_slots = BTreeSet::from([parser.clone(), interpreter.clone()]);
    let mut input = pipeline_input(core_slots, Some(2));
    input.lineage_artifacts = vec![
        lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser"),
        lineage_artifact(
            &interpreter,
            "sha256:delegate-interpreter",
            "sha256:native-interpreter",
        ),
    ];
    let artifact = registry
        .evaluate_ga_release_guard(&input)
        .expect("guard should evaluate");

    assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
    assert!(artifact.blocking_slots.is_empty());
    assert_eq!(artifact.core_delegate_count, 0);
    assert_eq!(artifact.non_core_delegate_count, 1);
    assert_eq!(
        artifact.lineage_dashboard_ref,
        "frankentui://replacement-lineage/ga-release"
    );
}

#[test]
fn version_matrix_workflow_runs_ga_delegate_guard_check() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("read workflow");
    assert!(
        workflow.contains("./scripts/check_ga_delegate_core_slots.sh ci"),
        "workflow must run GA delegate guard check script"
    );
}
