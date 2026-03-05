use std::collections::BTreeSet;

use frankenengine_engine::declassification_pipeline::{
    DeclassificationPipeline, DeclassificationRequest, LossAssessment,
};
use frankenengine_engine::flow_lattice::{
    Clearance, DeclassificationObligation, FlowCheckResult, FlowLatticeError, Ir2FlowLattice,
    LabelClass,
};
use frankenengine_engine::ifc_artifacts::{
    DeclassificationRoute, FlowPolicy, IfcSchemaVersion, Label,
};
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

fn make_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "policy-ifc-runtime".to_string(),
        extension_id: "ext-ifc-runtime".to_string(),
        label_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        clearance_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![DeclassificationRoute {
            route_id: "declass-secret-internal".to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Internal,
            conditions: vec!["audit_approval".to_string()],
        }],
        epoch_id: 7,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    }
}

fn make_request(route_id: &str) -> DeclassificationRequest {
    DeclassificationRequest {
        request_id: format!("req-{route_id}"),
        source_label: Label::Secret,
        sink_clearance: Label::Internal,
        extension_id: "ext-ifc-runtime".to_string(),
        code_location: "runtime::egress".to_string(),
        trace_id: "trace-ifc-runtime".to_string(),
        requested_route_id: route_id.to_string(),
        is_emergency: false,
        timestamp_ms: 1_700_000_010_000,
    }
}

fn low_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 10_000,
        data_sensitivity_bps: 1_200,
        sink_exposure_bps: 800,
        historical_abuse_detected: false,
        summary: "low risk".to_string(),
    }
}

fn high_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 500_000,
        data_sensitivity_bps: 9_200,
        sink_exposure_bps: 8_400,
        historical_abuse_detected: true,
        summary: "high risk".to_string(),
    }
}

#[test]
fn runtime_lattice_emits_receipt_linkage_for_authorized_declassification() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 4,
            use_count: 0,
        })
        .expect("register obligation");

    let flow_check = lattice.check_flow(
        &LabelClass::Secret,
        &Clearance::NeverSink,
        "trace-ifc-runtime",
    );
    assert_eq!(
        flow_check,
        FlowCheckResult::RequiresDeclassification {
            obligation_id: "obl-secret-egress".to_string(),
        }
    );

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([5u8; 32]);
    let receipt = pipeline
        .process(
            &make_request("declass-secret-internal"),
            &make_policy(),
            &low_loss(),
            &signing_key,
        )
        .expect("allow receipt");

    lattice
        .use_declassification_with_receipt("obl-secret-egress", &receipt, "trace-ifc-runtime")
        .expect("receipt-linked usage should succeed");

    let last_event = lattice.events().last().expect("event");
    assert_eq!(last_event.event, "use_declassification");
    assert_eq!(last_event.outcome, "ok");
    assert_eq!(
        last_event.obligation_id.as_deref(),
        Some("obl-secret-egress")
    );
    assert_eq!(
        last_event.decision_contract_id.as_deref(),
        Some("decision-contract-ifc")
    );
    assert_eq!(
        last_event.receipt_id.as_deref(),
        Some(receipt.receipt_id.as_str())
    );
    assert_eq!(
        last_event.receipt_replay_command.as_deref(),
        Some(receipt.replay_command().as_str())
    );
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(1)
    );
}

#[test]
fn runtime_lattice_rejects_denied_receipt_and_keeps_obligation_unused() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let flow_check = lattice.check_flow(
        &LabelClass::Secret,
        &Clearance::NeverSink,
        "trace-ifc-runtime",
    );
    assert!(matches!(
        flow_check,
        FlowCheckResult::RequiresDeclassification { .. }
    ));

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([6u8; 32]);
    let denied_receipt = pipeline
        .process(
            &make_request("declass-secret-internal"),
            &make_policy(),
            &high_loss(),
            &signing_key,
        )
        .expect("pipeline returns deny receipt");
    assert_eq!(denied_receipt.decision.to_string(), "deny");

    let event_count_before = lattice.events().len();
    let err = lattice
        .use_declassification_with_receipt(
            "obl-secret-egress",
            &denied_receipt,
            "trace-ifc-runtime",
        )
        .expect_err("deny receipt must fail closed");
    assert!(matches!(err, FlowLatticeError::FlowBlocked { .. }));
    assert_eq!(lattice.events().len(), event_count_before);
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}

#[test]
fn runtime_lattice_rejects_tampered_allow_receipt_signature() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([7u8; 32]);
    let mut tampered_receipt = pipeline
        .process(
            &make_request("declass-secret-internal"),
            &make_policy(),
            &low_loss(),
            &signing_key,
        )
        .expect("allow receipt");
    tampered_receipt.policy_evaluation_summary = "tampered summary".to_string();

    let event_count_before = lattice.events().len();
    let err = lattice
        .use_declassification_with_receipt(
            "obl-secret-egress",
            &tampered_receipt,
            "trace-ifc-runtime",
        )
        .expect_err("tampered receipt must fail closed");
    match err {
        FlowLatticeError::FlowBlocked { detail } => {
            assert!(
                detail.contains("failed signature verification"),
                "unexpected error detail: {detail}"
            );
        }
        other => panic!("expected FlowBlocked for tampered receipt, got {other:?}"),
    }
    assert_eq!(lattice.events().len(), event_count_before);
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}
