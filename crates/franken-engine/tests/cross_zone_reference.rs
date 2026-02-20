use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability::trust_zone::{
    CrossZoneReferenceChecker, CrossZoneReferenceRequest, ReferenceType, TrustZoneError,
    ZoneHierarchy,
};

fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
    caps.iter().copied().collect()
}

#[test]
fn multi_zone_extensions_can_reference_foreign_audit_data_via_provenance() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");

    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-prov-1",
            ),
        )
        .expect("provenance cross-zone reference should be permitted");

    let event = checker.events().last().expect("event");
    assert_eq!(event.trace_id, "trace-prov-1");
    assert_eq!(event.from_zone.as_deref(), Some("community"));
    assert_eq!(event.to_zone.as_deref(), Some("team"));
}

#[test]
fn cross_zone_authority_reference_and_capability_escalation_are_denied() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-community", "community", "trace-assign")
        .expect("assign");

    let mut checker = CrossZoneReferenceChecker::new();
    let err = hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "private",
                ReferenceType::Authority,
                "trace-auth-deny",
            ),
        )
        .expect_err("authority cross-zone ref must be denied");
    assert!(matches!(err, TrustZoneError::CrossZoneAuthorityLeak { .. }));

    let requested = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    let err = hierarchy
        .enforce_ceiling("community", &requested, "trace-ceiling-deny")
        .expect_err("community ceiling must deny attempted escalation");

    assert!(matches!(
        err,
        TrustZoneError::CapabilityCeilingExceeded { .. }
    ));
}
