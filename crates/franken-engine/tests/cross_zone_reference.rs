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

// ────────────────────────────────────────────────────────────
// Enrichment: zone hierarchy, entity lifecycle, error paths
// ────────────────────────────────────────────────────────────

#[test]
fn standard_hierarchy_creates_expected_zones() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize");
    // Standard hierarchy creates maintainer, team, community, private zones
    assert!(json.contains("maintainer"));
    assert!(json.contains("team"));
    assert!(json.contains("community"));
    assert!(json.contains("private"));
}

#[test]
fn entity_assignment_succeeds_for_existing_zone() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-1", "community", "trace-assign-1")
        .expect("assign to community zone should succeed");
}

#[test]
fn entity_assignment_fails_for_missing_zone() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let err = hierarchy
        .assign_entity("ext-1", "nonexistent-zone", "trace-missing-zone")
        .expect_err("assign to missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    assert!(err.to_string().contains("nonexistent-zone"));
}

#[test]
fn provenance_not_permitted_when_not_allowed() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    // do NOT allow provenance from community to team

    let err = hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-prov-denied",
            ),
        )
        .expect_err("provenance without explicit allow must fail");

    assert!(matches!(
        err,
        TrustZoneError::CrossZoneProvenanceNotPermitted { .. }
    ));
}

#[test]
fn cross_zone_reference_checker_serde_round_trip() {
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");

    let json = serde_json::to_string(&checker).expect("serialize checker");
    let recovered: CrossZoneReferenceChecker =
        serde_json::from_str(&json).expect("deserialize checker");

    // Validate the recovered checker works the same
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-recovered",
            ),
        )
        .expect("recovered checker should allow same provenance");

    let _ = recovered; // confirm deserialization succeeded
}

#[test]
fn zone_hierarchy_serde_round_trip() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize hierarchy");
    let recovered: ZoneHierarchy = serde_json::from_str(&json).expect("deserialize hierarchy");

    let recovered_json = serde_json::to_string(&recovered).expect("serialize recovered");
    assert_eq!(json, recovered_json);
}

#[test]
fn enforce_ceiling_allows_subset_capabilities() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    // The owner zone should have a generous ceiling
    let requested = capset(&[RuntimeCapability::VmDispatch]);
    hierarchy
        .enforce_ceiling("owner", &requested, "trace-ceiling-ok")
        .expect("owner ceiling should allow VmDispatch");
}

#[test]
fn trust_zone_error_display_is_non_empty() {
    let errors: Vec<TrustZoneError> = vec![
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".to_string(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".to_string(),
        },
        TrustZoneError::CrossZoneAuthorityLeak {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneProvenanceNotPermitted {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "z".to_string(),
            requested: capset(&[RuntimeCapability::VmDispatch]),
            ceiling: BTreeSet::new(),
        },
    ];

    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {err:?} must not be empty");
    }
}

#[test]
fn reference_type_serde_round_trip() {
    for ref_type in [ReferenceType::Provenance, ReferenceType::Authority] {
        let json = serde_json::to_string(&ref_type).expect("serialize");
        let recovered: ReferenceType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ref_type, recovered);
    }
}

#[test]
fn cross_zone_reference_request_serde_round_trip() {
    let request = CrossZoneReferenceRequest::new(
        "community",
        "team",
        ReferenceType::Provenance,
        "trace-serde-rt",
    );
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: CrossZoneReferenceRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(request.source_zone, recovered.source_zone);
    assert_eq!(request.target_zone, recovered.target_zone);
    assert_eq!(request.reference_type, recovered.reference_type);
}

#[test]
fn checker_events_are_recorded() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");

    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-event-check",
            ),
        )
        .expect("should succeed");

    assert!(!checker.events().is_empty());
    let event = &checker.events()[0];
    assert_eq!(event.trace_id, "trace-event-check");
}
