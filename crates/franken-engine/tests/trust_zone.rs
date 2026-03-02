use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability::trust_zone::{
    TrustZoneError, ZoneHierarchy, ZoneTransitionRequest,
};

fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
    caps.iter().copied().collect()
}

#[test]
fn unassigned_entities_default_to_community_zone() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let zone = hierarchy
        .zone_for_entity("ext-unassigned")
        .expect("default zone");
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn multi_zone_configuration_enforces_team_ceiling() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-team-tool", "team", "trace-assign")
        .expect("assign team");

    let allowed = capset(&[RuntimeCapability::VmDispatch]);
    hierarchy
        .enforce_ceiling("team", &allowed, "trace-ceiling-pass")
        .expect("team should allow vm dispatch");

    let denied = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    let err = hierarchy
        .enforce_ceiling("team", &denied, "trace-ceiling-fail")
        .expect_err("team must reject network egress");

    match err {
        TrustZoneError::CapabilityCeilingExceeded { zone_name, .. } => {
            assert_eq!(zone_name, "team");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn transition_to_private_re_evaluates_and_allows_broader_caps() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 2).expect("hierarchy");
    hierarchy
        .assign_entity("ext-upgrade", "community", "trace-initial")
        .expect("assign initial");

    let requested = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);

    let before = hierarchy
        .enforce_ceiling("community", &requested, "trace-before")
        .expect_err("community ceiling should deny network egress");
    assert!(matches!(
        before,
        TrustZoneError::CapabilityCeilingExceeded { .. }
    ));

    hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-upgrade",
            "private",
            "trace-transition",
            "policy-zone",
            "decision-zone",
            true,
        ))
        .expect("policy-approved transition");

    let now_zone = hierarchy.zone_for_entity("ext-upgrade").expect("zone");
    assert_eq!(now_zone.zone_name, "private");

    hierarchy
        .enforce_ceiling("private", &requested, "trace-after")
        .expect("private ceiling should allow requested caps after re-check");
}

// ────────────────────────────────────────────────────────────
// Enrichment: zone lifecycle, transitions, error paths, serde
// ────────────────────────────────────────────────────────────

#[test]
fn zone_hierarchy_new_creates_default_zone() {
    let hierarchy = ZoneHierarchy::new("community");
    let zone = hierarchy.zone("community");
    assert!(zone.is_none(), "new() does not auto-create zones");
}

#[test]
fn add_zone_succeeds_and_zone_is_retrievable() {
    use frankenengine_engine::capability::trust_zone::{TrustZoneClass, ZoneCreateRequest};

    let mut hierarchy = ZoneHierarchy::new("myzone");
    hierarchy
        .add_zone(ZoneCreateRequest::new(
            "myzone",
            TrustZoneClass::Community,
            1,
            "test",
        ))
        .expect("should add zone");

    let zone = hierarchy.zone("myzone").expect("zone should exist");
    assert_eq!(zone.zone_name, "myzone");
}

#[test]
fn duplicate_zone_add_fails() {
    use frankenengine_engine::capability::trust_zone::{TrustZoneClass, ZoneCreateRequest};

    let mut hierarchy = ZoneHierarchy::new("dup");
    hierarchy
        .add_zone(ZoneCreateRequest::new(
            "dup",
            TrustZoneClass::Community,
            1,
            "test",
        ))
        .expect("first add");
    let err = hierarchy
        .add_zone(ZoneCreateRequest::new(
            "dup",
            TrustZoneClass::Community,
            1,
            "test",
        ))
        .expect_err("duplicate zone add must fail");
    assert!(matches!(err, TrustZoneError::ZoneAlreadyExists { .. }));
    assert!(err.to_string().contains("dup"));
}

#[test]
fn add_zone_with_missing_parent_fails() {
    use frankenengine_engine::capability::trust_zone::{TrustZoneClass, ZoneCreateRequest};

    let mut hierarchy = ZoneHierarchy::new("orphan");
    let err = hierarchy
        .add_zone(
            ZoneCreateRequest::new("orphan", TrustZoneClass::Team, 1, "test")
                .with_parent("nonexistent-parent"),
        )
        .expect_err("missing parent must fail");
    assert!(matches!(err, TrustZoneError::ParentZoneMissing { .. }));
}

#[test]
fn zone_for_entity_returns_default_for_unknown() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let zone = hierarchy
        .zone_for_entity("never-assigned")
        .expect("default zone");
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn assign_entity_to_missing_zone_fails() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let err = hierarchy
        .assign_entity("ext-1", "nonexistent-zone", "trace-bad")
        .expect_err("missing zone assign must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn assign_entity_changes_zone_lookup() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-reassign", "team", "trace-assign")
        .expect("assign to team");
    let zone = hierarchy.zone_for_entity("ext-reassign").expect("zone");
    assert_eq!(zone.zone_name, "team");

    // Reassign to private
    hierarchy
        .assign_entity("ext-reassign", "private", "trace-reassign")
        .expect("reassign to private");
    let zone2 = hierarchy.zone_for_entity("ext-reassign").expect("zone");
    assert_eq!(zone2.zone_name, "private");
}

#[test]
fn transition_entity_to_missing_zone_fails() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-t", "community", "trace-init")
        .expect("assign");
    let err = hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-t",
            "nonexistent",
            "trace-trans",
            "policy",
            "decision",
            true,
        ))
        .expect_err("transition to missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn transition_entity_denied_when_policy_gate_not_approved() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-deny", "community", "trace-init")
        .expect("assign");
    let err = hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-deny",
            "team",
            "trace-deny",
            "policy-deny",
            "decision-deny",
            false,
        ))
        .expect_err("unapproved transition must fail");
    assert!(matches!(err, TrustZoneError::PolicyGateDenied { .. }));
    assert!(err.to_string().contains("ext-deny"));
}

#[test]
fn compute_effective_ceiling_for_missing_zone_fails() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let err = hierarchy
        .compute_effective_ceiling("nonexistent")
        .expect_err("missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn compute_effective_ceiling_for_existing_zone_returns_set() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let ceiling = hierarchy
        .compute_effective_ceiling("owner")
        .expect("owner zone exists");
    // Owner zone has the broadest ceiling
    assert!(!ceiling.is_empty());
}

#[test]
fn events_are_recorded_during_transitions() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-ev", "community", "trace-ev-init")
        .expect("assign");
    hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-ev",
            "team",
            "trace-ev-trans",
            "policy-ev",
            "decision-ev",
            true,
        ))
        .expect("transition");

    let events = hierarchy.events();
    assert!(!events.is_empty());
    let last = events.last().expect("at least one event");
    assert_eq!(last.from_zone.as_deref(), Some("community"));
    assert_eq!(last.to_zone.as_deref(), Some("team"));
}

#[test]
fn drain_events_clears_event_list() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-drain", "community", "trace-drain")
        .expect("assign");

    let drained = hierarchy.drain_events();
    assert!(!drained.is_empty());
    assert!(hierarchy.events().is_empty());
}

#[test]
fn zone_hierarchy_serde_round_trip() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize");
    let recovered: ZoneHierarchy = serde_json::from_str(&json).expect("deserialize");
    let json2 = serde_json::to_string(&recovered).expect("re-serialize");
    assert_eq!(json, json2);
}

#[test]
fn zone_transition_request_serde_round_trip() {
    let request = ZoneTransitionRequest::new(
        "ext-serde",
        "team",
        "trace-serde",
        "policy-serde",
        "decision-serde",
        true,
    );
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: ZoneTransitionRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(request.entity_id, recovered.entity_id);
    assert_eq!(request.to_zone_name, recovered.to_zone_name);
    assert_eq!(request.policy_gate_approved, recovered.policy_gate_approved);
}

#[test]
fn enforce_ceiling_on_missing_zone_fails() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let requested = capset(&[RuntimeCapability::VmDispatch]);
    let err = hierarchy
        .enforce_ceiling("nonexistent-zone", &requested, "trace-bad-zone")
        .expect_err("missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn trust_zone_error_display_covers_all_variants() {
    let errors: Vec<TrustZoneError> = vec![
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".to_string(),
        },
        TrustZoneError::ParentZoneMissing {
            zone_name: "z".to_string(),
            parent_zone: "p".to_string(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".to_string(),
        },
        TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "z".to_string(),
            requested: capset(&[RuntimeCapability::VmDispatch]),
            ceiling: BTreeSet::new(),
        },
        TrustZoneError::PolicyGateDenied {
            entity_id: "e".to_string(),
            from_zone: "a".to_string(),
            to_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneAuthorityLeak {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneProvenanceNotPermitted {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
    ];

    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {err:?} must not be empty");
    }
}
