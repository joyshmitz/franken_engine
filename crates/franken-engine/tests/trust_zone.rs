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
