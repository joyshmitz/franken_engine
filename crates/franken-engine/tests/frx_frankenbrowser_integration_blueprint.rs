#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::Deserialize;

const BLUEPRINT_SCHEMA_VERSION: &str = "frx.frankenbrowser-integration-blueprint.v1";
const BLUEPRINT_JSON: &str =
    include_str!("../../../docs/frx_frankenbrowser_integration_blueprint_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct BlueprintContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    required_structured_log_fields: Vec<String>,
    architecture: Architecture,
    migration_phases: Vec<MigrationPhase>,
    prerequisites: Vec<Prerequisite>,
    scenarios: Vec<Scenario>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Architecture {
    embedding_boundaries: Vec<EmbeddingBoundary>,
    scheduler_contract: SchedulerContract,
    security_policy_boundaries: Vec<SecurityPolicyBoundary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EmbeddingBoundary {
    boundary_id: String,
    host_surface: String,
    sidecar_surface: String,
    isolation_mode: String,
    allowed_capabilities: Vec<String>,
    denied_capabilities: Vec<String>,
    fallback_route: String,
    deterministic_contract: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SchedulerContract {
    host_scheduler: String,
    sidecar_scheduler: String,
    arbitration_mode: String,
    preemption_budget_us: u64,
    require_replay_stable_queue_order: bool,
    require_explicit_handoff_receipts: bool,
    fallback_route: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityPolicyBoundary {
    policy_surface: String,
    enforcement_mode: String,
    requires_signed_receipt: bool,
    fallback_route: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MigrationPhase {
    phase_id: String,
    position: u32,
    entry_criteria: Vec<String>,
    exit_criteria: Vec<String>,
    promotion_blockers: Vec<String>,
    rollback_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Prerequisite {
    bead_id: String,
    reason: String,
    status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Scenario {
    scenario_id: String,
    category: String,
    required_phase: String,
    expected_decision_path: String,
    expected_outcome: String,
    log_template: ScenarioLogTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScenarioLogTemplate {
    scenario_id: String,
    component: String,
    decision_path: String,
    outcome: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_blueprint() -> BlueprintContract {
    serde_json::from_str(BLUEPRINT_JSON)
        .expect("frankenbrowser integration blueprint JSON must parse")
}

#[test]
fn frx_09_3_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_FRANKENBROWSER_INTEGRATION_BLUEPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX FrankenBrowser Integration Blueprint V1",
        "## Scope",
        "## Embedding Boundaries",
        "## Scheduler and Runtime Interaction Contract",
        "## Security and Policy Boundaries",
        "## Migration Path (Optional Sidecar -> First-Class Browser Subsystem)",
        "## Deterministic Logging and Evidence Contract",
        "## Dependencies and Prerequisites",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "deterministic",
        "fallback",
        "scheduler",
        "security",
        "migration",
        "sidecar",
        "frankenbrowser",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "missing required phrase in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_09_3_contract_is_machine_readable_and_track_bound() {
    let blueprint = parse_blueprint();

    assert_eq!(blueprint.schema_version, BLUEPRINT_SCHEMA_VERSION);
    assert_eq!(blueprint.bead_id, "bd-mjh3.9.3");
    assert_eq!(blueprint.generated_by, "bd-mjh3.9.3");
    assert_eq!(blueprint.track.id, "FRX-09.3");
    assert_eq!(blueprint.track.name, "FrankenBrowser Integration Blueprint");
    assert!(blueprint.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_09_3_embedding_boundaries_are_explicit_and_fail_closed() {
    let blueprint = parse_blueprint();
    let boundaries = &blueprint.architecture.embedding_boundaries;

    assert!(boundaries.len() >= 3);

    let mut boundary_ids = BTreeSet::new();
    for boundary in boundaries {
        assert!(
            boundary_ids.insert(boundary.boundary_id.as_str()),
            "duplicate boundary_id: {}",
            boundary.boundary_id
        );
        assert!(!boundary.host_surface.trim().is_empty());
        assert!(!boundary.sidecar_surface.trim().is_empty());
        assert!(!boundary.isolation_mode.trim().is_empty());
        assert!(!boundary.allowed_capabilities.is_empty());
        assert!(!boundary.denied_capabilities.is_empty());
        assert!(!boundary.deterministic_contract.trim().is_empty());
        assert!(
            boundary.fallback_route.contains("safe_mode")
                || boundary.fallback_route.contains("disable_sidecar"),
            "boundary fallback route must be deterministic and fail-closed: {}",
            boundary.fallback_route
        );

        let allowed: BTreeSet<&str> = boundary
            .allowed_capabilities
            .iter()
            .map(String::as_str)
            .collect();
        let denied: BTreeSet<&str> = boundary
            .denied_capabilities
            .iter()
            .map(String::as_str)
            .collect();
        assert!(
            allowed.is_disjoint(&denied),
            "allowed/denied capabilities overlap in {}",
            boundary.boundary_id
        );
    }

    for expected in [
        "browser_host_boundary",
        "scheduler_bridge_boundary",
        "policy_enforcement_boundary",
    ] {
        assert!(
            boundary_ids.contains(expected),
            "missing required boundary {expected}"
        );
    }
}

#[test]
fn frx_09_3_scheduler_contract_is_deterministic() {
    let blueprint = parse_blueprint();
    let scheduler = &blueprint.architecture.scheduler_contract;

    assert_eq!(scheduler.arbitration_mode, "deterministic_turn_based");
    assert_ne!(scheduler.host_scheduler, scheduler.sidecar_scheduler);
    assert!(scheduler.preemption_budget_us > 0);
    assert!(scheduler.preemption_budget_us <= 20_000);
    assert!(scheduler.require_replay_stable_queue_order);
    assert!(scheduler.require_explicit_handoff_receipts);
    assert!(scheduler.fallback_route.contains("safe_mode"));
}

#[test]
fn frx_09_3_migration_phases_are_ordered_and_reversible() {
    let blueprint = parse_blueprint();
    let mut phases: Vec<&MigrationPhase> = blueprint.migration_phases.iter().collect();

    assert_eq!(phases.len(), 4);

    phases.sort_by_key(|phase| phase.position);
    assert_eq!(phases[0].phase_id, "P0_optional_sidecar");
    assert_eq!(phases[3].phase_id, "P3_first_class_subsystem");

    let expected_positions: BTreeSet<u32> = [0, 1, 2, 3].into_iter().collect();
    let observed_positions: BTreeSet<u32> = phases.iter().map(|phase| phase.position).collect();
    assert_eq!(observed_positions, expected_positions);

    for phase in &phases {
        assert!(!phase.entry_criteria.is_empty());
        assert!(!phase.exit_criteria.is_empty());
        assert!(!phase.promotion_blockers.is_empty());
        assert!(!phase.rollback_action.trim().is_empty());
    }

    let phase_ids: BTreeSet<&str> = phases.iter().map(|phase| phase.phase_id.as_str()).collect();
    for scenario in &blueprint.scenarios {
        assert!(
            phase_ids.contains(scenario.required_phase.as_str()),
            "scenario {} references unknown required_phase {}",
            scenario.scenario_id,
            scenario.required_phase
        );
    }
}

#[test]
fn frx_09_3_prerequisites_include_required_dependencies() {
    let blueprint = parse_blueprint();

    let prereq_map: BTreeMap<&str, &Prerequisite> = blueprint
        .prerequisites
        .iter()
        .map(|prereq| (prereq.bead_id.as_str(), prereq))
        .collect();

    for bead_id in ["bd-mjh3.7.2", "bd-mjh3.9.2"] {
        let prereq = prereq_map
            .get(bead_id)
            .unwrap_or_else(|| panic!("missing required prerequisite bead {bead_id}"));
        assert_eq!(prereq.status, "required");
        assert!(!prereq.reason.trim().is_empty());
    }
}

#[test]
fn frx_09_3_scenarios_cover_boundary_scheduler_policy_and_cutover() {
    let blueprint = parse_blueprint();

    assert!(blueprint.scenarios.len() >= 4);

    let categories: BTreeSet<&str> = blueprint
        .scenarios
        .iter()
        .map(|scenario| scenario.category.as_str())
        .collect();
    for category in [
        "embedding_boundary",
        "security_policy",
        "scheduler_runtime",
        "migration_cutover",
    ] {
        assert!(
            categories.contains(category),
            "missing required scenario category {category}"
        );
    }

    for scenario in &blueprint.scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.expected_decision_path.trim().is_empty());

        assert!(
            scenario.expected_outcome == "pass" || scenario.expected_outcome == "fallback",
            "invalid expected_outcome for {}: {}",
            scenario.scenario_id,
            scenario.expected_outcome
        );

        if scenario.expected_outcome == "fallback" {
            assert!(
                scenario.expected_decision_path.contains("fallback")
                    || scenario.expected_decision_path.contains("deny"),
                "fallback scenario {} must route through deny/fallback decision path",
                scenario.scenario_id
            );
        }

        let template = &scenario.log_template;
        assert_eq!(template.scenario_id, scenario.scenario_id);
        assert_eq!(
            template.component,
            "frx_frankenbrowser_integration_blueprint"
        );
        assert_eq!(template.decision_path, scenario.expected_decision_path);
        assert_eq!(template.outcome, scenario.expected_outcome);
    }
}

#[test]
fn frx_09_3_structured_log_requirements_and_operator_commands_are_present() {
    let blueprint = parse_blueprint();

    let required_fields: BTreeSet<&str> = [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();

    let actual_fields: BTreeSet<&str> = blueprint
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        blueprint.operator_verification.iter().any(|entry| {
            entry.contains("run_frx_frankenbrowser_integration_blueprint_suite.sh ci")
        }),
        "operator verification must include CI gate command"
    );
    assert!(
        blueprint
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("frx_frankenbrowser_integration_blueprint_replay.sh") }),
        "operator verification must include replay command"
    );
    assert!(
        blueprint.operator_verification.iter().any(|entry| entry
            .contains("jq empty docs/frx_frankenbrowser_integration_blueprint_v1.json")),
        "operator verification must include JSON validation command"
    );
}
