#[path = "../src/test262_release_gate.rs"]
mod test262_release_gate;

use std::fs;
use std::path::PathBuf;

use test262_release_gate::{
    ProfileDecision, Test262EvidenceCollector, Test262GateRunner, Test262HighWaterMark,
    Test262ObservedOutcome, Test262ObservedResult, Test262PinSet, Test262Profile,
    Test262RunnerConfig, Test262WaiverSet, deterministic_worker_assignments, next_high_water_mark,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(path)
}

fn observed(test_id: &str, clause: &str, outcome: Test262ObservedOutcome) -> Test262ObservedResult {
    Test262ObservedResult {
        test_id: test_id.to_string(),
        es2020_clause: clause.to_string(),
        outcome,
        duration_us: 42,
        error_code: None,
        error_detail: None,
    }
}

fn runner(run_date: &str, acknowledge_pass_regression: bool) -> Test262GateRunner {
    Test262GateRunner {
        config: Test262RunnerConfig {
            run_date: run_date.to_string(),
            acknowledge_pass_regression,
            ..Test262RunnerConfig::default()
        },
    }
}

fn load_profile() -> Test262Profile {
    let profile =
        Test262Profile::load_toml(fixture("test262_es2020_profile.toml")).expect("profile load");
    profile.validate().expect("profile validate");
    profile
}

fn load_pins() -> Test262PinSet {
    let pins =
        Test262PinSet::load_toml(fixture("test262_conformance_pins.toml")).expect("pins load");
    pins.validate().expect("pins validate");
    pins
}

fn load_waivers() -> Test262WaiverSet {
    let waivers = Test262WaiverSet::load_toml(fixture("test262_conformance_waivers.toml"))
        .expect("waivers load");
    waivers.validate().expect("waivers validate");
    waivers
}

#[test]
fn fixture_files_parse_and_validate() {
    let _ = load_profile();
    let _ = load_pins();
    let _ = load_waivers();
}

#[test]
fn profile_selects_includes_and_excludes() {
    let profile = load_profile();

    assert!(matches!(
        profile.classify("language/expressions/optional-chaining/case.js"),
        ProfileDecision::Included
    ));
    assert!(matches!(
        profile.classify("built-ins/Promise/allSettled/case.js"),
        ProfileDecision::Included
    ));
    assert!(matches!(
        profile.classify("language/annexB/legacy/escape.js"),
        ProfileDecision::Excluded { .. }
    ));
    assert!(matches!(
        profile.classify("built-ins/intl402/DateTimeFormat/default.js"),
        ProfileDecision::Excluded { .. }
    ));
    assert!(matches!(
        profile.classify("harness/assert.js"),
        ProfileDecision::NotSelected
    ));
}

#[test]
fn zero_silent_failures_block_unwaived_test() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/expressions/optional-chaining/pass.js",
                    "13.3.1",
                    Test262ObservedOutcome::Pass,
                ),
                observed(
                    "language/statements/for/let-fail.js",
                    "13.7",
                    Test262ObservedOutcome::Fail,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(run.blocked, "unwaived failure must block release gate");
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.summary.waived, 0);
    assert_eq!(run.summary.blocked_failures, 1);

    let fail_log = run
        .logs
        .iter()
        .find(|entry| entry.test_id == "language/statements/for/let-fail.js")
        .expect("missing fail log");
    assert_eq!(fail_log.error_code.as_deref(), Some("FE-T262-1005"));
}

#[test]
fn active_waiver_allows_failures_without_blocking() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[
                observed(
                    "language/expressions/optional-chaining/short-circuiting.js",
                    "13.3.1",
                    Test262ObservedOutcome::Fail,
                ),
                observed(
                    "built-ins/Array/prototype/map/basic.js",
                    "23.1.3",
                    Test262ObservedOutcome::Pass,
                ),
            ],
            None,
        )
        .expect("gate run");

    assert!(!run.blocked, "waived failures should not block gate");
    assert_eq!(run.summary.passed, 1);
    assert_eq!(run.summary.waived, 1);
    assert_eq!(run.summary.failed, 0);
    assert_eq!(run.summary.blocked_failures, 0);
}

#[test]
fn expired_waiver_is_not_applied() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "built-ins/Promise/allSettled/reject-late.js",
                "27.2.4",
                Test262ObservedOutcome::Fail,
            )],
            None,
        )
        .expect("gate run");

    assert!(run.blocked);
    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.summary.waived, 0);
}

#[test]
fn deterministic_worker_assignment_is_stable() {
    let test_ids = vec![
        "language/b.js".to_string(),
        "language/a.js".to_string(),
        "built-ins/z.js".to_string(),
        "built-ins/m.js".to_string(),
    ];

    let first = deterministic_worker_assignments(&test_ids, 3);
    let second = deterministic_worker_assignments(&test_ids, 3);

    assert_eq!(first, second);
    assert_eq!(first[0].test_id, "built-ins/m.js");
    assert_eq!(first[1].test_id, "built-ins/z.js");
    assert_eq!(first[2].test_id, "language/a.js");
    assert_eq!(first[3].test_id, "language/b.js");
}

#[test]
fn pass_regression_requires_acknowledgement() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let previous_hwm = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 3,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let observed_results = vec![
        observed("language/a.js", "13.1", Test262ObservedOutcome::Pass),
        observed("language/b.js", "13.2", Test262ObservedOutcome::Pass),
    ];

    let blocked = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &observed_results,
            Some(&previous_hwm),
        )
        .expect("gate run");
    assert!(blocked.blocked);
    assert_eq!(blocked.summary.blocked_failures, 1);
    assert!(
        blocked
            .summary
            .pass_regression_warning
            .as_ref()
            .is_some_and(|warning| warning.acknowledgement_required && !warning.acknowledged)
    );

    let acknowledged = runner("2026-02-22", true)
        .run(
            &pins,
            &profile,
            &waivers,
            &observed_results,
            Some(&previous_hwm),
        )
        .expect("gate run");
    assert!(!acknowledged.blocked);
    assert_eq!(acknowledged.summary.blocked_failures, 0);
}

#[test]
fn high_water_mark_is_monotonic() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "language/a.js",
                "13.1",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    let previous = Test262HighWaterMark {
        schema_version: "franken-engine.test262-high-water-mark.v1".to_string(),
        profile_hash: "abc".to_string(),
        pass_count: 10,
        recorded_at_utc: "2026-02-21T00:00:00Z".to_string(),
    };

    let next = next_high_water_mark(&run, Some(&previous));
    assert_eq!(next.pass_count, 10);
}

#[test]
fn collector_writes_manifest_and_evidence() {
    let profile = load_profile();
    let pins = load_pins();
    let waivers = load_waivers();

    let run = runner("2026-02-22", false)
        .run(
            &pins,
            &profile,
            &waivers,
            &[observed(
                "built-ins/Array/prototype/filter/basic.js",
                "23.1.3",
                Test262ObservedOutcome::Pass,
            )],
            None,
        )
        .expect("gate run");

    let unique = format!(
        "collector-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos()
    );
    let temp_root = fixture("artifacts")
        .join("test262_release_gate")
        .join(unique);

    let collector = Test262EvidenceCollector::new(&temp_root).expect("collector create");
    let hwm = next_high_water_mark(&run, None);
    let artifacts = collector.collect(&run, &hwm).expect("collect");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.high_water_mark_path.exists());
    let loaded_hwm = Test262HighWaterMark::load_json(&artifacts.high_water_mark_path)
        .expect("load hwm")
        .expect("hwm present");
    assert_eq!(loaded_hwm.pass_count, hwm.pass_count);

    let evidence = fs::read_to_string(&artifacts.evidence_path).expect("read evidence");
    assert!(evidence.contains("test262_case_evaluated"));
    assert!(evidence.contains("built-ins/Array/prototype/filter/basic.js"));
}
