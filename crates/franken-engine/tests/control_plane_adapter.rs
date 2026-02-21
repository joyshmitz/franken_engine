use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::control_plane::mocks::{
    MockBudget, MockCx, MockDecisionContract, MockEvidenceEmitter, MockFailureMode,
    decision_id_from_seed, policy_id_from_seed, schema_version_from_seed, trace_id_from_seed,
};
use frankenengine_engine::control_plane::{
    self, ContextAdapter, ControlPlaneAdapterError, DecisionAdapter, DecisionRequest,
    DecisionVerdict, EvidenceEmitter,
};

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let entries = fs::read_dir(root)
        .unwrap_or_else(|err| panic!("failed to read directory {}: {err}", root.display()));
    for entry in entries {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn control_plane_imports_are_isolated_to_adapter_module() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("repo root");

    let mut sources = Vec::new();
    collect_rs_files(&manifest_dir.join("src"), &mut sources);
    collect_rs_files(
        &repo_root.join("crates/franken-extension-host/src"),
        &mut sources,
    );

    for source in sources {
        let normalized = source.to_string_lossy().replace('\\', "/");
        let in_adapter = normalized.contains("/crates/franken-engine/src/control_plane/");
        if in_adapter {
            continue;
        }

        let content = fs::read_to_string(&source)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", source.display()));
        let forbidden = [
            "use franken_kernel",
            "use franken_decision",
            "use franken_evidence",
            "extern crate franken_kernel",
            "extern crate franken_decision",
            "extern crate franken_evidence",
        ];
        for token in forbidden {
            assert!(
                !content.contains(token),
                "direct upstream control-plane import found in {}: {}",
                normalized,
                token
            );
        }
    }
}

#[test]
fn mock_control_plane_components_support_isolated_extension_host_tests() {
    let trace_id = trace_id_from_seed(11);
    let mut mock_cx = MockCx::new(trace_id, MockBudget::new(50));
    mock_cx.consume_budget(20).expect("budget consume");
    assert_eq!(mock_cx.budget_state().remaining_ms(), 30);
    assert_eq!(mock_cx.trace_id(), trace_id);

    let request = DecisionRequest {
        decision_id: decision_id_from_seed(11),
        policy_id: policy_id_from_seed(11),
        trace_id,
        ts_unix_ms: 1_700_000_000_011,
        calibration_score_bps: 9_500,
        e_process_milli: 100,
        ci_width_milli: 50,
    };

    let mut contract = MockDecisionContract::new([
        DecisionVerdict::Allow,
        DecisionVerdict::Deny,
        DecisionVerdict::Timeout,
    ]);
    assert_eq!(
        contract.evaluate(&request).expect("allow decision"),
        DecisionVerdict::Allow
    );
    assert_eq!(
        contract.evaluate(&request).expect("deny decision"),
        DecisionVerdict::Deny
    );
    assert_eq!(
        contract.evaluate(&request).expect("timeout decision"),
        DecisionVerdict::Timeout
    );

    let entry = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(request.ts_unix_ms)
        .component("control_plane_adapter_test")
        .action("allow")
        .posterior(vec![0.9, 0.1])
        .expected_loss("allow", 0.01)
        .expected_loss("deny", 0.5)
        .chosen_expected_loss(0.01)
        .calibration_score(0.95)
        .fallback_active(false)
        .build()
        .expect("valid evidence entry");

    let mut emitter = MockEvidenceEmitter::new();
    emitter.emit(&request, entry).expect("emit evidence");
    assert_eq!(emitter.entries().len(), 1);
    assert_eq!(emitter.events().len(), 1);
    assert_eq!(emitter.events()[0].component, "control_plane_adapter");

    let schema = schema_version_from_seed(42);
    assert_eq!(schema.to_string(), "1.2.42");
}

#[test]
fn mock_failure_modes_cover_fail_after_n_fail_always_and_panic_paths() {
    let request = DecisionRequest {
        decision_id: decision_id_from_seed(33),
        policy_id: policy_id_from_seed(33),
        trace_id: trace_id_from_seed(33),
        ts_unix_ms: 1_700_000_000_033,
        calibration_score_bps: 9_000,
        e_process_milli: 200,
        ci_width_milli: 100,
    };

    let mut fail_after_n = MockDecisionContract::new([DecisionVerdict::Allow]).with_failure_mode(
        MockFailureMode::FailAfterN {
            remaining_successes: 1,
            code: "mock_fail_after_n",
        },
    );
    assert_eq!(
        fail_after_n
            .evaluate(&request)
            .expect("first call succeeds"),
        DecisionVerdict::Allow
    );
    let err = fail_after_n
        .evaluate(&request)
        .expect_err("second call should fail");
    assert!(matches!(
        err,
        ControlPlaneAdapterError::DecisionGateway {
            code: "mock_fail_after_n"
        }
    ));

    let entry = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(request.ts_unix_ms)
        .component("control_plane_adapter_test")
        .action("deny")
        .posterior(vec![0.2, 0.8])
        .expected_loss("allow", 0.6)
        .expected_loss("deny", 0.05)
        .chosen_expected_loss(0.05)
        .calibration_score(0.9)
        .fallback_active(false)
        .build()
        .expect("valid evidence entry");

    let mut fail_always_emitter =
        MockEvidenceEmitter::new().with_failure_mode(MockFailureMode::FailAlways {
            code: "mock_evidence_fail_always",
        });
    let emit_err = fail_always_emitter
        .emit(&request, entry)
        .expect_err("fail-always should error");
    assert!(matches!(
        emit_err,
        ControlPlaneAdapterError::EvidenceEmission {
            code: "mock_evidence_fail_always"
        }
    ));

    let mut panic_contract = MockDecisionContract::new([DecisionVerdict::Allow])
        .with_failure_mode(MockFailureMode::PanicOnCall);
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = panic_contract.evaluate(&request);
    }));
    assert!(panic_result.is_err(), "panic mode must panic on evaluate");
}
