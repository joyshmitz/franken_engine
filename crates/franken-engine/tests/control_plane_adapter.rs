use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::control_plane::{
    self, ContractDecisionAdapter, DecisionAdapter, DecisionContract, DecisionRequest,
    DecisionVerdict, EvidenceEmitter, FallbackPolicy, InMemoryEvidenceEmitter, LossMatrix,
    Posterior,
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
        // Lint/audit guard modules necessarily contain forbidden tokens as
        // test data (string literals with example source code).  Skip them.
        let is_guard_module =
            normalized.contains("authority_guard") || normalized.contains("lint_guard");
        if in_adapter || is_guard_module {
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

struct MiniContract {
    loss_matrix: LossMatrix,
    fallback: FallbackPolicy,
}

impl MiniContract {
    fn new() -> Self {
        Self {
            loss_matrix: LossMatrix::new(
                vec!["good".to_string(), "bad".to_string()],
                vec![
                    "allow".to_string(),
                    "deny".to_string(),
                    "timeout".to_string(),
                ],
                vec![
                    0.01, 0.4, 0.6, // good
                    0.8, 0.1, 0.3, // bad
                ],
            )
            .expect("valid loss matrix"),
            fallback: FallbackPolicy::default(),
        }
    }
}

impl DecisionContract for MiniContract {
    fn name(&self) -> &str {
        "mini_contract"
    }

    fn state_space(&self) -> &[String] {
        self.loss_matrix.state_names()
    }

    fn action_set(&self) -> &[String] {
        self.loss_matrix.action_names()
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.loss_matrix
    }

    fn update_posterior(&self, posterior: &mut Posterior, state_index: usize) {
        let _ = state_index;
        posterior.bayesian_update(&[0.8, 0.2]);
    }

    fn choose_action(&self, posterior: &Posterior) -> usize {
        self.loss_matrix.bayes_action(posterior)
    }

    fn fallback_action(&self) -> usize {
        2 // timeout
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

#[test]
fn adapter_surfaces_decision_and_evidence_without_direct_upstream_imports() {
    let contract = MiniContract::new();
    let posterior = Posterior::uniform(2);
    let mut adapter = ContractDecisionAdapter::new(contract, posterior);

    let request = DecisionRequest {
        decision_id: control_plane::DecisionId::from_parts(1_700_000_000_500, 55),
        policy_id: control_plane::PolicyId::new("test.policy", 1),
        trace_id: control_plane::TraceId::from_parts(1_700_000_000_500, 7),
        ts_unix_ms: 1_700_000_000_500,
        calibration_score_bps: 9_500,
        e_process_milli: 100,
        ci_width_milli: 50,
    };

    let verdict = adapter.evaluate(&request).expect("decision");
    assert!(matches!(
        verdict,
        DecisionVerdict::Allow | DecisionVerdict::Deny | DecisionVerdict::Timeout
    ));
    assert_eq!(adapter.events().len(), 1);

    let entry = control_plane::EvidenceLedgerBuilder::new()
        .ts_unix_ms(request.ts_unix_ms)
        .component("control_plane_adapter_test")
        .action(verdict_to_action(verdict))
        .posterior(vec![0.8, 0.2])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.2)
        .expected_loss("timeout", 0.3)
        .chosen_expected_loss(0.1)
        .calibration_score(0.95)
        .fallback_active(false)
        .build()
        .expect("valid evidence entry");

    let mut emitter = InMemoryEvidenceEmitter::new();
    emitter.emit(&request, entry).expect("emit evidence");
    assert_eq!(emitter.entries().len(), 1);
    assert_eq!(emitter.events().len(), 1);
    assert_eq!(emitter.events()[0].component, "control_plane_adapter");
}

fn verdict_to_action(verdict: DecisionVerdict) -> &'static str {
    match verdict {
        DecisionVerdict::Allow => "allow",
        DecisionVerdict::Deny => "deny",
        DecisionVerdict::Timeout => "timeout",
    }
}
