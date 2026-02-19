# PLAN_TO_CREATE_FRANKEN_ENGINE

> Canonical name: **FrankenEngine**
> Runtime product layered on top: **franken_node**
> Status: Architecture charter + execution plan

## CAVEAT: Ambition-First Operating Rule
This plan is intentionally extreme. It is designed to create a category-defining, radically disruptive runtime, not an incremental alternative.

Out-of-charter behavior:
- Scope trimming framed as "practicality" when it weakens disruptive potential.
- Ambition reduction without explicit owner request.
- Suggesting parity as a destination instead of a temporary checkpoint.

In-charter behavior:
- Increase technical boldness while preserving proof discipline.
- Add capabilities that are impossible-by-default in incumbent runtimes.
- Convert ambitious ideas into executable programs with measurable artifacts.

Directive alignment statement (verbatim intent):
> "Not interested at all in feedback about cutting scope or ambition. The objective is to make this more ambitious and radically innovative/disruptive. Contributions must align with that vision."

## 1. Background And Origin
FrankenEngine is a direct offshoot of what we built in `pi_agent_rust`.

`pi_agent_rust` proved three critical things:
- Rust-native agent infrastructure can be fast, auditable, and operationally sane.
- Extension-host behavior can be treated as a first-class systems problem, not a plugin afterthought.
- Security and performance must be co-designed, not bolted on later.

FrankenEngine exists because the next step requires full end-to-end control of the JavaScript/TypeScript runtime layer itself, not just the host around it.

## 2. Core Thesis
FrankenEngine will be the beating heart of `franken_node`.

- `frankenengine` is the native execution substrate.
- `franken_node` is the compatibility/runtime surface built on top of it.

The purpose is full Rust-native ownership of the entire pipeline:
- parser to execution
- memory model to scheduling
- extension lifecycle to capability policy
- monitoring to automated containment

No dependency on external JS engine bindings for core runtime behavior.

## 3. Strategic Objective
Build a de novo Rust-native runtime family that does not merely replace Node/Bun, but functionally obsoletes them for extension-heavy agent workloads, while delivering:
- alien-artifact-grade performance
- mathematically explicit security decisions
- operationally explainable automated defense

This project’s explicit objective is to make FrankenEngine + franken_node the first practical runtime stack with default-on, probabilistic, active defense against untrusted extension supply-chain attacks, a posture not provided by standard Node/Bun default architectures.
This will be achieved through creative, radically innovative application of `$extreme-software-optimization`, `$alien-artifact-coding`, and `$alien-graveyard`.

Category-defining disruptive floor (non-optional):
- `>= 3x` throughput on extension-heavy benchmark suites versus baseline Node/Bun configurations at equivalent behavior.
- `>= 10x` reduction in successful red-team host compromise rate versus baseline Node/Bun default posture.
- `<= 250ms` median time from high-risk signal crossing to containment action.
- `100%` deterministic replay coverage for security-critical allow/deny/escalation decisions.
- At least `3` production features that are impossible by default in standard Node/Bun deployments (for example posterior-explained policy actions, signed policy checkpoints with rollback resistance, autonomous quarantine mesh).

If outcomes are parity-only or incremental, the program is considered off-charter.

## 3.1 Category-Creation Doctrine
FrankenEngine is not pursuing "best-in-class among similar tools"; it is pursuing a new class.

Required doctrine:
- Build a runtime that treats untrusted extension execution as a first-class adversarial systems problem.
- Make security, performance, and explainability co-optimized rather than traded off.
- Force incumbents into an impossible choice: retain unsafe defaults or adopt FrankenEngine semantics.
- Convert novel claims into externally verifiable artifacts so category leadership is defensible, not rhetorical.
- Define the benchmark standards and conformance language that others are forced to follow.

Category-creation test:
- If a capability can be reproduced by a thin wrapper around Node/Bun defaults, it is not sufficient.
- If a capability cannot survive red-team pressure or deterministic replay, it is not sufficient.
- If a capability does not materially increase enterprise trust/adoption velocity, it is not sufficient.

## 3.2 Impossible-by-Default Capability Index
The program MUST deliver and productionize capabilities that are not available by default in incumbent runtimes:

1. Posterior-explained allow/deny/escalation decisions with cryptographic receipts.
2. Deterministic incident replay with counterfactual policy simulation.
3. Signed policy checkpoints with rollback/fork resistance and freshness guarantees.
4. Fleet-wide autonomous quarantine mesh with bounded convergence SLOs.
5. Proof-carrying adaptive optimization with translation validation and auto-rollback.
6. Capability-typed extension execution contract (no ambient authority by construction).
7. Risk-aware scheduler with deterministic resource exhaustion semantics and p99 contracts.
8. Revocation-first execution gates with explicit degraded-mode policy proofs.
9. Distributed anti-entropy trust reconciliation with machine-verifiable repair artifacts.
10. Continuous autonomous red/blue co-evolution harness driving defense upgrades.

## 4. Non-Negotiable Constraints
- Build native engines from scratch in Rust.
- Do not use runtime wrappers/bindings around upstream engines (`rusty_v8`, `rquickjs`, or equivalents) for core execution.
- Use `/dp/franken_engine/legacy_quickjs/` and `/dp/franken_engine/legacy_v8/` as reference corpora for ideas and test vectors only.
- Every adaptive subsystem must include deterministic safe-mode fallback.
- Every major performance or safety claim must ship with artifacts proving it.
- No parity trap: compatibility milestones are valid only when paired with a net-new capability advantage.
- No hidden compatibility shims for unsafe behavior; compatibility must be explicit, typed, and policy-visible.

## 5. Method Stack (Required)
This program is intentionally driven by three complementary methodologies:

### 5.1 extreme-software-optimization (Execution Discipline)
Mandatory loop:
1. Baseline (p50/p95/p99, throughput, memory)
2. Profile (hotspots only)
3. Prove behavior invariance/isomorphism
4. Implement one lever
5. Verify golden outputs
6. Re-profile

No optimization lands without profile evidence and post-change verification.

### 5.2 alien-artifact-coding (Mathematical Decision Core)
Use formal decision systems instead of hand-tuned heuristics:
- posterior inference
- expected-loss minimization
- evidence ledgers
- formal calibration wrappers

Security and routing decisions must be explainable via equations plus plain-language interpretation.

### 5.3 alien-graveyard (High-EV Primitive Selection)
Use graveyard-driven idea selection with risk gates:
- EV thresholding (`EV >= 2.0`)
- relevance weighting
- failure-mode countermeasures
- budgeted fallback modes

No novelty-for-novelty engineering.

## 6. Security Doctrine: Untrusted Extension Defense
### 6.1 Problem Statement
Untrusted JS/TS extensions are a supply-chain risk surface. The runtime must assume hostile capability abuse is possible even when extension packages appear legitimate.

### 6.2 Design Goal
Detect and contain malicious behavior before host compromise using probabilistic inference and online decisioning.

### 6.3 Threat Model
Adversary classes:
- credential theft and exfiltration
- privilege escalation via hostcall abuse
- destructive filesystem/process actions
- covert long-tail persistence and delayed payloads
- policy evasion using benign-looking call sequences

### 6.4 Bayesian Runtime Sentinel
Maintain latent threat state `Z_t` (benign, suspicious, malicious) per extension/session.

Observed evidence stream `X_t` includes:
- hostcall sequence motifs
- path/process/network intent deltas
- permission-mismatch attempts
- anomaly scores from temporal behavior
- cross-session signature reoccurrence

Posterior update shape:
- `P(Z_t | X_{1:t})` via online Bayesian filtering
- accumulate log-likelihood contributions per evidence atom
- maintain an evidence ledger for audit/replay

### 6.5 Sequential Safety Testing
Use anytime-valid decision boundaries (e-process/e-value style):
- low risk: allow
- medium risk: challenge or constrained sandbox
- high risk: block/kill/quarantine

This avoids static thresholds and supports real-time stopping with controlled false-positive behavior.

### 6.6 Expected-Loss Action Policy
Actions: `{allow, warn, challenge, sandbox, suspend, terminate, quarantine}`.

Decision rule:
- choose action minimizing expected loss under current posterior
- losses encode asymmetry (false allow of malicious code is far costlier than false quarantine)

### 6.7 Safety Guarantees Target
FrankenEngine will target measurable and publishable guarantees:
- bounded false-negative rate under defined attack suites
- bounded false-positive rate under benign extension corpora
- deterministic fallback semantics when probabilistic subsystem unavailable

### 6.8 Supply-Chain Resilience Pipeline
- pre-load validation (manifest/signature/provenance policy)
- static risk scoring
- runtime probabilistic monitoring
- automatic containment and host protection
- post-incident replay and forensic trace export

## 7. Performance Doctrine: Alien-Artifact Throughput + Tail Control
Performance is treated as a proof-bearing systems property.

### 7.1 Core Principles
- zero-copy where possible
- cache-aware data layouts
- bounded allocator churn
- predictable tail latency under extension churn
- lock avoidance on hot paths

### 7.2 Candidate High-EV Primitives (To Validate By Profile)
- superinstructions in interpreter dispatch
- lock-free hostcall queues
- arena/region allocation for short-lived IR artifacts
- adaptive tiering with strict rollback guards
- amortized parsing and module cache invalidation strategies

### 7.3 Measurement Artifacts (Required Per Change)
- baseline benchmark report
- flamegraph or equivalent profile artifact
- golden output checksums
- isomorphism note
- before/after latency and allocation tables

## 8. Architecture Blueprint
### 8.1 Core Packages
- `/dp/franken_engine/crates/franken-engine` (package `frankenengine-engine`): core execution substrate
- `/dp/franken_engine/crates/franken-extension-host` (package `frankenengine-extension-host`): extension policy/runtime defense layer
- `/dp/franken_node/crates/franken-node` (package `frankenengine-node`): runtime interface and compatibility composition layer

Repository topology rule:
- `franken_engine` is the canonical engine repository.
- `franken_node` is the compatibility/product repository.
- Dependency direction is one-way: `franken_node` depends on `franken_engine`; engine code must not be re-forked in `franken_node`.

### 8.2 Engine Lanes
- `quickjs_inspired_native`: deterministic and low-overhead execution lane
- `v8_inspired_native`: throughput/compatibility-oriented lane
- `hybrid_router`: policy-directed selection with deterministic fallback

### 8.3 Planes
- data plane: parser, IR, execution, GC, module loading
- decision plane: risk inference, expected-loss actioning, policy enforcement, evidence ledger

### 8.4 Asupersync Constitutional Integration (Adopted)
FrankenEngine will deeply integrate `/dp/asupersync` as the control-plane substrate while preserving de novo native ownership of the execution data plane.

#### 8.4.1 Control-Plane Adoption Scope
Adopt and treat the following as canonical building blocks:
- `franken-kernel`: canonical `TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`, `Budget`, `Cx`.
- `franken-decision`: decision-contract runtime for allow/deny/escalation and loss-matrix actioning.
- `franken-evidence`: canonical evidence-ledger schema and exporters for decision forensics.
- `frankenlab`: deterministic scenario runner, replay, and schedule/fault exploration harness.

#### 8.4.2 Data-Plane vs Control-Plane Partition
- Data plane remains fully native to FrankenEngine: parser, IR, interpreter/tiering, GC, object model, module execution, and hot dispatch loops.
- Control plane is asupersync-constitutional: capabilities, cancellation protocol, obligation semantics, decision contracts, evidence receipts, deterministic incident replay.
- Extension-host lifecycle orchestration is the seam: the engine executes code; the asupersync-derived control plane governs permissions, lifecycle, and containment.

#### 8.4.3 Non-Negotiable Integration Invariants
1. `Cx` capability threading is required at every effectful extension-host boundary.
2. Extension execution is region-scoped: one execution cell per extension/session with quiescent close semantics.
3. Cancellation follows `request -> drain -> finalize` for unload, quarantine, and revocation actions.
4. All high-impact runtime safety actions (`allow`, `challenge`, `sandbox`, `suspend`, `terminate`, `quarantine`) must execute through decision contracts.
5. All high-impact safety actions must emit canonical evidence-ledger artifacts linked to trace and policy IDs.
6. Deterministic `frankenlab` scenarios are release blockers for security-critical control paths.

#### 8.4.4 Anti-Coupling Constraints
- Do not couple VM dispatch/JIT hot loops directly to asupersync runtime internals.
- Do not fork canonical control-plane types (`TraceId`, `DecisionId`, `Cx`, `Budget`) in FrankenEngine crates.
- Do not import the entire asupersync runtime into every crate; keep narrow, explicit boundary adapters at extension-host/control-plane seams.
- Any acceleration path (HTM/kernel-bypass/etc.) must preserve control-plane semantics and deterministic fallback behavior.

#### 8.4.5 Why This Is Mandatory
- This integration converts deterministic replay, cancellation safety, and capability governance from “policy intentions” into enforceable runtime structure.
- It allows FrankenEngine to keep radical data-plane innovation while inheriting mature control-plane correctness machinery.
- It directly strengthens the category-defining claim set: security decisions become auditable, reproducible, and operationally explainable under adversarial load.

### 8.5 Sibling-Repo Leverage Policy (Adopted, Binding)
To avoid rebuilding solved foundations and to maximize category-shift velocity, FrankenEngine will adopt the following hard integration policy for relevant surfaces:

#### 8.5.1 Console/TUI Surfaces
- Any operator console output surface beyond trivial logs (interactive diagnostics, incident replay viewers, policy explanation consoles, control dashboards) must be built on `/dp/frankentui`.
- Do not build parallel local TUI frameworks in `franken_engine` for these use cases.
- CLI output for developer tooling may remain lightweight text, but any advanced interactive terminal UX belongs to `frankentui` components/adapters.

#### 8.5.2 SQLite and Embedded Data Planes
- Any subsystem needing SQLite semantics (state stores, replay index stores, artifact catalogs, benchmark/result ledgers, local control-plane persistence) must use `/dp/frankensqlite`.
- Do not add ad-hoc local SQLite wrappers that bypass `frankensqlite` contracts and conformance surfaces.
- `/dp/sqlmodel_rust` is the preferred optional layer when typed schema/model ergonomics materially improve safety and maintainability for those stores.

#### 8.5.3 Service/API Integration Surfaces
- For HTTP/REST control-plane APIs, integrate patterns and reusable components from `/dp/fastapi_rust` where relevant.
- For non-HTTP transports (including gRPC), use dedicated transport adapters but preserve shared schema, policy, evidence, and observability contracts so behavior remains equivalent across protocols.
- Avoid bespoke service scaffolding in `franken_engine` when `fastapi_rust` provides equivalent or stronger primitives.

#### 8.5.4 Boundary and Ownership Rules
- `franken_engine` remains canonical for engine/runtime semantics; sibling repos provide specialized infrastructure substrates.
- Integration should occur through explicit adapter crates/interfaces with versioned contracts, not by copy-pasting implementations.
- Where overlapping capability exists, preference order is: `frankentui` for TUI, `frankensqlite` for SQLite-backed persistence, `sqlmodel_rust` for typed SQL models, `fastapi_rust` for service API scaffolding.
- Any exception must be documented in an ADR with measurable justification.

### 8.6 Determinism Boundary Contract (Adopted)
To preserve hard replay guarantees while allowing advanced adaptive/learning systems:

- Replay determinism is mandatory for runtime decision execution given fixed inputs: code artifact, policy artifact, evidence stream, model snapshot, and randomness transcript.
- Online learning/calibration may be stochastic, but stochasticity must be explicit: seed commitments and randomness transcript hashes must be logged as evidence artifacts.
- A learned model cannot directly alter live safety behavior until promoted to a signed, versioned, deterministic snapshot artifact.
- If randomness transcript integrity/freshness is unavailable for high-impact decisions, the system must degrade to deterministic conservative safe mode.
- Conformance and release gates must validate both layers: deterministic replay for decision execution and budget/correctness safety for stochastic learning.

## 9. Multi-Phase Build Program
### Phase A: Native VM Substrate
- parser + AST + lowering
- IR + verifier
- interpreter + callframes + exception model
- object/prototype/closure semantics
- initial native GC

Exit gate:
- deterministic evaluator green on conformance seed corpus
- proof-carrying compilation artifacts emitted for core lowering and verifier passes

### Phase B: Security-First Extension Runtime
- hostcall ABI finalized
- capability policy hardening
- Bayesian sentinel v1 integrated
- automated containment actions wired
- asupersync-constitutional control plane integrated at extension lifecycle boundaries (`Cx`, region close, cancel protocol, decision/evidence contracts)

Exit gate:
- attack simulation harness demonstrates containment without host compromise
- red-team campaign demonstrates `>= 10x` compromise-rate reduction versus baseline Node/Bun default posture
- median detection-to-containment time meets `<= 250ms`
- deterministic `frankenlab` scenario suite passes for unload/quarantine/revocation/cancel-drain-finalize paths

### Phase C: Performance Uplift
- hotspot-guided optimizations only
- dispatch/queue/memory improvements
- optional tiered execution strategy

Exit gate:
- measured p95/p99 improvements over baseline with behavior parity
- one primary benchmark lane demonstrates `>= 3x` throughput versus baseline Node/Bun at equivalent behavior

### Phase D: Node/Bun Surface Superset (franken_node)
- module interop modes
- process/fs/network/child-process compatibility layers
- ecosystem-facing runtime ergonomics
- beyond-parity features surfaced as first-class APIs

Exit gate:
- targeted compatibility suite reaches release threshold
- at least 3 beyond-parity capabilities are production-grade and documented

### Phase E: Production Hardening
- security regression matrix
- fuzz/property/metamorphic testing
- rollout ladder (shadow -> canary -> ramp -> default)

Exit gate:
- evidence-backed operational readiness report
- autonomous quarantine and revocation propagation validated under fault-injection drills
- deterministic replay audit passes for all high-severity incidents in canary environments

## 9A. Idea-Wizard Top 10 Initiatives (Adopted)
These ten initiatives are approved for execution as part of the core program.
Decision: pursue all ten, in staged order.

1. **TS-first authoring -> native capability-typed IR execution.**  
   Extension developers keep JS/TS ergonomics and ecosystem velocity, but execution is moved onto a native IR that explicitly carries capability intent, effect boundaries, and host interaction metadata. This gives high contributor throughput without surrendering runtime control to opaque third-party engine behavior. The rationale is to preserve rapid iteration and broad contributor participation while making security and performance constraints enforceable by the runtime itself, not by conventions.

2. **Probabilistic Guardplane (Bayesian + sequential inference) as a first-class runtime subsystem.**  
   Security decisions should be online inference, not static denylist checks. The Guardplane maintains posterior risk over extension behavior using hostcall patterns, temporal anomalies, and policy mismatch signals, then updates decisions continuously as evidence accumulates. The rationale is that supply-chain attacks adapt over time; a posterior-driven system with anytime-valid boundaries can detect drift and react earlier with quantifiable error control.

3. **Deterministic evidence graph + replay for all security/performance decisions.**  
   Every meaningful decision is recorded as linked artifacts (`claim -> evidence -> policy -> action`) with deterministic replay support. This makes security actions auditable, performance claims reproducible, and debugging grounded in replayable facts rather than logs alone. The rationale is that strong guarantees require explainability and post-incident forensics; otherwise both security and optimization claims are fragile.

4. **Alien-performance core with strict profile-first optimization discipline.**  
   Performance work is governed by baseline/profile/prove/implement/verify loops, one optimization lever at a time, with artifact-backed before/after evidence. Candidate techniques include superinstructions, lock-free queues, cache-local layouts, and allocation control, but only when profile-justified. The rationale is to achieve world-class performance without regressions by turning optimization into a measurable systems practice rather than intuition-driven tuning.

5. **Supply-chain trust fabric integrated with runtime containment actions.**  
   Install-time trust (signatures, provenance, reproducible builds) must be coupled to runtime behavior controls, so trust is dynamic and revocable when observed behavior becomes suspicious. Static provenance alone is insufficient if runtime behavior goes malicious later. The rationale is to close the gap between package-level trust and live runtime risk, which is where many ecosystems remain exposed.

6. **Shadow-run + differential executor for safe extension onboarding.**  
   New or updated extensions run in observe-only shadow mode first, with behavioral diffs against expected outputs, policy expectations, and hostcall traces before gaining active privileges. This creates a low-risk adoption wedge that catches subtle abuse or breakage before production impact. The rationale is to preserve developer velocity while materially reducing rollout risk for untrusted code.

7. **Capability lattice + typed policy DSL for machine-checkable policy.**  
   Capability permissions are modeled as a composable lattice with typed policy rules, allowing formal validation, deterministic merges, and explicit escalation paths. This reduces policy ambiguity and makes access decisions predictable across teams and environments. The rationale is that fine-grained security at scale fails without strongly structured policy semantics and tool-verified correctness.

8. **Deterministic per-extension resource budgets with explicit exhaustion semantics.**  
   CPU, memory, I/O, hostcall rate, and network budgets are enforced per extension with explicit exhaustion outcomes (`throttle`, `sandbox`, `suspend`, `terminate`) and deterministic logging. This prevents noisy-neighbor failures and denial-of-service amplification from malicious or buggy extensions. The rationale is to make runtime safety operationally reliable while preserving fairness and predictable system behavior.

9. **Adversarial security corpus + continuous fuzzing for regression resistance.**  
   Maintain curated malicious-extension corpora plus continuous fuzzing and metamorphic test suites across parser, policy, hostcall, and containment paths. Security controls are only meaningful if they survive continuous adversarial pressure in CI and pre-release gates. The rationale is long-term resilience: defenses that are not continuously attacked in testing will regress silently.

10. **Provenance + revocation fabric for rapid quarantine/recall of compromised extensions.**  
    Build fast trust revocation and quarantine pathways that can invalidate compromised artifacts and propagate kill decisions to runtime instances quickly. This includes attestation chain tracking and deterministic revocation handling. The rationale is incident response speed: once compromise is discovered, containment latency is often the deciding factor between nuisance and catastrophe.

Recommended staged order:
1. TS-first authoring -> native capability-typed IR execution.
2. Probabilistic Guardplane.
3. Deterministic evidence graph + replay.
4. Shadow-run + differential executor.
5. Deterministic resource budgets.
6. Capability lattice + typed policy DSL.
7. Adversarial security corpus + continuous fuzzing.
8. Supply-chain trust fabric integrated with containment.
9. Provenance + revocation fabric.
10. Alien-performance deep optimization rounds (continuous across all phases).

## 9B. Alien-Graveyard Enhancement Map (Per Top 10)
The following upgrades apply graveyard primitives directly to each initiative so implementation is higher-leverage, safer, and easier to verify.

1. **TS-first authoring -> native capability-typed IR execution**  
   Enhance with §5.1 Typestate, §5.2 Session Types, and §5.4 Algebraic Effects so IR passes can statically encode lifecycle legality, protocol constraints, and effect boundaries before runtime. Add §6.1 incremental/self-adjusting compilation for low-latency rebuilds under rapid extension edits. Use §0.19 policy-as-data signing for compiler policy bundles so compilation and capability semantics are versioned and verifiable.

2. **Probabilistic Guardplane**  
   Upgrade with §0.8 runtime decision core, §12.1 conformal prediction, §0.18 e-process sequential testing, and §12.13 BOCPD drift detection. The Bayesian posterior drives base risk, conformal wrappers provide finite-sample calibration guarantees, and e-process thresholds give anytime-valid stopping for escalation decisions. BOCPD detects regime shifts and triggers deterministic safe-mode fallback when distributional assumptions break.

3. **Deterministic evidence graph + replay**  
   Strengthen with artifact-graph discipline from the canonical summary, plus §3.10 hindsight logging and §6.20 deterministic simulation testing. Record minimal nondeterminism and bind every decision to `trace_id`, `policy_id`, and `decision_id` so incidents replay identically across machines. Add replay compatibility checks at every schema/version bump to prevent silent interpretation drift.

4. **Alien-performance core with profile discipline**  
   Apply §14.10 EBR to lock-free data structures, §7.9 modern allocator strategy for allocation-heavy paths, and §6.17 adaptive compilation where profile evidence supports it. Use S3-FIFO-style cache policy inspiration for hostcall/event buffers when contention appears in p95/p99 profiles. Gate each optimization through one-lever trace replay and isomorphism artifacts to prevent throughput wins that degrade correctness or tails.

5. **Supply-chain trust fabric integrated with containment**  
   Add §0.20 progressive delivery controls (shadow/canary/ramp/default) to trust promotion, with runtime policy tied to observed behavior and not just signatures. Use §11.13 authenticated data structures and §11.16 key transparency concepts for tamper-evident trust state. Combine with §11.8 macaroon-style attenuation for least-privilege token delegation so trust grants are scope-limited and revocable.

6. **Shadow-run + differential executor**  
   Enhance via §0.20 progressive delivery and §6.20 deterministic simulation to compare shadow vs active outcomes under identical replay conditions. Add metamorphic invariants from §0.11 formal assurance ladder for cases where exact bitwise equality is inappropriate. Require measurable deltas and explicit pass/fail contracts before promotion from shadow to canary.

7. **Capability lattice + typed policy DSL**  
   Lift with §3.4 object-capability discipline, §11.8 macaroons for attenuation, and §0.19 signed policy-as-data controllers. Treat policy compilation as a typed artifact build step with deterministic validation and explicit incompatibility rejection (`schema_version`, `min_runtime_version`). Add composability checks from §0.25 to catch conflicting policy controllers before runtime.

8. **Deterministic per-extension resource budgets**  
   Upgrade with §0.4 expected-loss actioning, §12.3 online convex optimization for bounded tuning, and §12.13 drift detection for workload regime changes. Budgets become adaptive only inside audited bounds, with hard deterministic caps and explicit exhaustion semantics always preserved. Calibration and fallback triggers are mandatory artifacts so auto-tuning never silently widens risk.

9. **Adversarial corpus + continuous fuzzing**  
   Expand using §6.10 concolic execution for path discovery, §6.12 property-based testing, §6.18 model checking for concurrency invariants, and §6.15 hierarchical delta debugging for rapid minimization of failing cases. This gives broader attack-surface coverage and faster triage when regressions appear. Tie corpus evolution to replayable seed policies so failures are reproducible and non-flaky.

10. **Provenance + revocation fabric**  
    Reinforce with §11.16 key transparency, §11.17 certificate-transparency-style append-only logs, and §11.15 threshold signatures for high-assurance revocation actions. Use §13.9 anti-entropy replication patterns to propagate revocation state quickly and consistently across runtime nodes. Require deterministic precedence rules (revoke always beats allow-cache) and replay tests for emergency recall paths.

## 9C. Alien-Artifact Enhancement Map (Per Top 10)
The following upgrades apply `alien-artifact-coding` principles so each initiative lands with mathematical rigor, explainability, and formal safety framing rather than heuristic behavior.

1. **TS-first authoring -> native capability-typed IR execution**  
   Add a proof-carrying compilation contract: each lowering stage emits invariants and a machine-checkable witness that capability annotations are preserved end-to-end. For optimization passes, use an isomorphism ledger that records ordering/tie-break semantics and verifies behavioral equivalence on golden corpora. Expose a galaxy-brain “why this lowered shape is safe” panel that shows source capability intent, transformed IR constraints, and preserved proof obligations.

2. **Probabilistic Guardplane**  
   Implement the full Bayesian decision loop (`classify -> quantify -> decide -> explain -> calibrate`) as first-class runtime APIs. Model each action (`allow/challenge/sandbox/...`) with explicit expected-loss matrices and require posterior + regret-by-action logging for every decision. Add conformal coverage wrappers and PAC-Bayes-style confidence accounting so risk thresholds are justified by finite-sample or distribution-robust bounds, not ad-hoc constants.

3. **Deterministic evidence graph + replay**  
   Extend evidence records with Bayes-factor decomposition so operators can see exactly which terms moved a decision from benign to suspicious. Every replay should re-materialize the same posterior trajectory (or fail with explicit non-determinism diagnosis), enabling proof-grade forensic narratives. Add a “counterfactual action report” that quantifies why the chosen action minimized expected loss versus alternatives.

4. **Alien-performance core with profile discipline**  
   Treat each optimization as an experiment with prior, posterior, and stopping rule: stop early only using anytime-valid evidence criteria rather than eyeballing benchmarks. Add a Value-of-Information gate to choose the next profiling probe that maximizes expected performance gain per engineering hour. Publish confidence intervals for p50/p95/p99 improvements and require uncertainty-aware regression gates before promotion.

5. **Supply-chain trust fabric integrated with containment**  
   Replace binary trust levels with posterior trust distributions over extension/package identities and update them online as behavior evidence arrives. Use hazard-style decay for stale trust and Bayesian recovery for long benign streaks, with explicit asymmetry that penalizes false-allow more than false-quarantine. Provide explainable trust cards showing prior, new evidence, posterior, and policy effect in plain language.

6. **Shadow-run + differential executor**  
   Turn shadow promotion into a formal hypothesis test: the extension advances only when statistical evidence supports “no harmful divergence” under defined risk budgets. Use conformal residual bands over shadow-vs-active deltas to detect subtle behavioral drift without hard-coded thresholds. Add VOI-guided scenario selection so shadow validation focuses on the most discriminative workloads first.

7. **Capability lattice + typed policy DSL**  
   Give policy evaluation a formal semantics with explicit monotonicity and non-interference properties, then encode these as executable checks in policy CI. For composition, use mathematically explicit merge operators with proofs or bounded counterexamples when rules conflict. Add galaxy-brain policy explanations that show rule application traces, confidence context, and why denied alternatives remain unsafe.

8. **Deterministic per-extension resource budgets**  
   Model budget control as a sequential decision process with asymmetric costs (service degradation vs compromise risk) and solve via expected-loss minimization. Use Bayesian demand estimation with BOCPD drift segmentation so adaptation reacts to regime change while preserving strict hard caps. When uncertainty spikes, force graceful deterministic fallback and log the precise trigger condition and posterior rationale.

9. **Adversarial corpus + continuous fuzzing**  
   Upgrade test strategy from “more cases” to calibrated risk measurement: track posterior defect probability by subsystem and allocate fuzzing budget where uncertainty is highest. Use metamorphic properties and posterior shrinkage metrics to quantify when a subsystem has enough evidence to promote. Add explicit false-negative and false-positive target curves over the malicious corpus so security progress is measurable, not anecdotal.

10. **Provenance + revocation fabric**  
    Frame revocation as a safety-critical decision under uncertainty with explicit loss for delayed quarantine, wrongful quarantine, and propagation lag. Use sequential evidence thresholds to trigger emergency revocation quickly while preserving auditability of escalation rationale. Add probabilistic SLOs for revocation latency and containment probability, with replay-backed verification that emergency paths meet those guarantees under fault scenarios.

## 9D. Extreme-Software-Optimization Enhancement Map (Per Top 10)
The following upgrades apply `$extreme-software-optimization` discipline so each initiative ships with measurable wins, behavior proofs, and tail-latency control.

Global rule for every item:
- Baseline first (`p50/p95/p99`, throughput, memory, syscalls).
- Profile top-5 hotspots before changes.
- Implement one lever per commit with opportunity score `>= 2.0`.
- Prove isomorphism (ordering/tie-break/seed behavior).
- Verify against golden outputs and re-profile.

1. **TS-first authoring -> native capability-typed IR execution**  
   Build a fixed compilation benchmark suite (parse/lower/check/emit) and profile each phase separately to avoid blind optimization. Prioritize high-score levers like arena allocation for IR nodes, memoized symbol resolution, and batch validation passes to remove N+1 checks in large extension graphs. Gate every compiler optimization with semantic equivalence fixtures and deterministic IR snapshot checksums.

2. **Probabilistic Guardplane**  
   Benchmark the full decision pipeline by stage (feature extraction, posterior update, action selection) and enforce strict per-stage latency budgets so security does not become a throughput tax. Profile model-update hotpaths for allocation churn and branch misprediction, then optimize only the dominant contributors. Keep mathematically equivalent fast paths (precomputed constants, batched updates) behind isomorphism proof notes and golden decision traces.

3. **Deterministic evidence graph + replay**  
   Measure append/write/read/replay throughput and p99 replay latency on realistic incident traces, then profile serialization and index lookup hotspots. Apply one-lever improvements such as zero-copy encoding, small-buffer reuse, and keyed index acceleration only when scores justify it. Require bit-for-bit replay parity on deterministic traces and explicit migration failure behavior for version changes.

4. **Alien-performance core with profile discipline**  
   Treat this initiative as the optimization control tower: maintain hotspot matrices, score each candidate, and reject unprofiled work. Use staged rounds (low-hanging -> algorithmic -> advanced) with one lever per change and immediate re-profile after each merge. Keep performance CI focused on stable KPIs and fail builds when regressions exceed agreed p95/p99 or allocation thresholds.

5. **Supply-chain trust fabric integrated with containment**  
   Profile trust-check paths under high extension churn to prevent signature/provenance validation from inflating startup and request tails. Optimize with batched verification, cache locality, and incremental trust-state refresh where behavior remains identical. Verify equivalence by replaying trust decisions over historical manifests and ensuring the same containment outcomes before/after optimization.

6. **Shadow-run + differential executor**  
   Benchmark shadow overhead explicitly as a percentage of active-mode runtime and cap it with a hard SLO. Profile diff-engine cost centers (normalization, comparison, storage) and optimize only top hotspots, favoring streaming comparison and buffer reuse. Prove that optimization does not alter diff semantics by re-running mismatch corpora and validating identical divergence classification.

7. **Capability lattice + typed policy DSL**  
   Baseline policy compile/load/eval times and profile rule-evaluation bottlenecks on worst-case policy sets. Apply data-structure upgrades (lookup maps, precompiled decision DAGs) only after hotspot confirmation and retain deterministic evaluation order guarantees. Use golden policy suites to confirm optimized evaluators produce identical allow/deny/escalation outcomes.

8. **Deterministic per-extension resource budgets**  
   Benchmark enforcement overhead on hot execution loops and profile scheduler/accounting paths that impact tail latency. Optimize with prefix-sum or ring-buffer accounting strategies and preallocated counters to reduce per-event cost while preserving exact quota semantics. Validate isomorphism with exhaustion scenario fixtures that assert unchanged throttle/suspend/terminate transitions.

9. **Adversarial corpus + continuous fuzzing**  
   Optimize the security-testing pipeline itself: baseline execution time per corpus slice, profile fixture loading and mutation generation, then parallelize or cache only bottlenecked steps. Enforce deterministic seed management so failures remain reproducible after performance tuning. Track corpus throughput and unique-crash yield as first-class KPIs to ensure speedups do not degrade bug-finding power.

10. **Provenance + revocation fabric**  
    Baseline revocation propagation latency (median and p99) across realistic node topologies and profile bottlenecks in fan-out, verification, and local cache invalidation. Apply one-lever transport/index improvements and re-measure until emergency SLO targets are met without semantic drift. Verify with golden incident drills that optimized propagation still yields identical final revocation state and precedence behavior.

## 9E. FCP-Spec-Inspired Accretive Additions (Complementary To Top 10)
The following additions mine high-value protocol/security patterns from `/dp/flywheel_connectors/FCP_Specification_V2.md` and adapt them to FrankenEngine + franken_node without changing the core thesis. These are additive control-plane and runtime-hardening upgrades mapped to the existing top-10 initiative set.

1. **Canonical object identity discipline for security-critical state** (primary links: #1, #3, #7, #10)  
   Introduce a strict `EngineObjectId` derivation for policy objects, evidence records, revocations, and signed manifests using domain-separated hashing over canonical bytes plus scope identifiers (zone/trust-scope + schema/version). Silent normalization is forbidden for these classes: non-canonical forms are rejected. This reduces signature ambiguity, prevents cross-implementation drift, and makes replay/audit state deterministic across machines.

2. **Deterministic serialization and signature preimage contracts** (primary links: #3, #7, #10)  
   Require deterministic CBOR (or equivalently strict deterministic binary encoding) for signed objects, with schema-hash prefixing and a single unsigned-view signature preimage rule. Multi-signature vectors must be sorted by stable signer key ordering before verification. This gives language-agnostic signature reproducibility and shuts down malleability via field/order differences.

3. **Checkpointed policy frontier with rollback/fork protection** (primary links: #3, #5, #10)  
   Add a quorum-signed `PolicyCheckpoint` chain carrying monotonic `checkpoint_seq` and epoch metadata, persisted as the canonical root of enforceable policy state. Verifiers persist the highest accepted frontier and reject regressions even when signatures are valid. Equal-sequence divergent content is treated as a fork incident requiring safe-mode entry and operator-visible forensics.

4. **Authority chain hardening with non-ambient capability delegation** (primary links: #5, #7, #10)  
   Extend the capability lattice with tokenized delegated authority chains (owner -> issuer -> delegate) and explicit attenuation semantics, so every privileged action can be traced to a cryptographic grant path. Bind tokens to audience, expiry, checkpoint frontier, and revocation freshness markers. This turns "explicit authority" into verifiable runtime mechanics rather than policy prose.

5. **Key-role separation plus owner-signed attestation lifecycle** (primary links: #5, #10)  
   Separate signing, encryption, and issuance keys for runtime principals and bind them through owner-signed attestations with expiry windows, nonce freshness, and optional device-posture evidence. Add optional threshold owner signing for high-impact operations (rotations/revocations) to reduce single-key compromise blast radius. This mirrors FCP's identity hygiene in a runtime-centric model.

6. **Session-authenticated high-throughput hostcall channel** (primary links: #2, #4, #8)  
   For extension-host data plane, use handshake-authenticated sessions with per-message MAC plus monotonic sequence anti-replay instead of expensive per-message signatures on hot paths. Keep deterministic nonce derivation rules for AEAD contexts and explicit replay-drop telemetry. This preserves throughput while improving anti-replay and tamper detection semantics.

7. **Revocation-head freshness semantics and degraded-mode policy** (primary links: #5, #8, #10)  
   Model revocation as hash-linked append-only objects with monotonic head sequence, and require revocation checks before token acceptance, high-risk operation execution, and connector/extension activation. Add explicit degraded-mode rules for stale revocation state (safe-only by default, risky/dangerous gated by interactive override policy). Every degraded decision must emit audit events.

8. **Zone-style trust segmentation and cross-scope reference rules** (primary links: #6, #7, #8)  
   Introduce explicit trust zones (for example owner/private/team/community) with capability ceilings and policy inheritance. Cross-zone references are permitted for provenance/audit but must not silently grant execution reachability or policy authority in foreign zones. This keeps trust boundaries explicit and simplifies both policy reasoning and garbage-collection semantics.

9. **Normative observability surface and stable error taxonomy** (primary links: #2, #3, #8, #10)  
   Standardize required counters, structured logs, and stable reason/error codes for authentication failures, capability denials, replay drops, policy-checkpoint violations, and revocation freshness failures. Add append-only hash-linked audit chain requirements with correlation/trace identifiers and redaction-by-default guarantees. This creates cross-version comparability and forensic reliability.

10. **Conformance/golden-vector/migration gates as release blockers** (primary links: #1, #3, #9, #10)  
    Add mandatory conformance suites for canonical encoding, ID derivation, signature verification, revocation freshness, and epoch ordering, plus golden vectors and schema contracts for interop stability. Require fuzz/adversarial corpora for decode-DoS, handshake replay/splicing, and token verification edge cases. Migration policy should be explicit cutover with deterministic compatibility boundaries, not hidden translator behavior in security-critical paths.

## 9F. Moonshot Bets: Top 15 Category-Shift Initiatives
The following initiatives are intentionally extreme. They are designed to produce outcomes that advanced runtime engineers would consider genuinely surprising rather than incremental. Each item is expected to ship with benchmarks, security artifacts, and deterministic replay evidence.

1. **Verified Adaptive Compiler**  
   **What it entails:** Build a profile-driven adaptive compilation system with explicit optimization classes (`superinstructions`, `trace specialization`, `layout specialization`, `devirtualized hostcall fast paths`) that are generated automatically but only activated after proof obligations pass.  
   **How it works:** A baseline interpreter/IR path remains canonical. The optimizer proposes a candidate transform and emits: translation witness, invariance digest, rollback token, and replay compatibility metadata. A translation-validation checker verifies semantic equivalence against baseline IR traces and golden corpora. Activation is staged (`shadow -> canary -> ramp -> default`) and continuously monitored by p95/p99 and correctness guardrails.  
   **Why it is useful/compelling:** This turns performance into a continuous compounding advantage instead of one-off tuning campaigns, while removing fear that “smart optimization” silently corrupts behavior. Teams can accept aggressive throughput improvements without sacrificing trust in correctness.  
   **Rationale/justification:** Traditional adaptive optimizers fail socially because operators cannot prove why they are safe. Proof-carrying activation solves that trust gap and creates a defensible technical moat: fast paths with verification-grade confidence instead of heuristic optimism.

2. **Fleet-Scale Runtime Immune System**  
   **What it entails:** Create a distributed defense plane where each node publishes signed evidence atoms and posterior risk deltas, then converges on containment intent with deterministic local action policies.  
   **How it works:** Nodes emit evidence packets (`trace_id`, `extension_id`, `evidence_hash`, `posterior_delta`, `policy_version`). A fleet protocol (gossip plus quorum checkpoints) reconciles evidence, resolves conflicts with deterministic precedence, and propagates containment decisions (`sandbox`, `suspend`, `terminate`, `quarantine`) with bounded convergence SLOs. Partition mode enforces deterministic degraded semantics rather than “best effort.”  
   **Why it is useful/compelling:** One verified detection should protect all nodes quickly; no repeated rediscovery of the same adversary behavior on every machine. This shrinks blast radius and response time in the exact window where incidents become expensive.  
   **Rationale/justification:** Endpoint-local defense is structurally too slow for modern supply-chain attacks. A collective inference and action plane creates network effects for security: every incident increases fleet immunity, not just local hardening.

3. **Deterministic Time-Travel + Counterfactual Replay**  
   **What it entails:** Upgrade replay from debugging aid to causal decision laboratory with branching counterfactual simulation.  
   **How it works:** Record minimal nondeterminism, evidence ledger updates, policy snapshots, and action transitions in hash-linked deterministic traces. Replay reproduces exact runtime behavior and decision trajectories bit-for-bit. Counterfactual branches re-run identical traces under alternate thresholds, loss matrices, and policy versions, producing a quantitative “action delta report” (harm prevented, false-positive cost, latency impact).  
   **Why it is useful/compelling:** Postmortems become experiments, not narratives. Teams can prove whether alternative policy choices would have improved outcomes before production changes, dramatically reducing policy tuning cycle time and incident ambiguity.  
   **Rationale/justification:** Security and reliability programs fail when they cannot answer “what would have happened if we changed X?” Deterministic counterfactual replay makes that answer measurable and reproducible.

4. **Capability-Typed TS Execution Contract**  
   **What it entails:** Preserve TS developer ergonomics while enforcing runtime authority and effect boundaries at compile-time and IR-time.  
   **How it works:** TS sources compile into capability-typed IR with explicit effect annotations (`fs.read`, `net.connect`, `proc.spawn`, `policy.request`). Capability lattice checks occur during lowering and optimization; ambiguous authority paths and ambient side effects are rejected before execution. Runtime verifies capability proofs and executes only within declared contracts.  
   **Why it is useful/compelling:** Developers keep familiar JS/TS productivity, but operators get hard guarantees that extensions cannot silently exceed declared authority. This combines ecosystem adoption velocity with rigorous least-privilege semantics.  
   **Rationale/justification:** Runtime-only checks are too late and too noisy at scale. Embedding authority semantics into the compilation contract creates enforceability by construction and a category-level differentiator against wrapper-based runtimes.

5. **Cryptographic Decision Receipts**  
   **What it entails:** Every high-impact runtime decision produces an immutable, signed, independently verifiable receipt.  
   **How it works:** Receipt schema includes `decision_id`, `policy_id`, `artifact_hash`, `evidence_hash`, posterior snapshot, expected-loss vector, chosen action, timestamp/epoch, and signature bundle. Receipts append to transparency-style logs with inclusion and consistency proofs. Independent verifier tools can validate signatures, log consistency, and replay linkage without trusting runtime internals.  
   **Why it is useful/compelling:** Security governance becomes auditable evidence, not trust-me logging. Operators, customers, and auditors can verify not only what happened but why and under which policy artifact.  
   **Rationale/justification:** As runtime autonomy increases, explainability must become cryptographic, not rhetorical. Receipts create accountability primitives equivalent to financial-grade audit trails.

6. **Tri-Runtime Lockstep Oracle**  
   **What it entails:** Continuous differential execution across Node, Bun, and FrankenEngine with automatic divergence minimization and triage.  
   **How it works:** A deterministic harness runs equivalent workloads across all three runtimes, canonicalizes observable outputs, and flags divergences with structured classifications (`engine bug`, `intentional semantic improvement`, `compatibility debt`, `ecosystem ambiguity`). Hierarchical delta debugging shrinks failures into minimal fixtures that feed conformance suites and migration kits.  
   **Why it is useful/compelling:** Compatibility risk becomes measurable daily instead of a release-time surprise. Migration teams gain hard evidence on where semantics diverge and why.  
   **Rationale/justification:** “Mostly compatible” claims are fragile without a standing oracle. Lockstep differential infrastructure transforms compatibility from static checklist to continuously verified property.

7. **Autonomous Red-Team Generator**  
   **What it entails:** Build perpetual adversarial campaign generation that evolves faster than static malicious corpora.  
   **How it works:** Attack grammar and mutation engines generate exploit strategies across hostcall sequences, temporal payload staging, privilege escalation attempts, and policy evasion motifs. Campaigns are scored by exploit quality and containment difficulty. Failures auto-minimize into deterministic repros and are promoted into permanent regression corpora.  
   **Why it is useful/compelling:** Defense quality improves continuously under realistic pressure instead of periodic manual red-team events. The system discovers blind spots before adversaries do and keeps pressure on stale assumptions.  
   **Rationale/justification:** Static security tests decay. A co-evolving adversarial generator institutionalizes offensive pressure as a product capability.

8. **Policy Compiler With Formal Merge Guarantees**  
   **What it entails:** Replace ad-hoc policy composition with typed, proof-producing policy compilation.  
   **How it works:** Policies compile into a formal IR with machine-checkable properties: monotonicity, non-interference, attenuation legality, determinism of merges, and precedence stability. Model-checking/SMT passes validate compositions. On conflict, compiler emits bounded counterexample traces and deterministic rejection diagnostics.  
   **Why it is useful/compelling:** Large teams can safely compose many policy sources without hidden privilege escalations or merge-order bugs. Policy evolution becomes disciplined engineering, not textual patching.  
   **Rationale/justification:** Policy sprawl is a known failure mode in secure platforms. A theorem-backed compiler is the only scalable route to high-assurance policy governance.

9. **Revocation Mesh SLO**  
   **What it entails:** Treat revocation propagation as a reliability-critical data plane with explicit SLOs and proofs, not a background best-effort process.  
   **How it works:** Revocations are monotonic hash-linked objects with signed heads and freshness constraints. Dissemination uses hybrid push plus anti-entropy repair. Local precedence rules guarantee `revoke > allow-cache` under all modes. Observability surfaces per-zone convergence lag, stale-head exposure time, and failed refresh causes. Fault injection validates partition and delay behavior.  
   **Why it is useful/compelling:** Compromise response quality depends on revocation speed and certainty. Tight convergence guarantees materially reduce exposure windows after key or extension compromise.  
   **Rationale/justification:** Most systems over-invest in detection and under-invest in distribution correctness. Revocation Mesh SLO closes that gap with measurable, enforceable containment semantics.

10. **SLO-Proven Scheduler**  
    **What it entails:** Deliver per-extension scheduling with deterministic resource semantics and explicit fairness/tail guarantees under adversarial load.  
    **How it works:** Scheduler operates with lane separation (`cancel`, `timed`, `ready`, `background`) and hard per-extension budgets (CPU, memory, IO, hostcall rate). Exhaustion transitions are explicit (`throttle`, `sandbox`, `suspend`, `terminate`). Queue discipline, admission, and preemption policies are validated via deterministic stress traces and fairness/starvation invariants.  
    **Why it is useful/compelling:** Predictable p95/p99 behavior and bounded blast radius under noisy-neighbor or malicious extension behavior become first-class guarantees, not emergent outcomes.  
    **Rationale/justification:** Extension-heavy runtimes collapse operationally when scheduler semantics are implicit. Proved scheduling contracts are necessary for enterprise trust and high-density deployment.

11. **Semantic Build Graph For Extensions**  
    **What it entails:** Build pipeline as a deterministic, attested semantic graph spanning source, manifests, capability schemas, policy bundles, and runtime compatibility contracts.  
    **How it works:** Graph nodes are content-addressed artifacts with typed edges (`depends_on`, `validated_by`, `attested_by`, `compatible_with`). Invalidation is semantic, not timestamp-based. Each promoted build carries provenance lineage, signing metadata, and replay-ready reproducibility descriptors.  
    **Why it is useful/compelling:** Extension authoring remains fast while trust, reproducibility, and incident forensics all improve. Build outputs become auditable security objects, not opaque binaries.  
    **Rationale/justification:** In hostile extension ecosystems, build systems are part of the attack surface. A semantic attested build graph turns supply-chain integrity into a default runtime property.

12. **Zero-Copy Capability IPC Fabric**  
    **What it entails:** Re-architect extension-host communication around zero-copy transport with embedded capability and authenticity semantics.  
    **How it works:** Shared-memory ring channels carry typed frames with capability tags, monotonic sequence counters, and authenticated envelopes (session MAC/AEAD). Fast paths avoid copies and minimize allocator churn; backpressure is deterministic and policy-aware. Replay-drop and nonce misuse are first-class telemetry signals.  
    **Why it is useful/compelling:** Hostcall-heavy workloads get major throughput and tail-latency gains without weakening security controls. Capability enforcement happens at transport boundary, not as expensive afterthought logic.  
    **Rationale/justification:** Most runtimes trade security for transport speed on hot paths. This fabric is designed to break that tradeoff and make secure performance the default.

13. **Adversarial Benchmark Standard**  
    **What it entails:** Publish and maintain the category’s reference benchmark and verification suite for secure extension runtimes.  
    **How it works:** Standard includes workload families, threat scenarios, replay correctness tests, containment latency metrics, false-positive/false-negative envelopes, and mandatory artifact contracts (`env`, `manifest`, `repro`, evidence linkage). Neutral verifier mode enables independent reproduction and claim validation.  
    **Why it is useful/compelling:** Benchmark ownership sets the language of competition. External users gain objective comparison tools, while FrankenEngine’s strengths become measurable by industry-standard criteria rather than vendor narratives.  
    **Rationale/justification:** Category leadership requires defining the scoreboard, not merely competing on someone else’s speed-only metrics.

14. **Autopilot Performance Scientist**  
    **What it entails:** Internal optimization intelligence that selects next experiments using value-of-information and expected gain per engineering hour.  
    **How it works:** System ingests profiling corpus, prior optimization results, uncertainty estimates, and rollback risk. It proposes one-lever experiments with stopping rules, required artifacts, and predicted confidence intervals. Human reviewers approve promotions; automated guards reject unsafe or low-signal experiments.  
    **Why it is useful/compelling:** Optimization effort concentrates where probability of meaningful win is highest, reducing random tuning churn and accelerating sustained frontier movement.  
    **Rationale/justification:** High-performance engineering is often bottlenecked by prioritization noise, not coding speed. A principled experiment planner converts performance work into disciplined portfolio optimization.

15. **Live Safety Twin**  
    **What it entails:** Continuous shadow decision twin that forecasts near-term risk trajectories and recommends preemptive containment actions with uncertainty bounds.  
    **How it works:** Twin consumes real-time evidence streams, runs forecast models, simulates candidate interventions, and emits ranked recommendations with expected-loss projections and rollback commands. High-uncertainty states force conservative policy advice. All recommendations are replay-linkable and auditable.  
    **Why it is useful/compelling:** Moves security posture from reactive to anticipatory. Operators can constrain risk before irreversible damage, with explicit tradeoff visibility instead of opaque alarms.  
    **Rationale/justification:** In adversarial systems, delay kills. A safety twin creates forward-looking control capacity while retaining deterministic fallback and human accountability.

Program-level justification for adopting all 15:
- These initiatives are mutually reinforcing rather than redundant: compiler trust, policy trust, fleet trust, and operator trust are treated as one integrated system.
- Together they create multiple impossible-by-default differentiators: proof-carrying optimization, cryptographic decision governance, deterministic counterfactual replay, and fleet-wide autonomous containment.
- Combined execution produces a defensible category shift: superior performance, superior security, superior explainability, and superior reproducibility at once.

## 9G. FrankenSQLite-Spec-Inspired Accretive Additions (Complementary To Top 10)
The following additions mine high-transfer systems ideas from `/dp/frankensqlite/COMPREHENSIVE_SPEC_FOR_FRANKENSQLITE_V1.md` and adapt them to FrankenEngine + franken_node. The focus is runtime security/performance rigor, deterministic operations, and proof-grade resilience, not database-specific internals.

1. **Capability-context-first runtime with ambient-authority prohibition** (primary links: #1, #2, #7)  
   Push `Cx`-style capability threading through all critical engine and extension-host paths, including compile-time narrowing at layer boundaries and explicit prohibition of ambient side effects in security-critical modules. This turns authority control into a type/system property, not coding convention, and directly reduces hidden privilege-escalation surfaces.

2. **Cancellation as a protocol, not a best-effort signal** (primary links: #2, #3, #8)  
   Adopt a strict cancel lifecycle (`request -> drain -> finalize`) with required checkpoint placement in long loops, bounded masking only for tiny atomic publication steps, and region-level quiescence criteria before close/upgrade transitions. This makes shutdown, failover, and containment actions predictable under pressure and avoids half-applied security operations.

3. **Linear-obligation discipline for safety-critical effects** (primary links: #2, #3, #10)  
   Treat reservations and two-phase effects (commit publications, containment actions, revocation propagation handoffs) as obligations that must deterministically resolve to committed/aborted states. Leak detection should be fatal in lab and incident-grade in production. This eliminates silent ghost state and makes protocol safety auditable.

4. **Deterministic lab runtime with systematic interleaving exploration** (primary links: #3, #9)  
   Build deterministic schedule/fault/cancellation exploration for critical concurrency paths (policy updates, checkpoint/revocation propagation, extension lifecycle transitions), with replay-stable traces and artifact bundles. This upgrades testing from probabilistic "hope we hit it" to reproducible exploration of race-sensitive behaviors.

5. **Policy controller with expected-loss actions under anytime-valid guardrails** (primary links: #2, #4, #8)  
   Move adaptive tuning and risk-response knobs onto an explicit controller that minimizes expected loss across candidate actions while never violating active e-process guardrails. Use BOCPD regime detection and VOI-budgeted monitoring for high-cost checks. This yields adaptive behavior without correctness drift or opaque heuristics.

6. **Epoch-scoped validity + key derivation with transition barriers** (primary links: #5, #10)  
   Introduce monotonic epochs for trust-state transitions (policy key rotation, revocation frontier transitions, remote durability config changes), fail-closed validation windows, and explicit epoch barriers so no single high-risk operation straddles incompatible security epochs. This hardens anti-replay and prevents mixed-configuration ambiguity.

7. **Remote-effects contract for distributed runtime operations** (primary links: #5, #6, #10)  
   Any remote operation must require explicit capability, use named computations (no closure shipping), include idempotency keys, enforce lease-backed liveness, and express multi-step workflows as deterministic sagas. This makes distributed containment and policy propagation robust under retries, partitions, and cancellations.

8. **Scheduler lane model + global bulkheads for tail control** (primary links: #4, #8)  
   Formalize priority lanes (cancel/timed/ready) and bound remote/background concurrency with bulkheads. Cancellation cleanup and deadline-sensitive policy operations must not be starved by background work. This directly improves p99 behavior during incident spikes and extension churn.

9. **Three-tier integrity strategy + append-only tamper-evident decision stream** (primary links: #3, #10)  
   Separate hot-path integrity hashing, content identity hashing, and cryptographic authenticity responsibilities instead of overloading one mechanism. Pair this with append-only hash-linked marker streams for high-value decisions and optional MMR-style compact proofs for prefix/inclusion verification across nodes. This strengthens both speed and forensic confidence.

10. **O(Delta) anti-entropy reconciliation + proof-carrying recovery artifacts** (primary links: #5, #9, #10)  
    For distributed trust/evidence state, use set-reconciliation protocols (IBLT-style) to converge efficiently on differences, with deterministic fallback paths when reconciliation fails. Every repair/degraded-mode event should emit machine-verifiable proof artifacts. This improves recovery speed, observability, and operational credibility at scale.

## 9H. Frontier Programs Canonical Mapping (Adopted, Non-Duplicate)
This section is a canonical lens over already-adopted scope, not an additional parallel backlog. It exists to preserve strategic narrative clarity while keeping execution ownership single-sourced in `9F`, `9I`, and section `10.x` tracks.

1. **Proof-Carrying Adaptive Optimizer** -> canonical owner: `9F.1` (Verified Adaptive Compiler), execution: `10.12`.
2. **Fleet Immune System Consensus Plane** -> canonical owner: `9F.2`, execution: `10.12`.
3. **Causal Time-Machine Runtime** -> canonical owner: `9F.3`, execution: `10.12`.
4. **Attested Execution Cells** -> canonical owner: `9I.1` (TEE-bound receipts) + attested cell runtime tasks in `10.12`.
5. **Policy Theorem Engine** -> canonical owner: `9F.8`, execution: `10.12`.
6. **Autonomous Red/Blue Co-Evolution System** -> canonical owner: `9F.7`, execution: `10.12`.
7. **Global Trust Economics Layer** -> canonical owner: `9F.15` + trust-economics tasks in `10.12`.
8. **Secure Extension Reputation Graph** -> canonical owner: frontier feature track in `10.12` + success criteria in `13`.
9. **Operator Copilot For Safety Control** -> canonical owner: `9F.15` + operator copilot tasks in `10.12`.
10. **Public Category Benchmark + Verification Standard** -> canonical owner: `9F.13`, `14`, execution: `10.12`.

Canonicalization rule for this plan:
- New frontier scope must be added once (single owner section), then referenced from mapping views.
- Mapping views may reframe intent but must not create duplicate implementation obligations.

## 9I. Delta Moonshots (New Additions, Fully Adopted)
These four additions are intentionally selected as non-trivial upgrades that deepen existing 9F/9H scope with new constitutional constraints and verification surfaces. Where conceptual overlap exists, it is a deliberate refinement profile (stronger guarantees, stricter gates), not additional duplicated scope.

1. **TEE-Bound Cryptographic Decision Receipts**
   **What it entails:** Extend decision receipts so they are not only signed by software keys but also bound to confidential-compute attestation evidence (measured runtime identity + code hash + policy hash + evidence hash).
   **How it works:**  
   - Decision pipeline emits canonical receipt payload (`decision_id`, `trace_id`, `policy_id`, posterior/loss vector, action, evidence links).  
   - Receipt signer runs inside an attested execution cell and attaches attestation quote metadata (platform, measurement digest, validity window, nonce challenge, signer key binding).  
   - Verifier toolkit checks three layers: cryptographic signature validity, transparency-log inclusion/consistency, and attestation-chain validity proving receipt was produced by approved measured software.  
   - Replay tooling validates that receipt-linked traces reproduce the same decision under the attested build manifest; divergence is escalated as a trust incident.  
   - Fallback semantics are explicit: if attestation freshness/proof fails, high-impact autonomous actions degrade to deterministic safe mode (challenge/sandbox-first) until trust is restored.
   **Why it is useful/compelling:** This upgrades auditability from "signed by our service" to "provably emitted by known measured code in a constrained environment." That materially improves external trust for enterprise governance, incident response, regulator/auditor review, and cross-organization evidence sharing.
   **Rationale/justification:** As runtime autonomy and blast radius increase, software-only signing is insufficient for strongest assurance claims. Binding decisions to hardware-rooted attestation makes provenance tampering dramatically harder and turns explainability into verifiable trust infrastructure, not policy theater.

2. **Privacy-Preserving Fleet Learning Layer**
   **What it entails:** Add a fleet-wide learning mechanism that improves risk calibration, drift handling, and containment policy quality without centralizing raw tenant-sensitive traces.
   **How it works:**  
   - Each deployment computes local model updates/summary statistics from evidence streams (calibration residuals, drift indicators, action outcomes, false-positive/false-negative signals).  
   - Updates are clipped, noised, and budget-accounted under explicit differential-privacy policy (`epsilon`, `delta`, per-epoch budget burn, composition accounting).  
   - Secure aggregation combines updates so coordinator learns only aggregate signals, not individual tenant contributions.  
   - Global model/policy deltas are redistributed with signed versioning, replay identifiers, and deterministic rollback tokens.  
   - Runtime actioning remains deterministic: live decision paths consume only signed snapshot artifacts; stochastic learning state cannot directly bypass deterministic decision contracts.
   - Quality gates require: no budget violation, no regression on safety metrics, and no policy-promotion without shadow validation against representative replay corpora.
   **Why it is useful/compelling:** Fleet learning yields faster adaptation to novel attack patterns and workload shifts while preserving strong privacy boundaries. Operators get compound intelligence without having to trade away sensitive operational data.
   **Rationale/justification:** Centralized telemetry learning often fails adoption due to confidentiality and compliance constraints. A privacy-preserving approach enables large-scale collective intelligence while keeping privacy risk explicitly measured, budgeted, and enforceable.

3. **Moonshot Portfolio Governor (EV/Risk/Compute Constitutional Control)**
   **What it entails:** Add a formal governance engine that allocates engineering and compute budget across moonshots using explicit expected-value, risk, uncertainty, and artifact-quality scores, with automatic promote/hold/kill decisions.
   **How it works:**  
   - Every moonshot initiative carries a machine-readable contract: hypothesis, target metrics, expected-loss model, required proof artifacts, max budget, fallback mode, and exit criteria.  
   - Governor computes rolling scorecards (`EV`, confidence, risk-of-harm, implementation friction, cross-initiative interference risk, operational burden).  
   - Stage-gate automation enforces transitions (`research -> shadow -> canary -> production`) only when pre-declared artifact and metric thresholds are met.  
   - Kill-switch and pause semantics are first-class: initiatives that consume budget without signal, violate risk constraints, or fail reproducibility gates are automatically demoted or terminated.  
   - Human override remains available but must emit signed justification artifacts so governance drift is auditable.
   **Why it is useful/compelling:** This prevents the common failure mode where ambitious programs drown in undifferentiated experimentation. Capital, attention, and compute remain focused on highest-leverage ideas with verifiable traction.
   **Rationale/justification:** Large innovation portfolios fail less from lack of ideas than from weak selection pressure. A constitutional governor converts strategic ambition into disciplined compounding execution and reduces organizational self-deception.

4. **FrankenSuite Cross-Repo Conformance Lab**
   **What it entails:** Build a dedicated interoperability and contract-validation laboratory spanning `franken_engine`, `/dp/asupersync`, `/dp/frankentui`, `/dp/frankensqlite`, optional `/dp/sqlmodel_rust`, `/dp/fastapi_rust`, and `franken_node` boundary surfaces.
   **How it works:**  
   - Define canonical cross-repo contracts: identifier schemas, decision/evidence payload schemas, API message contracts, persistence semantics, replay/export formats, and TUI event/state contracts.  
   - Generate conformance vectors and property-based fuzz suites that test both happy-path interoperability and adversarial edge cases (schema drift, stale revocation head, replay mismatch, degraded-mode transitions).  
   - Run matrix testing across version combinations (N/N-1/N+1 compatibility policy where applicable) with deterministic replay requirements.  
   - Failures produce minimized repro artifacts with contract-delta classification (`breaking`, `behavioral`, `observability`, `performance regression`).  
   - Release gating requires clean conformance lab pass for any change touching shared contracts or sibling integration adapters.
   **Why it is useful/compelling:** Cross-repo systems usually fail at boundaries, not internals. A first-class conformance lab turns integration trust from tribal knowledge into continuously validated, machine-checkable reality.
   **Rationale/justification:** FrankenEngine’s strategic advantage depends on coordinated sibling-repo leverage and strict split contracts. Without formal cross-repo conformance infrastructure, the architecture will drift, regress, and eventually self-sabotage under rapid iteration pressure.

## 10. Ultra-Detailed TODO (Program Level)
### 10.0 Top 10 Initiative Tracking
- [ ] Implement TS-first authoring pipeline with native capability-typed IR target.
- [ ] Implement Probabilistic Guardplane runtime subsystem.
- [ ] Implement deterministic evidence graph + replay tooling.
- [ ] Implement alien-performance profile discipline and hotpath program gates.
- [ ] Implement supply-chain trust fabric integrated with containment policy.
- [ ] Implement shadow-run + differential executor onboarding mode.
- [ ] Implement capability lattice + typed policy DSL.
- [ ] Implement deterministic per-extension resource budget subsystem.
- [ ] Implement adversarial security corpus + continuous fuzzing harness.
- [ ] Implement provenance + revocation fabric and recall workflow.

### 10.1 Charter + Governance
- [ ] Add runtime charter document that codifies native-only engine policy.
- [ ] Add claim language policy so marketing claims require evidence artifacts.
- [ ] Add reproducibility contract (`env.json`, `manifest.json`, `repro.lock`) template.

### 10.2 VM Core
- [ ] Define parser trait + canonical AST invariants.
- [ ] Define IR trait + verification rules.
- [ ] Implement baseline interpreter skeleton for both lanes.
- [ ] Implement deterministic error and exception semantics.
- [ ] Implement prototype/object model conformance subset.
- [ ] Implement closure and lexical scope model.

### 10.3 Memory + GC
- [ ] Define allocation domains and lifetime classes.
- [ ] Implement initial GC with deterministic test mode.
- [ ] Add pause-time instrumentation and regression budgets.

### 10.4 Module + Runtime Surface
- [ ] Implement module resolver trait with policy hooks.
- [ ] Implement module cache invalidation strategy.
- [ ] Add explicit compatibility mode matrix for Node/Bun module edge cases (no hidden shims).

### 10.5 Extension Host + Security
- [ ] Port extension manifest validation into compile-active modules.
- [ ] Port extension lifecycle manager into compile-active modules.
- [ ] Implement hostcall telemetry schema and recorder.
- [ ] Implement Bayesian posterior updater API.
- [ ] Implement expected-loss action selector.
- [ ] Implement containment actions (`sandbox`, `suspend`, `terminate`, `quarantine`).
- [ ] Implement forensic replay tooling for incident traces.

### 10.6 Performance Program
- [ ] Create baseline benchmark suite and golden outputs.
- [ ] Add flamegraph pipeline and artifact storage.
- [ ] Add opportunity matrix scoring to optimization workflow.
- [ ] Enforce one-lever-per-change performance policy.

### 10.7 Conformance + Verification
- [ ] Integrate transplanted extension conformance assets into runnable suites.
- [ ] Add probabilistic security conformance tests (benign vs malicious corpora).
- [ ] Add metamorphic tests for parser/IR/execution invariants.
- [ ] Add stress tests for high-concurrency extension workloads.

### 10.8 Operational Readiness
- [ ] Add runtime diagnostics and evidence export CLI.
- [ ] Add deterministic safe-mode startup flag.
- [ ] Add release checklist requiring security and performance artifact bundles.

### 10.9 Moonshot Disruption Track
- [ ] Release gate: official Node/Bun comparison harness is delivered with reproducible benchmark artifacts and publishable methodology (implementation ownership: `10.12` + section `14`).
- [ ] Define and enforce disruption scorecard (`performance_delta`, `security_delta`, `autonomy_delta`) as release blockers.
- [ ] Release gate: autonomous quarantine mesh is implemented and validated under fault injection (implementation ownership: `10.12`).
- [ ] Release gate: proof-carrying optimization pipeline is enabled with replayable validation artifacts (implementation ownership: `10.12`).
- [ ] Release gate: continuous adversarial campaign runner demonstrates measurable compromise-rate suppression versus baseline engines (implementation ownership: `10.12`).
- [ ] Publish first category-shift report demonstrating beyond-parity capabilities with evidence bundles.

### 10.10 FCP-Inspired Hardening + Interop Track
- [ ] Define `EngineObjectId` derivation (`domain_sep || zone_or_scope || schema_id || canonical_bytes`) for all signed security-critical objects.
- [ ] Reject non-canonical encodings for security-critical object classes (no silent normalization).
- [ ] Implement deterministic serialization module with schema-hash prefix validation.
- [ ] Implement signature preimage contract using unsigned-view encoding and deterministic field ordering.
- [ ] Enforce deterministic ordering for multi-signature arrays before verification.
- [ ] Define `PolicyCheckpoint` object with `prev_checkpoint`, `checkpoint_seq`, `epoch_id`, policy heads, and quorum signatures.
- [ ] Persist highest accepted checkpoint frontier and reject rollback/regression attempts.
- [ ] Implement same-sequence divergent-checkpoint fork detection and incident pathway.
- [ ] Extend capability token format with audience, expiry/nbf, jti, checkpoint binding, and revocation freshness binding.
- [ ] Implement delegated capability attenuation chain verification (no ambient authority path).
- [ ] Split principal key roles into signing/encryption/issuance and enforce independent revocation.
- [ ] Implement owner-signed key attestation objects with expiry and nonce freshness requirements.
- [ ] Add optional threshold-signing workflow for emergency revocation and key rotation operations.
- [ ] Implement session-authenticated extension hostcall channel with per-message MAC.
- [ ] Implement monotonic message sequence and replay-drop enforcement on session channels.
- [ ] Implement deterministic nonce derivation for any AEAD-protected data-plane envelope.
- [ ] Define revocation object chain (`revocation`, `revocation_event`, `revocation_head`) with monotonic head sequence.
- [ ] Enforce revocation checks before token acceptance, risky operation execution, and extension activation.
- [ ] Implement revocation freshness policy with explicit degraded-mode behavior and audit emission.
- [ ] Define trust-zone taxonomy and capability ceilings with deterministic inheritance semantics.
- [ ] Enforce cross-zone reference constraints (provenance/audit allowed, authority leakage forbidden).
- [ ] Define mandatory runtime metrics and structured logs for auth/capability/replay/revocation/checkpoint failures.
- [ ] Define stable, versioned error-code namespace and compatibility policy.
- [ ] Implement append-only hash-linked audit chain with `correlation_id` and optional full trace context.
- [ ] Add conformance suite for canonical serialization, ID derivation, signatures, revocation freshness, and epoch ordering.
- [ ] Add golden vectors for critical binary encodings and verification paths.
- [ ] Add fuzz/adversarial targets for decode DoS, replay/splice handshake attacks, and token verification edge cases.
- [ ] Add activation/update/rollback contract: sandbox setup, ephemeral secret injection, staged rollout, crash-loop auto-rollback, known-good pinning.
- [ ] Add migration contract for explicit cutover boundaries on security-critical formats and policies.

### 10.11 FrankenSQLite-Inspired Runtime Systems Track
- [ ] Define canonical runtime capability profiles (`FullCaps`, `EngineCoreCaps`, `PolicyCaps`, `RemoteCaps`, `ComputeOnlyCaps`) and enforce them at API boundaries.
- [ ] Add compile-time ambient-authority audit gate for forbidden direct calls in engine security-critical modules.
- [ ] Add explicit checkpoint-placement contract for long-running loops (dispatch, scanning, policy iteration, replay, decode/verify paths).
- [ ] Implement region-quiescence close protocol (`cancel -> drain -> finalize`) for engine and host subsystems.
- [ ] Add bounded masking helper for tiny atomic publication steps only; block long-operation masking by policy.
- [ ] Implement obligation-tracked channels for safety-critical two-phase internal protocols.
- [ ] Add obligation leak response policy split (`lab=fatal`, `prod=diagnostic + scoped failover`).
- [ ] Define supervision tree for long-lived services with restart budgets, escalation, and monotone severity outcomes.
- [ ] Build deterministic lab runtime harness with schedule replay, virtual time, and cancellation injection.
- [ ] Add systematic interleaving explorer coverage for checkpoint/revocation/policy-update race surfaces.
- [ ] Define mandatory evidence-ledger schema for all controller/security decisions (candidates, constraints, chosen action, witnesses).
- [ ] Require deterministic ordering/stability for evidence entries (candidate sort, witness ids, bounded size policy).
- [ ] Implement `PolicyController` service for non-correctness knobs with explicit action sets and loss matrices.
- [ ] Implement e-process guardrail integration that can hard-block unsafe automatic retunes.
- [ ] Add BOCPD-based regime detector for workload/health stream shifts feeding policy decisions.
- [ ] Add VOI-budgeted monitor scheduler for high-cost diagnostic probes.
- [ ] Define monotonic `security_epoch` model and validity-window checks across signed trust artifacts.
- [ ] Implement epoch-scoped derivation for symbol/session/authentication keys with domain separation.
- [ ] Implement epoch transition barrier across core services to prevent mixed-epoch critical operations.
- [ ] Gate all remote operations behind explicit runtime capability (no implicit network side effects).
- [ ] Implement named remote computation registry with deterministic input encoding and schema validation.
- [ ] Implement idempotency-key derivation and dedup semantics for retryable remote actions.
- [ ] Implement lease-backed remote liveness tracking with explicit timeout/escalation paths.
- [ ] Implement saga orchestrator for multi-step publish/evict/quarantine workflows with deterministic compensation.
- [ ] Map work classes to scheduler lanes (`cancel`, `timed`, `ready`) and require task-type labeling for observability.
- [ ] Add global bulkheads for remote in-flight operations and background maintenance concurrency.
- [ ] Implement three-tier hash strategy contract (hot integrity, content identity, trust authenticity) with explicit scope boundaries.
- [ ] Add append-only hash-linked decision marker stream for high-impact security/policy transitions.
- [ ] Add optional MMR-style compact proof support for marker-stream inclusion/prefix verification.
- [ ] Implement O(Delta) anti-entropy reconciliation for distributed revocation/checkpoint/evidence object sets.
- [ ] Add deterministic fallback protocol when anti-entropy reconciliation cannot peel/resolve.
- [ ] Emit proof-carrying recovery artifacts for degraded-mode repairs and rejected trust transitions.
- [ ] Add phase gates for this track: deterministic replay pass, interleaving suite pass, conformance vectors pass, and fuzz/adversarial pass.

### 10.12 Frontier Programs Execution Track (9H Canonical Owners)
- [ ] Define proof schema and signer model for optimizer activation witnesses (`opt_receipt`, `rollback_token`, `invariance_digest`).
- [ ] Implement translation-validation gate on adaptive optimization paths with fail-closed rollback.
- [ ] Define fleet immune-system message protocol for signed evidence, local confidence, and containment intent propagation.
- [ ] Implement deterministic convergence + degraded partition policy for fleet containment actions.
- [ ] Build deterministic causal replay engine with counterfactual branching over policy/action parameters.
- [ ] Add incident replay artifact bundle format and verifier CLI for external audit.
- [ ] Define attested execution-cell architecture and trust-root interface contract.
- [ ] Implement measured attestation handshake between execution cells and runtime policy plane.
- [ ] Build policy theorem compiler passes and machine-check hooks for non-interference and merge determinism.
- [ ] Add counterexample synthesizer for conflicting policy controllers and ambiguous merges.
- [ ] Build continuous adversarial campaign generator with mutation grammars and exploit objective scoring.
- [ ] Integrate red/blue loop outputs into guardplane calibration and policy regression suites.
- [ ] Define trust-economics model inputs (`loss_matrix`, `attacker_cost`, `containment_cost`, `blast_radius`).
- [ ] Implement runtime decision scoring with explicit expected-loss and attacker-ROI outputs.
- [ ] Define secure extension reputation graph schema with provenance, behavior evidence, revocation edges, and trust transitions.
- [ ] Implement low-latency reputation updates and explainable trust-card generation for operators.
- [ ] Build operator safety copilot surfaces with recommended actions, confidence bands, and deterministic rollback commands.
- [ ] Define and publish category benchmark specification with reproducible harness and transparent scoring methodology.
- [ ] Implement third-party verifier toolkit that can independently validate benchmark, replay, and containment claims.
- [ ] Add quarterly frontier demo gates: at least one externally auditable breakthrough artifact per quarter.

### 10.13 Asupersync Constitutional Integration Track
- [ ] Define a formal control-plane adoption ADR naming `/dp/asupersync` crates as canonical sources for `Cx`, decision contracts, and evidence schema.
- [ ] Add dependency policy: no local forks of `TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`, `Budget`, or `Cx`.
- [ ] Introduce a narrow control-plane adapter layer in `franken_engine` that imports `franken-kernel`, `franken-decision`, and `franken-evidence` without pulling broad runtime internals into VM hot paths.
- [ ] Thread `Cx` through all effectful extension-host APIs (hostcall gateways, policy checks, lifecycle transitions, telemetry emitters).
- [ ] Enforce region-per-extension/session execution cells with quiescent close guarantees.
- [ ] Implement cancellation lifecycle compliance checks (`request -> drain -> finalize`) for unload, quarantine, suspend, terminate, and revocation events.
- [ ] Add obligation-tracking for two-phase safety-critical operations and fail lab runs on unresolved obligations.
- [ ] Route all high-impact safety actions through `franken-decision` decision contracts with explicit loss matrices and fallback policies.
- [ ] Emit canonical evidence entries via `franken-evidence` for all high-impact actions, linked to `trace_id`, `decision_id`, `policy_id`, and artifact hashes.
- [ ] Add deterministic evidence replay checks ensuring decision/evidence linkage replays identically across machines.
- [ ] Integrate `frankenlab` scenarios for extension lifecycle and containment paths (startup, normal shutdown, forced cancel, quarantine, revocation, degraded mode).
- [ ] Make `frankenlab replay` and deterministic scenario pass/fail outputs release blockers for security-critical paths.
- [ ] Add interference tests for multiple controllers touching same metrics with required timescale-separation statements.
- [ ] Add compile-time lint/CI guard rejecting ambient authority in extension-host control paths.
- [ ] Add migration compatibility tests ensuring control-plane schema evolution preserves replay compatibility or fails with explicit machine-readable migration errors.
- [ ] Add benchmark split showing control-plane overhead remains bounded while VM hot-loop performance remains decoupled.
- [ ] Add fallback validation proving control-plane failure degrades to deterministic safe mode rather than undefined behavior.
- [ ] Publish an operator-facing “control-plane invariants dashboard” sourced from evidence ledgers and replay artifacts.

### 10.14 FrankenSuite Sibling Integration Track
- [ ] Add an ADR declaring `/dp/frankentui` as the required substrate for advanced operator console/TUI surfaces in FrankenEngine.
- [ ] Define a `franken_engine` TUI adapter boundary for incident replay views, policy explanation cards, and control dashboards backed by `frankentui` components.
- [ ] Add CI/policy guard preventing new local interactive TUI frameworks in `franken_engine` without explicit ADR exception.
- [ ] Add an ADR declaring `/dp/frankensqlite` as the required substrate for SQLite-backed control-plane persistence in FrankenEngine.
- [ ] Inventory every current/planned local persistence need (replay index, evidence index, benchmark ledger, policy artifact cache) and map each to a `frankensqlite` integration point.
- [ ] Create a `franken_engine` storage adapter layer that binds runtime persistence contracts to `frankensqlite` APIs.
- [ ] Define when `/dp/sqlmodel_rust` must be used: typed schema/model workflows with material correctness or migration advantages.
- [ ] Add migration policy prohibiting ad-hoc local SQLite wrappers once `frankensqlite` adapter coverage exists.
- [ ] Add conformance tests proving deterministic replay/index behavior across `frankensqlite`-backed stores.
- [ ] Add an ADR for `/dp/fastapi_rust` reuse scope across FrankenEngine service/API control surfaces.
- [ ] Build a thin integration template for service endpoints (health, control actions, evidence export, replay control) using `fastapi_rust` conventions/components where relevant.
- [ ] Add cross-repo contract tests validating schema/API compatibility for integration boundaries (`frankentui`, `frankensqlite`, `sqlmodel_rust`, `fastapi_rust`).
- [ ] Add benchmark gates confirming sibling-repo integrations do not regress critical p95/p99 control-plane SLOs.
- [ ] Add release checklist item requiring explicit “reuse vs reimplement” justification for any new console, SQLite, or service layer work.

### 10.15 Delta Moonshots Execution Track (9I)
- Scope note: this track deepens guarantees for `9I` capabilities and extends (does not duplicate) baseline sibling-integration work in `10.14`.
- [ ] Define TEE attestation policy for decision-receipt emitters (`approved measurements`, `attestation freshness window`, `revocation sources`, `platform trust roots`).
- [ ] Extend receipt schema to include attestation bindings (`quote_digest`, `measurement_id`, `attested_signer_key_id`, `nonce`, `validity_window`).
- [ ] Build verifier pipeline that validates signature chain, transparency log proofs, and attestation chain in one deterministic command.
- [ ] Add deterministic fallback policy: when attestation validation fails or expires, high-impact autonomous actions degrade to conservative safe mode.
- [ ] Define privacy-learning contract for fleet calibration (`feature schema`, update cadence, clipping strategy, DP budget semantics, secure-aggregation requirements).
- [ ] Implement budget accountant for differential privacy with epoch-scoped burn tracking and hard fail-closed budget exhaustion behavior.
- [ ] Emit randomness transcript commitments and seed-hash evidence for stochastic learning phases so downstream replay remains audit-deterministic at snapshot boundaries.
- [ ] Add shadow-evaluation gate that blocks global model/policy promotion unless privacy-preserving updates improve safety metrics without exceeding privacy budgets.
- [ ] Define moonshot contract schema (`hypothesis`, `target metrics`, `EV model`, `risk budget`, `artifact obligations`, `kill criteria`, `rollback plan`).
- [ ] Implement portfolio governor scoring engine and stage-gate automation for moonshot lifecycle transitions.
- [ ] Add governance audit ledger capturing all automatic and human override promote/hold/kill decisions with signed rationale.
- [ ] Define advanced conformance-lab contract catalog (semantic version classes, failure taxonomy, replay obligations) extending `10.14` baseline boundary tests.
- [ ] Build conformance-vector generator and property/fuzz harness for cross-repo boundary invariants, including degraded/fault-mode scenarios.
- [ ] Add version-matrix CI lane (N/N-1/N+1 where applicable) for contract compatibility checks across supported repo/version combinations.
- [ ] Add minimized repro artifact format for conformance failures with deterministic replay and machine-readable delta classification.
- [ ] Make matrix+fault conformance lab pass a release blocker for shared-boundary changes, complementing the baseline compatibility gates in `10.14`.
- [ ] Publish quarterly scorecard reporting: attested-receipt coverage, privacy-budget health, moonshot-governor decisions, and cross-repo conformance stability.

## 11. Evidence And Decision Contracts (Mandatory)
Every major subsystem proposal must include:
- change summary
- hotspot/threat evidence
- EV score and tier
- expected-loss model
- fallback trigger
- rollout wedge
- rollback command
- benchmark and correctness artifacts

No contract, no merge.

## 12. Risk Register
- Scope explosion:
  - Countermeasure: strict phase gates and one-lever optimization discipline.
- False confidence from heuristic security:
  - Countermeasure: Bayesian + sequential testing + calibration audits.
- Performance regressions from over-hardening:
  - Countermeasure: profile-driven optimization and tail-latency budgets.
- Operational complexity:
  - Countermeasure: evidence-ledger tooling and deterministic fallback mode.

## 13. Program Success Criteria
FrankenEngine is considered successful when:
- native execution lanes run without external engine bindings
- franken_node composes those lanes for practical runtime usage
- untrusted extension code is actively monitored and auto-contained under attack scenarios
- security and performance claims are artifact-backed and reproducible
- compatibility and reliability meet release gates
- extension-heavy benchmark suites show `>= 3x` throughput versus baseline Node/Bun at equivalent behavior
- red-team programs show `>= 10x` reduction in successful host compromise versus baseline Node/Bun default posture
- high-risk detections reach containment in `<= 250ms` median time under defined load envelopes
- deterministic replay coverage is `100%` for high-severity decisions and incidents, with deterministic re-execution defined over fixed artifacts (`code`, `policy`, `model snapshot`, `randomness transcript`)
- control-plane identifiers and capability context are canonicalized through asupersync-derived types (no competing local forks)
- all high-impact safety actions are executed through decision contracts and emitted through canonical evidence ledgers
- extension lifecycle transitions (`start`, `reload`, `suspend`, `terminate`, `quarantine`, `revoke`) satisfy `request -> drain -> finalize` protocol invariants
- release gates include deterministic `frankenlab` scenario replay for security-critical lifecycle and containment paths
- all advanced operator terminal UX surfaces are delivered through `/dp/frankentui` integration rather than parallel local TUI frameworks
- all SQLite-backed control-plane persistence in FrankenEngine is delivered through `/dp/frankensqlite` integration, with `/dp/sqlmodel_rust` used where typed model layers materially improve safety
- service/API control surfaces relevant to runtime operations leverage `/dp/fastapi_rust` patterns/components where they provide equal or better capability
- at least 3 beyond-parity capabilities are in production with operator-facing evidence and documentation
- at least 2 independent third parties reproduce core benchmark claims using published tooling
- fleet quarantine convergence meets published SLOs under partition/fault injection drills
- proof-carrying optimization path is enabled by default for at least one high-impact optimization family
- secure extension reputation graph drives measurable reduction in first-time compromise windows
- category benchmark standard is adopted by external runtime/security research participants
- >= 95% of high-impact decision receipts include valid non-expired attestation bindings verifiable by independent tooling
- privacy-preserving fleet learning operates continuously with zero budget-overrun incidents and measurable calibration/drift-improvement over local-only baselines
- moonshot portfolio governor enforces documented promote/hold/kill gates with 100% governance decision artifact completeness
- cross-repo conformance lab pass rate is a hard release gate for shared-boundary changes, with deterministic repro artifacts for every failure class

## 14. Public Benchmark + Standardization Strategy
FrankenEngine will define and own the reference benchmark standard for secure extension runtimes.

Program commitments:
- Publish benchmark specification, harness code, datasets, and scoring formulas.
- Include both performance and security co-metrics (not speed-only benchmarks).
- Require reproducibility artifacts for every published result.
- Maintain a neutral verifier mode so third parties can run and validate claims.
- Update standards on a fixed cadence with explicit versioning and migration notes.

Required metric families:
- Throughput/latency (`p50`, `p95`, `p99`) under extension-heavy workloads.
- Containment quality (time-to-detect, time-to-contain, false-positive/false-negative envelopes).
- Replay correctness (determinism pass rate, artifact completeness).
- Revocation/quarantine propagation (freshness lag distribution, convergence SLO attainment).
- Adversarial resilience (campaign success-rate suppression vs baseline engines).

## 15. Ecosystem Capture Strategy
FrankenEngine should not only outperform incumbents; it should become the default platform for high-trust extension ecosystems.

Execution pillars:
- Signed extension registry with enforceable provenance, attestation, and revocation policies.
- Migration kits that convert existing Node/Bun extension workflows into capability-typed FrankenEngine workflows.
- Enterprise governance hooks (policy-as-code pipelines, audit export, compliance evidence contracts).
- Reputation graph APIs for ecosystem-wide trust sharing and rapid incident response.
- Partner program for early lighthouse adopters who validate category-shift outcomes in production.

Adoption targets:
- Time-to-first-safe-extension in under 30 minutes for greenfield teams.
- Migration of representative Node/Bun extension packs with deterministic behavior validation artifacts.
- Public case studies showing materially improved security and operational outcomes.

## 16. Scientific Contribution Targets
FrankenEngine is also a research-producing engineering program. Each major novelty should produce reusable scientific/technical artifacts.

Required contributions:
- Open specifications for core trust/replay/policy primitives.
- Reproducible datasets for incident replay and adversarial campaign evaluation.
- Reference proofs or proof sketches for key policy and protocol safety claims.
- External red-team and academic-style evaluations with published methodology.
- Public technical reports that document failures, fixes, and measured frontier movement.

Annual output contract:
- At least 4 publishable technical reports with reproducible artifact bundles.
- At least 2 externally replicated high-impact claims.
- At least 1 open benchmark or verification tool release adopted outside the project.
