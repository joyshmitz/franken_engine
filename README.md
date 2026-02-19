# FrankenEngine

<div align="center">
  <img src="franken_engine_illustration.webp" alt="FrankenEngine - Native Rust runtime for high-trust extension workloads">
</div>

<div align="center">

[![Rust 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Unsafe Forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://doc.rust-lang.org/reference/unsafe-keyword.html)
[![Deterministic Replay](https://img.shields.io/badge/replay-deterministic-blue.svg)](./PLAN_TO_CREATE_FRANKEN_ENGINE.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

</div>

Native Rust runtime for adversarial extension workloads, with deterministic replay, cryptographic decision receipts, and fleet-scale containment.

<div align="center">
<h3>Quick Install</h3>

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh?$(date +%s)" | bash
```

<p><em>Linux, macOS, and Windows support with architecture-aware binaries.</em></p>
</div>

---

## TL;DR

### The Problem
Node and Bun are fast enough for many workloads, but extension-heavy agent systems need a different default posture: active containment, deterministic forensics, and explicit runtime authority boundaries.

### The Solution
FrankenEngine provides two native execution lanes, a probabilistic guardplane with expected-loss actioning, deterministic replay for high-severity decisions, and signed evidence contracts for every high-impact containment event.

### Why Use FrankenEngine?

| Capability | What You Get In Practice |
|---|---|
| Native dual-lane execution | `quickjs_inspired_native` for deterministic control paths and `v8_inspired_native` for throughput-heavy paths |
| Probabilistic Guardplane | Bayesian risk updates and e-process boundaries that trigger `allow/challenge/sandbox/suspend/terminate/quarantine` |
| Deterministic replay | Bit-stable replay for high-severity decision paths with counterfactual policy simulation |
| Cryptographic governance | Signed decision receipts with transparency-log proofs and optional TEE attestation bindings |
| Fleet immune system | Quarantine and revocation propagation with bounded convergence SLOs |
| Capability-typed execution | TS-first workflow that compiles to capability-typed IR with ambient-authority rejection |
| Cross-repo constitution | Control plane on `/dp/asupersync`, TUI on `/dp/frankentui`, SQLite on `/dp/frankensqlite` |
| Evidence-first operations | Every published performance and security claim ships with reproducible artifact bundles |

## Quick Example

```bash
# 1) Install and verify
frankenctl version

# 2) Initialize a runtime workspace
frankenctl init --profile secure --path ./demo-runtime

# 3) Compile an extension package to capability-typed IR
frankenctl ext compile ./examples/weather-ext --out ./build/weather.fir

# 4) Run in shadow mode with lockstep Node/Bun diff
frankenctl shadow-run ./build/weather.fir --lockstep node,bun --report ./artifacts/shadow.json

# 5) Promote to active with signed policy checkpoint
frankenctl promote ./build/weather.fir --policy ./policies/default.toml --checkpoint-sign

# 6) Trigger an incident drill and inspect containment action
frankenctl drill run suspicious-exfiltration --target weather-ext
frankenctl decision show --last --explain --receipt

# 7) Verify receipt and replay deterministically
frankenctl receipt verify --id $(frankenctl decision show --last --json | jq -r .receipt_id)
frankenctl replay run --trace $(frankenctl decision show --last --json | jq -r .trace_id)
```

## Design Philosophy

1. **Runtime ownership over wrappers**
FrankenEngine owns parser-to-scheduler semantics in Rust. Compatibility is a product layer in `franken_node`, not a hidden wrapper around third-party engines.

2. **Security and performance as co-equal constraints**
The project does not trade correctness for speed or speed for policy theater. Optimizations ship with behavior proofs and rollback artifacts.

3. **Deterministic first, adaptive second**
Live decisions must replay deterministically from fixed artifacts. Adaptive learning is allowed, but only through signed promoted snapshots.

4. **Evidence before claims**
Benchmarks, containment metrics, and policy assertions are tied to reproducible artifacts. No artifact, no claim.

5. **Constitutional integration**
FrankenEngine reuses stronger sibling substrates instead of rebuilding them: asupersync control contracts, frankentui operator surfaces, and frankensqlite persistence.

## Comparison

| Dimension | FrankenEngine | Node.js | Bun |
|---|---|---|---|
| Core execution ownership | Native Rust lanes | V8 embedding | JavaScriptCore + Zig runtime |
| Deterministic replay for high-severity decisions | Built in, mandatory release gate | External tooling only | External tooling only |
| Probabilistic containment policy | Built in guardplane | Not default runtime behavior | Not default runtime behavior |
| Cryptographic decision receipts | First-class runtime artifact | Not a core runtime primitive | Not a core runtime primitive |
| Fleet quarantine convergence model | Explicit SLO + fault-injection gates | App-specific integration | App-specific integration |
| Capability-typed extension contract | Native IR contract | Not native to runtime | Not native to runtime |
| Cross-runtime lockstep oracle | Built in Node/Bun differential harness | N/A | N/A |

## Installation

### Option 1: One-Line Installer

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh" | bash
```

### Option 2: Cargo

```bash
cargo install frankenengine-cli
```

### Option 3: Build From Source

```bash
git clone https://github.com/Dicklesworthstone/franken_engine.git
cd franken_engine
cargo build --release --workspace
./target/release/frankenctl version
```

### Optional Operator Stack

```bash
# Required for advanced TUI views
cd /dp/frankentui && cargo build --release

# Required for SQLite-backed replay/evidence stores
cd /dp/frankensqlite && cargo build --release
```

## Quick Start

1. **Create config and keys**
```bash
frankenctl init --profile secure --path ./runtime
frankenctl keys generate --out ./runtime/keys
```

2. **Enable control plane integration**
```bash
frankenctl control-plane bind --asupersync /dp/asupersync
```

3. **Compile and validate extension package**
```bash
frankenctl ext compile ./examples/hello-ext --out ./runtime/ext/hello.fir
frankenctl ext verify ./runtime/ext/hello.fir
```

4. **Run guarded runtime**
```bash
frankenctl run --config ./runtime/franken-engine.toml
```

5. **Inspect decisions and evidence**
```bash
frankenctl decision tail --follow
frankenctl evidence export --since 1h --out ./artifacts/evidence.jsonl
```

6. **Test deterministic replay and revocation paths**
```bash
frankenctl replay run --trace latest
frankenctl revocation drill --scenario stale-head-recovery
```

## Command Reference

| Command | Purpose | Example |
|---|---|---|
| `frankenctl init` | Create runtime workspace and default config | `frankenctl init --profile secure --path ./runtime` |
| `frankenctl run` | Start runtime with configured lanes and guardplane | `frankenctl run --config ./runtime/franken-engine.toml` |
| `frankenctl ext compile` | Compile TS extension package to capability-typed IR | `frankenctl ext compile ./ext/foo --out ./build/foo.fir` |
| `frankenctl ext verify` | Validate capability declarations and IR invariants | `frankenctl ext verify ./build/foo.fir` |
| `frankenctl shadow-run` | Run observe-only with lockstep differential analysis | `frankenctl shadow-run ./build/foo.fir --lockstep node,bun` |
| `frankenctl promote` | Promote extension after shadow/conformance gates | `frankenctl promote ./build/foo.fir --checkpoint-sign` |
| `frankenctl decision show` | Inspect last decision with posterior and loss terms | `frankenctl decision show --last --explain` |
| `frankenctl receipt verify` | Verify cryptographic receipt and log consistency | `frankenctl receipt verify --id rcpt_01J...` |
| `frankenctl replay run` | Deterministically replay incident trace | `frankenctl replay run --trace trace_01J...` |
| `frankenctl quarantine` | Trigger containment action for extension/session | `frankenctl quarantine --extension foo --reason high-risk` |
| `frankenctl revocation` | Manage revocation heads and propagation checks | `frankenctl revocation status --zone prod-us-east` |
| `frankenctl benchmark` | Run category benchmark and emit reproducible artifacts | `frankenctl benchmark run --suite extension-heavy` |
| `frankenctl lockstep` | Execute Node/Bun/FrankenEngine differential harness | `frankenctl lockstep run --suite compat-smoke` |
| `frankenctl tui` | Open advanced operator console via frankentui | `frankenctl tui --view incident-replay` |
| `frankenctl api serve` | Expose control APIs for operations and automation | `frankenctl api serve --bind 127.0.0.1:8787` |

## Configuration

`franken-engine.toml`

```toml
# Runtime identity and environment
[runtime]
cluster = "prod"
zone = "us-east-1"
mode = "secure"

# Select execution lanes and router policy
[lanes]
default = "hybrid_router"
quickjs_inspired_native_enabled = true
v8_inspired_native_enabled = true

[router]
policy = "risk_aware"
fallback_lane = "quickjs_inspired_native"

# Guardplane decision settings
[guardplane]
enabled = true
posterior_model = "bayes-online-v1"
sequential_test = "e_process"

[guardplane.loss]
allow = 0
warn = 5
challenge = 15
sandbox = 30
suspend = 60
terminate = 90
quarantine = 100

# Cryptographic decision receipts
[receipts]
enabled = true
transparency_log = "sqlite"
require_signature = true

# Optional TEE attestation binding for high-impact actions
[receipts.attestation]
enabled = true
min_quote_freshness_seconds = 300
fail_mode = "safe"

# Deterministic replay requirements
[replay]
enabled = true
record_randomness_transcript = true
require_snapshot_signature = true

# Control-plane substrate from asupersync
[control_plane]
provider = "asupersync"
path = "/dp/asupersync"
require_cx_threading = true
require_cancel_drain_finalize = true

# SQLite-backed persistence via frankensqlite
[storage]
provider = "frankensqlite"
path = "/var/lib/franken_engine/runtime.db"
wal_mode = true

# Operator TUI surfaces via frankentui
[ui]
provider = "frankentui"
default_view = "control-dashboard"

# API layer conventions from fastapi_rust
[api]
enabled = true
bind = "127.0.0.1:8787"
transport = "http"

# Scheduler and resource governance
[scheduler]
lanes = ["cancel", "timed", "ready", "background"]
default_cpu_budget_millis = 50
default_memory_budget_mb = 128
```

## Architecture

```text
                    +-----------------------------------+
                    |           franken_node            |
                    |  compatibility + product surface  |
                    +----------------+------------------+
                                     |
                                     v
+-------------------------------------------------------------------+
|                           FrankenEngine                            |
|                                                                   |
|  +-------------------+      +----------------------------------+  |
|  | Native Data Plane |      |  Control Plane (Constitutional) |  |
|  |-------------------|      |----------------------------------|  |
|  | parser + IR       |      | Cx capability contracts          |  |
|  | execution lanes   |<---->| decision contracts               |  |
|  | GC + scheduler    |      | evidence + receipts              |  |
|  | module runtime    |      | cancel -> drain -> finalize      |  |
|  +-------------------+      +----------------------------------+  |
|            |                                   |                  |
+------------+-----------------------------------+------------------+
             |                                   |
             v                                   v
  +---------------------+             +--------------------------+
  | /dp/frankensqlite   |             | /dp/frankentui          |
  | replay/evidence DB  |             | operator dashboards/TUI |
  +---------------------+             +--------------------------+
             |
             v
  +---------------------+
  | /dp/asupersync      |
  | kernel/decision/    |
  | evidence/frankenlab |
  +---------------------+
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `missing Cx context` errors | Effectful host path is bypassing control-plane threading | Run `frankenctl doctor cx` and update integration boundary to pass `Cx` |
| Replay mismatch on high-severity trace | Snapshot or randomness transcript missing | Verify `replay.record_randomness_transcript=true` and rerun `frankenctl replay verify --trace ...` |
| Receipt verification failure | Stale signature chain or broken transparency-log inclusion proof | Run `frankenctl receipt verify --repair-log` and check signer key rotation state |
| Revocation lag above SLO | Anti-entropy backlog or network partition | Run `frankenctl revocation repair --zone <zone>` and inspect partition diagnostics |
| Lockstep diff shows behavior drift | Intentional semantic change not declared, or regression in lane policy | Use `frankenctl lockstep explain --case <id>` and add policy declaration or patch runtime |

## Limitations

- High-security mode adds measurable overhead on latency-sensitive low-risk workloads.
- Capability-typed extension onboarding requires explicit manifests and policy declarations; this is extra setup for small prototypes.
- Deterministic replay and evidence retention increase storage footprint.
- Full Node ecosystem compatibility remains an active target; edge behavior differences can still appear in low-level module or process APIs.
- Fleet-level immune features assume stable cryptographic identity and time synchronization across participating nodes.

## FAQ

### 1. Is FrankenEngine a Node replacement?
For extension-heavy, high-trust workloads, yes. For broad legacy compatibility-only use cases, `franken_node` is the product layer that provides migration paths.

### 2. Do I need asupersync to use this?
Yes, for full control-plane guarantees. FrankenEngine can run with reduced local mode, but constitutional guarantees require `/dp/asupersync` integration.

### 3. Can I run without frankentui?
Yes for basic CLI workflows. Advanced operator views, replay dashboards, and policy explanation consoles use `/dp/frankentui`.

### 4. Why require frankensqlite for SQLite workloads?
It enforces shared persistence contracts and conformance behavior across replay, evidence, benchmark, and control artifacts.

### 5. How are false positives controlled?
Through explicit expected-loss matrices, sequential testing boundaries, calibrated posterior models, and shadow promotion gates.

### 6. What does deterministic replay guarantee exactly?
Given fixed code, policy, model snapshot, evidence stream, and randomness transcript, high-severity decision execution replays identically.

### 7. Can I verify your benchmark claims independently?
Yes. The benchmark harness, manifests, and artifact bundles are designed for third-party reproduction.

### 8. How fast is containment in practice?
Operational target is at or below 250ms median from high-risk threshold crossing to containment action under defined load envelopes.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT, see [LICENSE](./LICENSE).
