# Quality and qualification contract

## Status and evidence boundary

**Current definition: proposed; renewed maintainer approval required before T001–T100 execution.** The verification-contract refinement adds explicit foundation smoke entrypoints, C1 reload/cancellation scenarios and split core/host benchmark execution. The prior U1/U2/I1 approval remains valid only for its recorded bytes, not this revised definition. Storage policy, sensor selection, tool versions, existing performance thresholds and aggregate gate budgets are unchanged; new C1 scenario bounds below are proposed qualification limits, not measured results. Tools still require configuration and demonstrated sensitivity; missing, stale, empty, failed or inconclusive required readings block acceptance. Permission to refine these documents is not approval of the resulting gate definition.

Software Observatory MCP discovery, full-entry inspection and coverage assessment were performed on 2026-10-27. Suggestions were keyword-based, not endorsements. The selected sensors are required for the scopes below. Entries reported catalog review date 2026-08-24.

For this verification-contract refinement, the full SO-002b and SO-002c MCP entries were reconsulted on 2026-10-27. They require explicit expected/observed outcomes and real dependency boundaries; fixture failures are not behavioral readings, mocks do not establish native interoperability, and retries must not conceal timing failures. Existing sensor relevance, limitations and family gaps remain recorded below; no benchmark sensor ID is added.

| Sensor | Project use | Limitation |
|---|---|---|
| [SO-002b Example-Based Tests](https://softwareobservatory.com/sensors/example-based-tests/) | Lifecycle boundaries, CLI results, rejected certificates, restore publication | Same-author examples miss omitted behavior; fixture failure is no reading. |
| [SO-002c Integration Tests](https://softwareobservatory.com/sensors/integration-tests/) | Actual daemon, USB device, Haskell client, systemd and independent node | Mocks do not establish boundary compatibility. |
| [SO-005e Property-Based Testing](https://softwareobservatory.com/sensors/property-based-testing/) | Generated evolution, discard/activation, retries, slot reuse and crash sequences | Only stated invariants; report rejected inputs and shrinking. |
| [SO-003 Mutation Testing](https://softwareobservatory.com/sensors/mutation-testing/) | Detect weakened period, identity, cleanup and restore checks | Operator coverage is incomplete; survivors require investigation, not score averaging. |
| [SO-003c Line Coverage](https://softwareobservatory.com/sensors/line-coverage/) | Expose unexecuted shared-core and host error paths | Execution does not prove assertions or firmware coverage. |
| [SO-005 Fuzzing](https://softwareobservatory.com/sensors/fuzzing/) | USB, node-service, management, certificate and artifact decoders | Crash oracle alone misses wrong but valid-looking results. |
| [SO-016 Model Checking](https://softwareobservatory.com/sensors/model-checking/) | Exhaustive finite Rust lifecycle model: torn commits, retries, activation/discard ordering | Proof is bounded to the model, not implementation or physical flash. |
| [SO-005c Differential Testing](https://softwareobservatory.com/sensors/differential-testing/) | Sum6KES and file encoding against independent Haskell implementation | Agreement can share a bug; resolve disagreement against the governing format. |
| [SO-005d Fault Injection](https://softwareobservatory.com/sensors/fault-injection/) | Transaction cut points, lost replies, reconnect, actual power removal | Only injected faults covered; simulated storage is not physical qualification. |
| [SO-006e Load Testing](https://softwareobservatory.com/sensors/load-testing/) | Real 64-pool delivery/recovery with 128 resident generations | Synthetic timing alone misses correctness; independently verify each returned key. |

The initial seven-sensor coverage query covered structural, behavioral, test-effectiveness and adversarial families. Adding differential/fault sensors deepens adversarial coverage; load testing adds runtime coverage. Remaining family gaps: invariants, change, architecture, evolution and human comprehension. Explicit release invariants, native compatibility runs, boundary review and an operator exercise address risks without claiming catalog completeness. History-based prediction has no meaningful local implementation history. Production shadow/A-B/chaos execution against real pool keys is inappropriate; use isolated disposable qualification networks. SO-014 Static Security Analysis was inspected but not selected: no Rust taint-analysis tool has been demonstrated here; Clippy/audit must not be mislabeled SAST. Independent trust-boundary/security review remains required. Microbenchmarks are a project gate, not an invented sensor ID.

## Tool and target selection

- Rust/Cargo 1.99.1, edition 2024; rustfmt/Clippy/LLVM tools from the same toolchain. The planning host reports Rust commit `58cf8f9c35b355199727627d07ae34a4e2846d67`, LLVM 23.1.1.
- Host: `x86_64-unknown-linux-gnu`. Firmware: `thumbv8m.main-none-eabihf`, RP2350 Cortex-M33. Firmware target is not installed on the planning host; installation and real target builds are implementation prerequisites, not completed checks.
- `proptest =1.11.0`, `criterion =0.8.2`; versions selected from the predecessor's recorded tool inventory, not dependencies already present here.
- `cargo-mutants 27.0.0` is installed and version-observed. Select `cargo-llvm-cov 0.9.1`, `cargo-fuzz 0.13.1`, and isolated `nightly-2026-10-22` for fuzz sanitizers; install/pin them before activation. Do not let the fuzz toolchain change production builds.
- `cargo-audit 0.22.1` and `cargo-deny 0.19.8` are installed and version-observed; dependency/license review is a project gate, not a substitute for the selected sensors.
- Native node/client and independent oracle pins are in [research.md](../research.md). Record actual GHC/Cabal versions and resolved native dependency plan with every integration reading.
- Physical tooling: record actual picotool, power-controller, probe, board silicon, fitted flash JEDEC/SFDP identity, firmware digest and stock clock. Do not inherit an A4-only criterion.

## Executable gate design

Commands name planned targets, not existing executables. Implement the targets and nonempty oracles before accepting their scope. `qualification` is a Cargo-host package invoking real tools/devices; it must return non-success on missing prerequisites and retain sanitized reports under `evidence/<candidate>/<gate>/`.

| Gate / sensors | Command | Oracle and pass rule | Budget and evidence |
|---|---|---|---|
| G1 build/dependencies | `cargo fmt --check`; `cargo check --locked`; `cargo test --locked`; `cargo clippy --all-targets -- -D warnings`; firmware `cargo build --locked -p pico2-kes-firmware --release --target thumbv8m.main-none-eabihf` and target-specific Clippy; `cargo audit`; `cargo deny check`; native `cabal build cardano-node` | All host default members and firmware configurations checked; no errors/warnings, unreviewed dependency advisories or license incompatibilities. Maintained KES adaptation gets its own host/no_std checks, not an implicit dependency lint pass. | 30 min host/build, 2 h native; commands, lockfiles, versions, diagnostics, link map. |
| G2 behavior/integration / SO-002b, SO-002c | `cargo test --locked --workspace --exclude pico2-kes-firmware`; `cargo run --locked -p qualification -- foundation`; `cargo run --locked -p qualification -- smoke --fixture "$FIXTURE"`; `cargo run --locked -p qualification -- native-regression --fixture "$FIXTURE"` | Named acceptance transitions and failures; foundation executable checks below, actual native receiver/finalizer regressions, and real CLI/daemon/socket/device smoke. No ignored required cases. Tests assert consumer-visible results, not forwarding, copied values or text. Foundation-only evidence does not pass full G2. | 30 min host including foundation/native regressions, 1 h device; case inventory and expected/observed public results. |
| G3 properties/model / SO-005e, SO-016 | `PROPTEST_CASES=10000 cargo test --locked -p kes-core --test lifecycle_properties`; `cargo test --locked -p kes-core --test lifecycle_model` | >=10,000 sequences of 1–256 actions over 64 pools; zero identity/monotonicity/cleanup/retention violations. Exhaustive finite model with 2 pools, active+staged, 3 periods, retries, torn write/erase and all race orderings; all reachable states explored, not random sampling. Compare implementation transitions with model traces. | 30 min; seeds, shrunk public traces, state/transition counts and model bounds; exhaustion is inconclusive. |
| G4 mutation / SO-003 | `cargo mutants -p kes-core -p kes-protocol -p pico2-kes-agent --timeout 120` | Zero unexplained non-equivalent survivors in identity, period, retry, cleanup, artifact authentication or output publication; >=90% detection per remaining measured module. Report invalid mutants separately; classify timeouts rather than assume a broken harness is detection. | 2 h; fixed operators/file set, per-mutant outcomes, reviewed equivalence reasons. |
| G5 coverage / SO-003c | `cargo llvm-cov --workspace --exclude pico2-kes-firmware --exclude qualification --ignore-filename-regex '(^|/)pico2-kes-agent/src/config\.rs$' --json --output-path evidence/coverage.json` | >=90% line coverage per production host/shared crate, no regression on changed-line coverage from approved baseline; behavioral scenarios exercise every changed security/lifecycle decision. Application settings in root `src/config.rs` are configuration schema/loading rather than executable product behavior and are excluded from coverage results. `qualification`, `tests`, `benches`, fuzz targets, test support and other qualification-only code have no percentage threshold. Annotated uncovered production lines reviewed. | 30 min; JSON/LCOV and exclusions. Hardware-only paths covered by G8, not called host-covered. |
| G6 fuzz / SO-005 | `cargo +nightly-2026-10-22 fuzz run usb -- -max_total_time=3600`; repeat for `node_service`, `management`, `certificate`, `artifact` | Nonempty corpora reaching actual parsing/state validation; no crash, sanitizer violation, unbounded allocation or semantic invariant failure. Record executions and coverage growth. | 1 h/target routine, 24 h/target before release; sanitized minimized failures, corpus hashes and counters. |
| G7 differential / SO-005c | `cargo run --locked -p qualification -- interop --fixture "$FIXTURE"` | Every primitive period 0–63 including 31→32, first invalid period, network lifetime <64; verification keys, signatures and serialized state agree with independent Haskell oracle. Restored key0 bytes equal disposable device generation-time reference; independent conventional decoder extracts identical bytes. Tampering/wrong recipient/wrong identity publish no usable file. | 2 h; public vector/result hashes, oracle/source versions and file-permission outcomes. No secret fixtures retained. |
| G8 faults / SO-005d | `cargo run --locked -p qualification -- power-loss --fixture "$FIXTURE" --cuts 10` | Exhaustive software persistent-transition boundaries plus 10 attended physical cuts across generation, certification, evolution, activation, discard, deletion and cleanup. Zero acknowledged/released rollback; erase/read verification of every obsolete secret region; corrupt/ambiguous pool fails closed. The operator records each cut point and recovery result; unattended automation is not required. | 24 h; cut schedule, before/after identities/periods, occupancy and erase verification. |
| G9 primary node / SO-002c | `cargo run --locked -p qualification -- node --fixture "$FIXTURE"` | Actual patched bulk node with 64 agent pools, separate mixed legacy/versioned file-agent and singleton cases; complete the SIGHUP reload qualification below. Preserve supported baseline sources and malformed/missing-file semantics without restoring removed forge changes. Independently accepted blocks before/after evolution, SIGHUP, rotation and full power recovery; healthy pools continue during an isolated agent outage and that agent recovers on return. Missing leadership opportunities are inconclusive, never a pass. No backup producer required. | 8 h controlled accelerated network; peer-accepted block hashes and opportunities, unchanged PID during reload, receiver/socket retirement, file immutability, fresh delivery and per-pool outcomes. |
| G10 operator/security / SO-002b, SO-002c | `cargo run --locked -p qualification -- operator --fixture "$FIXTURE"` | Operator completes quickstart via installed utility; common socket policy, no extra credentials, no direct CLI USB. Denied/unavailable/rejected/uncertain outcomes distinguished. No secret logs/dumps/files on primary. Offline restore and all warnings exercised. | 1 day; actual manual steps, public outcomes and deployment inspection. |
| P1 physical capacity / SO-006e | `cargo run --locked -p qualification -- load --fixture "$FIXTURE" --rounds 1000` | 64 active+64 staged fit simultaneously. Every one of 64 concurrent current-key requests finishes within 10 s; all valid pools recover within 60 s after all stated prerequisites are available. Verify pool/certificate/signing correctness for every result. Exercise slow/malformed clients, reconnect, full-boundary evolution and background generation. No percentile hides a missed pool. Endurance must satisfy the [storage policy](device-storage.md#endurance-acceptance-policy): five-year/1,827-day workload, monthly extra churn, and `2 * (prior wear + projected service erases) <= guaranteed rating` for every physical sector; missing inputs are inconclusive. | 4 h; per-request admission-to-verified-delivery latency, recovery start prerequisites, RAM/flash high-water, measured per-sector erase costs, part/rating/conditions, prior campaign wear, network/workload counts, projection arithmetic and limiting-sector margin. Lifetime projection is not a five-year soak test. |
| P0 microbenchmark / project | `cargo run --locked -p qualification -- benchmarks --baseline "$BASELINE_REV"` | Execute both `kes-core/lifecycle` and `pico2-kes-agent/host` targets for the approved correct baseline and candidate as specified below. Three runs per revision; every required workload's 95% runtime-ratio CI wholly <=1.05 passes, wholly >1.05 fails, crossing threshold is inconclusive. Neither a missing workload nor a direct Criterion exit is an aggregate pass. | 30 min combined measurement/comparison budget; 100 samples, 5 s warmup/10 s measurement per case, separate raw runs, source revisions, CPU/governor/build and filesystem settings. |

### Foundation executable smoke

T014 implements `qualification/src/foundation.rs` and its dispatch in `qualification/src/main.rs`; T016 integrates evidence validity and T020 executes `cargo run --locked -p qualification -- foundation` before US1. It requires the implemented T010/T011 codecs, T013 host protection and T014 fixture parser, but no daemon/CLI executable, hardware, external fixture, node or production credentials. The subcommand creates only disposable public inputs and isolated child processes:

- Feed malformed, truncated and over-limit USB/management frames into the real bounded decoders. Assert the documented rejection classes and allocation bounds, not merely a nonzero exit.
- In an unprivileged child with no memory-lock bypass capability and `RLIMIT_MEMLOCK=0`, call the real protected-memory initializer on nonempty disposable data. Observe the OS denial and fail-closed initialization, no ready state and no secret-bearing output. If the environment cannot enforce denial, report unavailable rather than substitute a mocked error.
- Pass generated invalid public fixture documents to the actual fixture parser and verify rejection before opening USB, starting external tools or contacting a node.

The runner records each input class, expected/observed outcome, execution count and environment in `evidence/<candidate>/foundation/report.json` using the common evidence schema. Exit 0 requires all named checks to execute and satisfy their oracles; missing execution, unavailable prerequisites, unexpected behavior and timeout return nonzero with a failed/inconclusive verdict. Diagnostics go to stderr, the public result to stdout/report. The checks share G2's 30-minute host budget and do not activate unimplemented story, native or hardware scopes. No production command or alternate memory-protection implementation is introduced.

### SIGHUP reload qualification

The [node-service reload contract](node-service.md#sighup-credential-reload) is normative for source/failure semantics. T004 inventories the corrected native baseline; T047 reproduces the actual receiver/finalizer failure before T054 changes cancellation handling. Both the dedicated `AsyncCancelled` handler and broad `SomeException` handler must propagate asynchronous termination; genuine service failures retain reconnect behavior.

T047/T055 register native behavioral cases in their native test runners and the existing `qualification/native/Main.hs` adapter. T015's `qualification/src/oracle.rs` and `qualification/src/main.rs` expose `native-regression --fixture "$FIXTURE"` to invoke those real native cases, recording the resolved source/build/test command and per-case outcomes. The isolated historical exception-loop probe cannot satisfy G2. T058/T059/T094 run the actual node via `node --fixture "$FIXTURE"` for G9; no protocol-only test or successful signal delivery substitutes.

| Scenario | Bound and required evidence |
|---|---|
| G2 awaited receiver cancellation | Exercise blocked service I/O and reconnect delay; each cancellation and resource/key finalization completes within 5 seconds, with zero reconnect attempts after cancellation. Record native failing-before/passing-after outcomes. |
| G9 repeated successful reload | Ten sequential, observed-complete post-initialization reloads for each valid topology: 64 agents, separate mixed file/agent, singleton agent and singleton file. Include unchanged and updated valid credential contents. Alternate blocked-I/O and reconnect-delay cases for agent receivers where applicable; coalesced signals do not count as completed reloads. |
| G9 healthy replacement readiness | With valid period context and healthy sources already available, all healthy replacement workers become usable within 60 seconds of the post-initialization SIGHUP. Awaited receiver cancellations retain the 5-second bound. Record unchanged node PID, old receiver/socket retirement, zero receiver accumulation, file-key catch-up without rewriting files and fresh correctly bound agent bundles. |
| G9 isolated agent outage/return | During explicit reload the unavailable agent replacement may remain keyless, without blocking healthy workers or falling back to a file. On return, obtain a usable fresh bundle within 60 seconds of transport and valid context availability; verify accepted blocks at the fixture's declared leadership opportunities. Ordinary disconnect without reload instead preserves the existing worker's valid key. |
| G2/G9 boundary and failure cases | Exercise early-init not-effective behavior only after the SIGHUP handler is installed; never signal an unprepared process. Preserve T004's exact malformed/missing-file outcomes, reject unsupported sources, and prove future/expired file keys cannot sign outside validity. These cases are not successful reloads. |

The fixture predeclares topology, reload sequence, source state, expected healthy pools, observation points, and leadership windows within G9's unchanged 8-hour budget. Expected valid pools must have observed opportunities before and after the named transitions; missing opportunities/evidence are inconclusive. Hung cancellation, leaked receivers, changed key files, wrong-pool delivery or missed readiness bounds fail. Keep the existing 10-second steady delivery and 60-second recovery gates; these additional reload bounds neither promise zero-gap replacement nor make SIGHUP necessary for automatic rotation. All evidence excludes raw keys and secret-bearing traffic.

### Core and host benchmark execution

T019 registers two Criterion 0.8.2 targets with `harness = false`: `lifecycle` in `crates/kes-core/Cargo.toml`, pointing to `../../benches/lifecycle.rs`, and `host` in root `Cargo.toml`, pointing to `benches/host.rs`. T096 completes real workloads; host journaling/I/O dependencies must not enter the no_std core.

| Target | Required workload scope | Direct measurement command |
|---|---|---|
| `kes-core/lifecycle` | Generation; one-period evolution and valid multi-period catch-up including 31→32; certificate and artifact verification with disposable independently checked inputs | `cargo bench --locked -p kes-core --bench lifecycle -- --save-baseline "$RUN_LABEL"` |
| `pico2-kes-agent/host` | Actual protocol framing at ordinary and maximum valid message sizes; public intent/result journal append with real fsync and restart reconciliation at declared small/near-admission-limit sizes | `cargo bench --locked -p pico2-kes-agent --bench host -- --save-baseline "$RUN_LABEL"` |

`qualification/src/benchmarks.rs`, dispatched by `qualification/src/main.rs`, owns the aggregate command in P0. `BASELINE_REV` identifies a recorded, maintainer-approved first correct implementation, not the initial skeleton. Run both targets in isolated baseline and candidate build locations under identical pinned toolchain, dependency/build flags, CPU/governor, filesystem/mount/device and cache-preparation controls. Record the concrete input sizes, periods, journal occupancy and cleanup strategy before measurement; do not change them between revisions or after failure.

Collect three separately retained runs for each revision and target, with unique `RUN_LABEL` values so results are not overwritten. Each case uses 100 samples, 5-second warmup and 10-second measurement. The runner computes the specified runtime-ratio interval per workload and retains samples, baseline approval/source digest, candidate identity and all verdicts in `evidence/<candidate>/P0/report.json`. It exits nonzero if either target or any required workload is absent, fails, is stale or inconclusive, or the combined 30-minute budget is exceeded. Do not average away a regression across targets. First-baseline approval establishes comparison input; it is not itself evidence of a passing candidate comparison. Demonstrate controlled-regression sensitivity for both target scopes before trusting their readings.


## Activation, scope and release rules

Before trusting a gate, demonstrate that it detects a disposable seeded defect: stale period acceptance, cross-pool substitution, skip-before-release erase, duplicate generation on retry, discard of a now-active generation, bypassed artifact signature/output collision, malformed frame over-allocation, and controlled latency above the threshold. The endurance evaluator must reject a single over-budget sector even when average wear passes, accept exact equality at the 2× bound, and mark missing rating/history/network inputs inconclusive. Model checking must find the corresponding deliberately invalid transition; coverage must expose an unexecuted error path. Remove all seeded defects before measuring the candidate. Pin corpus/operator/model scope before evaluation; do not shrink it after failure.

Every reading binds candidate revision plus dirty-source digest, gate-definition hash/approval, command/tool versions, dependency pins, environment, scope/exclusions, counts, measurements and verdict. Secret-bearing traffic, plaintext KES state and backup credentials must never enter reports. Destructive campaigns require disposable credentials and an explicitly selected isolated fixture. A retained disposable secret reproducer must be replaced by a public/synthetic reproducible case before evidence publication.

Hardware qualification uses full occupancy where the operation permits: generation starts with 64 active/63 staged and one vacant target staged slot; evolution with 64/64; activation/discard/deletion record intentional occupancy changes. Recover before restoring occupancy through supported commands. Do not reset replay history to simplify campaigns.

For each implementation increment, all selected gates apply to the implemented scope; unimplemented scenarios are explicitly pending, never passed. Hardware-dependent acceptance needs actual A2 readings. Before complete product acceptance, all G1–G10/P0/P1 scopes and all SC-001–SC-009 criteria must pass for the same candidate. Missing tooling, hardware, leadership or approval is a blocker, not an exclusion invented after the result.

### U1/U2/I1 oracle refinement

The existing G2/G3/G8/G10 scopes include the [focused commissioning, publication and floor scenarios](../quickstart.md#focused-u1u2i1-validation). G2/G10 exercise the actual CLI/daemon/USB/pin-installation path; G3 models identity commitment, publication atomicity and independent same-network pool floors; G8 cuts first-identity and publication transactions plus reply/confirmation/deletion handoff boundaries. P1 includes additional context-floor/commissioning/deletion writes and unchanged maximum-size/endurance constraints. No new production network or key material is authorized.

Full MCP entries for [SO-002c](https://softwareobservatory.com/sensors/integration-tests/) and [SO-005d](https://softwareobservatory.com/sensors/fault-injection/) were reconsulted for this refinement. Retain actual dependencies, distinguish fixture failure from boundary failure, and record the injected fault and verdict for each invariant. A model or mock cannot establish the physical commissioning or erasure result; only injected boundaries are covered. Sensor applicability and tool selection remain unchanged.

Extend existing sensitivity probes to reject reinitialization of nonblank storage, a changed timestamp for the same publication after reconnect, loss of a terminal deletion timestamp before receipt handoff, and acceptance below a live incarnation's period floor. Also require positive cases for equal-period no-write refresh, independent healthy-pool progress and fresh-incarnation context after verified deletion. All existing campaign counts, deadlines and evidence rules still apply; insufficient execution budget is inconclusive, not permission to omit these paths.

## Approval record

**Current authorization: APPROVED on 2026-10-28.** The physical-cut threshold approval below satisfies the definition-approval prerequisite for T001–T100. The definition above is preserved byte-for-byte as reviewed, including its proposal-time status wording; this dated approval supersedes the prior threshold while retaining all other gates. Approval does not activate gates or establish passing readings.

### Historical approval — superseded for the revised contract

- **Approver:** Project maintainer (the user in this conversation).
- **Date:** 2026-10-27.
- **Authorization:** Explicit confirmation: "quality-gate approved."
- **Scope:** Complete G1–G10/P0/P1 definition, including sensor mappings, measured scopes, thresholds, exclusions, execution budgets, evidence and activation rules, and the referenced five-year/2× endurance policy with monthly extra churn.
- **Definition SHA-256:** `b92299bfabe0a6667f29f28f10a8f762c8d055b22e4af975cfc0279e3468a997`.
- **Definition hash boundary:** SHA-256 of this file's UTF-8 bytes before the `## Approval record` heading, including the blank line immediately preceding it. All gate-definition content must precede this final metadata section; the approval record is excluded to avoid a self-referential digest.
- **Referenced storage-contract SHA-256:** `4de27418123a432b5dc6bb78cb826bd483cc435cfeb56fc689f417b2a9eaf272`, over the complete UTF-8 bytes of `device-storage.md`, including its endurance acceptance policy.
- **Effect at approval:** Authorized only the historical gate/storage bytes identified above, not the later U1/U2/I1 revisions. The renewed approval below governs those revisions. No gate activation or passing candidate reading follows from either approval.

### Prior U1/U2/I1 definition — approved for its recorded bytes

- **Approver:** Project maintainer (the user in this conversation).
- **Date:** 2026-10-27.
- **Authorization:** Explicit confirmation: "quality-gate/storage definition is re-approved."
- **Reviewed definition SHA-256:** `a6cfbb0e4c44b2e911e8ed45b112cf6d1bbf1ecb3e22f1ee546756fb4e8a4f5f`, verified against the proposal before recording approval.
- **Recorded definition SHA-256:** `0bc714f0a5fe5810454ec14a2917ba7aa226da0e7832065df33781bfe0ebdda9`, using the definition boundary above. At that approval, only the opening approval-status paragraph differed from the reviewed digest; normative scopes, oracles, thresholds, budgets and rules were unchanged. This digest does not identify the current verification-contract proposal.
- **Approved storage-contract SHA-256:** `94a1a97f024163dca8f05958617b974a0d96a6c6628237c9203a743d5a8d0a9e`, over the unchanged complete UTF-8 storage contract.
- **Approved scope:** The refined commissioning/publication/per-incarnation contracts and associated G2/G3/G8/G10/P1 oracles. All other sensor mappings, pinned tools, numerical thresholds, budgets, exclusions and endurance policy remain as previously specified.
- **Effect at approval:** Satisfied the definition-approval prerequisite for the U1/U2/I1 definition only. It does not authorize the subsequent verification-contract changes or imply any gate activation or passing reading. Renewed approval of the current definition is required before T001–T100 execution.

### Prior verification-contract definition — superseded for physical-cut threshold

- **Status:** Superseded by the 2026-10-28 physical-cut threshold approval below.
- **Approver:** Project maintainer (the user in this conversation).
- **Date:** 2026-10-27.
- **Authorization:** Explicit confirmation: "approved quality-gate definition."
- **Scope:** Explicit foundation command, actual native cancellation and SIGHUP scenarios with predeclared bounds, and core/host P0 target execution and aggregation. Existing gate budgets, tool/sensor selection, storage/endurance policy and original 10/60-second product targets remain unchanged.
- **Approved definition SHA-256:** `459d6cf02020e7ee7c4249d6b0fa208de9693829f1d1cd56e4603678d48cf85f`, verified against the reviewed proposal and computed over the complete UTF-8 definition preceding `## Approval record` using the boundary above. Recording approval does not change those bytes.
- **Referenced storage-contract SHA-256:** `94a1a97f024163dca8f05958617b974a0d96a6c6628237c9203a743d5a8d0a9e`, unchanged from the prior approved storage bytes.
- **Effect:** The definition-approval prerequisite for T001–T100 is satisfied. T005 must verify this approved definition and the referenced storage digest and bind its manifest to this approval. All other prerequisites remain; no implementation task is marked complete and no gate activation or passing reading is asserted. Further substantive definition changes require renewed approval.

### Attended physical-cut threshold — approved

- **Status:** Approved.
- **Approver:** Project maintainer (the user in this conversation).
- **Date:** 2026-10-28.
- **Authorization:** Explicit confirmation to use 10 attended physical power cuts instead of 1,000 automated cuts and continue software-only qualification, including coverage.
- **Scope:** G8 and SC-002 require 10 attended physical cuts, with each cut point and recovery result recorded. Unattended power automation is not required. Exhaustive software persistent-cut coverage, all other G1–G10/P0/P1 scopes, storage/endurance policy, and the 10/60-second product targets remain unchanged.
- **Approved definition SHA-256:** `000436ef01bb80b4ca0594ecaa0f7ab1d1fafe50c7a0a705af5b0db44b3a03da`, computed over the complete UTF-8 definition preceding `## Approval record` using the boundary above.
- **Referenced storage-contract SHA-256:** `94a1a97f024163dca8f05958617b974a0d96a6c6628237c9203a743d5a8d0a9e`, unchanged from the prior approved storage bytes.
- **Effect:** The reduced attended physical-cut threshold is authorized for qualification. This does not count any cut as executed and does not relax software fault injection, coverage, lifecycle-model, integration, endurance, or same-candidate evidence requirements.

### Production-coverage scope and storage format v2 — approved

- **Status:** Approved.
- **Approver:** Project maintainer (the user in this conversation).
- **Date:** 2026-10-28.
- **Authorization:** Explicit approval of both exact hashes after review of the implemented manual-testing path.
- **Scope:** Coverage percentage thresholds apply to production host/shared crates, not `qualification`, tests, benches, fuzz targets, test support or other qualification-only code. Storage format v2 adds the durable operation-handoff banks, discard-operation recovery identity, terminal deletion recovery record and corresponding `0x308000` allocated-state end. The clean cutover has no format-v1 migration or decoder fallback.
- **Approved definition SHA-256:** `0b386ae30a5e8c116b02be90cfe79029d7cb19a5c38c5ed09a0b1482e13257eb`, computed over the complete UTF-8 definition preceding `## Approval record` using the boundary above.
- **Referenced storage-contract SHA-256:** `3dfe989d2f5ae7726ba1e722cedf7241b01b7a8703a389cdcc8000f8684a0aa4`, over the complete current `device-storage.md` bytes.
- **Effect:** The definition/storage approval prerequisite is satisfied for these exact bytes. It does not supply a physical measurement, execute a cut, activate a pending gate, waive the production coverage threshold or establish an acceptance verdict.

### Application-settings coverage exclusion — approved

- **Status:** Approved.
- **Approver:** Project maintainer (the user in this conversation).
- **Date:** 2026-10-28.
- **Authorization:** Explicit direction that root `src/config.rs` contains application settings and is excluded from code-coverage results.
- **Scope:** G5 omits root `src/config.rs` from measured coverage. No other production source exclusion or percentage-threshold reduction is authorized.
- **Approved definition SHA-256:** `0207d0c9d901c10b6bda77b68775d8062bf703e691163a41881c8b68dc9a5396`, computed over the complete UTF-8 definition preceding `## Approval record` using the boundary above.
- **Referenced storage-contract SHA-256:** `3dfe989d2f5ae7726ba1e722cedf7241b01b7a8703a389cdcc8000f8684a0aa4`, unchanged from the approved storage-format-v2 bytes.
- **Effect:** The exact-byte definition/storage approval prerequisite remains satisfied. The exclusion does not supply execution evidence, waive the 90% threshold for measured production crates or establish a G5 pass.
