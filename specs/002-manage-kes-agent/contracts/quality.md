# Quality definition for p2kesup

## Acceptance policy

End-user testing of the actual packaged tool is the primary quality gate for this feature. The maintainer explicitly requested this scope on 2026-11-02: no high-code-coverage requirement and no over-engineered unit/integration testing program. This supersedes the earlier feature-specific coverage, mutation, property-testing, fuzz-campaign and separate microbenchmark requirements, not the constitutional performance gate below. Scope approval is not a passing implementation or hardware result.

There is **no code-coverage target, minimum percentage, changed-line coverage gate or mandatory coverage report**. Do not create a dedicated manager unit/integration/property suite, new fuzz target, mutation campaign or benchmark executable just to satisfy this plan. Existing repository checks remain in place; this feature does not remove or weaken tests protecting the shared daemon, protocol, firmware, backup or release tools.

New nontrivial logic still needs a small behavioral test or assert-based self-check, preferably using an existing test location. Concentrate these checks on concrete risks such as accepting an unauthenticated artifact, overwriting external files, publishing a key on invalid evidence, or resubmitting an uncertain operation. No test-count target, test pyramid, broad mock framework or rendering snapshot suite. An end-user scenario can provide the executable check for orchestration already protected by existing tools; it need not be duplicated in a new automated suite.

## Required end-user acceptance

Run [quickstart Q1–Q11](../quickstart.md) against the candidate packaged `p2kesup`, real local services and the applicable disposable devices/backup host. These scenarios are the acceptance procedure, not a specification for eleven automated suites.

- Exercise installation/reopening, prerequisites, partial installations, complete inventory, configuration/service actions, every lifecycle operation, release selection, compatible upgrade/downgrade, offline use and uninstall.
- Include refusal, cancellation and interrupted-operation paths: altered/untrusted releases, unknown compatibility, wrong device, stale target, denied permissions, output collisions and original-operation reconciliation. Successful happy paths alone do not establish safe maintenance.
- Observe keyboard-only/no-color navigation, resize, diagnostics and terminal restoration after foreground handoffs. Use the fixed five-person eligibility and evaluation rules in [SC-003](../spec.md#measurable-outcomes); at least four participants must each complete all three actions using only the manager and linked instructions.
- Measure SC-002 directly during Q1/Q3: overview within 5 seconds, all responsive 64 pools within 10 seconds, loss visible within 10 seconds. Use the actual 64-active/64-staged workload where applicable, not a smaller substitute. Record elapsed times and the environment; no new microbenchmark or statistical regression platform is required.
- Verify preserved configuration, permissions, identities, pool/generation state and original receipts across host/device maintenance. Explain legitimate forward lifecycle transitions; do not accept unexplained loss.
- Backup acceptance uses the isolated host and the existing evidence/memory/output rules. OTP and firmware acceptance use the existing qualified physical procedure; end-user confidence or a simulation does not replace required physical evidence.
- Producer hardening remains file installation plus actual requested systemd command results. No dedicated suite, multi-producer fixture, runtime-policy audit or changed preflight.

Record candidate commit/build and dirty-source digest if applicable, supported host/device configuration, exact command or UI scenario, expected and observed result, elapsed time where required, and public error/receipt evidence under `evidence/`. Record all failures or unavailable prerequisites explicitly; do not mark an unrun scenario passed. A short scenario report is sufficient—no new reporting framework. Never retain secret keys, passphrases, restored output contents or raw secret-bearing traffic.

### Inherited release qualification

Before T070 promotes a complete component tuple, link candidate-applicable evidence for the
[feature-001 qualification gates](../../001-pico2-kes-agent/contracts/quality-gates.md) under
[constitution 2.0.0, Principle II](../../../.specify/memory/constitution.md#ii-verifiable-behavior):
deterministic fault injection at every modeled persistent transition boundary; one ordinary
complete host/device power-loss recovery smoke on the identified Pico2 A2 and fitted storage,
preserving pin and acknowledged state with cleanup/catch-up before delivery; the specified
64-active/64-staged workload; pinned native-node build/protocol regressions; and
[backup fidelity](../../001-pico2-kes-agent/contracts/backup.md) against disposable generation-time
state with an independent standard-format decoder. A USB reset alone does not satisfy the
power-loss smoke. Retain the qualified storage, firmware and OTP evidence required by the selected
operations. Missing, failed, stale or inapplicable required evidence blocks promotion.

These are external qualification checks, not node functionality added to `p2kesup`. Reference
existing reports only when their source/payload, configuration, hardware/tool and measured scope
remain applicable; record that assessment and rerun invalidated checks. Repeated physical-cut,
live SIGHUP and accepted-block campaigns are optional; list unrun campaigns as unverified rather
than implying physical durability or live forging was measured.

## Required project performance gate

This is a planned project gate, not an invented Software Observatory sensor. Before evaluating a candidate, the maintainer must approve and record its baseline revision and build identity, workload, thresholds, exclusions, environment and measurement tools. For the first manager release, select an explicit existing comparable implementation/revision that performs the same Q1/Q3 observations; an absent manager or missing observation is not a zero-time baseline, and the candidate cannot be its own baseline. If no comparable implementation exists, establish and freeze a separate initial comparable baseline before candidate comparison; until then the gate is inactive and acceptance is blocked. Do not select or revise the baseline or thresholds to accommodate a candidate result.

Use the packaged baseline and candidate on the same otherwise idle host, OS/kernel, terminal dimensions, daemon/device configuration, 64 disposable pools with 64 active and 64 staged generations, and same service state, permissions and connectivity. Record these identities, CPU, memory, power policy, terminal, package/build identities, and any background activity; use identical setup and operator actions for each run. Record Rust/Cargo 1.99.1 from `qualification/tools.toml`, locked dependencies and exact installed package versions. Use a monotonic elapsed-time instrument with at least 0.1-second resolution; record and preapprove its identity and version with the environment. The supported actual device and real local services are required for Q1/Q3; host fixtures cannot stand in for them.

1. Build or obtain both packages under their recorded identities, perform one unrecorded warmup of each, then collect five baseline/candidate pairs, alternating order AB, BA, AB, BA, AB. Reopen the manager with an empty in-process observation cache and the same non-destructive starting state before every run; never restore device/journal snapshots. An observer uses the approved monotonic stopwatch to time visible events while the operator performs the same actions; record numeric readings and public event descriptions only, not terminal recordings. Start both initial clocks at the keypress launching `p2kesup`: stop the overview clock when local overview is populated and the pool clock when all 64 responsive pools and both generations are inspectable, navigating promptly without resetting the clock. For loss, start at controlled disconnect/access denial and stop when affected values visibly become stale/unavailable. Record each elapsed time to 0.1 seconds and correctness using identical boundaries for both builds. Timing the whole interactive process or starting after cached data loads is not a measurement of these events.
2. Each candidate sample must satisfy SC-002: overview ≤5 seconds, all responsive pools ≤10 seconds, and loss visible ≤10 seconds. Incorrect, missing, or unexercised observations fail; an unavailable prerequisite, interruption, timer failure or timeout gives an inconclusive reading, not a pass. Allow at most 30 minutes for the five pairs after setup and warmup; do not silently discard outliers or retry until green.
3. For each metric separately, compute each build's median of five samples and its range (maximum minus minimum). If either range exceeds 0.5 seconds, the comparison is inconclusive. Otherwise let `delta = candidate median - baseline median`, regression limit `L = max(0.5 seconds, 20% of baseline median)`, and uncertainty `U = 0.25 seconds`. A regression fails if `delta - U > L`; it passes if `delta + U ≤ L`; otherwise it is inconclusive. All three comparisons and all candidate absolute limits must pass. A failed or inconclusive comparison blocks acceptance; report absolute-limit failures even when a comparison is inconclusive.
4. Before trusting readings, demonstrate sensitivity once for the approved environment and tooling: on a disposable non-production copy of the comparable baseline, temporarily insert a 2-second delay on the actual Overview completion path before the result is displayed, rebuild with the same pinned Cargo toolchain, and run the same five paired Q1 measurements against the unmodified baseline. The regression comparison in step 3 must fail specifically for Overview, not merely trip the absolute limit. Record the exact temporary change, build identities and readings, then remove the slowdown; never distribute or use that altered build as the candidate. If the detection is not observed, the gate is not active. Re-exercise calibration when the measurement path, tools or approved environment changes.

Run `cargo run --locked -p qualification -- load` as supporting capacity/client-isolation evidence, not as a measurement of the TUI: its existing `evidence/<revision>-<dirty-sha256>/load/report.json` records host-model checks and their elapsed command times, including test execution overhead. The existing runner has a 120-second limit per check and CI a 30-minute job limit; empty or failed checks are not evidence of a passing workload. Its fixtures are not proof of device durability, capacity or node interoperability. The actual Q1/Q3 measurement and existing physical qualification remain independent required gates.

Retain the approval, baseline/candidate and calibration identities, commands/UI actions, instrument version, setup and exclusions, all samples, calculations, correctness observations, verdicts and reason for any unavailable or inconclusive result in `evidence/p2kesup/<candidate>/performance.md`, with baseline identity recorded inside. Link the supporting load report and relevant physical evidence without copying secrets. Activation requires an approved baseline, environment and pinned/configured tools plus an exercised passing sensitivity demonstration; this document supplies no measured result or claim of activation.

## Existing developer checks

Run these existing checks once after integrated changes, not after each edit:

```sh
cargo fmt --all --check
cargo check --locked
cargo test --locked --workspace --exclude pico2-kes-firmware
cargo clippy --locked --workspace --exclude pico2-kes-firmware --all-targets -- -D warnings
cargo audit
cargo deny check
python3 -I -m unittest discover -s tools/tests
```

If core/protocol/firmware changes are needed for observations, keep their existing checks and update affected consumers/fixtures together:

```sh
cargo check --locked -p kes-core --no-default-features
cargo check --locked -p kes-protocol --no-default-features
cargo check --locked -p pico2-kes-firmware --target thumbv8m.main-none-eabihf
cargo build --locked --release -p pico2-kes-firmware --target thumbv8m.main-none-eabihf
cargo clippy --locked -p pico2-kes-firmware --target thumbv8m.main-none-eabihf -- -D warnings
cargo run --locked -p qualification -- load
```

Use the existing Rust/Cargo 1.99.1 toolchain and repository dependency/tool pins; no additional coverage/mutation/property/benchmark tools are required for this feature. Existing CI jobs are not removed. Updating an existing fuzz consumer to compile against a changed public enum is interface maintenance, not a requirement for a new fuzzing program. Linked firmware must still fit its target and work on the accepted hardware; an all-green host suite is not hardware proof.

## Software Observatory applicability

The constitution requires explicit sensor selection and valid readings for selected required checks; it does not specify a high code-coverage percentage or mandate a separate automated suite per feature. Full entries for the following sensors were reconsulted for this revised scope:

| Sensor | Required reading | Pass rule and execution limit | Limitation |
|---|---|---|---|
| [SO-002b — Example-Based Tests](https://softwareobservatory.com/sensors/example-based-tests/) | Existing Cargo/Python commands above and small checks for newly introduced logic | Assert intended results; no failed or skipped required behavior. Existing CI limits apply (30-minute host job); harness failure/timeout is no reading. | Examples do not prove unexercised behavior. |
| [SO-002c — Integration Tests](https://softwareobservatory.com/sensors/integration-tests/) | Operator-executed Q1–Q11 through `p2kesup` and its actual dependencies | Observed outcome matches the scenario; complete the existing finite scenario set, record duration, and stop on failure. Physical prompts retain their procedure's limits. | This sensor labels the real end-to-end exercise; it does not require a new automated integration suite. |
| [SO-006e — Load Testing](https://softwareobservatory.com/sensors/load-testing/) | Q3 measured at 64 pools/128 generations; existing `qualification -- load` when shared service/core changes | SC-002 timing and healthy-pool behavior pass; existing runner has a 30-minute job limit. Empty, smaller or unmeasured workload is not a pass. | Synthetic/model results do not replace the actual TUI/device observation. Full entry reconsulted for the performance gate; its generated-traffic limitations and threshold choice apply. |

Retain tool/build versions and scenario conditions with readings. Wrong-input/disconnect/interruption cases exercise rejection behavior; passing them alone does not demonstrate that the tools detect an implementation defect. Complete the behavioral calibration below before trusting those readings; the controlled slowdown above separately calibrates performance measurement. Missing, failed, stale or inconclusive required readings still block acceptance. The maintainer's scope decision is made before candidate evaluation, not an excuse to hide a known failure.

### Behavioral tool calibration

T001 approves the defect, affected invariant, exact commands/scenario, tool versions, environment, budget and expected failure before evaluation. T067 records the demonstration in `evidence/p2kesup/<candidate>/behavioral-calibration.md`; T070 checks its applicability before accepting readings. This is a bounded check of the selected tooling, not a mutation score, campaign or new framework.

1. Use T016's deterministic `manager::observe::tests::stale_after_observation_failure` check and Q3's disconnect/denied-access observation. Run `cargo test --locked --lib manager::observe::tests::stale_after_observation_failure -- --exact`, requiring exactly one executed, passing test, and the corresponding packaged Q3 scenario on the supported disposable setup. Record the correct fresh-to-stale/unavailable transition within 10 seconds without changing the retained last-success evidence.
2. In a separate disposable source/build copy, change only the failed-observation handling so it incorrectly retains `fresh` status after access is lost. Keep tests, expected outcomes and scenario instructions unchanged. Rebuild with the same pinned toolchain and rerun the exact check and Q3 observation against that build. The assertion must fail on the stale-state invariant, and the operator must record Q3 as failed for the falsely fresh display. A build error, timeout, unrelated failure or zero selected tests is not defect detection. Never deploy this build to production or include it in release promotion.
3. Remove the temporary defect, rebuild and repeat both checks; both must pass. Allow at most 30 minutes per build and 30 minutes for the three observation/test runs after setup, stopping with an explicit blocked result on timeout. Retain original/defective/restored source and build identities, the temporary diff, exact commands, tool/environment identities, expected/observed results and the assertion/scenario failure. Confirm the release candidate contains no calibration defect.
4. Link existing passing defect-detection evidence for other behavioral runners used by the gate, including the Python test runner. If none is applicable, approve and perform an analogous single known-defect demonstration with an existing affected check under the same bounds. Only claim calibration for the runners and observation paths actually exercised; invalid-input rejection alone is insufficient.
5. Previously retained calibration may be reused only when T067 records why its runner/version, assertion or observation path, invariant and environment remain applicable. Changed tooling or detection paths require recalibration. Missing evidence, an undetected defect or a failed restored check blocks acceptance; do not weaken the expected result. The deliberately defective run is calibration evidence, never a passing candidate reading.

### Exclusions and retained obligations

- **SO-003c line coverage / SO-003 mutation testing:** no report, score or campaign gate. For this user-focused orchestration surface, direct workflow outcomes and targeted safety checks are the chosen evidence; a percentage is not an acceptance criterion.
- **SO-005e property-based testing:** no new generated campaign or `manager_properties` suite. Reuse existing shared-core properties where relevant; use small explicit boundary cases for new arithmetic/selection logic.
- **SO-005 fuzzing:** no new `release_manifest` target or mandatory feature-specific campaign. Retain existing parser/CI protections; exercise malformed and untrusted input refusal in the scoped checks and operator scenarios.
- **Reproducible performance benchmarks:** the bounded Q1/Q3 project gate above measures regressions and exercises one controlled slowdown; no `benches/manager.rs`, new benchmark executable, benchmark framework or elaborate sampling campaign is required.
- **SO-014 static security analysis:** no new analyzer/ruleset. Existing dependency checks and explicit review of input-to-command/path/privilege/terminal boundaries remain; do not label them a SAST pass.

Selected families are behavioral and runtime. Structural, invariants, adversarial, test-effectiveness, change, architecture, evolution and comprehension are not fully represented by selected catalog sensors. Existing compiler/linter checks, safety review, negative scenarios and operator testing address some of these risks without claiming exhaustive analysis. Manual testing can miss rare combinations and timing races; small checks for new critical logic and retained shared-component regressions are the backstop, not a high-coverage program.

The separately approved constitution 2.0.0 amendment and synchronized feature-001 guidance govern inherited qualification above. This prospective feature selection does not waive a failed required reading or cryptographic validation, key custody, data preservation, accessibility, qualified storage/OTP checks, or the required physical power-loss smoke. Principle VI's sensor and performance obligations remain unchanged.
