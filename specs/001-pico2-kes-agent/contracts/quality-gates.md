# Quality and qualification contract

## Status and evidence boundary

The project maintainer approved this pragmatic scope: make the software work on the actual Pico2 A2 and preserve the specified lifecycle, recovery, interoperability, and operator behavior. Voltage, temperature, endurance, repeated manual power-cut, fixed coverage/mutation/benchmark, and supplied-leadership campaigns are not acceptance requirements.

Evidence MUST identify the exact source candidate. A passing report from another source digest is historical evidence only. Reports MUST contain public outcomes only; operational or device-generated KES state, passphrases, recipient secrets, and raw secret-bearing traffic MUST NOT be retained. Only the generator's deliberately public synthetic seeds/states MAY be committed as compatibility fixtures, labelled `PUBLIC SYNTHETIC TEST KEYS - NEVER USE FOR FUNDS`; real keys, random qualification secrets, credentials, and secret-bearing evidence remain prohibited.

## Required qualification

| Scope | Command or scenario | Pass rule |
|---|---|---|
| Host quality | `cargo fmt --all --check`; workspace tests; workspace Clippy with warnings denied | All commands pass with no ignored required behavior. |
| Firmware | Release build for `thumbv8m.main-none-eabihf`; `qualification hardware` | Production firmware links within the fitted flash/RAM geometry and reports the production USB identity. |
| Lifecycle and recovery | `cargo test --locked -p kes-core --test recovery` | Deterministic fault injection exercises every modeled persistent transition boundary; retry/reboot behavior, cleanup, activation/discard ordering, and pool isolation pass without acknowledged/released rollback or ambiguous state served. |
| Capacity and isolation | `cargo run --locked -p qualification -- load` | 64 active plus 64 staged generations work; a 65th enrollment and stalled/malformed clients do not disturb healthy pools; requests remain within 10 seconds and recovery within 60 seconds. |
| Protocol robustness | Bounded runs of every registered fuzz target | USB, management, node-service, certificate, and artifact inputs cause no crash, unbounded allocation, or invariant failure. |
| Restore interoperability | `cargo test --locked --test backup_restore` | The recovered conventional key is exact; tampered, wrong-recipient, and identity-mismatched inputs publish no output. |
| Cardano compatibility vectors | `cargo test --locked -p kes-core --features qualification --test crypto_compatibility`; `cargo test --locked --test backup_restore`; `cargo test --locked --test node_service` | Current-candidate results pass all 64 Haskell-derived state/signature/key periods, certificate identity/signature/counter cases, the real restored envelope comparison, and existing V2 protocol regressions. Four feature-enabled crypto tests MUST execute; zero selected tests is not evidence. |
| Operator path | Staged or production install smoke; `operator_cli` and `host_security` tests | Installed binaries/configuration work, CLI exit classes and durable reconciliation are correct, and normal CLI operation never opens USB directly. |
| Device path | One ordinary complete host/device power-loss recovery smoke on the accepted Pico2 A2 with identified fitted storage, followed by daemon/CLI status and recovered-generation use | The same pinned device identity reconnects and returns ready without re-enrollment or state reconstruction; the certified generation, verification key and certificate are preserved and valid signing succeeds. USB reset alone is not a substitute. |

The foundation runner remains a useful bounded codec and memory-protection smoke. It MAY be run with `cargo run --locked -p qualification -- foundation`; it is not a substitute for the device, feature-enabled crypto, or operator checks above.

### Compatibility evidence scope

PRs and unsigned release builds MUST run the fixed reference comparisons on GitHub-hosted runners. External node builds and live Haskell comparisons are not mandatory for PRs or releases. Maintainers regenerate the corpus only when reference versions, formats, or vector cases deliberately change, using the pinned generator and validation commands in [quickstart](../quickstart.md#maintainer-only-vector-regeneration). Generation is outside candidate CI and never refreshes expectations from Rust output; a mismatch must be resolved against the governing format/reference, not overwritten to make a candidate pass.

| Sensor | Command, oracle and pass rule | Budget and evidence | Limitation |
|---|---|---|---|
| SO-002b — Example-Based Tests | The compatibility commands above, with Rust/Cargo 1.99.1 and locked dependencies, compare the actual Rust core and production restore output to the pinned Haskell-derived corpus; all assertions and existing node-service regressions pass. | Existing hosted host job: 30 minutes; unsigned release build: 40 minutes. Retain current-candidate command/test outcomes and CI logs. Missing, failed, empty or timed-out results block acceptance. | One seed/message across all 64 periods plus four certificates and one envelope is bounded regression evidence, not a live cross-language campaign or proof over all inputs. |
| SO-005c — Differential Testing | Maintainer-only generation uses GHC 9.12.4, cabal-install 3.16.1.0 and `qualification/native/pins.json`; independent Haskell operations, native verification/decoding self-checks and identical repeated output establish reference bytes for comparison. | One finite 64-period/four-certificate/envelope corpus per deliberate regeneration; stop on any tool, pin or self-check failure. Retain the generator/config/pins, public fixture and regeneration outcome, not a machine-specific build plan in the fixture. | Offline independent reference generation supplies the differential reference; each candidate's fixed-input comparisons are SO-002b evidence, not a fresh SO-005c campaign. |

These vectors do not test native receiver cancellation, bulk loading, live forging, device behavior, or complete Service V2 serialization. Existing Rust `node_service` tests remain required. Actual future changes in external node/consensus integration repositories still require their native builds/tests and interoperability evidence; this migration does not waive those checks.

## Optional diagnostics

Coverage, mutation testing, microbenchmarks, live SIGHUP campaigns, peer-accepted blocks, repeated physical cuts, and environmental/endurance measurements MAY be run when useful. Their absence does not block this feature's acceptance, and they MUST NOT be represented as required feature-001 campaigns. This local diagnostic scope does not waive separately applicable constitutional or feature-specific gates, including the manager's bounded performance comparison and calibration.

## Evidence and release rules

- Qualification runners MUST fail rather than manufacture a pass when a required command or prerequisite is unavailable.
- Software tests MUST assert consumer-visible behavior and invariants, not copied values, source wording, or mock echoes.
- The fitted-device smoke MUST preserve the enrolled state partition; qualification MUST NOT add a production plaintext-export or reset command.
- Full-capacity tests use disposable software fixtures. Any destructive network exercise uses disposable credentials and an isolated network.
- Acceptance requires one current-candidate passing result for every required row above. Optional diagnostics do not compensate for a required failure.

## Approval record

- **Status:** Approved.
- **Date:** 2026-10-28.
- **Approver:** Project maintainer (the user in this conversation).
- **Authorization:** Remove over-detailed qualification requirements and continue making the software work on the device.
- **Approved definition SHA-256:** `f6d0e7962bad19bb142afb22251c63a0aba41ba2dda7cc63a9db71f2f26493ce`.
- **Referenced storage-contract SHA-256:** `2e8f615650cbd09f156827a4716e1411df25c91aff4f87e10ec324b34ede93c7`.
- **Effect:** Functional software/device evidence remains required; voltage/temperature/endurance labs, repeated attended cuts, fixed coverage/mutation/benchmark thresholds, and supplied-leadership/accepted-block campaigns are excluded.
- **Storage-linkage amendment:** The approved secure Pico2 provisioning/update plan adds signed firmware-only ranges, the read-only security report and explicitly attended OTP conversion. This updates the storage-contract linkage without promoting existing hardware evidence to secure-boot qualification.

### Storage-linkage amendment — 2026-10-31

- **Approver:** Project maintainer (approval of the KES bugs and simplification execution plan).
- **Referenced storage-contract SHA-256:** `9b0616cbd3e3ef3e5ee5e82f276e61e83df38faa6653a1c1fd45fea96ba6862b`, verified against the complete unchanged UTF-8 storage contract.
- **Scope:** Rebind the reviewed storage contract, including its existing public Context diagnostic evidence requirements. The required qualification definition and its SHA-256 remain unchanged; the historical approval above remains intact.
- **Evidence boundary:** This linkage is authorization, not a qualification pass, firmware attestation, or closure of the original advancing-Context incident.

### Acceptance-baseline amendment — 2026-11-02

- **Approver:** Project maintainer (the user in this conversation).
- **Scope:** Require deterministic fault injection at every modeled persistent transition and one ordinary complete host/device power-loss recovery smoke on the accepted Pico2 A2 with identified fitted storage; USB reset alone does not satisfy it. Keep the specified 64-pool workload and pinned native build and protocol regressions required. Repeated physical cuts and live SIGHUP/accepted-block campaigns remain optional.
- **Evidence boundary:** This amendment changes the qualification definition, not the historical approval hashes or measured results; current-candidate evidence must independently satisfy the amended requirements.

### Hosted compatibility-vector amendment — 2026-11-17

- **Status:** Approved.
- **Date:** 2026-11-17.
- **Approver:** Project maintainer (approval of the hosted KES compatibility-vector execution plan).
- **Scope:** Replace mandatory per-candidate native builds/live decoding with fixed Haskell-generated public vectors, feature-enabled Rust comparisons, real restored-envelope comparison and existing V2 regressions on hosted PR/release jobs, under constitution 3.0.0.
- **Evidence boundary:** SO-002b labels candidate regression results; SO-005c labels offline independent reference generation. One seed/message is not a live differential campaign, native receiver/bulk integration test, hardware result or full-input proof. No failed crypto check or production secret protection is waived.
- **Approved definition SHA-256:** `a16b157e5b3cb32df0697cfe7029448688d1a91065c4296d278982692e1adecb`, over the UTF-8 bytes preceding the first `## Approval record`.
- **Referenced storage-contract SHA-256:** `9b0616cbd3e3ef3e5ee5e82f276e61e83df38faa6653a1c1fd45fea96ba6862b` (unchanged).
