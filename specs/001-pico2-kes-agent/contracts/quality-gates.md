# Quality and qualification contract

## Status and evidence boundary

The project maintainer approved this pragmatic scope: make the software work on the actual Pico2 A2 and preserve the specified lifecycle, recovery, interoperability, and operator behavior. Voltage, temperature, endurance, repeated manual power-cut, fixed coverage/mutation/benchmark, and supplied-leadership campaigns are not acceptance requirements.

Evidence MUST identify the exact source candidate. A passing report from another source digest is historical evidence only. Reports MUST contain public outcomes only; plaintext KES state, passphrases, recipient secrets, and raw secret-bearing traffic MUST NOT be retained.

## Required qualification

| Scope | Command or scenario | Pass rule |
|---|---|---|
| Host quality | `cargo fmt --all --check`; workspace tests; workspace Clippy with warnings denied | All commands pass with no ignored required behavior. |
| Firmware | Release build for `thumbv8m.main-none-eabihf`; `qualification hardware` | Production firmware links within the fitted flash/RAM geometry and reports the production USB identity. |
| Lifecycle and recovery | `cargo test --locked -p kes-core --test recovery` | Deterministic transaction cuts, retry/reboot behavior, cleanup, activation/discard ordering, and pool isolation pass. |
| Capacity and isolation | `cargo run --locked -p qualification -- load` | 64 active plus 64 staged generations work; a 65th enrollment and stalled/malformed clients do not disturb healthy pools; requests remain within 10 seconds and recovery within 60 seconds. |
| Protocol robustness | Bounded runs of every registered fuzz target | USB, management, node-service, certificate, and artifact inputs cause no crash, unbounded allocation, or invariant failure. |
| Restore interoperability | `cargo test --locked --test backup_restore` | The recovered conventional key is exact; tampered, wrong-recipient, and identity-mismatched inputs publish no output. |
| Native compatibility | `cargo run --locked -p qualification -- native-regression` | The pinned cardano-node source builds and the exact node-service protocol regressions pass. Live SIGHUP and accepted-block campaigns are optional. |
| Operator path | Staged or production install smoke; `operator_cli` and `host_security` tests | Installed binaries/configuration work, CLI exit classes and durable reconciliation are correct, and normal CLI operation never opens USB directly. |
| Device path | Production USB reset or ordinary power cycle, followed by daemon/CLI status | The same pinned device identity reconnects and returns ready without re-enrollment or state reconstruction. |

The foundation runner remains a useful bounded codec and memory-protection smoke. It MAY be run with `cargo run --locked -p qualification -- foundation`; it is not a substitute for the device, native, or operator checks above.

## Optional diagnostics

Coverage, mutation testing, microbenchmarks, live SIGHUP campaigns, peer-accepted blocks, repeated physical cuts, and environmental/endurance measurements MAY be run when useful. Their absence does not block acceptance. They MUST NOT be represented as required work in task plans or operator instructions.

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
