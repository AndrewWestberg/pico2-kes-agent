# Implementation Plan: Pico2 KES Agent Management TUI

**Feature identifier returned by setup**: `002-manage-kes-agent` | **Actual Git branch**: `feature` | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

**Input**: `specs/002-manage-kes-agent/spec.md`.

**Status**: Phase 0 research and Phase 1 design complete. Proposed design, not implementation approval, an installed manager, signed release publication or hardware qualification. `setup-plan.sh --json` returned BRANCH=`002-manage-kes-agent`; `git branch --show-current` returned `feature`. No branch was created or changed.

## Summary

Add a persistent Rust terminal manager installed by one authenticated shell bootstrap, with complete local inventory, guided setup, version selection/upgrade/downgrade, existing pool/KES lifecycle operations, service/configuration/diagnostics/uninstall, separate backup-host use, optional attended OTP and the narrowly scoped producer drop-in action. Support x86-64 Debian 12 and Ubuntu 24.04 release targets without a source checkout or user build.

Reuse the existing daemon's USB ownership, management socket, CLI receipts, strict public input validation, backup custody and foreground firmware tooling. Add bounded public observations for missing firmware/build and certificate/context details. Publish signed host distribution metadata around unchanged firmware bundles, separating exact compatibility authorization from candidate/qualified release status. First-install firmware before commissioning when no application exists; preserve stricter pinned pre/post checks for updates. Immutable component directories, one atomic selected-tuple pointer and public maintenance checkpoints preserve installed/running distinctions and uncertain results. No node discovery/connection/management outside the supplied drop-in/reload/approved-restart exception.

## Technical Context

**Language/Version**: Rust 1.99.1 / edition 2024, existing Python 3 firmware/publication tools and POSIX shell bootstrap. Firmware remains Rust for RP2350 A2, `thumbv8m.main-none-eabihf`.

**Primary Dependencies**: Existing serde 1.0.228, serde_json 1.0.145, rustix 1.1.5, protocol/core/client/receipt/file helpers. Pinned Ratatui 0.30.2 (`default-features = false`, Crossterm backend only) and Crossterm 0.29.0 for actual widgets/events; no async framework. The maintainer approved revising Ratatui from 0.29.0 after its dependency gate failed, then aligning Crossterm with the actual backend during T002; see the quickstart dependency review. Trusted OS GPG/GPGV/OpenSSL/Python for release verification and firmware tooling; authenticated patched picotool 2.3.1 for admitted device workflows. Resolve/audit lockfile and dependency maintenance/licenses before implementation adoption.

**Storage**: Existing public config/journal/receipts and device storage unchanged. New bounded JSON installation/maintenance records, immutable host artifacts and XDG metadata cache. No database or primary plaintext-key storage. Firmware state `[0x10100000,0x10308000)` never appears in update payloads.

**Testing**: End-user acceptance through the actual packaged `p2kesup` workflows is primary. Keep existing Cargo/Python checks and affected shared-component regressions, with small behavioral checks for new critical logic. No code-coverage target/report, dedicated new manager unit/integration/property suite, mutation campaign, new fuzz target or microbenchmark framework is required. Before trusting behavioral readings, demonstrate bounded known-defect detection and restored passing behavior, or record applicable retained calibration evidence. The separate bounded performance gate reuses Q1/Q3 and existing Cargo tooling with an approved baseline, controlled environment, noise-aware comparison and demonstrated slowdown sensitivity. See [quality contract](contracts/quality.md); absent baseline/tool/calibration evidence blocks gate activation, not feature design.

**Target Platform**: First qualified host releases target Debian 12 and Ubuntu 24.04 x86-64, glibc ≥2.36, systemd/udev. Other hosts clearly unsupported for installation; local diagnostics remain best effort/read-only. One local installation/device per session; backup role local-only and device-free. No new supported CPU or device stepping is implied.

**Project Type**: Existing Rust embedded/service/CLI workspace plus one terminal executable and source-free signed distribution.

**Performance Goals**: Local overview ≤5 seconds, all responsive 64 pools inspectable ≤10 seconds, lost access visible ≤10 seconds. Local UI never waits on release-network discovery. Existing daemon healthy-pool delivery/isolation remains unaffected by monitoring.

**Constraints**: One daemon owns USB; 64 active +64 staged generations; management frames ≤16,384 bytes and USB payloads ≤4,096 bytes; no per-pool credentials/new socket role. Exact identities/revisions/receipts; no unknown-compatibility update, erasure, period/state rollback, private recipient on primary, or fabricated health. All mutation is deliberate, target-bound and retains original uncertainty. Producer workflow intentionally has no new runtime-policy audit or dedicated suite.

**Scale/Scope**: Eight user stories, FR-001–FR-029, SC-001–SC-012. One terminal event thread, bounded local observation worker and independent bounded release worker; single management request outstanding, refreshes coalesced. Up to 64 entries per device/configured/effective source, up to 128 live device generations; joins display every unmatched source identity rather than evicting entries. Foreground secret/OTP children inherit the terminal, not a captured log.

## Constitution Check

**Pre-research gate: PASS for scoped design work.** Read the feature specification and constitution before choosing changes. Existing lifecycle/custody/authorization/storage boundaries are retained. Research unknowns were UI dependency choice, observation gaps, source-free release trust/ABI, ownership/compatibility, handoffs and quality tooling; all are resolved in [research](research.md). No code or qualification claim is made.

**Post-design gate: refined after analysis; implementation/release acceptance is NOT passed.** Operator-led acceptance and the no-high-coverage/no-new-framework scope remain. The quality definition retains the constitution's performance-gate obligations rather than treating timed happy paths as a regression measurement. Candidate admission and factory first installation are explicit. T001 must record approval of the concrete baseline/environment/tool definition before evaluation; required readings and physical qualification cannot be inferred from this plan.

| Principle | Design decision / check | Acceptance gate |
|---|---|---|
| I — Scope/correctness | Full FR/SC traceability; explicit unknown/stale/uncertain states; no node integration beyond exception | Every scenario exercised; missing result never represented as success |
| II — Verifiable behavior | Real executable/terminal, VM/systemd, device and isolated backup scenarios; no host test presented as physical proof | Actual 64-pool and SC-003 cohort evidence; T070 also requires the inherited qualification evidence defined in the quality contract under constitution 2.0.0 |
| III — Stable interfaces | New additive read actions/USB kinds; old mutation/storage/node/backup bytes unchanged; exact schema/error/migration contracts | All repository parsers/callers/fixtures/docs updated together; incompatible combinations blocked |
| IV — Trust/custody | Independently authenticated bootstrap and manifests; protected privilege boundary; pin/receipt preservation; off-primary secrets | Operator-exercised rejection paths, small checks for new critical logic, secret-output review and qualified physical handoffs; no attestation/fencing claim |
| V — Simplicity/bounds | Existing package/tools; two justified TUI crates, no database/runtime engine; bounded pages/queues/files | Host/firmware build/resource checks and actual full-capacity user exercise |
| VI — Observatory | Applicable full entries reconsulted; risk-based selection and exclusions recorded; bounded project performance gate | Existing behavioral/user-scenario readings plus approved baseline, controlled measurement, noise-aware regression rule and sensitivity evidence; no coverage percentage or new framework |
| Technical/workflow | Rust/sole USB owner/forward KES/storage/capacity preserved; no operational reset or cold-key handling | Review and target smoke; unsupported platform/dependency fails explicitly |

**Governance decision:** The constitution requires valid selected sensor readings and configured/exercised benchmark tooling, but not a high code-coverage percentage or a new automated suite for every feature. The [quality definition](contracts/quality.md) retains the bounded SC-002 workload comparison and calibration while excluding elaborate feature-specific coverage/mutation/property/fuzz/microbenchmark campaigns. The separately approved constitution 2.0.0 amendment aligns recovery/native qualification with the pragmatic feature-001 baseline; T070 verifies that inherited evidence before promotion. Existing shared-component checks, security requirements and qualified storage/OTP checks remain. No subordinate scope decision waives a constitutional MUST or a missing, failed or inconclusive reading.

## Project Structure

### Documentation (this feature)

```text
specs/002-manage-kes-agent/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
    ├── manager.md
    ├── observations.md
    ├── distribution.md
    └── quality.md
```

`tasks.md` belongs to Phase 2 and is not generated by this command.

### Source Code (repository root)

Proposed additions are marked; existing modules retain their roles.

```text
Cargo.toml / Cargo.lock             # manager binary and reviewed terminal dependencies
src/bin/p2kesup.rs                  # new terminal entrypoint
src/manager/                       # new UI, observation, release/host-action orchestration
src/bin/pico2-kes-agent{d,-cli}.rs  # existing executable version interfaces
src/cli/                           # existing lifecycle/client/receipt; new read commands
src/daemon/                        # sole USB owner; bounded observations/running build
src/config.rs / src/files.rs        # existing validation and protected file primitives
src/backup/ / src/memory.rs         # unchanged custody/crypto authorities
crates/kes-protocol/                # additive bounded management and USB observations
crates/kes-core/                    # public lifecycle observation accessors only
firmware/                          # observation dispatch/build metadata; no storage migration
install.sh                         # new authenticated source-free bootstrap
 deploy/                           # existing service/udev/install/remove assets; bundle cutover
 tools/firmware.py                  # reuse verification/OTP, add attended normal update
 tools/publish_release.py           # extend publication to signed host distribution
 tools/tests/                      # maintain affected existing tool regressions
 tests/                            # existing suites; small checks for new critical behavior
 fuzz/                             # maintain affected existing consumers; no new target
 qualification/                    # reuse load/hardware/security/evidence conventions
 .github/workflows/                # host bundles, checks, source-free release acceptance
 README.md / docs/maintainer-security.md
```

**Structure Decision:** Keep one Cargo package and one device owner. A small manager module separates terminal rendering from existing command execution and host changes; no separate service, plugin system, workflow DSL or cross-repository node work. Existing Python owns firmware/OTP verification and physical interaction, rather than duplicating it in Rust.

## Phase 0 result

[research.md](research.md) records evidence, decisions, rationales and alternatives for nine topics. Three independent repository investigations covered observations/lifecycle, release/maintenance and custody/provisioning. Parent research covered dependency compatibility, quality sensors and integration. No unresolved `NEEDS CLARIFICATION` value remains in Technical Context. Signing access, release artifacts and hardware readings are future acceptance prerequisites, not invented existing capabilities.

## Phase 1 design

[Data model](data-model.md) defines identities, authority, freshness, storage bounds and operation transitions. [Manager contract](contracts/manager.md) defines entrypoints/screens, existing command mapping and foreground handoffs. [Observations](contracts/observations.md) defines new bounded public messages, version outputs and snapshot consistency. [Distribution](contracts/distribution.md) defines trust, supported platforms, exact combinations, ownership, update/removal and uncertainty. [Quickstart](quickstart.md) defines runnable acceptance scenarios and expected results without implementation code.

### Dependency order for implementation (not a task list)

1. Approve the operator-led quality definition and performance baseline-selection/environment/tool procedure, and review terminal dependencies; add public version/observation contracts across firmware/protocol/daemon/CLI with affected existing fixtures and bounded read smoke.
2. Build non-mutating TUI inventory and freshness; prove partial/disconnected/64-pool views before adding mutation affordances.
3. Establish authenticated host packaging/bootstrap, signed exact compatibility authorization, candidate-only local acceptance and ownership transactions; prove no-source VM installation and rejected trust/compatibility cases before permitting downloaded execution. Final qualification is not a prerequisite to exercising its own candidate.
4. Add the attended `first-install` firmware handoff before US2 commissioning for factory/BOOTSEL-only boards; existing compatible blank applications skip transfer. Connect existing lifecycle/service/config/backup/OTP workflows and reuse the firmware helper for pinned normal updates. Producer action remains the existing drop-in plus systemd commands.
5. Run end-user quickstart scenarios, the bounded performance gate and existing affected developer checks; record actual outcomes and update release/user/security documentation together. Q10 covers every workflow, including service/uninstall and producer hardening. Promote only unchanged tested payload digests after required scenarios and physical evidence pass; metadata promotion is not a post-test code change.

### Reach and intentional non-changes

| Surface | Required reach |
|---|---|
| Exports/build | Register manager binary and module; add version metadata generation for manager/CLI/daemon/firmware; update Cargo pins/lockfile and packaged assets |
| Protocol/firmware | `crates/kes-protocol/src/{management,usb}.rs`, public core accessors, firmware dispatch, daemon USB/management/context/runtime; no storage schema or secret-bearing status |
| Callers | CLI read dispatch and renderer, manager shared client/mutation subprocesses, protocol test/fake-device adapters, qualification/fuzz consumers of changed enums |
| Host setup | `deploy/install.sh`, `deploy/uninstall.sh`, service executable paths, ownership-aware bundle install, config example only if actual fields change; preserve service hardening and host-check semantics |
| Release/tools | Bootstrap, publication workflow/tool/tests, signed compatibility and qualification metadata, patched tool packaging, first-install and normal-update handoffs; unchanged inner bundle verifier/OTP admission rules |
| Tests/fixtures | Maintain affected existing protocol, CLI, service, recovery, host-security and backup checks; add only small tests/self-checks for new nontrivial behavior, not a dedicated manager test program; public disposable fixtures only |
| Docs | README, maintainer security, existing management contract and feature contracts synchronized during implementation |
| Intentionally unchanged | Node-service protocol and external repositories, device state layout, backup crypto/format, socket authority, activation rules, producer policy bytes, normal-mode host preflight |

## Requirement traceability

| Requirements | Design surface | Validation scenario / success criteria |
|---|---|---|
| FR-001–002 | Bootstrap, platform/prerequisite review, persistent TUI | Q1/Q2; SC-001, SC-003, SC-005 |
| FR-003–006 | Version evidence, complete membership joins, period/context details, freshness/UI | Q1/Q3/Q10; SC-001–003, SC-008 |
| FR-007–008 | Resumable setup, factory first installation or existing blank application, reviewed commissioning/pins/config/security | Q2/Q4; SC-003, SC-005–006, SC-011 |
| FR-009–015 | Signed compatibility/qualification separation, tuple selection, host/firmware retention/recovery, offline cache | Q1/Q5/Q6; SC-003–006 |
| FR-016–018 | All existing lifecycle actions, custody, original receipts | Q4/Q7/Q8; SC-005–007, SC-009–010 |
| FR-019–023 | Service/config/diagnostics/removal, node boundary, secret filtering, USB ownership | Q1/Q5/Q6/Q9/Q10; SC-001, SC-004–006, SC-008, SC-011 |
| FR-024–025 | Optional qualified attended OTP/record handoff | Q7; SC-007, SC-009 |
| FR-026–027 | Isolated backup role, restoration evidence/output policy/fencing explanation | Q8; SC-007, SC-010–011 |
| FR-028–029 | Validated unit names, supplied drop-in/reload/approved running-unit restart | Q11; SC-012 |

## Complexity Tracking

No constitutional exception requested. Ratatui/Crossterm replace handwritten terminal parsing/rendering; signed outer distribution metadata avoids modifying strict firmware bundle semantics; public maintenance records are required because existing device mutation receipts do not describe filesystem/service/firmware transfers. No other framework, schema migration or optional feature is introduced.

## Planning verification and hook disposition

Documentation checks cover eight generated artifacts, balanced code fences, resolving local links, all 29 functional requirements, all 12 success criteria, and 11 quickstart scenarios. Repository-fact assertions verify the Rust/edition baseline, five pinned quality tools, management/USB bounds, currently unused extension kinds, authority fingerprints and firmware/state address ranges. These checks validate the design documents, not the proposed implementation.

`.specify/extensions.yml` was absent at both the required pre-plan and post-plan checks; no extension hook was registered or executed. Phase 2 tasks, application changes, release signing, runtime scenarios and hardware qualification were not performed.

**Acceptance refinement — 2026-11-02:** The maintainer removed high-code-coverage and elaborate automated-test requirements in favor of end-user testing. The specification, research, quality contract and quickstart now use that scope. Earlier validation of tool pins records repository facts only; it does not make coverage/mutation tools required for this feature.

**Analysis remediation — 2026-11-02:** Approved documentation refinements restore the bounded constitutional performance gate, separate candidate compatibility admission from final qualification, define source-free first firmware installation before commissioning, and extend keyboard/no-color acceptance to every workflow. Q1 now conditions bootstrap execution on successful signature verification and both pinned fingerprints; the behavioral gate separately requires known-defect detection and restored passing evidence through T001/T016/T067/T070. All 70 implementation tasks remain pending; these documentation fixes do not establish release authenticity, candidate calibration or hardware qualification.

**Governance/cohort remediation — 2026-11-02:** The maintainer explicitly authorized constitution 2.0.0 to resolve inherited qualification conflicts. Release promotion requires candidate-applicable deterministic transition, physical power-loss recovery, full-capacity, native compatibility and independent backup-fidelity evidence; repeated physical-cut/live-block campaigns remain optional and unmeasured unless actually run. SC-003 now defines one fixed five-person eligible cohort and requires four participants each to complete all three actions without coaching or prior workflow rehearsal. These are acceptance definitions, not passing readings.
