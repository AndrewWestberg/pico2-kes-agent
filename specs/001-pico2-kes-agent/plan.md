# Implementation Plan: Persistent Pico2 Multi-Pool KES Agent

**Git branch at refinement**: `feature` | **Setup feature identifier**: `001-pico2-kes-agent` | **Date**: 2026-10-27 | **Spec**: [spec.md](spec.md)

**Input**: `specs/001-pico2-kes-agent/spec.md`

**Status**: Phase 0 research and Phase 1 design refined for executable verification contracts and corrected feature metadata. The C1 node contract, quickstart and approved gate definition are synchronized; foundation smoke and separate core/host benchmark ownership are explicit. Existing 100 task IDs are preserved, not regenerated. The maintainer explicitly approved the refined definition as recorded in `contracts/quality-gates.md`; the definition-approval prerequisite is satisfied. This is a documentation deliverable, not implementation or qualification acceptance. No source changes, firmware installation or irreversible operations are included.

## Summary

Build a Rust current-key provider for the accepted Pico2 A2: persist 64 independently enrolled pools with one active and one staged Sum6KES generation each; evolve forward using fresh network-specific period context; commit/erase/read-verify before acknowledging or releasing successors. Generate immutable recipient-encrypted key0 artifacts and automatic activation intent together, with certificate/timing prerequisites but no backup-host approval. Explicit generation-bound staged discard preserves the active key; retirement removes device artifacts without revoking external copies.

`pico2-kes-agentd` owns USB, exposes one existing-protocol node-service socket per pool plus an equally authorized management socket, and persists only public configuration/reconciliation receipts. `pico2-kes-agent-cli` performs the full lifecycle through that daemon and restores conventional key files locally on the backup host. Extend the native bulk loader and receive validation without changing the node-service protocol or adding file fallback. Preserve supported baseline credential semantics; do not recreate the removed predecessor external-signing integration. Node retains delivered keys and signs locally.

Research selects a single-image 3,104-KiB flash allocation instead of the inherited dual-image layout that would exceed 4 MiB at 64 pools. The allocation includes a durable operation-handoff journal so managed sequence/receipt state survives reboot. One shared KES workspace avoids retaining a full public tree per pool in RAM. Hardware fit, erase behavior and target timings remain measured acceptance gates.

U1 uses explicit attended daemon commissioning and a public enrollment record before normal pinned startup. U2 makes publication timestamps device-owned, atomically committed with visible state and returned unchanged over USB. I1 keeps only per-pool-incarnation period floors while enrolled; deletion removes the floor, with no historical network registry. Required public retry/deletion receipts retain ordering continuity without keeping obsolete operational secrets. See research R11–R13 and the refined storage/management/node contracts.

C1 reuses cardano-node's existing post-initialization SIGHUP handler. File-backed reload rereads credentials and relies on subsequent slot-driven in-memory KES evolution; agent-backed reload creates replacement receivers requiring fresh current bundles. Protocol compatibility alone does not establish bulk-loader support or safe cancellation. The native integration must cover both, without requiring SIGHUP for ordinary device evolution or rotation.

## Technical Context

**Language/Version**: Rust edition 2024, Rust/Cargo 1.99.1 for firmware, daemon and CLI. Native Haskell node/consensus changes follow their pinned Cabal/GHC build graph; record exact toolchain and resolved plan before integration acceptance.

**Primary Dependencies**: Embassy RP 0.10.0/USB 0.6.0/sync 0.8.0; nusb 0.2.9; reviewed no_std kes-summed-ed25519 0.2.1 adaptation; Ed25519-dalek 2.2.0; HPKE 0.13.0/X25519 2.0.1/HKDF-SHA256/ChaCha20-Poly1305 0.10.1; zeroize 1.8.2; serde 1.0.228/serde_json 1.0.145/rustix 1.1.5. Exact selected versions/source pins and maintenance review obligations are in [research](research.md). No dependencies are installed into the project by this plan.

**Storage**: Raw qualified NOR; paired authenticated pool/configuration snapshots with explicit COMMIT/CLEAN and physical sector erase/read verification; immutable per-generation public trees/artifacts. Nominal 4-MiB layout allocates 1 MiB firmware, 16 KiB config, 2 MiB pool regions, 1,008 KiB reserve. Host public append-only mutation/receipt journal (64-MiB admission bound); no primary plaintext key persistence.

**Endurance Goal**: Five years (1,827 days) with a 2× per-physical-sector margin against the fitted part's guaranteed rating, including prior qualification wear. The operator-selected workload includes network-derived evolution/rotation plus monthly extra rotation and generate/discard cycles per pool, monthly device-wide recipient change and one pool delete/re-enrollment, and daily interrupted-operation recovery. The authoritative counts, projection formula and failure rules are in [the storage endurance policy](contracts/device-storage.md#endurance-acceptance-policy); P1/T093 owns final evidence. This is an unmeasured service-life target, not an API rate limit or approval of the entire quality gate.

**Testing**: Cargo behavioral/integration tests, proptest 1.11.0, cargo-mutants 27.0.0, cargo-llvm-cov 0.9.1, cargo-fuzz 0.13.1 with nightly-2026-10-22, finite exhaustive Rust lifecycle model, Criterion 0.8.2, independent Haskell/Cardano decoders, actual A2 power/load/erasure campaigns and accepted primary blocks. See [quality gates](contracts/quality-gates.md).

**Verification entrypoints**: `qualification foundation` exercises real codec/protection/fixture failure paths before daemon/CLI availability; `qualification native-regression --fixture` invokes actual native receiver/finalizer cases; `qualification node --fixture` proves real SIGHUP and accepted blocks. P0 uses `qualification benchmarks --baseline` to aggregate `kes-core/lifecycle` and `pico2-kes-agent/host`. Full Cargo commands, ownership, evidence and approved deadlines are in [quality gates](contracts/quality-gates.md); no command is claimed implemented by planning.

**Target Platform**: Linux x86_64 systemd primary and Linux recipient host; RP2350 A2 Cortex-M33 `thumbv8m.main-none-eabihf`, one daemon/device, USB bulk. Do not inherit an A4 requirement. Firmware target is not installed on the planning host; cross-build and physical execution remain implementation work.

**Project Type**: Embedded firmware + Unix service + operator CLI + native Cardano integration; no web UI/general HSM.

**Performance Goals**: Every healthy pool in a concurrent 64-pool current-key burst within 10 seconds; all 64 valid pools recovered within 60 seconds after device/service/fresh context/requesting nodes are available; 10 attended physical power interruptions plus exhaustive software persistent cut points. Targets are unmeasured.

**Constraints**: 64 active +64 staged generations; fixed device buffers/no avoidable copies; 128-KiB planned owned RAM budget plus measured framework overhead and >=32-KiB spare SRAM. Common socket authority, no runtime PIN, no secret import, cold signing external, one shared backup recipient private key off-primary, no plaintext primary cache/dumps/swap. No full-system forward-security, physical extraction resistance, captured-flash rollback resistance or producer-fencing claim.

**Scale/Scope**: 64 pool subscriptions (one per pool guaranteed), 128 generations/artifacts; one USB request in flight, bounded per-pool scheduling and management queue. Rust root package retained; new small no_std libraries and firmware/qualification members. Recorded native revision pins are node `7af71936a6164119a7a1446152b1ba2f7df54e07` and consensus `6673fce255f12addb602b0ae2d0a20f51a2cd519`; the user subsequently corrected the consensus working-tree baseline by removing old cardano-kes-forge changes. Those changes are not part of this integration target. Use pinned kes-agent 1.3.0.0/crypto 1.1.0.0 source archives and capture the corrected native source inventory before implementation acceptance.

## Constitution Check

**Pre-research gate:** PASS for this documentation refinement. Scope is verification-contract completeness and metadata correction, not a new product capability or constitutional exception. Existing technical choices and model remain applicable; full MCP entries for the affected behavioral/integration sensors were reconsulted before finalizing their checks. Implementation remains subject to recorded approval and executable evidence.

**Post-design gate:** PASS for design consistency; no constitutional exception is required. Foundation smoke has an executable owner before US1, P0 covers both no_std-compatible core and host-only workloads, and C1 semantics/scenarios are synchronized across plan, node contract, tasks and quickstart. **Implementation definition-approval prerequisite: SATISFIED** by the explicit maintainer approval recorded against the unchanged reviewed definition digest. Historical U1/U2/I1 authorization is retained separately. Existing sensor/tool selection, aggregate budgets, original 10/60-second targets, endurance policy and physical evidence requirements remain; C1 scenario bounds are approved but unmeasured. Neither design completion nor approval is a passing sensor reading.

**Approval boundary:** The maintainer explicitly confirmed "approved quality-gate definition." The current approval record identifies the reviewed definition digest, approver and date; T005 verifies and translates those approved bytes. The definition is preserved byte-for-byte, with its proposal-time status labels superseded by the dated approval record. Approval satisfies this prerequisite only; implementation, tool activation, baseline approval and candidate evidence remain required. Further substantive definition changes need renewed approval.

| Principle / constraint | Design evidence | Acceptance boundary |
|---|---|---|
| I. Explicit scope/correctness | Current-key provider only; full FR-001–FR-021 mapping below; external cold signing, explicit failures | No block-signing API, imported key or backup-readiness gate |
| II. Verifiable behavior | Quickstart public-interface scenarios; independent decoder/node; 64+64 and power campaigns | Hardware, timings and accepted blocks must actually be measured; documentation validation does not replace them |
| III. Stable interfaces | Management/USB/storage/artifact/node contracts; identity-bound retries and native source migration | Pin combined candidate; migrate every affected native caller; no silent legacy reinterpretation |
| IV. Trust boundaries | Common socket permissions, recipient off-primary, erase-before-release, accepted A2 exclusions | Deployment and secret-output review; independent crypto vectors; no stronger admin credential |
| V. Maintainable Rust/bounds | Shared no_std core, fixed flash/RAM geometry, serialized flash ownership, bounded queues | Link/RAM/load qualification and five-year/2× per-sector endurance projection under the storage policy; isolated pool failure and unsupported storage fail closed |
| VI. Observatory quality gate | MCP full entries inspected; selected IDs, gaps, pinned tools, executable gate definitions and sensitivity probes | Maintainer approval of the definition before implementation; demonstrated gate sensitivity before trusting readings; missing/stale/failing/inconclusive readings block acceptance |
| Technical/workflow constraints | Rust 2024 preserved; device+host targets; only requested docs changed | Native/firmware smoke and mandatory checks occur during implementation; no inherited A4/provisioning machinery |

Baseline correction: the user reports that old cardano-kes-forge changes have been removed from ouroboros-consensus. Supersede the earlier instruction to preserve/reintegrate those changes. The node's observed loader supports legacy triples, and the specification's cited `Shelley/Credentials.hs` is absent; predecessor parser references are historical, not requirements to reconstruct removed functionality. Add file/agent bulk entries and preserve supported baseline interfaces. FR-004's protection of existing external-signing configurations is a compatibility constraint wherever such support exists, not a mandate to add it to the corrected baseline.

## SIGHUP credential reload

### Native behavior and integration decision

- Reuse `Cardano/Node/Run.hs`'s `installSigHUPHandler` and `updateBlockForging`: after consensus initialization, SIGHUP reconstructs protocol/forging credentials from the existing configured paths and calls `setBlockForging`. Before initialization, the handler reports forging reload as not effective. This is not a general reload of startup-only command-line paths or a new daemon command.
- Extend the shared singleton/bulk loader so the same strict source selection applies at startup and SIGHUP. The inspected singleton loader supports `KESAgentSocketPath`; the bulk loader currently accepts only embedded file-key triples. A compatible Rust V2 provider does not remove the need for this native bulk-source integration.
- File-backed credentials instantiate a hot key from the reread key/certificate. The forging slot callback invokes `HotKey.evolve` to catch up within certificate/network validity; do not evolve in the signal handler or rewrite the key file. Future-start and expired keys remain unusable outside their validity.
- Agent-backed credentials instantiate a keyless dynamic hot key and a new receiver. The forging controller cancels old workers before constructing replacements. The provider must deliver its latest eligible bundle on a new subscription, using the existing V2 bytes and durable publication descriptor. Explicit reload may leave an unavailable agent pool unable to forge until fresh delivery; healthy file/agent pools must still operate. Ordinary agent disconnect keeps the existing worker's key and is a different case. Do not add a key-transfer cache, file fallback or mandatory reload during automatic rotation.
- Preserve baseline reload error behavior rather than inventing transactional configuration replacement: ordinary parse/validation errors are reported without installing a new forging set; missing credential-file errors handled by `updateBlockForging` can disable the entire forging set. Record the exact corrected baseline cases in T004 and preserve them in T047/T053/T055. Agent connection failure is asynchronous source unavailability, not a missing credential-file error.

### Cancellation safety and proof

`HotKey.mkHotKeyWith` finalizes an agent-backed key with `cancel keyThreadAsync >> unset`. The inspected `runKESAgentClient` catches `AsyncCancelled` inside `forever`, then retries after ten seconds; its broad `SomeException` handler also requires cancellation-aware treatment. Cancellation must propagate out of both handlers, while genuine recoverable service failures retain their reconnect behavior. Reproduce the native receiver/finalizer failure before fixing it, then verify termination, socket/resource cleanup and key cleanup before replacement. Do not suppress errors, detach old receivers, or merely remove the dedicated catch while leaving the broad handler to swallow cancellation.

T047/T054/T055 own native behavioral regression and integration; T058/T059/T094 own actual SIGHUP runs and accepted-block evidence. Exercise cancellation during connected/blocked service I/O and reconnect delay, repeated reloads, 64 agent pools, separate mixed file/agent and singleton cases, unchanged and updated valid credential contents, malformed/missing files, future/expired file keys, and an agent that is unavailable then returns. The synchronized [SIGHUP qualification contract](contracts/quality-gates.md#sighup-reload-qualification) fixes approved deadlines, repeat counts and evidence within the existing budgets. Record unchanged node PID, receiver/connection retirement, file-key immutability, current-period signing and per-pool outcomes. A hung teardown or unavailable required evidence cannot pass; provider notifications alone are not a SIGHUP test.

The existing SC-003/SC-004 recovery/delivery targets remain mandatory; this refinement does not claim zero-gap credential replacement or change those targets. Actual SIGHUP completion and native cancellation safety remain unmeasured until the implementation campaigns.


## Project Structure

### Documentation (this feature)

```text
specs/001-pico2-kes-agent/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
    ├── backup.md
    ├── device-storage.md
    ├── management-cli.md
    ├── node-service.md
    └── quality-gates.md
```

`tasks.md` was generated by the separate Phase 2 workflow. This refinement updates only affected task contracts and proof obligations; task IDs and the 100-task delivery scope remain intact.

### Source code (planned, not created by planning)

```text
Cargo.toml                         # retain root pico2-kes-agent package; workspace/default host members
src/
├── lib.rs                         # shared host config, management, protected-memory helpers
├── bin/pico2-kes-agentd.rs
├── bin/pico2-kes-agent-cli.rs
├── daemon/                        # USB ownership, polling/scheduling, sockets, public receipt journal
└── backup/                        # recipient custody and local-only restoration
crates/
├── kes-core/src/                   # no_std lifecycle, canonical KES, certificate, artifact, storage model
└── kes-protocol/src/               # no_std bounded device codecs; host node/management codecs
firmware/                          # pico2-kes-firmware; Embassy RP2350, flash/TRNG/USB adapter
third-party/kes-summed-ed25519/     # minimal reviewed no_std adaptation with original provenance/license
qualification/                     # host executable: real scenarios/evidence, not a second application service
fuzz/                              # bounded public/USB/artifact/certificate parser targets
benches/
├── lifecycle.rs                   # kes-core target lifecycle; explicit ../../ path in core manifest
└── host.rs                        # root pico2-kes-agent target host; framing and real journal I/O
tests/                             # host behavior/integration and native interoperability fixtures
deploy/                            # systemd unit, udev ownership, public configuration example
```

The existing trivial `src/main.rs` is replaced by the two explicitly named binaries during implementation; no compatibility executable or obsolete source remains. If HPKE needs the predecessor's manifest-only no_std correction, maintain only that documented patch, not a second custom primitive.

External integration: `cardano-node` credential decoder/loader/source types/native tests and the existing `Run.hs` SIGHUP path; `ouroboros-consensus` agent receive validation, cancellation-safe receiver finalization and hot-key construction. Module boundaries and reload semantics are synchronized in [node-service.md](contracts/node-service.md). No external source is edited during this planning command.

**Structure decision:** core/protocol separation permits firmware and host-model checking without importing Linux dependencies; root host package shares lifecycle-independent CLI/daemon code; firmware owns hardware operations; qualification owns real cross-language/hardware measurements. Avoid a framework, database service, updater, cloud subsystem or generic HSM abstraction.

Verification ownership: T014/T016 provide `qualification/src/foundation.rs` and its main/gate dispatch; T020 runs it against T010/T011/T013 without depending on T042's binaries. T015 supplies the native adapter/dispatch used by T047/T055's real regressions. T019 registers both benchmark manifests and aggregate runner; T096 completes workload/baseline evidence. Keep production entities, USB/storage/management/backup formats and the [data model](data-model.md) unchanged.

## Delivery sequence and proof obligations

1. Obtain recorded approval of the revised quality/storage definition before implementation; configure and demonstrate each gate's sensitivity before trusting its readings. Pin tools/native source inventory; establish independent KES/artifact/service-byte vectors and actual fitted A2 geometry. Build bounded codecs including explicit commissioning, per-incarnation context and device-owned publication descriptors.
2. Implement attended blank-device commissioning and verify pin installation/reconciliation before normal startup. Implement device generation/artifact/evolution and verified two-bank cleanup. Prove single-pool recovery then 64+64 flash/RAM fit and boundary workload before assuming scaling.
3. Implement daemon public receipts, device reconnection/identity/time context, common sockets and CLI lifecycle. Exercise commissioning cuts, publication commit/reply/confirmation cuts, per-incarnation floors, lost replies, staged conflict/discard race, recipient change and retirement. Same-pool re-enrollment uses the retained public deletion timestamp floor, never a retired network-period floor.
4. Integrate exact V2 stream and native mixed file/agent bulk selection/receive validation; fix cancellation-safe receiver teardown and exercise SIGHUP through the actual node. Demonstrate all 64 pool bindings, file-key catch-up, fresh agent delivery, outage isolation and rotation without node restart or mandatory SIGHUP. Preserve legacy file and singleton-agent semantics and baseline malformed/missing-file diagnostics; do not restore removed forge integration.
5. Implement recipient-host-only restoration and independent conventional decoding. Complete real systemd/operator path, full A2 power/load/erasure campaign and primary accepted blocks. No backup producer runtime requirement.

These are design sequencing constraints, not Phase 2 task generation. No phase may be accepted on scaffolds or empty readings.

## Requirement traceability

| Requirements | Contract / proof |
|---|---|
| FR-001, FR-003, FR-004 | Node-service V2, bulk source union, receive validation and SIGHUP/cancellation contract above; T047/T053–T055/T058–T060/T094, G2/G7/G9/P1 |
| FR-002 | 64 independent 32-KiB regions, active+staged state/public objects; P1 and G8 occupancy |
| FR-005, FR-006 | COMMIT/CLEAN and erase-before-release recovery; G3/G8/SC-002/SC-009 |
| FR-007, FR-008 | PeriodContext, certificate/counter checks, entropy and forward evolution; G2/G3/G7 |
| FR-009, FR-018 | Device outstanding receipt + durable public journal; export-triggered activation; G3/G8/SC-005 |
| FR-010, FR-011, FR-012, FR-017 | Immutable KESBKP01, recipient custody/local restore, exact retention; G7/G10/SC-006 |
| FR-013, FR-014, FR-015 | systemd/reconnect/socket identity, memory/queue/deployment limits; G2/G10/P1 |
| FR-016, FR-020 | Full management/CLI surface and common access, offline restore; G10/SC-008 |
| FR-019 | Accepted A2 storage/entropy qualification and explicit threat exclusions; G8/G10 |
| FR-021 | Generation-bound staged discard and activation serialization; G2/G3/G8 |
| SC-001–SC-009 | Full scenarios in quickstart and G1–G10/P0/P1 gate definition; final qualification requires all |

## Complexity Tracking

No constitutional deviations. The public host receipt journal is justified by exact retry reconciliation with bounded device flash; a small evicting flash cache cannot honestly preserve historical operation outcomes. One firmware image deliberately avoids unnecessary update complexity and makes 64-pool geometry fit; attended firmware maintenance is outside ordinary operational power-loss guarantees.

## Planning validation record

Executed documentation checks: all 9 generated artifacts have titles and balanced code fences; 19 local Markdown links resolve; all 10 shell blocks pass `bash -n`; FR-001–FR-021 and SC-001–SC-009 have traceability entries; flash allocation, reserve and sector alignment arithmetic pass. Source checks confirmed artifact `device_signature`, fixed identity widths, V2 direct stream encoding, four-byte receive-result codes and microsecond timestamps. Final MCP coverage reported 10 recognized sensors across five families; remaining family gaps are recorded in the quality contract.

Pre-plan and post-plan checks found no `.specify/extensions.yml`; no hooks were registered through that file. Setup returned feature identifier `001-pico2-kes-agent`; Git reported branch `feature`. The branch was not switched. No product build, firmware runtime, hardware qualification or accepted-block result is claimed.

### U1/U2/I1 refinement record

At the earlier U1/U2/I1 refinement, planning setup returned JSON `BRANCH=001-pico2-kes-agent` as the feature identifier and preserved the existing plan; this was not an observation of the actual Git branch. Research compared explicit attended commissioning against automatic trust/reset, device-owned timestamps against host publication journals, and live-pool floors against retained network histories. The operator confirmed minimal nonsecret metadata retention. Pre-design review found no need to change the constitution; post-design review preserved sole-daemon USB ownership, common socket authority, qualified cleanup, full capacity and mandatory physical evidence. Historical validation above applies to the earlier plan, not proof of later interface refinements. No implementation, hardware or native interoperability result was claimed.

Refinement documentation validation: 11 feature Markdown artifacts checked for titles/frontmatter, balanced fences and consistent table columns; 35 relative Markdown links and their referenced heading anchors resolve; all 13 shell blocks pass `bash -n`; 100 sequential unique tasks, 19 parallel markers and all 30 FR/SC identifiers remain. The obsolete per-network-floor, USB kinds 1–9 and daemon-timestamp-assignment instructions are absent. Current gate/storage proposal SHA-256 values are recorded separately from the historical approval. Full MCP integration/fault-injection entries were reconsulted; no new sensor or tool was selected. These are documentation checks, not product runtime proof.

### C1 SIGHUP refinement record

The operator clarified reload as SIGHUP to cardano-node. Source inspection traced `Run.hs` through credential loading, forging replacement, `Praos/Common.hs`, `Ledger/HotKey.hs`, slot-driven evolution and `Praos/AgentClient.hs`. The installed node reported `11.1.3` and revision `7af71936a6164119a7a1446152b1ba2f7df54e07`; its CLI exposed singleton agent support, while a read-only agent-shaped bulk preflight failed with `expected Array, but encountered Object` before database/network startup. The reported revision does not prove an exact dirty-source/build match.

An isolated in-memory Haskell cancellation probe using installed `io-classes 1.10.1.0` reproduced the receiver loop's exception structure: cancellation was caught, the loop re-entered after its ten-second delay, and the waiting cancellation did not complete. This demonstrates the control-flow hazard, not a live-node SIGHUP hang or a passing fix. No running producer was signaled; no accepted-block reload, full native receiver regression or hardware qualification result was claimed. That historical refinement updated only spec, plan and tasks; the verification-contract refinement below now synchronizes its linked contract/gate execution details without extending historical approval.

### Verification-contract and metadata refinement

Setup preserved the existing plan and returned feature identifier `001-pico2-kes-agent`; `git branch --show-current` reported `feature`. Spec/plan metadata now distinguishes those facts and records completed task generation. Research R14–R16 resolves the foundation executable, host/core benchmark split and C1 verification boundaries using existing tools and module conventions. SO-002b/SO-002c full entries were reconsulted; no sensor or dependency was added.

The updated artifacts are `spec.md`, `plan.md`, `research.md`, `tasks.md`, `contracts/quality-gates.md`, `contracts/node-service.md` and `quickstart.md`. `data-model.md`, storage, backup and management contracts remain intentionally unchanged: no persistent entity, lifecycle mutation, wire format or operator command changes. Planning stopped at this design; the subsequent explicit maintainer approval is now recorded separately from the unperformed implementation and qualification work.

Validation executed for this refinement: 12 feature Markdown artifacts have titles and balanced fences; 49 local links and heading anchors resolve; 17 tables have consistent column counts; all 18 shell blocks pass `bash -n`. The task inventory remains 100 unique sequential unchecked IDs with 19 parallel markers and no undefined task references; all 30 FR/SC identifiers remain. Foundation/native-regression/benchmark commands agree across tasks, gate definition and quickstart. The recorded proposal SHA-256 matches its definition boundary, and the storage digest still matches the prior approved bytes. No product executable, native regression, benchmark, firmware or hardware campaign was run; these checks validate the documentation only.

Approval recording validation: verified the explicit maintainer authorization, approver/date and approved digest; the reviewed gate definition and referenced storage contract remain byte-identical. Seven synchronized documents have balanced fences and 41 resolving local links/anchors. All 100 tasks remain unchecked, with 19 parallel markers. Only the definition-approval prerequisite is satisfied; no implementation or runtime check was performed by recording approval.
