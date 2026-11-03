# Research: KES Agent Management TUI

Date: 2026-11-02. Scope: Phase 0 design research, not implementation or qualification.

## R1 — Existing surface and integration boundary

**Decision:** Add `p2kesup` to the existing Rust package. The short operator-facing name follows the rustup/ghcup convention; daemon and CLI names remain unchanged. Use existing CLI commands for lifecycle mutations, exports, receipts, and reconciliation; use the shared bounded management client for frequent public observations. Keep the daemon the sole operational USB owner. Do not build a new daemon, web service, mutation protocol, or node integration.

**Evidence:** `src/cli/mod.rs` implements commissioning, enrollment/deletion, generation/discard, public-key/artifact export, certificate/recipient installation, reconciliation, and backup-host operations. `src/cli/client.rs` bounds management I/O; `src/cli/receipt.rs` creates protected no-clobber public receipts before submission. `src/daemon/management.rs` already implements authenticated device inventory, paginated host bindings, and public pool status. `crates/kes-protocol/src/management.rs` limits frames to 16,384 bytes; USB payloads are limited to 4,096 bytes.

**Rationale:** Reusing commands retains validation and durable uncertain-outcome behavior. The manager orchestrates existing authorities rather than acquiring their secret material.

**Alternatives considered:** Reimplement mutations in the TUI (duplicates receipt/validation rules); parse human CLI output (unstable); direct USB access (violates sole ownership); one giant inventory response (exceeds bounded framing at 64 pools).

## R2 — Terminal implementation and bounded refresh

**Decision:** Rust 1.99.1, edition 2024; exact dependencies `ratatui = 0.30.2` with default features disabled and features `crossterm` and `unstable-rendered-line-info`, and `crossterm = 0.29.0`. Rendered-line information enforces the pinned renderer's scroll bound before approval. The maintainer approved the Ratatui revision during T002 after the original 0.29.0 dependency graph failed `cargo deny check`, then approved aligning Crossterm with the backend's actual selected version; no advisory suppression is authorized. Reuse serde/serde_json/rustix and standard-library threads/channels. One terminal event owner, one local observation worker, one independently bounded release-fetch worker; foreground mutations suspend refresh. No async runtime, plugin framework, generic workflow engine, or theme configuration.

**Evidence:** `cargo info ratatui@0.30.2` reports MIT and Rust 1.88 minimum; [Ratatui documentation](https://docs.rs/ratatui/0.30.2/ratatui/) describes the widget/backend API. Its backend dependency enables Crossterm 0.29 by default and selects the highest enabled version, so enabling `crossterm_0_28` does not retain a 0.28-only graph. [Crossterm events](https://docs.rs/crossterm/0.29.0/crossterm/event/index.html) require `poll`/`read` on the same thread. The repository uses `panic = abort`; restoration must therefore occur in normal exits, handoffs, and a panic hook, not rely only on unwinding.

**Rationale:** Tables, keyboard navigation, resizing, and terminal restoration justify these dependencies; handwritten escape/input handling does not. These are proposed compatible pins, not a claim that they are the latest releases. Lockfile resolution, license/advisory review and build checks are required before adoption.

**Bounds:** 64 device pools, 64 configured and 64 effective host bindings, 128 device generation observations; the join retains up to 192 distinct source identities. UI event poll at most 100 ms; refresh starts every 2 seconds without overlapping scans. A local scan has an 8-second deadline and publishes partial results as they arrive; stale state is visible within 10 seconds. One management request outstanding; at most one queued refresh (coalesced). Release fetch has a separate 10-second deadline and cannot block local rendering. No polling of node-service sockets. Minimum interactive terminal 80×24; smaller terminals show a plain resize/quit message without mutation.

**Alternatives considered:** Shell dialog menus (poor concurrent state/freshness UX); custom terminal code (larger correctness burden); Tokio (unneeded runtime); unbounded per-pool workers (compete with key delivery).

## R3 — Observation gaps and wire evolution

**Decision:** Preserve management v1 envelopes and existing action meanings; add `host.observe`, `device.info`, and `pool.observe` as read-only actions, each with `schema_version: 1` results. Add USB v1 kinds 13 (`FirmwareInfo`) and 14 (`PoolObservation`) without changing kinds 1–12, storage, or mutation encodings. Document them in [observations](contracts/observations.md). Update all protocol encoders/decoders, daemon/firmware dispatch, CLI commands, tests and fuzz consumers together.

**Evidence:** `HelloIdentity` exposes protocol/storage versions and capacity, not a firmware release/build identifier. Existing `GenerationStatus` exposes generation/revision/role/period/health/artifact digest, not certificate bounds. Device membership already exists and is checked for duplicate identities and the pinned device. `pool.list` uses positional cursors over a reconstructed config/journal registry, so it is not a coherent cross-page snapshot during concurrent changes.

**Rationale:** New bounded read-only messages avoid changing strict existing layouts. A one-time unsupported extension probe is classified unavailable, followed by normal reauthentication if framing was rejected; it is not repeated every refresh. Unsupported observations block maintenance that needs them, not local inspection. Never substitute protocol version for firmware version. Firmware build metadata is an application report, not independent attestation.

**Decision:** `host.observe` returns running build identity and snapshot-bound pages of host bindings, including configured and effective bindings with tombstone/conflict classifications. `pool.observe` targets device membership directly, including pools absent from host configuration. Missing host context is explicit. Certificate and generation period fields originate in device public lifecycle state; trusted context comes from the daemon's existing context provider. No host-invented expiry or node queries.

**Alternatives considered:** Aggregate every pool in one frame (breaks bounds); modify strict v1 status schemas in place (breaks callers); infer device membership from configuration (incorrect); cache certificate inputs only on host (misses existing/unmatched device generations).

## R4 — Release trust and source-free delivery

**Decision:** Publish an outer `distribution.json` plus detached OpenPGP signature from the existing independently trusted project authority. Keep each existing firmware bundle unchanged in its own directory: its exact-file-set schema and firmware-key authorization remain authoritative. The outer manifest binds host binaries, manager, deployment files, patched tools, bootstrap, and the complete inner bundle by path, size and SHA-256. See [distribution contract](contracts/distribution.md).

**Evidence:** `tools/firmware.py::verify_bundle` rejects extra files and authenticates the schema-1 firmware manifest via the authorized firmware key. `README.md` already requires authenticating downloaded `firmware.py` before execution. The project authority fingerprints are primary `9FF957E79B5D853544805F4725491F18087931B6`, signer `78C0F32094CD02A4BAFA444C684E37A210480F82`. Current release publication is firmware-only; `deploy/install.sh` consumes source-built `target/release` binaries.

**Rationale:** Reuse the root authority without broadening the firmware-key delegation to host code or breaking provisioning tools. A downloaded verifier cannot bless itself. The standard pipeline explicitly trusts the initial launcher via HTTPS hosting; independently verifying its detached signature remains an option. Trusted OS tools verify downloaded payloads against the pinned authority before bundled project programs execute.

**Decision:** Initial packaging targets Debian 12 and Ubuntu 24.04, x86-64, systemd/udev, glibc ≥2.36; build on Debian 12 and qualify both images. These are selected support targets, not currently qualified releases. Use only distro `apt-get` for approved missing packages; no generic distro abstraction or source-build fallback. Ship the project's patched picotool 2.3.1 as an authenticated host artifact for firmware/OTP paths, not an arbitrary distribution picotool. Runtime users need no Git/Rust/CMake/ARM compiler or Cardano CLI. Existing agent host-memory preflight remains unchanged, including its `cardano-node.service` constraint; the manager does not introduce node detection or configure around that constraint.

**Decision:** Discover qualified stable releases from the project's GitHub releases endpoint by default; treat API data as untrusted hints. Signed manifests determine versions, stable/prerelease channel, separate candidate/qualified status, platform and compatibility. Explicit `--version TAG` or local `--bundle` acceptance can admit an authenticated compatible candidate on reviewed disposable targets without claiming qualification. Display cache age and reverify offline bundles at use. No unattended changes. Authenticity alone is not proof of newest metadata, qualification or revocation freshness.

**Alternatives considered:** Extend the strict firmware manifest (unnecessary migration); checksums from the download site without independent authority (not authenticity); execute a fetched verifier first (circular trust); support all Linux distributions (unqualified claim).

## R5 — Compatibility, ownership and host changes

**Decision:** Each manifest names exact component digests, readable config/journal/receipt/installation schemas, USB/storage/security profiles, signed authorized compatible tuples and independent `qualification: candidate|qualified`. A selected combination must be explicitly authorized; unknown is blocked. Candidate testing uses explicit attended local-bundle admission with unchanged trust/state/hardware prerequisites. Final qualification promotes metadata only after evidence for unchanged tested payloads/source; no post-test rebuild or historical overwrite. No implicit data migrations or state rollback. Per-component choice remains confined to complete authorized tuples.

**Decision:** Install immutable component directories under `/usr/lib/pico2-kes-agent/components/<component>/<digest>/`; a generation directory links the selected tuple, and a single atomic `current` symlink selects it. Stable entry points in `/usr/bin` follow `current`. A protected ownership registry and public maintenance record identify approved paths, hashes, prior service state, and confirmed steps. Reuse existing config/state paths and system account. External/custom installations stay visible but are not silently adopted or overwritten.

**Rationale:** A single switch makes mixed-component selection coherent and avoids overwriting the running manager. Host configuration/service/udev changes still need per-file records because they cannot participate in that one atomic rename. Stage and fsync on the target filesystem; validate candidate configuration as the service identity before stopping/replacing. On failure, rollback binaries only after checking they can read current state; never restore old journals/configuration/device snapshots. Persist uncertain steps before proposing recovery.

**Self-update:** Stage the new tuple, leave the running executable intact, then offer explicit re-exec. Keep the old tuple until validation. A changed manager alone does not force daemon/firmware replacement. Lock host maintenance; revalidate ownership/digests immediately before privileged writes. Elevate only a finite reviewed host action via a verified manager invocation, not the full interactive UI; privileged code revalidates all untrusted plan fields.

**Alternatives considered:** In-place binary replacement (partial/self-update hazards); package-database adoption (external ownership conflicts); one fixed version for every component (misses selected combinations); automatic snapshot rollback (unsafe KES state rollback).

## R6 — Attended firmware maintenance and retention

**Decision:** Add attended `first-install` and normal `update` commands to trusted `tools/firmware.py`; neither exists yet. Implement `first-install --bundle DIR --record FILE [--apply]` before US2 commissioning for a factory/BOOTSEL-only target without an application serial/pin. Reuse verification, unambiguous attended board/mount selection, UF2 range checks and protected transfer records. The sole restricted commissioning daemon must then observe the selected compatible blank application before separately confirmed commissioning/pinning. Existing compatible blank applications skip flashing. Normal updates reuse transfer helpers but still capture complete pre-state and require the existing pin and retained-state comparison after reconnection. Neither path permits OTP or erasure.

**Evidence:** `README.md` firmware-update procedure uses the signed UF2, excludes storage `[0x10100000, 0x10308000)`, and requires post-reconnect identity/state checks. Current tool commands are verify/inspect/seal/provision/erase-state/reconcile-prepare, not normal update. Firmware image range is `[0x10000000, 0x10100000)`.

**Rationale:** A successful copy/flush is only a transfer checkpoint. Completion requires the pinned identity, selected build identifier, compatible storage, same pool/incarnation membership and accounted-for generation transitions. Advancing periods, staged-to-active transitions and certificate expiry are permitted only when bound evidence explains them. Unexplained disappearance is uncertain, not automatically accepted as expiry. Never reset/re-pin/recommission/restore older state to obtain a match.

**Alternatives considered:** Implement flashing in Rust too (duplicates dangerous logic); unattended serial guessing (wrong-device risk); compare snapshots byte-for-byte (rejects valid forward transitions); always reinstall old firmware after timeout (may be incompatible and outcome is unknown).

## R7 — Backup custody and provisioning handoffs

**Decision:** Primary mode handles public recipient/certificate/identity inputs and encrypted backups only. `--role backup` enables recipient creation/restoration after checking local role evidence before reading any private file. An active agent, known primary configuration/state or installation role contradicts backup use; inaccessible evidence is not absence. Installed CLI binaries alone are not evidence of a primary. No bypass; host history cannot be proven, so explain the operator's separate-host obligation.

**Evidence:** `src/backup` and `src/memory.rs` enforce protected buffers, no active swap, dump protection, strict evidence and no-clobber output. Existing CLI has no role detector. Foreground invocation of `recipient create` and `restore` retains passphrase interaction without exposing secrets in argv, environment, UI state, capture or logs.

**Decision:** Optional OTP uses existing foreground `provision --stage prepare|enable|lock`, read-only preview, original schema-2 records, physical confirmations and qualification evidence. Do not duplicate its state machine or expose `erase-state` in the manager. Only the original admitted pre-OTP `--resume` checkpoint and read-only `reconcile-prepare` are offered. Completion is observed locking, not hardware attestation; A2 qualification is required for writes.

**Rationale:** Existing tool ownership of secret/irreversible behavior is safer than TUI automation. Archive guidance is informational, never a new backup-readiness or activation approval gate. Cold certificate signing remains off-primary.

## R8 — Producer hardening exception

**Decision:** Validate operator-supplied concrete `.service` names (including escaped systemd names and concrete instances), reject traversal/control characters/empty template instances/other unit types; use argv, never shell interpolation. Install the existing drop-in at `/etc/systemd/system/<unit>.d/pico2-kes-memory.conf`, preserve unrelated files, run `systemctl daemon-reload`, offer approved restart only for selected running units. Leave stopped units stopped. Retain/list drop-ins on uninstall.

**Rationale:** This is a file-installation and systemd-command workflow, not a node or memory-policy audit. Existing normal daemon preflight is not redesigned. No dedicated producer test suite, multi-producer fixture or runtime-policy verification state machine is planned.

## R9 — Operator-led acceptance and quality scope

**Decision (refined after analysis, 2026-11-02):** End-user testing of packaged software remains primary. Retain existing affected checks, small behavioral checks and a bounded constitutional performance gate using Q1/Q3 and existing Cargo tooling, not a new manager suite or benchmark framework. Freeze a comparable baseline before candidate evaluation; record controlled conditions, measurement tools, noise-aware thresholds and one demonstrated slowdown detection. High coverage, elaborate property/mutation/fuzz campaigns and separate microbenchmark suites remain excluded.

**Rationale:** This is user-facing orchestration over existing lifecycle, crypto, custody and firmware authorities. Real workflows and small safety checks are more useful than broad mock-heavy suites or coverage scores. Absolute timed full-capacity observations satisfy SC-002, while the separately defined bounded comparison and calibration supply constitutional regression evidence without a new benchmark framework. Neither can substitute for the other.

**Sensor assessment:** Earlier MCP research inspected behavioral, integration, property, mutation, line-coverage, fuzzing, load and static-security entries. For this refinement, full [SO-002b](https://softwareobservatory.com/sensors/example-based-tests/), [SO-002c](https://softwareobservatory.com/sensors/integration-tests/) and [SO-006e](https://softwareobservatory.com/sensors/load-testing/) entries were reconsulted. Select existing behavioral checks, actual operator-executed integration and measured 64-pool behavior. The integration sensor describes the real end-to-end exercise; it does not require writing a new automated suite. The [quality contract](contracts/quality.md) records commands/scenarios, pass rules, evidence and explicit non-selection of the heavier campaigns.

**Limitations and alternatives:** Manual scenarios may miss rare races and input combinations; retain shared-component regressions and small checks for new critical behavior. Coverage/mutation reports do not replace successful user workflows. No software-only run proves OTP safety, physical flash preservation or independent attestation. Selected catalog families are behavioral and runtime; other families remain gaps, partly addressed by ordinary compiler/linter checks, trust-boundary review and negative scenarios without claims of exhaustive analysis.

**Governance:** This is prospective feature-specific selection, not a waiver of any constitutional MUST or failed reading. Operator-led scope does not remove benchmark baseline, environment, threshold, tool and sensitivity obligations. The [quality contract](contracts/quality.md#required-project-performance-gate) defines their bounded procedure and activation prerequisites; actual baseline/tool approval and calibration are still implementation acceptance work. The separately approved constitution 2.0.0 amendment on 2026-11-02 aligns recovery/native qualification with feature 001's pragmatic baseline. Its synchronized guidance and the quality contract's inherited release gate require candidate-applicable evidence before T070 promotion; existing checks, safety validation and qualified storage/OTP evidence remain mandatory.

## Resolution and delivery limits

The design now specifies UI/observation interfaces, distro/ABI, trust/ownership, signed candidate admission versus final qualification, first-install versus pinned update, custody/OTP and complete keyboard/no-color acceptance. New executable contracts remain implementation work, not existing commands. Signing access, compatible signed candidates, separately required hardware/tool/image qualification, a frozen comparable performance baseline and exercised calibration, candidate sensor readings, five-operator evidence and hardware results remain explicit prerequisites; this design supplies none of those results.
