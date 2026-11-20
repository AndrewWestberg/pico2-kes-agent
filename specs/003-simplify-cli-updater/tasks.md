---
description: "Task list for Simplify CLI, Daemon Lifecycle, and Software Updater"
---

# Tasks: Simplify CLI, Daemon Lifecycle, and Software Updater

**Input**: Design documents from `/specs/003-simplify-cli-updater/`
**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/cli.md`, `contracts/updater-and-flash.md`, `contracts/quality.md`, `quickstart.md`

**Organization**: Tasks are grouped by user story (`US1`–`US5`) so each story is independently implementable and testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: User story label (`[US1]`–`[US5]`) for story-phase tasks only

---

## Phase 1: Setup & Legacy Removal

**Purpose**: Ratify the constitutional binary rename, remove the obsolete 36,261-LOC manager/TUI and unused UI dependencies, and update workspace manifests.

- [x] T001 Ratify Constitution v4.0.0 in `.specify/memory/constitution.md` updating Technical Constraints to rename `pico2-kes-agent-cli` to `p2kes` and list `p2kesup` and `p2kes-flash` as established Rust binaries
- [x] T002 Remove `ratatui` and `crossterm` dependencies, remove `[[bin]] name = "pico2-kes-agent-cli"`, and declare `[[bin]]` targets `pico2-kes-agentd`, `p2kes` (`src/bin/p2kes.rs`), `p2kesup` (`src/bin/p2kesup.rs`), and `p2kes-flash` (`src/bin/p2kes-flash.rs`) in `Cargo.toml`
- [x] T003 [P] Delete legacy manager module directory `src/manager/` (all 44 files), `src/bin/pico2-kes-agent-cli.rs`, and `src/cli/receipt.rs`, and update module exports in `src/lib.rs`
- [x] T004 [P] Replace remaining raw `unsafe { libc::... }` file/socket/stat calls in `src/config.rs`, `src/cli/client.rs`, and `src/files.rs` with safe `rustix` equivalents where available

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared protocol framing, unified status action, and the single canonical release/signature verifier required by multiple stories.

**⚠️ CRITICAL**: No user story implementation can begin until this phase is complete.

- [x] T005 Raise host-only management `MAX_FRAME` from `16_384` to `131_072` (128 KiB), add `Action::Status` (optional `pool_id`), update `Action::OperationReconcile` to accept empty `{}` arguments, and remove legacy read actions (`device.status`, `device.security`, `device.inventory`, `host.observe`, `device.info`, `pool.list`, `pool.status`, `pool.observe`) in `crates/kes-protocol/src/management.rs`
- [x] T006 Update `crates/kes-protocol/tests/management.rs` to validate 128 KiB management framing, `Action::Status`, and rejection of removed legacy actions
- [x] T007 Implement the canonical release/signature verifier in `src/release.rs`: pinned OpenPGP primary/signer fingerprints (`PRIMARY`, `SIGNER`), delegated secp256k1 distribution-key verification via `gpgv`/`openssl`, `ReleaseManifest` (`schema_version == 2`, SemVer `version` ASCII `[A-Za-z0-9._-]` max 64 chars, `platform` `x86_64`/`linux`/`min_glibc = "2.36"`, `usb_protocol_major == 1`), and `ReleaseArtifact` path confinement (no `..`, leading `/`, or symlinks) + exact `size` and 64-hex `sha256` verification
- [x] T008 [P] Add unit and negative-input tests (tampered manifest signature, wrong `schema_version`, path traversal `..`, mismatched `sha256`) in `src/release.rs`

**Checkpoint**: Foundation ready — `cargo check --locked -p kes-protocol` and `src/release.rs` tests pass; user story phases can now proceed in parallel.

---

## Phase 3: User Story 1 - Everyday KES Lifecycle Through a Simple Operator CLI (Priority: P1) 🎯 MVP

**Goal**: Deliver the 10-workflow `p2kes` CLI with unified `status`, combined `key rotate`, automatic incarnation/staged-generation/revision resolution, interactive confirmation on destructive commands, and daemon-owned `reconcile` without receipt files or `--expected-peer-*` flags.

**Independent Test**: Run `tests/operator_cli.rs` and `tests/single_pool.rs` against a running `pico2-kes-agentd` with simulated USB transport exercising commission, `backup set-recipient`, `pool add`, `key rotate`, `key install-cert`, `status`, `key discard`, `pool rm`, and `reconcile`.

### Implementation for User Story 1

- [x] T009 [P] [US1] Implement daemon-side `status` management handler returning `UnifiedStatus` (`health`, `revision`, `pending_operation`, `device` including `usb_protocol_major` and `security`, and `pools` 0..=64 with `active` and `staged` summaries) in `src/daemon/management.rs`
- [x] T010 [P] [US1] Update `operation.reconcile` in `src/daemon/management.rs` to reconcile the sole pending journal mutation when called with empty `{}` arguments (no client-supplied `operation_id`/`request_digest` required)
- [x] T011 [US1] Create `src/bin/p2kes.rs` entry point handling `--help`, `--version [--json]`, and dispatching to `pico2_kes_agent::cli::run`
- [x] T012 [US1] Rewrite `src/cli/mod.rs` to implement the 10-workflow command surface per `contracts/cli.md` (`status [POOL_ID]`, `commission [--serial HEX] [--out FILE]`, `pool add`, `pool rm`, `key rotate`, `key export`, `key install-cert`, `key discard`, `reconcile`, `backup keygen`, `backup set-recipient`, `backup restore`), removing `--expected-peer-pid`, `--expected-peer-uid`, and mandatory `--receipt` / `--expected-revision` / `--incarnation`
- [x] T013 [US1] Implement implicit state resolution in `src/cli/mod.rs`: when `--expected-revision` or incarnation/staged generation is omitted on `pool rm`, `key rotate`, `key export`, `key install-cert`, or `key discard`, query `status` first, fail closed on ambiguous/missing state (e.g., occupied staged slot on `rotate`, no staged slot on `discard`), and submit explicit IDs + revision on the wire
- [x] T014 [US1] Implement combined `key rotate POOL_ID --vkey-out FILE --backup-out FILE` (calling `generation.create`, `generation.public_key`, and `generation.artifact`, writing both files no-clobber) and standalone `key export` re-export in `src/cli/mod.rs`
- [x] T015 [P] [US1] Update `src/cli/status.rs` to render `UnifiedStatus` cleanly for human operators (device health/identity/security, pending operation warning, and all 0..=64 pools) and pass through `--json`
- [ ] T016 [US1] Update `tests/operator_cli.rs`, `tests/single_pool.rs`, and `tests/management_recovery.rs` to verify the `p2kes` command surface, implicit resolution, destructive `y/N` confirmation, partial-failure `key rotate` (`--backup-out` collision) recovery via `p2kes key export` without regeneration, and receipt-free `p2kes reconcile`

**Checkpoint**: User Story 1 (`p2kes`) is complete and independently testable.

---

## Phase 4: User Story 2 - Reliable Live Daemon Operations Across Pool Changes and Restarts (Priority: P1)

**Goal**: Fix all five daemon runtime bugs: dynamic runtime pool polling (`LivePoolSet`), single-thread `rustix::event::poll` socket multiplexing, graceful shutdown drain, mutation-gated endpoint reconciliation, bounded journal compaction at 16 MiB, and clear firmware-protocol mismatch reporting.

**Independent Test**: Run `tests/node_service.rs`, `tests/service_lifecycle.rs`, and `cargo run --locked -p qualification -- load` verifying: zero-pool startup + runtime `pool add` delivers keys without restart (SC-004), runtime `pool rm` stops polling, `SIGTERM` drains in-flight mutations, 16 MiB journal compaction preserves active enrollments, and 64-pool idle wakeups <5/sec (SC-005).

### Implementation for User Story 2

- [ ] T017 [US2] Add `LivePoolSet { version: u64, pools: Vec<(PoolBinding, PoolSubscription)> }` (`pools.len() <= 64`) in `src/daemon/runtime.rs`; update `LiveEndpoints::reconcile()` to mutate `LivePoolSet`, bump `version`, and wake the accept loop; always spawn `poll_pools` in `RunMode::Normal` and refresh its snapshot whenever `version` changes
- [ ] T018 [US2] Replace the per-pool `serve_pool` `accept()` + `sleep(50ms)` threads in `src/daemon/runtime.rs` with a single `rustix::event::poll` accept loop over the management listener, all active pool listeners, and a self-pipe/eventfd wakeup
- [ ] T019 [US2] Implement graceful shutdown drain in `src/daemon/runtime.rs`: on `SIGTERM`/`SIGINT`, stop accepting new management connections, wait up to `MANAGEMENT_TIMEOUT` (5s) via `Condvar` for `active_management == 0` before joining `poller`, and log+drop instead of returning `Err` when management thread spawn fails
- [x] T020 [US2] Restrict `management.reconstructed_registry()` + `endpoints.reconcile()` in `serve_management` (`src/daemon/runtime.rs`) to run **only** when a mutation commits `CommittedResult::Enrolled` or `CommittedResult::Deleted`, never on read-only requests
- [x] T021 [P] [US2] Implement atomic journal compaction in `src/daemon/journal.rs`: when file size >= `16 * 1024 * 1024` (16 MiB) and `pending().is_none()`, retain the latest `Enrolled` record per active pool plus the last 256 completed records, write `operations.journal.compact` (`0600`), `sync_all()`, `rename()` over `operations.journal`, and `sync_all()` the parent directory
- [x] T022 [P] [US2] Detect USB firmware protocol major version mismatch on connect in `src/daemon/usb.rs` / `src/daemon/management.rs`, fail closed for unsafe operations, and populate `health = "incompatible_firmware"` with `usb_protocol_major`, `required_protocol_major`, and `sudo p2kes-flash flash` remediation guidance
- [ ] T023 [US2] Add integration and property tests in `tests/node_service.rs`, `tests/service_lifecycle.rs`, and `src/daemon/journal.rs` covering dynamic runtime pool add/remove, shutdown drain, firmware mismatch reporting, 10k-entry status latency (<100 ms), and journal compaction equivalence

**Checkpoint**: User Stories 1 and 2 are both complete and independently verified.

---

## Phase 5: User Story 3 - Focused Software Updater Separate from Firmware Flashing (Priority: P2)

**Goal**: Build the ~350-LOC `p2kesup` binary (`install`, `update`, `uninstall`, `status`, `--version`), slim `install.sh` displaying `apt-get --simulate` proposals without embedded Python, and ship static `deploy/` artifacts.

**Independent Test**: Run `tests/updater_and_flash.rs` against temporary root/bundle fixtures verifying `install`, tampered-bundle rejection, atomic `update` with firmware-change notification and zero systemd calls, and clean `uninstall`.

### Implementation for User Story 3

- [x] T024 [US3] Implement `src/updater.rs`: `InstalledState` (`/usr/local/share/pico2-kes-agent/installed.json`), `install`, `update`, `uninstall`, and `status` using `src/release.rs` verification, staging temp files + `fsync` + atomic `rename` into `/usr/local/bin` and `/usr/local/share/pico2-kes-agent`, printing `sudo systemctl restart pico2-kes-agentd` (and `sudo p2kes-flash flash` when `firmware_version` changes) without touching systemd or host OS config
- [x] T025 [US3] Rewrite `src/bin/p2kesup.rs` as a thin CLI entrypoint for `p2kesup install|update|uninstall|status|--help|--version [--json]` dispatching to `src/updater.rs`
- [x] T026 [P] [US3] Trim `install.sh` to a thin POSIX bootstrapper that prints `apt-get --simulate install` output to `/dev/tty` before prompting `y/N`, removes `python3` prerequisite and the 350-line embedded Python verifier, verifies the downloaded bundle via `gpgv`/`openssl`, and runs `sudo <bundle>/p2kesup install --bundle <bundle>`
- [x] T027 [P] [US3] Update static deployment files in `deploy/pico2-kes-agentd.service` (`ExecStart=/usr/local/bin/pico2-kes-agentd`), `deploy/config.example.json`, `deploy/70-pico2-kes-agent.rules`, and `deploy/cardano-node-memory-hardening.conf`, and delete obsolete `deploy/install.sh` and `deploy/uninstall.sh` wrappers superseded by `install.sh` + `p2kesup`
- [x] T028 [US3] Add integration tests in `tests/updater_and_flash.rs` covering `p2kesup install`, tampered bundle fail-closed, atomic `update` firmware-change notice, and `uninstall` preserving `/etc/pico2-kes-agent/` and `/var/lib/pico2-kes-agent/`

**Checkpoint**: User Story 3 (`p2kesup` + `install.sh` + `deploy/`) is complete and independently testable.

---

## Phase 6: User Story 4 - Explicit, Standalone Firmware Installation and Update (Priority: P2)

**Goal**: Deliver native Rust `p2kes-flash` (`verify`, `flash`, `wipe`, `otp`) sharing `src/release.rs`, removing Python from operator hosts while preserving all RP2350 policy, UF2, and OTP safety checks via bundled `picotool` v2.3.1.

**Independent Test**: Run `p2kes-flash` unit/property tests in `tests/updater_and_flash.rs` (UF2/ELF parsing, policy validation, malformed input rejection) plus real Pico 2 A2 hardware smoke for `verify`, `flash`, `wipe`, and `otp`.

### Implementation for User Story 4

- [x] T029 [P] [US4] Implement native ELF/UF2 header and sector validation (`FIRMWARE_START`, `FIRMWARE_END`, 512-byte UF2 block alignment, page match) and BOOTSEL USB mass-storage discovery/copy in `src/flash/uf2.rs`
- [x] T030 [P] [US4] Implement bounded `picotool` v2.3.1 subprocess wrapper, policy validation (`rp2350-signed-msd-v1`, A2/A4 stepping, fitted 4-MiB flash JEDEC/SFDP check), `wipe`, and 3-stage `otp` (`prepare`, `enable`, `lock`) attended confirmation flows in `src/flash/picotool.rs`
- [x] T031 [US4] Wire `src/flash/mod.rs` (`verify`, `flash`, `wipe`, `otp`) using `src/release.rs` canonical verification and create `src/bin/p2kes-flash.rs` CLI entrypoint per `contracts/updater-and-flash.md`
- [x] T032 [US4] Add `proptest` and unit tests for `src/flash/uf2.rs` and `src/flash/picotool.rs` policy/UF2 rejection in `tests/updater_and_flash.rs`
- [x] T033 [US4] Update `.github/workflows/release.yml` and `tools/publish_release.py` to package the 4-binary release tuple (`pico2-kes-agentd`, `p2kes`, `p2kesup`, `p2kes-flash`, `picotool`, firmware, `deploy/`) under `schema_version = 2`

**Checkpoint**: User Story 4 (`p2kes-flash`) is complete; hardware re-qualification on Pico 2 A2 is tracked in Phase 8.

---

## Phase 7: User Story 5 - Streamlined Offline Backup Key Creation and Recovery (Priority: P3)

**Goal**: Simplify `p2kes backup restore` to 4 required inputs (`--artifact`, `--key`, `--device-identity`, `--out`), verifying the signed CBOR artifact against `--device-identity` and writing the owner-restricted key immediately on valid verification.

**Independent Test**: Run `tests/backup_restore.rs` completely offline with no daemon or device attached, testing 4-input restore, tampered artifact/wrong `--device-identity` fail-closed, and optional assertion flag mismatch fail-closed.

### Implementation for User Story 5

- [x] T034 [US5] Update `src/backup/recover.rs` to extract `device`, `pool`, `incarnation`, `generation`, and `verification_key` directly from the signed CBOR artifact header, verify `device` and Ed25519 signature against `DeviceIdentityFile` (`--device-identity`), check any optional assertion flags (`--pool`, `--incarnation`, `--generation`, `--verification-key`), and decrypt/verify `SecretBuffer` immediately
- [x] T035 [US5] Wire `p2kes backup keygen`, `p2kes backup set-recipient`, and 4-input `p2kes backup restore` (printing verified device, pool, incarnation, generation, and verification key to stdout) in `src/cli/mod.rs`
- [x] T036 [US5] Update `tests/backup_restore.rs` to test 4-input offline `p2kes backup restore`, tampered artifact rejection, wrong `--device-identity` rejection, and optional assertion flag mismatch rejection

**Checkpoint**: All 5 user stories are complete and independently testable.

---

## Phase 8: Polish, Migration Docs, and Quality/Observatory Gates

**Purpose**: Document migration from legacy `p2kesup`/`pico2-kes-agent-cli`, verify code-size reduction (SC-006), and execute all Software Observatory and hardware qualification gates.

- [x] T037 [P] Update `README.md` and add a legacy-to-simplified migration guide (`p2kesup` / `pico2-kes-agent-cli` → `p2kes` / `p2kesup` / `p2kes-flash`) in `docs/migration.md`
- [x] T038 [P] Update `tests/host_security.rs` (or remove obsolete `src/manager` references) so the entire workspace test suite compiles and passes cleanly
- [ ] T039 Run Software Observatory gates per `contracts/quality.md`: `cargo fmt --all --check`, `cargo clippy --locked --workspace --exclude pico2-kes-firmware --all-targets -- -D warnings`, `cargo test --locked --workspace --exclude pico2-kes-firmware --features kes-core/qualification`, `cargo audit`, `cargo deny check`, and `cargo run --locked -p qualification -- load`
- [ ] T040 Measure SC-005 (64-pool `p2kes status --json` <100 ms with 10k journal entries; idle wakeups <5/sec) and SC-006 (host management/updater LOC reduction ≥85% vs. 36,261 LOC baseline), execute `specs/003-simplify-cli-updater/quickstart.md` Q1–Q5, and record real Pico 2 A2 hardware re-qualification evidence for `p2kes-flash` (`verify`, `flash`, `wipe`, `otp`) under `evidence/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: Starts immediately; T001–T004 prepare the workspace and remove `src/manager/`.
- **Foundational (Phase 2)**: Depends on Phase 1; BLOCKS all user stories (`kes-protocol` 128 KiB `MAX_FRAME` + `Action::Status` and `src/release.rs` verifier).
- **User Stories (Phases 3–7)**: All depend on Phase 2 completion and can run in parallel or in priority order:
  - **US1 (`p2kes` CLI, P1)** & **US2 (Daemon runtime, P1)**: Core MVP; T009/T010 (`src/daemon/management.rs`) and T017–T020 (`src/daemon/runtime.rs`) touch different daemon files and can run concurrently.
  - **US3 (`p2kesup`, P2)** & **US4 (`p2kes-flash`, P2)**: Independent of US1/US2 once `src/release.rs` (T007) is complete.
  - **US5 (`p2kes backup restore`, P3)**: Depends on T012 (`src/cli/mod.rs` skeleton) or can be developed in `src/backup/recover.rs` (T034) in parallel with US1.
- **Polish & Gates (Phase 8)**: Depends on Phases 3–7.

### Parallel Opportunities

```bash
# Phase 2 parallel batch (after T005):
T006 (crates/kes-protocol/tests/management.rs) | T007 (src/release.rs)

# Phase 3 + Phase 4 P1 parallel batch:
T009/T010 (src/daemon/management.rs) | T017-T020 (src/daemon/runtime.rs) | T021 (src/daemon/journal.rs)

# Phase 5 + Phase 6 P2 parallel batch (after T007):
T024-T025 (src/updater.rs) | T026 (install.sh) | T027 (deploy/*) | T029 (src/flash/uf2.rs) | T030 (src/flash/picotool.rs)
```

---

## Implementation Strategy

### MVP First (Phases 1–4: US1 + US2)

1. Complete Phase 1 (Constitution v4.0.0 amendment + delete `src/manager/` + `ratatui`/`crossterm` removal) and Phase 2 (`kes-protocol` + `src/release.rs`).
2. Complete Phase 3 (**US1**: `p2kes` 10-workflow CLI) and Phase 4 (**US2**: daemon dynamic polling, multiplexed `poll()`, shutdown drain, 16 MiB compaction).
3. **STOP and VALIDATE**: Run `cargo test` + `quickstart.md` Q2–Q3 to verify the core daemon and CLI work cleanly end to end.

### Incremental Delivery

4. Add Phase 5 (**US3**: `p2kesup` + slim `install.sh` + static `deploy/`) → validate Q1.
5. Add Phase 6 (**US4**: native Rust `p2kes-flash`) → validate Q4 + real Pico 2 A2 hardware re-qualification.
6. Add Phase 7 (**US5**: 4-input offline `p2kes backup restore`) → validate Q5.
7. Finish Phase 8 (migration docs, full Observatory & performance gates).
