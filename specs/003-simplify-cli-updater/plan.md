# Implementation Plan: Simplify CLI, Daemon Lifecycle, and Software Updater

**Branch**: `003-simplify-cli-updater` | **Date**: 2026-11-20 | **Spec**: [`spec.md`](spec.md)

**Input**: Feature specification from `/specs/003-simplify-cli-updater/spec.md`

## Summary

Redesign `pico2-kes-agent` around its core purpose—persistent multi-pool Cardano KES current-key delivery from a Pico 2 to `cardano-node`—by splitting host tooling into four focused, single-purpose Rust binaries (`pico2-kes-agentd`, `p2kes`, `p2kesup`, `p2kes-flash`), deleting the 36,261-line `src/manager/` god-manager and its Ratatui TUI (`ratatui`/`crossterm`), eliminating Python from operator hosts, establishing one canonical release-verification module (`src/release.rs`), collapsing the operator CLI to ~10 direct commands and 4-input offline backup recovery, and fixing five core daemon runtime bugs (dynamic pool polling, multiplexed socket accept loop, graceful shutdown drain, mutation-gated reconciliation, and bounded journal compaction).

## Technical Context

**Language/Version**: Rust edition 2024 (pinned toolchain `rustc 1.99.1` per `rust-toolchain.toml` / `qualification/tools.toml`); POSIX `sh` for thin `install.sh` bootstrapper.
**Primary Dependencies**: Existing workspace crates (`kes-core`, `kes-protocol`, `nusb`, `serde`, `serde_json`, `rustix`, `argon2`, `zeroize`, `sha2`, `blake2`, `chacha20poly1305`, `ed25519-dalek`, `hpke`, `x25519-dalek`). **Removed**: `ratatui`, `crossterm`, and redundant `libc` calls replaced by `rustix`. **External runtime tools**: `gpgv`/`openssl` for release trust-root verification; bundled patched `picotool` v2.3.1 for `p2kes-flash` hardware/OTP operations. Zero Python runtime on operator hosts.
**Storage**: Append-only checksummed binary operation journal (`/var/lib/pico2-kes-agent/operations.journal`, with atomic compaction at 16 MiB); JSON install record (`/usr/local/share/pico2-kes-agent/installed.json`); static configuration (`/etc/pico2-kes-agent/config.json`). On-device RP2350 flash storage v2 unchanged.
**Testing**: `cargo test` (unit + integration + `proptest` property tests), `cargo clippy -- -D warnings`, `cargo audit`, `cargo deny check`, `cargo run -p qualification -- load`, and real Pico 2 A2 hardware re-qualification for `p2kes-flash` (flash/wipe/OTP).
**Target Platform**: Debian 12, Ubuntu 24.04, Ubuntu 26.04 x86-64 Linux with systemd, udev, and glibc >= 2.36; RP2350 Pico 2 A2 firmware unchanged.
**Project Type**: Multi-binary Linux daemon + CLI + updater + firmware flasher workspace.
**Performance Goals**: Unified 64-pool `p2kes status --json` <100 ms locally regardless of journal size (10 vs. 10,000 entries); idle daemon wakeups across 64 pools <5 wakeups/sec; runtime pool enrollment delivers active key within 10s of certification without daemon restart.
**Constraints**: Host-only management `MAX_FRAME` raised from 16 KiB to 128 KiB (zero impact on RP2350 firmware); no systemd or `/etc/fstab` mutations in `p2kesup`; no breaking changes to commissioned Pico 2 storage, USB protocol v1, KES Service V2 node sockets, or encrypted backup format; host management/updater code reduced ≥85% vs. baseline `src/manager/` (36,261 LOC).
**Scale/Scope**: 1 operator per Linux block-producer host, 1 USB-attached Pico 2, up to 64 stake pools (64 active + 64 staged KES generations), 1 isolated offline backup host.

## Constitution Check

*GATE: Evaluated against `.specify/memory/constitution.md` v3.0.0 before Phase 0 research and re-evaluated after Phase 1 design.*

| Principle / Constraint | Pre-Design | Post-Design | Notes |
| --- | --- | --- | --- |
| **I. Explicit Scope & Correctness** | PASS | PASS | Strictly preserves persistent KES current-key provider scope; no HSM, no remote signing, no cold-key custody, no plaintext import. |
| **II. Verifiable Behavior** | PASS | PASS | Retains all core host/firmware/backup tests; mandates real Pico 2 A2 hardware re-qualification for native Rust `p2kes-flash` before production release (`contracts/quality.md`). |
| **III. Stable & Explicit Interfaces** | PASS | PASS | Explicit contracts in `contracts/cli.md` and `contracts/updater-and-flash.md`; explicit pool/incarnation/generation/operation IDs preserved on the wire; uncertain mutations reconciled via daemon journal without blind retry; migration path documented. |
| **IV. Security at Trust Boundaries** | PASS | PASS | Socket access remains the authorization boundary; operational keys remain transient; `p2kes backup restore` verifies Ed25519 origin signature against trusted `--device-identity` before decryption; single canonical release signature verifier (`src/release.rs`). |
| **V. Simple, Maintainable Rust** | PASS | PASS | Deletes ~36,261 LOC of `src/manager/`, removes `ratatui`/`crossterm`, eliminates per-pool sleep-polling threads and read-path journal replays, zero compatibility shims. |
| **VI. Software Observatory Quality Gate** | PASS | PASS | Live MCP consulted (`suggest_sensors`, full `get_sensor` entries for `SO-001`, `SO-002b`, `SO-002c`, `SO-005e`, `SO-006e`, and `stack_coverage`); gates, limitations, and gaps recorded in `contracts/quality.md`. |
| **Technical Constraint: CLI binary name** | **AMENDMENT NEEDED** | **AMENDMENT NEEDED** | Constitution v3.0.0 line 145 names `pico2-kes-agent-cli`. Per Clarification Q3, renaming to `p2kes` requires ratifying Constitution **v4.0.0** (MAJOR amendment) before implementation acceptance. Tracked in Complexity Tracking below. |

## Project Structure

### Documentation (this feature)

```text
specs/003-simplify-cli-updater/
├── plan.md                        # This file (/speckit.plan output)
├── research.md                    # Phase 0 design decisions & rationale
├── data-model.md                  # Phase 1 entities, schemas, state transitions
├── quickstart.md                  # Phase 1 end-to-end validation scenarios (Q1–Q5)
├── checklists/
│   └── requirements.md            # Spec quality checklist (16/16 passing)
├── contracts/
│   ├── cli.md                     # p2kes CLI grammar & management wire protocol
│   ├── updater-and-flash.md       # p2kesup, p2kes-flash, install.sh, /usr/local layout
│   └── quality.md                 # Software Observatory sensors, hardware gate, perf gate
└── tasks.md                       # Phase 2 output (/speckit.tasks - not yet created)
```

### Source Code (repository root)

```text
Cargo.toml                         # 4 binaries: pico2-kes-agentd, p2kes, p2kesup, p2kes-flash
                                   # Removes: ratatui, crossterm; removes src/bin/pico2-kes-agent-cli.rs
install.sh                         # Slim POSIX bootstrapper: displays apt --simulate proposal,
                                   # downloads & verifies bundle, invokes `sudo p2kesup install`
deploy/
├── pico2-kes-agentd.service       # Updated ExecStart=/usr/local/bin/pico2-kes-agentd
├── 70-pico2-kes-agent.rules       # Static udev rule for Pico 2 USB access
├── cardano-node-memory-hardening.conf
└── config.example.json            # Documented example config

crates/
├── kes-core/                      # Unchanged crypto, KES lifecycle, storage model
└── kes-protocol/
    └── src/management.rs          # MAX_FRAME = 131_072; unified `status` action; drop 7 legacy read actions

firmware/                          # Unchanged RP2350 firmware

src/
├── lib.rs                         # Exports: backup, build_info, cli, config, daemon, files, flash, memory, release, updater
├── build_info.rs
├── config.rs
├── files.rs
├── memory.rs
├── release.rs                     # NEW (~350 LOC): single canonical OpenPGP/secp256k1/SHA-256 bundle verifier
├── updater.rs                     # NEW (~350 LOC): atomic /usr/local install/update/uninstall/status
├── flash/                         # NEW (~900 LOC): native Rust p2kes-flash (verify, flash, wipe, otp via picotool)
│   ├── mod.rs
│   ├── uf2.rs                     # Native ELF/UF2 validation & BOOTSEL mass-storage copy
│   └── picotool.rs                # Bounded picotool v2.3.1 subprocess wrapper & OTP/wipe policy checks
├── backup/
│   ├── cbor.rs
│   ├── mod.rs
│   ├── recipient.rs
│   └── recover.rs                 # Updated: read bindings from signed CBOR artifact; verify against device.json
├── cli/
│   ├── mod.rs                     # Simplified ~10 commands; implicit incarnation/staged/revision resolution; no receipts
│   ├── client.rs                  # Uses rustix; removes --expected-peer-pid/uid
│   └── status.rs                  # Unified human + JSON rendering for device, security, and 0..=64 pools
├── daemon/
│   ├── journal.rs                 # Adds atomic compaction at 16 MiB preserving active enrollments + recent 256
│   ├── management.rs              # Unified `status` handler; daemon-owned `operation.reconcile`; drop legacy reads
│   ├── runtime.rs                 # Dynamic LivePoolSet polling; rustix::event::poll accept loop; graceful shutdown drain;
│   │                              # mutation-gated endpoint reconciliation; non-fatal spawn error handling
│   └── (context.rs, mod.rs, node_service.rs, registry.rs, scheduler.rs, sockets.rs, status.rs, usb.rs)
└── bin/
    ├── pico2-kes-agentd.rs        # Unchanged daemon entry point
    ├── p2kes.rs                   # NEW (replaces pico2-kes-agent-cli.rs)
    ├── p2kesup.rs                 # Replaced: thin CLI dispatch to src/updater.rs
    └── p2kes-flash.rs             # NEW: thin CLI dispatch to src/flash/

# DELETED:
# - src/manager/ (all 44 files, 36,261 LOC)
# - src/bin/pico2-kes-agent-cli.rs
# - src/cli/receipt.rs (no longer needed once daemon owns reconciliation)
# - tools/firmware.py runtime operator usage (maintainer seal/authorize tooling stays dev-only in tools/)

tests/
├── backup_restore.rs              # Updated for 4-input `p2kes backup restore`
├── management_recovery.rs         # Updated for daemon-owned `p2kes reconcile` & journal compaction
├── node_service.rs                # Updated + dynamic runtime pool enrollment/deletion test (SC-004)
├── operator_cli.rs                # Updated for `p2kes` 10-command surface & unified `status`
├── service_lifecycle.rs           # Updated + graceful shutdown drain & idle wakeup check (SC-005)
├── single_pool.rs                 # Updated for `p2kes`
└── updater_and_flash.rs           # NEW: atomic install/update/uninstall, tampered bundle refusal, UF2/policy validation
```

**Structure Decision**: Single Rust root package (`pico2-kes-agent`) with 4 lean `[[bin]]` targets sharing `src/release.rs`, `src/files.rs`, and `src/build_info.rs`, keeping `crates/kes-core`, `crates/kes-protocol`, and `firmware/` untouched except for the host-only `MAX_FRAME` and management action cleanup in `crates/kes-protocol/src/management.rs`. Total host management/updater code drops from **36,261 LOC (`src/manager/`)** to **~1,600 LOC (`src/release.rs` + `src/updater.rs` + `src/flash/`)**—a **>95% reduction** (exceeding SC-006's 85% target).

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
| --- | --- | --- |
| **Constitution v3.0.0 Technical Constraint (CLI binary name `pico2-kes-agent-cli` → `p2kes`)** | Operator ergonomics and clean cutover (Clarification Q3): eliminates a 19-character daily command name without retaining a compatibility symlink/shim (Constitution Principle V). | Keeping `pico2-kes-agent-cli` + symlink was explicitly rejected by maintainer in Clarification Q3; will be resolved by ratifying Constitution **v4.0.0** as the first task before implementation. |
