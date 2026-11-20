# Phase 0 Research: Simplify CLI, Daemon Lifecycle, and Software Updater

**Feature**: `003-simplify-cli-updater` | **Date**: 2026-11-20

## R1. Four-Binary Rust Architecture & Legacy Manager Deletion

- **Decision**: Replace the 3-binary layout (`pico2-kes-agentd`, `pico2-kes-agent-cli`, `p2kesup` with 36,261 LOC `src/manager/`) with a clean 4-binary Rust workspace (`pico2-kes-agentd`, `p2kes`, `p2kesup`, `p2kes-flash`), deleting `src/manager/` completely along with `ratatui` and `crossterm`.
- **Rationale**: Each executable owns exactly one job:
  - `pico2-kes-agentd`: sole USB owner, KES Service V2 socket server, durable operation journal.
  - `p2kes`: ~10 direct operator CLI commands over `management.sock` + offline backup keygen/restore.
  - `p2kesup`: ~300–500 LOC `rustup`-style system updater (`install`, `update`, `uninstall`, `--version`) targeting `/usr/local/bin` and `/usr/local/share/pico2-kes-agent` via `sudo`; never touches systemd or hardware.
  - `p2kes-flash`: native Rust standalone firmware tool (`verify`, `flash`, `wipe`, `otp`) sharing the canonical verifier with `p2kesup`; eliminates Python from operator hosts.
- **Alternatives considered**:
  - *Keep `tools/firmware.py` as `p2kes-flash`*: Lower initial effort, but retains Python 3 as an operator runtime prerequisite and duplicates release/signature verification across Python and Rust. Rejected per clarification Q4.
  - *Keep `pico2-kes-agent-cli` + `p2kes` symlink*: Avoids constitutional amendment, but retains legacy naming and symlink clutter. Rejected per clarification Q3.

## R2. Single Canonical Release & Signature Verifier

- **Decision**: Implement one shared Rust module (`src/release.rs`) containing the pinned OpenPGP primary/signer fingerprints, delegated secp256k1 distribution-key verification, release manifest parsing, and SHA-256 artifact verification. Both `p2kesup` and `p2kes-flash` call `src/release.rs`. Trim `install.sh` to a thin POSIX bootstrapper that displays proposed `apt-get` changes before confirmation, downloads the signed release bundle + checksum/signature, verifies `p2kesup` via `gpgv`/`openssl` (or runs the verified `p2kesup install --bundle DIR`), and removes the duplicated 350-line embedded Python verifier.
- **Rationale**: Eliminates the current three-way duplication of hardcoded PGP fingerprints and verification logic across `install.sh`, `src/manager/release.rs`, and `tools/firmware.py`.
- **Alternatives considered**:
  - *Keep embedded Python verifier in `install.sh`*: Re-introduces Python runtime dependency on operator hosts and duplicates trust roots. Rejected.

## R3. Native Rust `p2kes-flash` & Hardware Re-Qualification

- **Decision**: Port the operator-facing runtime commands of `tools/firmware.py` (`verify`, `first-install`/`update` → `flash`, `erase-state` → `wipe`, `provision` → `otp`) into `src/flash/` + `src/bin/p2kes-flash.rs`. Retain the bundled patched `picotool` v2.3.1 binary for RP2350 PICOBOOT/OTP/ELF operations, while performing ELF/UF2 header validation, policy validation, BOOTSEL USB mass-storage discovery/copy, and signature verification natively in Rust via `src/release.rs`. Keep maintainer-only release-signing scripts (`tools/publish_release.py`, `tools/firmware.py` seal/authorize) in `tools/` for CI/release engineering only (never shipped to operator hosts).
- **Rationale**: `tools/firmware.py` never uses Python USB libraries—it orchestrates `picotool`, `openssl`, and `gpgv` subprocesses plus pure-logic ELF/UF2 parsing. Rewriting the operator paths in Rust removes Python from operator hosts while preserving the exact patched `picotool` hardware interface.
- **Hardware qualification risk**: OTP writes on RP2350 silicon are permanent. Before any production release, `p2kes-flash` MUST be re-qualified on real accepted Pico 2 A2 hardware for flash, wipe, and OTP paths per Constitution Principle II.
- **Alternatives considered**:
  - *Reimplement PICOBOOT USB protocol natively in Rust*: High risk and unnecessary when patched `picotool` v2.3.1 is already bundled and qualified. Rejected.

## R4. Daemon Runtime Fixes (Dynamic Polling, Multiplexed Sockets, Graceful Shutdown, Bounded Journal)

- **Decision**:
  1. **Dynamic pool polling**: Replace the startup-frozen `pools: Vec<(PoolBinding, PoolSubscription)>` passed into `poll_pools` (`src/daemon/runtime.rs:680-712`) with a shared `Arc<Mutex<LivePoolSet>>` (containing a monotonic `version: u64` and `Vec<(PoolBinding, PoolSubscription)>`) updated by `LiveEndpoints::reconcile()`. Always spawn `poll_pools` in `RunMode::Normal`, even when `config.pools` is initially empty. On each poll cycle, `poll_pools` checks the version and refreshes its local snapshot when changed, immediately starting polls for newly enrolled pools and dropping deleted pools.
  2. **Multiplexed socket accept loop**: Replace the up to 64 per-pool `serve_pool` threads (each looping `accept()` + `sleep(50ms)` = up to 1,280 wakeups/sec idle) with a single accept thread using `rustix::event::poll` (already a dependency) over the management socket, all active pool listeners, and a self-pipe/eventfd wakeup triggered on shutdown or `LiveEndpoints::reconcile()`. Idle wakeups drop from >1,000/sec to ~0/sec.
  3. **Graceful shutdown & resilient dispatch**: On `SIGTERM`/`SIGINT`, stop accepting new management connections, signal `shutdown`, wait up to `MANAGEMENT_TIMEOUT` (5s) for `active_management` to reach 0 via a `Condvar`, then join `poller` and exit cleanly. On `thread::Builder::spawn` failure for a management connection, log to stderr and drop the connection rather than returning `Err` from `serve_until`.
  4. **Mutation-gated reconciliation**: In `serve_management`, call `management.reconstructed_registry()` and `endpoints.reconcile()` **only** when a mutation commits `Enrolled` or `Deleted`—never on read-only commands (`status`, `key export`, etc.).
  5. **Bounded journal compaction**: When `operations.journal` exceeds a compaction threshold (16 MiB, well below `JOURNAL_LIMIT = 64 MiB`) and no mutation is pending, atomically compact it to a sibling temp file (`operations.journal.compact`), `fsync` the file, `rename` over `operations.journal`, and `fsync` the parent directory. Compaction retains: (a) the authoritative `Enrolled` records for all currently active pools, and (b) the most recent `N` (e.g., 256) completed records for audit/replay safety.
- **Rationale**: Directly resolves Must-Fix findings 1–2 and Should-Fix findings 6, 7, 9 from the audit using existing dependencies (`rustix`, `std::sync::Condvar`) with zero new crates.
- **Alternatives considered**:
  - *Adopt `tokio` async runtime*: Massive dependency and complexity addition for a single-operator local daemon. Rejected per Constitution Principle V.
  - *External SQLite database for journal*: Adds C dependency and migration complexity; atomic file compaction of the existing checksummed binary journal is ~120 LOC and preserves the existing format. Rejected.

## R5. Unified `status` Framing & Simplified CLI Resolution

- **Decision**:
  1. Raise host-only management `MAX_FRAME` in `crates/kes-protocol/src/management.rs` from `16_384` (16 KiB) to `131_072` (128 KiB). A 64-pool unified status response (device identity + security + 64 pools × ~600 B active/staged metadata) is ~42–48 KiB, comfortably fitting in 128 KiB with zero pagination. RP2350 USB wire framing is untouched.
  2. Replace the 8 read actions (`device.status`, `device.security`, `device.inventory`, `host.observe`, `device.info`, `pool.list`, `pool.status`, `pool.observe`) with a single `status` management action (`optional pool_id`) that returns the complete device, security, and pool state in one frame.
  3. Implicit CLI resolution: when `p2kes` executes a pool-targeted command (`pool rm`, `key rotate`, `key export`, `key install-cert`, `key discard`), if `--expected-revision` is omitted, `p2kes` queries `status` first to resolve the pool's current active `incarnation_id`, current `staged` `generation_id` (where applicable), and current device revision, then submits the explicit IDs over the management protocol. Ambiguous or missing state (e.g., no staged generation on `key discard`, or already-occupied staged slot on `key rotate`) fails closed with a clear message before mutating.
  4. Daemon-owned reconciliation: remove mandatory `--receipt` files from `p2kes`. The daemon's durable `operations.journal` already records every pending mutation and auto-reconciles on reconnect (`reconcile_pending`). Expose `p2kes reconcile` to query/trigger reconciliation of the daemon's current pending operation and print its terminal outcome.
- **Rationale**: Preserves every Constitution Principle III invariant (explicit pool/generation/operation IDs on the wire, no blind retry of uncertain mutations) while removing 100% of manual operator ceremony.
- **Alternatives considered**:
  - *Keep 8 separate read commands and paginate at 16 pools*: Forces humans or wrapper tools to stitch 5+ calls together for a 64-pool host. Rejected.

## R6. Streamlined Offline `p2kes backup restore`

- **Decision**: `p2kes backup restore --artifact FILE --key FILE --device-identity FILE --out FILE` reads the signed CBOR artifact, verifies its Ed25519 signature against the trusted public key in `--device-identity` (failing closed if invalid), checks any optional caller-supplied assertion flags (`--pool`, `--incarnation`, `--generation`, `--verification-key`), prompts for the recipient passphrase, decrypts via HPKE, verifies the decrypted state matches the artifact's `verification_key`, writes the owner-restricted (`0600`, no-clobber) KES signing key file immediately, and prints the verified device, pool, incarnation, generation, and verification key to stdout.
- **Rationale**: Cryptographic security comes from verifying the artifact signature against the external trusted `--device-identity` file—not from making a human transcribe 5 other hex hashes by hand during disaster recovery. Per clarification Q5, no extra `y/N` prompt is needed after valid signature verification.

## R7. Constitutional Amendment & Dependency Cleanup

- **Decision**:
  - Ratify Constitution **v4.0.0** (MAJOR amendment to Technical Constraints) changing `pico2-kes-agent-cli` → `p2kes` and adding `p2kesup` and `p2kes-flash` to the established Rust executables before merging implementation.
  - Remove `ratatui` and `crossterm` from `Cargo.toml`. Replace redundant `unsafe { libc::... }` calls in remaining `src/` files with `rustix` equivalents where safe wrappers exist (keeping minimal `libc` only if needed for signal handlers or `nusb` error constants).
- **Rationale**: Satisfies Constitution Governance rules and Principle V ("remove code made obsolete by their replacement").
