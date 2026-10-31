# Phase 0 research

**Date:** 2026-10-27. **Scope:** planning only. Design choices are resolved below; implementation/qualification prerequisites are not represented as measurements. No open `NEEDS CLARIFICATION` decision remains.

## R1 — Baseline and native integration

**Decision:** retain root Cargo package `pico2-kes-agent`, edition 2024; use Rust/Cargo 1.99.1. Split reusable no_std core/protocol, firmware and host qualification packages while retaining daemon/CLI in the root package. Target Linux x86_64 and RP2350 Cortex-M33 `thumbv8m.main-none-eabihf`.

Observed integration baselines:

| Source | Exact identity / observation |
|---|---|
| Local `cardano-node` | HEAD `746f1b3cbdaada2c3ed2f702b0946643248dd30b`; pinned integrated native source used by the current build |
| Local `ouroboros-consensus` | Recorded HEAD `6673fce255f12addb602b0ae2d0a20f51a2cd519`; user subsequently confirmed removal of old cardano-kes-forge changes. The earlier modified-file inventory is superseded and those changes must not be reintegrated. Capture the corrected source inventory with the implementation candidate. |
| Local `cardano-kes-forge` | HEAD `871e795a7025976ac28bf7be8e0e9af5d1289a5a`; inspected working-tree source is reuse evidence, not a certified clean release |
| Local `pico-hsm` | HEAD `0ab29de6ce3897a61d82132884c3d56a4aa0e22b`; prior plan is design evidence, not current qualification |
| `kes-agent 1.3.0.0` source archive | SHA-256 `37b9729cb30590a0a520058b1d33f4ee1853b7503bbb46d3513be57d88369797` |
| `kes-agent-crypto 1.1.0.0` source archive | SHA-256 `43afbdfbb6ee992d34adb1d1b3ac1070da5395ffa2ddd8411c2cc4ad1818cc36` |
| Independent conventional CLI oracle | Select unmodified `cardano-cli 11.4.0.0`, commit `25f4d7a6b243d80ed7d716cc91b9c51d9265ace6`, from predecessor's documented independent oracle; build and verify source identity before use |

The specification cites `Cardano/Node/Protocol/Shelley/Credentials.hs` rejecting `kes-agent`; that file is absent in the inspected node checkout. Actual `Shelley.hs` bulk loading decodes legacy triples. The predecessor's version-1 object envelope supplies a useful schema convention, but its `cardano-kes-forge` source is not part of the corrected consensus baseline. Add `file` and `kes-agent` object sources while preserving legacy triples and singleton-agent behavior; do not recreate the removed external-source loader or consensus integration. FR-004 preserves external-signing semantics wherever already supported; it does not require rebuilding deliberately removed predecessor functionality. Record complete corrected source digests and Cabal resolved plans before acceptance. The user's baseline correction is authoritative; it is not a new Git-status measurement by this planning workflow.

**Rationale:** the corrected baseline supersedes historical working-tree assumptions. The accepted task adds current-key delivery and mixed file/agent bulk loading, not an external signing service.

**Alternatives considered:** restoring predecessor patches would undo the user's baseline correction and introduce unrelated external signing. Reuse the versioned envelope convention without its removed source branch rather than inventing another object shape.

## R2 — Existing node-service protocol

**Decision:** implement only negotiated Service V2 for the pinned 1.3 client, which advertises V2 first. Keep singleton-agent support and all existing node-service behavior; no new pool selector. One socket binds one pool. V0/V1-only clients are not this compatibility target; reject unsupported negotiation rather than invent a partial legacy decoder. The existing singleton 1.3 client also negotiates V2.

Source inspection of the exact package established direct big-endian stream encoding, 32-byte NUL-padded identifiers, server-offered version list, client selection, V2 key/drop messages and confirmations. Bundles carry current KES state/period and certificate; they are pushed, not requested. Timestamp is POSIX microseconds as defined by `kes-agent-crypto/KES/Bundle.hs` (an adjacent DirectCodec comment incorrectly says milliseconds). Use the actual conversion function as authority. See [node contract](contracts/node-service.md) for bytes and native migration.

**Rationale:** V2 carries explicit deletion and publication ordering; existing client negotiation makes protocol replacement unnecessary.

**Alternatives considered:** shared multi-pool stream, JSON/CBOR node protocol and external signing are outside the requested current-key-provider boundary. Upstream moving `master` is not the chosen compatibility pin.

## R3 — Rust firmware and USB

**Decision:** Embassy RP2350 Cortex-M33 firmware, no allocator in device hot paths, one core owns flash/KES state; USB uses Embassy USB vendor-specific bulk endpoints and host `nusb`. Use a dedicated USB interface instead of CCID/PCSC; daemon alone claims it. Serialize device mutations and use bounded cooperative generation/evolution work so healthy pool delivery progresses.

Source-evidenced dependency selections: `embassy-rp =0.10.0`, `embassy-usb =0.6.0`, `embassy-sync =0.8.0`, `embassy-futures =0.1.2`, `rp-pac =7.0.0`, `cortex-m-rt =0.7.7`, `nusb =0.2.9`. These are pins to introduce/review, not a lockfile already installed here. Complete transitive resolution/maintenance/license review belongs to G1.

**Rationale:** compatible Rust precedent without inheriting a C firmware, smartcard stack or mandatory remote update machinery.

**Alternatives considered:** CDC serial requires tty ownership/configuration but offers no useful node compatibility; CCID adds unrelated protocol surface. Dual-core concurrent flash access complicates erase/read guarantees.

## R4 — KES and certificates

**Decision:** adopt a reviewed minimal no_std adaptation of `kes-summed-ed25519 0.2.1` and the forge canonical-state wrapper. Preserve primitive algorithms; verify against independent Haskell Sum6KES, not only a Rust round trip. Sum6KES has 608-byte canonical state, 32-byte root vkey/seed, 4,064-byte public tree, 448-byte signature and 64 primitive periods. Pools each have independent network lifetime 1–64. Device is a key provider, not a block signer.

Selected crypto dependencies: `ed25519-dalek =2.2.0`, `blake2 =0.10.6`, `sha2 =0.10.9`, `zeroize =1.8.2`, `rand_chacha =0.9.0`, with default features disabled where needed. Reuse reviewed no_std adaptations of the predecessor, not its whole runtime. Validate certificate signature over Cardano's canonical signable representation, cold pool identity, hot vkey, counter, start and lifetime before commit.

**Rationale:** source demonstrates bounded canonical representation; independence and all-period comparisons remain mandatory gates.

**Alternatives considered:** new cryptographic primitives or a host seed would violate the constitution/specification; importing a whole predecessor service inherits incompatible authority and signing behavior.

## R5 — 64-pool storage and memory

**Decision:** new layout with one 1-MiB firmware image including image/boot metadata, 16 KiB configuration, 64 independent 32-KiB pool regions, a 16-KiB operation-handoff journal, and 992 KiB reserve in nominal 4-MiB flash. Each pool has two 4-KiB secret snapshots (each holds active and staged state), two 8-KiB public objects and 8 KiB spare. See [storage contract](contracts/device-storage.md).

Arithmetic: 1,048,576 + 16,384 + 64*32,768 + 16,384 = 3,178,496 bytes, leaving 1,015,808 bytes in 4 MiB. The final 16,384-byte term is the durable operation-handoff A/B journal required to retain managed sequence/receipt state across reboot. The old dual-1-MiB-firmware layout at 64 pools requires 4,176 KiB before that journal and does not fit. Single-image attended installation is explicitly chosen; no remote update or crash-resilient A/B firmware updater is promised.

Keep only compact pool descriptors in RAM and one shared KES/tree workspace, not 64 permanent tree caches. Design RAM ceilings: 32 KiB descriptors, 32 KiB crypto/KES workspace, 16 KiB USB frames, 32 KiB stacks/runtime, 16 KiB storage buffers; 128 KiB combined design allocation plus separately measured framework overhead. Require >=32 KiB whole-device measured spare SRAM and image <=1 MiB. These are allocation budgets, not measured link results.

**Rationale:** 64 full state+tree caches alone consume 299,008 bytes; flash-backed immutable trees and shared scratch avoid unnecessary copies. No hardware upgrade is assumed.

**Alternatives considered:** larger flash, fewer pools, shared staged slot and inherited A/B image layout rejected as unnecessary changes to the accepted device/scope. If qualified fitted geometry or measured image cannot meet this layout, implementation acceptance fails; do not silently reduce 64-pool capacity.

## R6 — Crash safety and bounded retries

**Decision:** authenticated two-bank snapshots with verified COMMIT then erase/read verification then CLEAN before any successor acknowledgment/release. Commit is authoritative even when cleanup was interrupted. Ambiguity quarantines, never falls back. Erase orphan public objects as well as abandoned secret candidates before reuse. Ordinary flash cleanup is not physical anti-extraction security.

Management retries combine a durable public daemon request/receipt journal and one device outstanding receipt. The daemon fsyncs intent before USB mutation, fsyncs result before returning success, then acknowledges receipt handoff. Automatic activation/evolution never waits for a backup or host receipt; managed mutation admission waits for its predecessor receipt to be safely journaled. Generation result records survive artifact retirement; a retry reports retirement rather than recreating a generation. Journal quota exhaustion rejects new managed mutations instead of evicting retry history. See [data model](data-model.md).

**Rationale:** bounded flash cannot remember every historical operation indefinitely. Durable nonsecret host receipts give exact CLI reconciliation across ordinary complete power loss without an unbounded device log or fabricated success after receipt eviction.

**Alternatives considered:** random IDs plus a small evicting flash cache could replay an old generation request; treating old/unknown operations as successful is incorrect. Unbounded flash history is infeasible.

## R7 — Backup and restore

**Decision:** reuse the forge `KESBKP01` CBOR artifact and domain strings. RFC 9180 HPKE base mode: X25519/HKDF-SHA256/ChaCha20-Poly1305, plus Ed25519 device-origin signature. Pin `hpke =0.13.0`, `hkdf =0.12.4`, `hmac =0.12.1`, `x25519-dalek =2.0.1`, `chacha20poly1305 =0.10.1`; apply only reviewed no_std dependency-manifest fixes needed for firmware. Recipient-file protection uses predecessor `argon2 =0.5.3` and existing authenticated recipient-file scheme.

The host selects HPKE's `alloc` and `x25519` features without defaults; the unused P-256 backend and its `crypto-bigint` dependency are excluded. This does not change the artifact's cryptographic suite.

Generate artifact once from exact key0 before success; preserve immutable bytes through evolution and recipient changes. Remove on generation retirement. Restore entirely on backup host into `KesSigningKey_ed25519_kes_2^6`, CBOR bytestring prefix `590260` plus 608 state bytes, validating trusted device/pool/generation/vkey first. Use independent decoder and in-memory disposable key0 comparison. No backup producer test or backup approval is required.

**Rationale:** reuses existing Rust producer/recovery semantics and conventional Cardano file representation.

**Alternatives considered:** older Pico binary artifact differs; new artifact/domain renaming is unnecessary. Re-exporting evolved secrets or retaining a plaintext key0 device copy violates scope.

## R8 — Period authority

**Decision:** daemon obtains per-network era/genesis parameters and current tip through the existing local node's query interface, with trusted synchronized host time. Use an unmodified configured `cardano-cli` executable for public local-state queries rather than implement another Cardano node-to-client stack. Run it directly with bounded outputs/timeouts, not via a shell. Configure node socket, network magic/genesis and an explicit 30-second maximum context/tip age; refresh every 5 seconds. Validate era-aware slot/time conversion, network binding, no future tip, and non-regression. A CLI/query/time failure withholds new time-dependent operations; never guess or reuse stale context after restart.

The device receives the validated absolute period, lifetime and context session/sequence addressed to each pool/incarnation, persists that incarnation's raised period floor before success, and expires freshness using its live monotonic timer. Equal-period refreshes do not write flash. The same network observation can serve multiple pools, but no persistent network-wide floor or retired-network registry is maintained. Deletion removes the pool's floor; re-enrollment requires fresh validated context. It is not a chain validator or trusted wall clock. Queries work while the node is syncing; pools await valid context without stopping other credentials. A controlled qualification network must have frequent enough slots/blocks for the selected freshness policy; missing/frozen tip is deliberately fail-closed.

**Rationale:** the node-service wire does not supply chain-time authority, and genesis/network settings must not be hardcoded to mainnet. Authorized-host manipulation remains an accepted trust risk.

**Alternatives considered:** wall-clock-only advancement, node-service timestamps as chain time, or inferring current period from a stale tip are unsafe.

## R9 — Host runtime and permissions

**Decision:** one systemd daemon, one common socket directory/group/mode, one pool socket per configured pool plus management socket. Linux owner/group permissions are the sole client authority; no PIN or stronger management role. Pin intended device identity at attended enrollment. Bound connections and output buffers, isolate each socket task, round-robin ready pool work, and coalesce obsolete queued publication notifications.

Use protected zeroizing transient buffers, locked memory with startup failure on inability to establish required protection, non-dumpable processes, disabled core dumps and no raw traffic logs. Deployment must disable primary swap/hibernation/snapshots or provide equally explicit protection for both node and daemon; the daemon cannot control malicious authorized copies. Host uses `serde =1.0.228`, `serde_json =1.0.145`, `rustix =1.1.5` and standard Linux polling/I/O, avoiding a second runtime solely for 64 sockets.

**Alternatives considered:** per-pool ACLs, admin secrets, plaintext durable cache, direct CLI USB and implicit file fallback contradict resolved policies.

## R10 — Quality tools and qualification

**Decision:** apply the MCP-derived sensor/gate definition in [quality-gates.md](contracts/quality-gates.md). Rust behavioral/proptest/fuzz/model checks complement actual A2 observations, Haskell differential decoding and measured full-capacity load. Optional diagnostics do not constitute acceptance evidence.

**Rationale:** source inspection and host simulations cannot prove flash erasure, 64-pool timings or accepted blocks. Planning approval is not gate activation or implementation acceptance.

**Alternatives considered:** tests alone, empty success reports, predecessor approval inheritance and an A4-only acceptance gate are rejected.

## R11 — U1: attended identity bootstrap

**Decision:** explicit daemon `--commission` mode owns USB and exposes only the ordinary-permission management socket for status, `device commission` and reconciliation. USB kind 10 initializes only a completely verified blank allocated state region. Sequence 0 and the operation digest bind the durable first identity; valid COMMIT recovers the same result, while nonblank partial/corrupt initial state fails closed without a format/reset command. The CLI publishes a no-clobber public enrollment record; the operator installs its pin and restarts normal mode for a fresh challenge check. Full inputs, outputs and failures are in [the commissioning contract](contracts/management-cli.md#attended-commissioning).

**Rationale:** the accepted attended trusted-firmware/physical-connection boundary provides initial trust without inventing a device display, factory attestation, fuse policy or administrator credential. Ordinary reconnect must never learn a replacement identity. A serial and self-signature are selection/key-possession evidence, not independent attestation. First-write ambiguity cannot safely be treated as a new blank device.

**Alternatives considered:** automatic trust-on-reconnect, direct CLI USB, reformat-on-corruption and a general provisioning service would weaken or expand scope. The explicit mode reuses the daemon, journal, socket policy and receipt convention.

## R12 — U2: one device-owned publication commit

**Decision:** carry synchronized `publication_time_us` with fresh, exact-target USB context. Device lifecycle commits one publication descriptor/timestamp with the corresponding key/certificate/period or Drop; expose only after CLEAN. USB status/current return it and the daemon forwards it verbatim on unchanged V2. Metadata-only revisions and redelivery do not mint timestamps. Deletion hands the terminal descriptor/high-water to the existing durable public receipt; same-pool re-enrollment derives its timestamp floor from those receipts, not old slot contents. Explicit deletion without a fresh time sample uses checked logical successor ordering, never inferred KES time.

**Rationale:** a second host publication commit would create an additional crash-consistency boundary. Binding ordering metadata to the authoritative device transition makes lost replies and reboot unambiguous. Public deletion receipts already retained for retry safety provide continuity across incarnations without keeping retired secrets or a new device log.

**Alternatives considered:** daemon-owned timestamp maps require additional fsync/reconciliation on every publication; per-incarnation reset alone can make a still-running V2 client reject a new incarnation after a lower host-time sample. Device-wide per-publication counters add shared-bank wear. Use the existing pool snapshot and receipt mechanisms instead.

## R13 — I1: minimal live-pool metadata, no retired network history

**Decision:** the operator explicitly selected retaining required nonsecret live-pool recovery/retry metadata, not obsolete secret states or a historical network registry. Each enrolled incarnation keeps its own highest accepted absolute period bound to its network; expiry, rotation and discard retain it, verified pool deletion removes it. Independent healthy pools never need a quarantined pool's floor. A fresh incarnation receives freshly validated context, not an old key or inherited slot floor.

**Rationale:** the constitution requires forward-only state under validated per-pool context. One scalar floor prevents regression without retaining earlier KES states. Encrypted key0 backups are the explicit retained-secret exception; their recoverability limits forward security against recipients and does not justify dropping live-pool monotonicity or retry protection.

**Alternatives considered:** permanent network-level history requires retention/capacity/garbage-collection policy and couples isolated pool failures. Removing all monotonicity/retry metadata would violate accepted recovery requirements. Neither is needed for the selected policy.

The earlier U1/U2/I1 refinements kept the existing crypto, tool pins, 64-pool geometry and G1–G10/P0/P1 selection. Their integration/fault oracles cover commissioning, exact publication replay and pool-local period floors. The maintainer explicitly re-approved those recorded gate/storage bytes; that historical authorization is preserved in [quality-gates.md](contracts/quality-gates.md#approval-record). It does not approve the subsequent verification-contract proposal below or establish passing readings.

## R14 — Executable foundation evidence before application wiring

**Decision:** T014 implements `qualification/src/foundation.rs`, dispatched from `qualification/src/main.rs` as `cargo run --locked -p qualification -- foundation`; T016 integrates validity checks and T020 executes it. It calls the actual bounded codecs, protected-memory initializer and fixture parser, with deterministic OS memory-lock denial in an isolated unprivileged child and generated invalid public input. It needs no T042 daemon/CLI binaries, hardware or external fixture. The exact oracles, failure results and host-only boundary are in [the foundation contract](contracts/quality-gates.md#foundation-executable-smoke).

**Rationale:** the foundation checkpoint must exercise implemented behavior through an executable without depending on a later story. The existing qualification package already owns sanitized evidence and subprocess isolation; no second service or production escape hatch is needed.

**Alternatives considered:** delaying all smoke until T042 creates a foundation/story dependency cycle; tests alone violate executable-proof policy; a mocked memory error would not exercise the OS boundary. The host-only result explicitly leaves firmware and story scopes pending.

## R15 — Benchmark scaffolding removed

The proposed benchmark targets and aggregate P0 runner were pending, not meaningful measurements. They have been removed; performance diagnostics remain optional and no baseline or benchmark runner is supplied.

## R16 — Synchronized C1 verification and honest approval metadata

**Decision:** synchronize the existing native reload/cancellation design into the node-service contract, quickstart and G2/G9 definition. G2 invokes actual registered native regression cases through `qualification native-regression --fixture`; G9 sends SIGHUP only to the identified disposable node after verifying handler/consensus state and observes replacement completion and accepted blocks. Approved qualification limits are explicit: awaited cancellation within 5 seconds, ten sequential completed reloads per valid topology, healthy replacement readiness within 60 seconds, and returning-agent delivery within 60 seconds of available transport/context. Existing 10-second delivery, 60-second recovery and aggregate gate budgets remain unchanged. The subsequent explicit maintainer approval is recorded against the unchanged reviewed definition; these bounds are not measured claims.

**Evidence and rationale:** the earlier native source inspection and cancellation probe are recorded in [plan.md](plan.md#c1-sighup-refinement-record), not rerun as proof of a fix. Full [SO-002b](https://softwareobservatory.com/sensors/example-based-tests/) and [SO-002c](https://softwareobservatory.com/sensors/integration-tests/) MCP entries were reconsulted during this refinement: distinguish harness failure from an observed behavioral failure, exercise actual dependencies, and do not retry away timing defects. Their existing relevance, limits and coverage gaps remain; no selection/tool change is needed. The current setup JSON returns the feature identifier while Git independently reports `feature`, so metadata now labels each accurately.

**Alternatives considered:** a provider notification or successful signal exit cannot prove native reload; reusing old approval for new definition bytes would misstate authorization; blanket transactional reload would change the accepted malformed/missing-file baseline. The design and historical approvals remain intact, and the separately hashed verification-contract definition now has its own explicit approval. Model/entities and storage/backup/management formats need no change.

## Evidence and empirical prerequisites

Research consulted local predecessor plan/crypto/backup/restore sources, exact package archives, native node/consensus sources, installed Rust/tool versions, and Software Observatory MCP. Public reference: [upstream KES agent](https://github.com/IntersectMBO/kes-agent), [behavior/security FAQ](https://github.com/IntersectMBO/kes-agent/blob/master/doc/faq.markdown), [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180).

Before implementation acceptance: identify the actual fitted flash geometry and A2 device, verify production firmware build/boot/USB identity, exercise erase/read failure behavior, verify all 64+64 generations fit and meet 10/60-second targets, build pinned native oracles, activate gates, and execute complete software/device campaigns. No voltage, temperature, or service-life qualification is required. None of these observations was completed during planning.
