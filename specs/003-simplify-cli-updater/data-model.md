# Data Model: Simplify CLI, Daemon Lifecycle, and Software Updater

**Feature**: `003-simplify-cli-updater` | **Date**: 2026-11-20

## 1. Release Tuple & Installed Record (`src/release.rs`)

### `ReleaseManifest`
Signed distribution manifest verified by the single canonical verifier (`src/release.rs`) shared by `p2kesup` and `p2kes-flash`.

| Field | Type | Validation Rules |
| --- | --- | --- |
| `schema_version` | `u32` | Must equal `2` (new simplified single-tuple schema) |
| `version` | `String` | SemVer tag (e.g., `v0.2.0`), ASCII `[A-Za-z0-9._-]`, max 64 chars |
| `published_at` | `String` | RFC 3339 UTC timestamp |
| `platform` | `PlatformSpec` | `arch = "x86_64"`, `os = "linux"`, `min_glibc = "2.36"` |
| `firmware_version` | `String` | Firmware release version; compared on update to notify operator if firmware changed |
| `usb_protocol_major` | `u16` | Must match daemon's supported USB protocol major version (`1`) |
| `artifacts` | `Vec<ReleaseArtifact>` | Complete, fixed tuple: `pico2-kes-agentd`, `p2kes`, `p2kesup`, `p2kes-flash`, `picotool`, `pico2-kes-firmware.signed.uf2`, `pico2-kes-firmware.signed.elf`, and static `deploy/*` files; no extra or missing files |

### `ReleaseArtifact`
| Field | Type | Validation Rules |
| --- | --- | --- |
| `path` | `String` | Relative path within bundle; no `..`, leading `/`, or symlinks |
| `kind` | `ArtifactKind` | `Binary` (installed to `/usr/local/bin`, `0755`), `Tool` (installed to `/usr/local/share/pico2-kes-agent/tools`, `0755`), `Firmware` (installed to `/usr/local/share/pico2-kes-agent/firmware`, `0644`), `Deploy` (installed to `/usr/local/share/pico2-kes-agent/deploy`, `0644`) |
| `size` | `u64` | Exact byte size; bounded |
| `sha256` | `String` | 64 lowercase hex chars; verified on staged copy before atomic rename |

### `InstalledState` (`/usr/local/share/pico2-kes-agent/installed.json`)
| Field | Type | Notes |
| --- | --- | --- |
| `version` | `String` | Currently installed release tuple version |
| `firmware_version` | `String` | Staged firmware version (used by `p2kesup update` to detect firmware changes) |
| `installed_at` | `String` | UTC timestamp of last install/update |
| `files` | `Vec<InstalledFile>` | Exact paths + SHA-256 digests managed by `p2kesup` (used for clean `uninstall`) |

**State transitions**:
`Uninstalled` → (`p2kesup install`) → `Installed(V1)` → (`p2kesup update`) → `Installed(V2)` → (`p2kesup uninstall`) → `Uninstalled`.
Every binary replacement stages into a sibling temp file in `/usr/local/bin` / `/usr/local/share/pico2-kes-agent`, `fsync`s, and atomically `rename`s; failure before rename leaves the prior installation untouched.

---

## 2. Live Daemon Pool Set (`src/daemon/runtime.rs`)

### `LivePoolSet`
Shared between `LiveEndpoints` (writer, on `Enrolled`/`Deleted` commits) and `poll_pools` (reader, on each poll cycle) behind `Arc<Mutex<LivePoolSet>>`.

| Field | Type | Notes |
| --- | --- | --- |
| `version` | `u64` | Monotonically incremented whenever a pool is added or removed |
| `pools` | `Vec<(PoolBinding, PoolSubscription)>` | Active pool bindings (0..=64) and their KES Service V2 broadcast subscriptions |

**Invariants**:
- `pools.len() <= 64`.
- No two entries share a `PoolId` or `socket_path`, and no entry shares `management_socket`.
- Whenever `LiveEndpoints::reconcile()` mutates `LivePoolSet`, it increments `version` and writes to the accept-loop wakeup pipe so the `poll()` loop immediately registers/deregisters listener file descriptors.

---

## 3. Compacted Operation Journal (`src/daemon/journal.rs`)

### `JournalRecord` (unchanged binary wire format `PKAJNL01`)
- `Intent` (operation ID, sequence, request digest, raw request JSON)
- `DeviceRequest` (encoded USB mutation frame)
- `Terminal` (public outcome + response bytes)

### Compaction Rule
- **Trigger**: Journal length ≥ `COMPACT_THRESHOLD` (16 MiB) AND `journal.pending().is_none()`.
- **Retained set**:
  1. The latest committed `Enrolled` record for every currently active (non-deleted) `PoolId` so `reconstructed_registry()` produces the exact same live `Vec<PoolBinding>`.
  2. The last `RETAINED_RECENT` (256) completed records in chronological order.
- **Atomicity**: Write to `operations.journal.compact` (`0600`), `sync_all()`, `rename()` over `operations.journal`, `sync_all()` on state directory. A crash before `rename()` leaves the original journal intact; a crash after `rename()` opens the valid compacted journal.

---

## 4. Unified Management Status (`crates/kes-protocol/src/management.rs`)

### `UnifiedStatus` (response to `status` action, max frame 128 KiB)
| Field | Type | Notes |
| --- | --- | --- |
| `health` | `String` | `"ready"`, `"recovering"`, `"unavailable"`, `"incompatible_firmware"`, `"commissioning"` |
| `revision` | `Option<u64>` | Current device state revision (used by `p2kes` for implicit optimistic concurrency) |
| `pending_operation` | `Option<PendingSummary>` | Present when the daemon journal has an unresolved pending mutation |
| `device` | `Option<DeviceSummary>` | `device_id`, `identity_public_key`, `usb_serial`, `firmware_version`, `usb_protocol_major`, `required_protocol_major`, `commissioning_state`, `recipient_configured`, `security` (OTP lock/stepping/flash summary) |
| `pools` | `Vec<PoolSummary>` | All enrolled pools (0..=64), or the single requested pool when `pool_id` filter is supplied |

### `PoolSummary`
| Field | Type | Notes |
| --- | --- | --- |
| `pool_id` | `String` | 56-hex pool identifier |
| `incarnation_id` | `String` | 32-hex current active incarnation |
| `network` | `String` | Configured Cardano network name |
| `socket_path` | `String` | Per-pool KES Service V2 Unix socket path |
| `active` | `Option<GenerationSummary>` | `generation_id`, `verification_key`, `start_period`, `current_period`, `max_period`, `counter` |
| `staged` | `Option<GenerationSummary>` | `generation_id`, `verification_key`, `certified`, `exported`, `start_period`, `counter` |

---

## 5. Offline Backup Restoration Input (`src/backup/recover.rs`)

### `DeviceIdentityFile` (trusted public input `--device-identity FILE`)
| Field | Type | Validation Rules |
| --- | --- | --- |
| `device_id` | `[u8; 16]` | 32 lowercase hex chars |
| `identity_public_key` | `[u8; 32]` | 64 lowercase hex chars (Ed25519 verifying key) |

### `RestoreRequest`
| Field | Required | Source |
| --- | --- | --- |
| `artifact` | Yes | Signed CBOR backup file (`--artifact FILE`) |
| `recipient_key` | Yes | Passphrase-encrypted X25519 private key file (`--key FILE`) |
| `device_identity` | Yes | Trusted public `device.json` (`--device-identity FILE`) |
| `out` | Yes | Destination path for restored KES key (`--out FILE`, no-clobber, `0600`) |
| `expected_pool` | No | Optional script assertion (`--pool HEX`) |
| `expected_incarnation` | No | Optional script assertion (`--incarnation HEX`) |
| `expected_generation` | No | Optional script assertion (`--generation HEX`) |
| `expected_vkey` | No | Optional script assertion (`--verification-key HEX`) |

**Verification sequence (fail-closed)**:
1. Parse CBOR artifact header and extract `device`, `pool`, `incarnation`, `generation`, `verification_key`, `recipient_id`, `recipient_public_key`.
2. Verify `device == device_identity.device_id` and verify the artifact's Ed25519 signature using `device_identity.identity_public_key`.
3. If any optional assertion flag was supplied, verify exact match.
4. Unlock `recipient_key` with passphrase, verify `recipient_id`/`recipient_public_key`, HPKE-decrypt period-0 KES state into `SecretBuffer`, verify `verification_key_from_state(&state) == artifact.verification_key`.
5. Publish conventional Cardano KES key file to `--out` (`0600`, no-clobber) and print verified bindings to stdout.
