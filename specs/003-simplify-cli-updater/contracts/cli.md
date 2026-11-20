# Contract: `p2kes` Operator CLI & Management Socket Protocol

**Feature**: `003-simplify-cli-updater` | **Binary**: `p2kes` (replaces `pico2-kes-agent-cli`)

## 1. Global Options & Exit Codes

```text
p2kes [--socket PATH] [--json] COMMAND [ARGS...]
p2kes --help | --version [--json]
```

- `--socket PATH`: Management Unix socket (default: `/run/pico2-kes-agent/management.sock`). Ignored by offline commands (`backup keygen`, `backup restore`).
- `--json`: Emit machine-readable JSON on stdout. Diagnostics and prompts go to stderr.
- Removed global flags: `--expected-peer-pid`, `--expected-peer-uid` (legacy `p2kesup` plumbing, deleted).

| Exit Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Invalid arguments or invocation |
| `3` | Permission denied |
| `4` | Daemon or device unavailable / incompatible firmware |
| `5` | Rejected by device or precondition (e.g., stale revision, occupied staged slot, bad cert) |
| `6` | Uncertain outcome (operation pending in daemon journal; run `p2kes reconcile`) |
| `7` | Internal or local I/O failure |

## 2. Command Surface (10 Core Workflows)

| Command | Required Args | Optional Args | Behavior |
| --- | --- | --- | --- |
| `p2kes status` | — | `[POOL_ID]` | Returns unified device identity, health, security posture, revision, pending operation (if any), and all enrolled pools (or the single specified pool). Zero pagination. |
| `p2kes commission` | — | `--serial HEX`, `--out FILE`, `--expected-revision N` | Commissions a blank Pico 2 when daemon is in `--commission` mode. Auto-detects serial if omitted when one blank board is connected. Writes public `device.json` if `--out` is supplied. |
| `p2kes pool add` | `--cold-vkey FILE`, `--network NAME` | `--expected-revision N` | Enrolls a pool and dynamically starts polling/serving its socket without daemon restart. |
| `p2kes pool rm` | `POOL_ID` | `--yes`, `--expected-revision N` | Auto-resolves current incarnation, prompts `y/N` unless `--yes`, deletes pool on device, and immediately stops polling/serving its socket. |
| `p2kes key rotate` | `POOL_ID`, `--vkey-out FILE`, `--backup-out FILE` | `--expected-revision N` | Auto-resolves active incarnation, generates a new staged generation, exports public KES verification key (`--vkey-out`, no-clobber) and encrypted backup artifact (`--backup-out`, no-clobber) in one command. |
| `p2kes key export` | `POOL_ID` | `--vkey-out FILE`, `--backup-out FILE`, `--generation HEX` | Re-exports verification key and/or encrypted backup artifact for the pool's staged (or specified) generation without regenerating. At least one `--*-out` required. |
| `p2kes key install-cert` | `POOL_ID`, `CERT_FILE` | `--generation HEX`, `--expected-revision N` | Auto-resolves active incarnation and staged generation (unless `--generation` specified) and installs the cold-signed OpCert. |
| `p2kes key discard` | `POOL_ID` | `--generation HEX`, `--yes`, `--expected-revision N` | Auto-resolves active incarnation and staged generation, prompts `y/N` unless `--yes`, discards staged generation without affecting active key. |
| `p2kes reconcile` | — | `--out FILE` | Reconciles the daemon's current pending journaled mutation after an uncertain outcome (no user receipt file required). Writes `device.json` if `--out` is supplied for a commissioned device. |
| `p2kes backup keygen` | `--out FILE`, `--public-out FILE` | — | **Offline.** Creates passphrase-protected X25519 recipient private file (`0600`) and public recipient file. |
| `p2kes backup set-recipient` | `PUB_FILE` | `--expected-revision N` | Installs the public backup recipient key on the device (applies to future generations). |
| `p2kes backup restore` | `--artifact FILE`, `--key FILE`, `--device-identity FILE`, `--out FILE` | `--pool HEX`, `--incarnation HEX`, `--generation HEX`, `--verification-key HEX` | **Offline.** Verifies artifact Ed25519 signature against `--device-identity`, fails closed on any optional assertion mismatch, decrypts with `--key`, writes conventional KES key (`0600`, no-clobber), and prints verified bindings to stdout. |

## 3. Management Socket Wire Contract (`crates/kes-protocol/src/management.rs`)

- **Framing**: 4-byte big-endian length prefix + UTF-8 JSON body.
- **`MAX_FRAME`**: Raised from `16_384` to **`131_072` (128 KiB)** (host-only Unix socket; RP2350 USB wire framing unchanged).
- **Retained / updated actions**:
  - `status` (replaces `device.status`, `device.security`, `device.inventory`, `host.observe`, `device.info`, `pool.list`, `pool.status`, `pool.observe`)
  - `device.commission`
  - `pool.enroll`, `pool.delete`
  - `generation.create`, `generation.public_key`, `generation.artifact`, `generation.certificate`, `generation.discard`
  - `recipient.set`
  - `operation.reconcile` (accepts empty `{}` arguments to reconcile the daemon's sole pending journal operation; no client receipt required)
- **Removed legacy actions**: `device.security`, `device.inventory`, `host.observe`, `device.info`, `pool.list`, `pool.status`, `pool.observe` (clean cutover, no shims).
- **Implicit revision & identity safety**: `p2kes` always sends explicit `pool_id`, `incarnation_id`, `generation_id`, `operation_id`, and `expected_revision` on the management wire (resolved from `status` when omitted by the user), preserving full substitution and concurrency protection.
