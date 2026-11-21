# Quickstart Validation Guide: Simplify CLI, Daemon Lifecycle, and Software Updater

**Feature**: `003-simplify-cli-updater`

Use this guide to validate the redesigned 4-binary system (`pico2-kes-agentd`, `p2kes`, `p2kesup`, `p2kes-flash`) end to end against the contracts in [`contracts/cli.md`](contracts/cli.md) and [`contracts/updater-and-flash.md`](contracts/updater-and-flash.md).

## Prerequisites

- Supported x86-64 Linux host (Debian 12 / Ubuntu 24.04 / Ubuntu 26.04) with systemd and `glibc >= 2.36`
- Built workspace binaries (`cargo build --release`) or a signed release bundle
- For hardware checks: an accepted Pico 2 A2 board; for host-only smoke: simulated USB transport in `cargo test`

## Q1. Updater Install, Update, and Uninstall (`p2kesup`)

1. On a clean test host, follow [Install p2kesup](../../README.md#install-p2kesup) to download and verify the release assets. If the verified bundle was prepared offline instead, install from its directory:
   ```sh
   sh /path/to/signed-bundle-v1/install.sh /path/to/signed-bundle-v1
   p2kesup status
   p2kes --version
   ```
   **Expected**: `/usr/local/bin/{pico2-kes-agentd,p2kes,p2kesup,p2kes-flash}` and `/usr/local/share/pico2-kes-agent/{installed.json,firmware/,tools/,deploy/}` are installed; no systemd units or `/etc/fstab` are modified. The installed updater does not require Python.
2. Tamper with one byte of any file in a copied bundle and run `sudo p2kesup update --bundle /tmp/tampered`.
   **Expected**: Fails closed with non-zero exit; existing `/usr/local/bin/*` and `installed.json` remain untouched.
3. Update to a newer signed bundle containing a new firmware version:
   ```sh
   sudo p2kesup update --bundle /path/to/signed-bundle-v2
   ```
   **Expected**: Binaries and staged firmware update atomically; `p2kesup` does **not** restart systemd, and prints both `sudo systemctl restart pico2-kes-agentd` and `sudo p2kes-flash flash`.
4. Uninstall:
   ```sh
   sudo p2kesup uninstall --yes
   ```
   **Expected**: Managed files removed cleanly; `/etc/pico2-kes-agent/` and `/var/lib/pico2-kes-agent/` untouched.

## Q2. Everyday CLI Lifecycle (`p2kes`)

1. Start `pico2-kes-agentd` in commissioning mode with a blank Pico 2, then commission:
   ```sh
   p2kes status
   p2kes commission --out /tmp/device.json
   ```
   **Expected**: Single `status` call shows blank device; `commission` emits `device.json` without requiring `--expected-revision` or `--receipt`.
2. Configure `pico2-kes-agentd` with the pinned identity and **zero** pools in `config.json`, start the daemon, then run:
   ```sh
   p2kes backup set-recipient /tmp/recipient.pub
   p2kes pool add --cold-vkey /tmp/cold.vkey --network mainnet
   p2kes key rotate <POOL_ID> --vkey-out /tmp/kes.vkey --backup-out /tmp/kes.backup
   p2kes key install-cert <POOL_ID> /tmp/node.cert
   p2kes status
   ```
   **Expected**:
   - Pool socket opens and begins delivering the active KES key **without restarting `pico2-kes-agentd`** (SC-004).
   - `key rotate` produces both `kes.vkey` and `kes.backup` in one command (SC-001).
   - `status` shows device, security, and pool state in one call with zero pagination (SC-002).
3. Delete the pool and confirm polling stops:
   ```sh
   p2kes pool rm <POOL_ID> --yes
   p2kes status
   ```
   **Expected**: Pool socket closes immediately and daemon stops polling the deleted pool.

## Q3. Daemon Reliability, Compaction, and Performance

1. Send `SIGTERM` to `pico2-kes-agentd` while a management mutation is in flight.
   **Expected**: Daemon stops accepting new requests, completes the in-flight mutation cleanly, and exits `0`.
2. Seed `operations.journal` past the compaction threshold (16 MiB) with completed operations, trigger compaction, and restart the daemon.
   **Expected**: Compacted journal shrinks well below 16 MiB, preserves all active pool bindings, and `p2kes status --json` responds in `<100 ms` (SC-005).
3. Run daemon with 64 enrolled pools idle for 10 seconds.
   **Expected**: Daemon idle wakeups `<5/sec` (SC-005).

## Q4. Standalone Firmware Tool (`p2kes-flash`)

1. Verify staged firmware offline:
   ```sh
   p2kes-flash verify
   ```
2. Hold BOOTSEL on a disposable Pico 2 A2 and flash:
   ```sh
   sudo p2kes-flash flash
   ```
   **Expected**: Signature, ELF/UF2, and board checks pass; firmware flashes cleanly without touching host service configs.
3. Connect a device with an older protocol version to `pico2-kes-agentd` and run `p2kes status`.
   **Expected**: Status reports `incompatible_firmware`, observed vs. required version, and prints `sudo p2kes-flash flash`.

## Q5. Offline Backup Keygen & 4-Input Restore

On an isolated machine with no daemon or Pico 2:
```sh
p2kes backup keygen --out /tmp/recipient.key --public-out /tmp/recipient.pub
p2kes backup restore \
  --artifact /tmp/kes.backup \
  --key /tmp/recipient.key \
  --device-identity /tmp/device.json \
  --out /tmp/restored-kes.skey
```
**Expected**:
- Signature verified against `device.json`; verified device, pool, incarnation, generation, and verification key printed to stdout; owner-restricted (`0600`) KES signing key written immediately without prompting for 5 extra hex flags (SC-003).
- Repeating with a tampered artifact or mismatched `--pool` assertion fails closed and writes no output file.
