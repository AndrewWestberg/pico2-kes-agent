# Contract: `p2kesup` Updater, `p2kes-flash`, and `install.sh`

**Feature**: `003-simplify-cli-updater`

## 1. Filesystem Layout (System-Wide, Managed via `sudo`)

| Path | Mode | Contents |
| --- | --- | --- |
| `/usr/local/bin/pico2-kes-agentd` | `0755` | Background USB daemon |
| `/usr/local/bin/p2kes` | `0755` | Operator CLI |
| `/usr/local/bin/p2kesup` | `0755` | Release updater |
| `/usr/local/bin/p2kes-flash` | `0755` | Standalone firmware flash / wipe / OTP tool |
| `/usr/local/share/pico2-kes-agent/installed.json` | `0644` | Installed release version, staged firmware version, managed file digests |
| `/usr/local/share/pico2-kes-agent/firmware/` | `0755` | Staged verified `pico2-kes-firmware.signed.uf2`, `.signed.elf`, and firmware manifest/signature |
| `/usr/local/share/pico2-kes-agent/tools/picotool` | `0755` | Bundled patched `picotool` v2.3.1 + runtime libs (if bundled) |
| `/usr/local/share/pico2-kes-agent/deploy/` | `0755` | Static reference files: `pico2-kes-agentd.service`, `70-pico2-kes-agent.rules`, `cardano-node-memory-hardening.conf`, `config.example.json` |

## 2. `p2kesup` CLI Contract

```text
sudo p2kesup install [--version TAG | --bundle DIR]
sudo p2kesup update  [--version TAG | --bundle DIR]
sudo p2kesup uninstall [--yes]
p2kesup status [--json]
p2kesup --help | --version [--json]
```

- **Authentication**: Every `install` and `update` verifies the release bundle through the single canonical verifier (`src/release.rs`): pinned OpenPGP trust root → delegated secp256k1 distribution key → `manifest.json` signature → SHA-256 of every artifact in the tuple. Unverified or partial tuples fail closed before touching `/usr/local`.
- **Atomic replacement**: Each target file is staged to a sibling temporary file in the destination directory, `fsync`ed, and atomically `rename`d. `installed.json` is written last.
- **No systemd mutations**: `p2kesup` NEVER starts, stops, masks, enables, or edits systemd units, `/etc/fstab`, swap, or `cardano-node`. After `update`, it prints:
  - `Run: sudo systemctl restart pico2-kes-agentd`
  - If `firmware_version` changed from the previously staged version: `New firmware vX.Y staged at /usr/local/share/pico2-kes-agent/firmware/pico2-kes-firmware.signed.uf2. During a maintenance window, hold BOOTSEL and run: sudo p2kes-flash flash`
- **No TUI / no hidden host subcommands**: All 24 legacy `HostAction` variants, `host-apply`/`host-admit`/`host-inspect`/`release-discovery-worker`, and Ratatui UI are removed.
- **Clean uninstall**: `p2kesup uninstall` removes only the files tracked in `installed.json` and `/usr/local/share/pico2-kes-agent/`. It never touches `/etc/pico2-kes-agent/`, `/var/lib/pico2-kes-agent/`, systemd units, or external backups.

## 3. `p2kes-flash` CLI Contract (Native Rust, Zero Python Runtime)

```text
p2kes-flash verify [--firmware-dir DIR]
sudo p2kes-flash flash [--firmware-dir DIR] [--serial HEX]
sudo p2kes-flash wipe --serial HEX [--yes]
sudo p2kes-flash otp --stage prepare|enable|lock --serial HEX [--firmware-dir DIR]
p2kes-flash --help | --version [--json]
```

- Default `--firmware-dir`: `/usr/local/share/pico2-kes-agent/firmware`.
- Uses the exact same canonical verifier (`src/release.rs`) as `p2kesup` before touching hardware.
- `flash`: Verifies signed ELF/UF2 + policy, guides operator to hold BOOTSEL if not in mass-storage mode, verifies fitted RP2350 target, writes `.signed.uf2`, and confirms completion.
- `wipe`: Unlocked boards only. Requires explicit attended confirmation describing irreversible loss of all device pools/keys, then erases and read-verifies the state region via bundled `picotool`.
- `otp`: Preserves the existing 3-stage (`prepare`, `enable`, `lock`) RP2350 `rp2350-signed-msd-v1` OTP provisioning safety checks and explicit attended confirmation via bundled `picotool`. **Must pass real Pico 2 A2 hardware re-qualification before production release.**

## 4. `install.sh` Bootstrapper Contract

```sh
curl -fsSL https://raw.githubusercontent.com/AndrewWestberg/pico2-kes-agent/master/install.sh | sh
curl -fsSL .../install.sh | sh -s -- --version TAG
```

- Checks platform (`x86_64`, Linux, systemd, `glibc >= 2.36`).
- Minimal prerequisites: `curl` (or `wget`), `gpgv`, `openssl`, `sudo` (when non-root). **No `python3` prerequisite.**
- If prerequisites are missing, runs `apt-get --simulate install`, **displays the exact proposed package changes to `/dev/tty`**, and asks for `y/N` confirmation before installing.
- Downloads the signed release bundle to a temporary directory, verifies the bundle signature via `gpgv`/`openssl`, and executes `sudo <bundle>/p2kesup install --bundle <bundle>`.
- Zero duplicated Python verifier code inside `install.sh`.
