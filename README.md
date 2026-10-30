# Pico2 KES Agent

Persistent Cardano KES state on a Raspberry Pi Pico 2, with a Linux daemon and operator CLI. The goal is to retain and recover current operational KES state after **both host and device lose power**, without an ordinary KES signing-key file on the primary host or a surviving RAM-only peer.

One USB-owning daemon supports up to **64 pools**, each with one active and one staged generation and its own KES Service V2 Unix socket. Nodes receive current key material and sign locally.

## Contents

- [Purpose and security boundary](#purpose-and-security-boundary)
- [Requirements and compatibility](#requirements-and-compatibility)
- [Build, flash, and install](#build-flash-and-install)
- [Commission and configure](#commission-and-configure)
- [Enroll and serve the first generation](#enroll-and-serve-the-first-generation)
- [Connect cardano-node](#connect-cardano-node)
- [Operations and maintenance](#operations-and-maintenance)
- [Offline restoration and failover](#offline-restoration-and-failover)
- [Troubleshooting and references](#troubleshooting-and-references)

## Purpose and security boundary

### Terms

| Term | Meaning |
| --- | --- |
| KES | Key Evolving Signatures: one verification key covers a finite sequence of secret signing states. Later states cannot derive earlier ones. |
| Period evolution | Advance an existing generation to the network's next absolute KES period; no new certificate. Period duration is network-dependent. |
| Generation rotation | Create a new KES series and obtain a new cold-signed certificate before the existing series expires. |
| Operational certificate / OpCert | Cold-key signature authorizing a KES verification key, issuance counter, and absolute start period. |
| Active / staged generation | Active is eligible for delivery; staged is the pending replacement, including a future-start certified generation. |
| Device identity | Persistent device ID and signing public key, pinned together with the application USB serial. |
| Pool incarnation | Unique enrollment lifetime; deleting and re-enrolling a pool creates a different incarnation. |
| Recipient key | Off-primary backup decryption key; only its public part is installed on the device. |
| Receipt | Durable local record of a mutation's operation ID, target, revision, request, and available result; retain it to reconcile uncertainty. |
| A2 / A4 | RP2350 silicon/boot-ROM steppings; unrelated to the Cardano KES Service V2 host protocol. A4 fixes several A2 ROM/OTP issues but retains invasive OTP-extraction limitations. |

### Why persistence?

The original [IntersectMBO KES agent](https://github.com/IntersectMBO/kes-agent) deliberately retains keys in mlocked RAM, evolves autonomously, and can refill a restarted agent from a surviving bootstrap peer, including over SSH-forwarded sockets. It already survives node-only restarts. Its [FAQ](https://github.com/IntersectMBO/kes-agent/blob/master/doc/faq.markdown) and [guide](https://github.com/IntersectMBO/kes-agent/blob/master/doc/guide.markdown) describe these availability and erasure choices.

| Dimension | Original RAM-based agent | Pico2 persistent agent |
| --- | --- | --- |
| Operational state | Agent/node RAM; optional live peers | Encrypted device storage plus daemon/node RAM |
| Node-process restart | Reconnect to agent for current state | Reconnect through per-pool socket with valid context |
| Agent / whole-host restart | Single agent loses RAM key; a running node still evolves/signs until expiry | Device retains operational state across loss of power; restart still requires identity and valid context |
| Recovery peer dependence | A surviving peer can refill the agent; simultaneous loss of all RAM copies requires operator intervention | No surviving RAM peer needed for intact-device recovery |
| Backup tradeoff | Avoid persistent initial signing-state backups; availability can use live peers | Encrypted period-zero artifacts allow offline recovery, but retained recipients/artifacts can reconstruct past states |

These are intentional design tradeoffs.

```mermaid
flowchart LR
  CLI[Operator CLI] -->|management socket| D[Linux daemon]
  P[Pico2 persistent state] <-->|authenticated USB session| D
  D -->|per-pool Service V2 socket: current KES state| N[cardano-node: local signing]
  C[Offline cold-key host] -->|public OpCert| CLI
  CLI -->|encrypted artifact and public records| B[Backup-recipient host]
```

**Not an HSM or remote signer.** Current KES material reaches daemon and node RAM. An authorized service client can copy it and derive later states. A compromised primary host can steal current keys. Cold signing keys and recipient private keys stay external; the node still holds its VRF secret.

Treat socket-group membership as full trust: management-socket access grants all pool-management authority. There is no PIN or per-pool privilege separation. Trusted host time and chain context remain necessary.

Device encryption and read-verified cleanup do **not** establish resistance to physical extraction, malicious firmware, captured-flash rollback, or invasive remanence analysis. Retained period-zero backups and recipient keys can reconstruct earlier periods. Changing recipients does not revoke old ciphertext. Device erasure, pool deletion, disconnection, and daemon shutdown cannot revoke node or backup copies.

The optional `rp2350-signed-msd-v1` profile uses native ROM secp256k1 signatures, disables ordinary PICOBOOT/debug/alternate execution paths, and retains physical USB mass-storage recovery. It targets straightforward post-lock USB/SWD reads and unsigned firmware substitution, not specialist invasive extraction or fault injection. An application report is diagnosis, not independent attestation; negative boot and recovery observations are required. Locking cannot revoke a previously copied RANDID/wrapping root, flash image or operational state. Treat a pre-extracted/untrusted board as compromised and use a trusted replacement before installing operational secrets.

## Requirements and compatibility

| Execution host | Responsibility |
| --- | --- |
| Linux producer / USB host ("primary") | Runs daemon, management CLI, and producer node; owns the USB device. A relay does not need this device. |
| Offline cold-key host | Keeps cold signing key and issuance counter; signs certificates. Never copy its secret to the primary. |
| Backup-recipient host | Creates/protects the recipient private file and passphrase; performs local restoration. Never copy that private file to the primary. |

Requirements:

- Linux with systemd and udev; Git, a native C compiler/linker and normal platform build prerequisites; rustup; `jq`; `sha256sum`; USB diagnostic tools.
- Rust **1.99.1**, pinned by [rust-toolchain.toml](rust-toolchain.toml), and `thumbv8m.main-none-eabihf`.
- [Picotool 2.3.1](https://github.com/raspberrypi/picotool), Python 3, OpenSSL and GPG/GPGV for bundle verification and attended provisioning. Picotool must include signing/verification and libusb support. Offline verification needs the program installed, but not access to a USB device. Locked-device updates use the verified UF2 through physical mass-storage BOOTSEL, not PICOBOOT.
- Pico 2 with the fitted 4-MiB flash profile checked by [firmware/src/flash.rs](firmware/src/flash.rs): JEDEC `ef4016`, SFDP `534644500a0100ff00080117800000ff`, density-minus-one `0x01ffffff`. The shared profile identifies A2/A4; A4 is expected-compatible and hardware-unverified. A2 secure-boot qualification is separate from the existing storage evidence. A3, RP2040, unknown revisions and other flash profiles are not admitted for this profile.
- A `cardano-node` release supporting the standard `--shelley-kes-agent-socket` interface and a matching `cardano-cli`. Obtain these using the [Cardano node installation guide](https://developers.cardano.org/docs/get-started/infrastructure/node/installing-cardano-node/). Check your installed node's help before cutover.
- Trusted genesis, network parameters, and actual era/slot-length history; synchronized host clock; access to the local node's query socket and the intended USB device.
- The node's ordinary network, topology, database, VRF key, and service configuration remain necessary. Building successfully or connecting a socket does not demonstrate live forging or peer-accepted blocks.

**Readiness limitation:** the current daemon recognizes clock synchronization only when `/run/systemd/timesync/synchronized` or `/run/systemd/timesync/synchronized-clock` contains trimmed `yes`, `1`, or `true`. Generic NTP enablement or an empty marker does not satisfy this implementation. It fails closed and withholds period-dependent delivery. If the host cannot provide genuine recognized synchronization state, stop at this prerequisite; do not fabricate markers or disable the check.

## Build, flash, and install

### Build

**Build host — from this checkout's root:**

```bash
rustup toolchain install 1.99.1 --profile minimal
rustup target add --toolchain 1.99.1 thumbv8m.main-none-eabihf
cargo build --locked --release --bin pico2-kes-agentd --bin pico2-kes-agent-cli
cargo build --locked --release -p pico2-kes-firmware --target thumbv8m.main-none-eabihf
```

Outputs:

- `target/release/pico2-kes-agentd`
- `target/release/pico2-kes-agent-cli`
- `target/thumbv8m.main-none-eabihf/release/pico2-kes-firmware`

The default source firmware build is **unsigned**. `ARM Secure` metadata does not enable signature enforcement. Locked devices require a published project-signed UF2; an unsigned local build cannot run on them. End users need only the release's **public** trust files—never a maintainer's private signing key, GitHub secret or personal GPG private key. Release production and lab procedures are documented separately in the [maintainer guide](docs/maintainer-security.md).

### Install firmware verification tools

Install Python 3, OpenSSL, GPG/GPGV and picotool **2.3.1 with signing/verification and USB support** from a trusted source. If building picotool is necessary, follow its [upstream build instructions](https://github.com/raspberrypi/picotool/blob/2.3.1/BUILDING.md). The device utility does not install packages for you. Check `picotool version` before starting.

The authenticated release includes `pico2-otp-permissions.elf`; end users do **not** build that helper or need the Pico SDK/CMake for the published-bundle provisioning path. It is unsigned preparation-only code, not an update image. Its bundle digest must verify before use; the provisioner binds it to the selected board. Never use stock `picotool otp permissions` for this profile.


### Authenticate a downloaded bundle before executing its verifier

Prefer `python3 -I tools/firmware.py verify --bundle DIR` from an already-trusted checkout. A downloaded verifier cannot establish its own trust by printing success. The checks below use only public certificates, keys and signatures; no GPG private key or passphrase is required.

Download the individual assets for your intended version from [Releases](https://github.com/AndrewWestberg/pico2-kes-agent/releases) into a fresh private directory; GitHub source archives are not firmware bundles. Browser download is sufficient—no GitHub account or repository administration is required. If you already use the optional GitHub CLI, this downloads the assets instead:

```bash
set -euo pipefail
umask 077
TAG=vREPLACE_WITH_ACTUAL_RELEASE
BUNDLE="$(mktemp -d "$HOME/pico2-bundle.XXXXXXXX")"
gh release download "$TAG" --repo AndrewWestberg/pico2-kes-agent --dir "$BUNDLE"
printf 'Downloaded bundle: %s\n' "$BUNDLE"
```

The bundle directory must contain **exactly these eleven files at its root**. Do not add logs, notes, source archives, qualification inputs or wrapping subdirectories:

```text
pico2-kes-firmware.signed.elf
pico2-kes-firmware.signed.uf2
pico2-otp-permissions.elf
firmware.py
otp-policy.json
firmware-signing-public.pem
firmware-key.json
firmware-key.json.asc
release-authority.asc
release.json
release.json.sig
```

If using a browser or a transferred local bundle, set `BUNDLE` to its actual absolute directory instead. The following bootstrap runs trusted local Python/GPGV/OpenSSL only until it has authenticated the downloaded verifier. Run the complete Bash block; any failure means stop:

```bash
(
set -euo pipefail
umask 077
: "${BUNDLE:?Set BUNDLE to the actual absolute bundle directory}"
TRUST="$(mktemp -d)"
trap 'rm -rf -- "$TRUST"' EXIT
python3 -I - "$BUNDLE" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
limits = {"release-authority.asc": 65536, "firmware-key.json": 65536,
          "firmware-key.json.asc": 16384, "firmware-signing-public.pem": 4096,
          "release.json": 1048576, "release.json.sig": 4096, "firmware.py": 1048576}
if not root.is_absolute() or not root.is_dir() or root.is_symlink():
    raise SystemExit("invalid bundle directory")
for name, limit in limits.items():
    path = root / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise SystemExit("missing, symlinked or oversized bootstrap input: " + name)
PY
gpg --batch --no-options --dearmor --output "$TRUST/authority.gpg" \
  "$BUNDLE/release-authority.asc"
gpgv --homedir "$TRUST" --keyring "$TRUST/authority.gpg" --status-fd 1 \
  "$BUNDLE/firmware-key.json.asc" "$BUNDLE/firmware-key.json" \
  > "$TRUST/authorization.status"
python3 -I - "$BUNDLE" "$TRUST/authorization.status" <<'PY'
import hashlib, json, pathlib, sys
def require(condition):
    if not condition:
        raise SystemExit("boot-authority authentication failed")
def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result
bundle, status = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
lines = status.read_text().splitlines()
valid = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
require(len(valid) == 1 and len(valid[0]) == 12)
require(valid[0][2] == "78C0F32094CD02A4BAFA444C684E37A210480F82")
require(valid[0][11] == "9FF957E79B5D853544805F4725491F18087931B6")
require(not any(f"[GNUPG:] {bad}" in line for line in lines
                for bad in ("REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG")))
statement = json.loads((bundle / "firmware-key.json").read_bytes(), object_pairs_hook=unique)
require(set(statement) == {"schema_version", "purpose", "project", "algorithm",
                           "bootkey_slot", "bootkey_sha256", "public_pem_sha256"})
require(type(statement["schema_version"]) is int and statement["schema_version"] == 1)
require(statement["purpose"] == "pico2-kes-firmware-boot-authority-v1")
require(statement["project"] == "https://github.com/AndrewWestberg/pico2-kes-agent")
require(statement["algorithm"] == "secp256k1")
require(type(statement["bootkey_slot"]) is int and statement["bootkey_slot"] == 0)
pem = bundle / "firmware-signing-public.pem"
require(hashlib.sha256(pem.read_bytes()).hexdigest() == statement["public_pem_sha256"])
PY
openssl dgst -sha256 -verify "$BUNDLE/firmware-signing-public.pem" \
  -signature "$BUNDLE/release.json.sig" "$BUNDLE/release.json"
python3 -I - "$BUNDLE" <<'PY'
import hashlib, json, pathlib, sys
def require(condition):
    if not condition:
        raise SystemExit("verifier authentication failed")
def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result
bundle = pathlib.Path(sys.argv[1])
manifest = json.loads((bundle / "release.json").read_bytes(), object_pairs_hook=unique)
require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1)
require(manifest["purpose"] == "pico2-kes-firmware-release-v1")
entries = [entry for entry in manifest["artifacts"] if entry["name"] == "firmware.py"]
require(len(entries) == 1)
data = (bundle / "firmware.py").read_bytes()
require(type(entries[0]["size_bytes"]) is int and len(data) == entries[0]["size_bytes"])
require(hashlib.sha256(data).hexdigest() == entries[0]["sha256"])
PY
python3 -I "$BUNDLE/firmware.py" verify --bundle "$BUNDLE"
)
```

Isolated Python (`-I`) prevents downloaded directories or `PYTHONPATH` from supplying shadow modules. Authentication uses explicit failures, not assertions that optimization could remove. GPGV's success alone is insufficient: the pinned fingerprint and PEM/verifier digest checks must pass before downloaded code runs. Complete verification additionally checks the ROM hash, every fixed asset and signed ELF/UF2 write/erase ranges. It contacts neither USB nor the network.

After authentication, check `release.json.tag` and `.commit` against the release/version you intended to install. Verification authenticates these signed values but does not contact GitHub or resolve a tag for you. Keep the last known-good storage-compatible bundle offline.


### Flash the intended unlocked board

**Unlocked/pre-lock boards only — USB host, attended maintenance:** stop any running agent before flashing. Hold BOOTSEL while connecting the board to USB. When several boards are attached, identify/select the intended board using picotool's current bus/address selection options, or disconnect the other boards before this command. Locked boards use the [signed UF2 upgrade and recovery procedure](#firmware-upgrade), never this unsigned source-build command.

```bash
sudo picotool load -v -x target/thumbv8m.main-none-eabihf/release/pico2-kes-firmware -t elf
```

`-t elf` is required because Cargo's output has no extension; `-v` verifies written bytes and `-x` boots. The linker confines firmware to its own 1-MiB region. Preserve the storage partition: **no whole-flash erase, raw-flash clone, format, or speculative rollback**. Flashing is an external attended procedure, not an agent CLI command. The application udev rule does not cover BOOTSEL; use privileged picotool rather than repeated chmod or world-writable USB rules.

### Install host software and access

**Primary — from the checkout root:**

```bash
sudo deploy/install.sh
OPERATOR_USER="$(id -un)"
sudo usermod -aG pico2-kes-agent "$OPERATOR_USER"
```

**Normal-operation host only:** also grant the actual node service account access. Skip this on a commissioning-only workstation:

```bash
NODE_USER=cardano-node   # replace with the actual node service account
sudo usermod -aG pico2-kes-agent "$NODE_USER"
```

The installer creates `pico2-kes-agent` user/group, installs binaries in `/usr/bin`, preflight in `/usr/libexec/pico2-kes-agent-host-check`, unit in `/usr/lib/systemd/system`, and rule in `/usr/lib/udev/rules.d`. Configuration lives under `/etc/pico2-kes-agent`; private daemon state under `/var/lib/pico2-kes-agent`. It preserves an existing `config.json` and enables, **but does not start**, the service. `DESTDIR` is staging only, not a runnable deployment. The shipped example's zero pins and empty networks are not usable normal configuration.

Start a new operator login to acquire group membership. On a normal-operation host, restart the node through your controlled service procedure when ready so it acquires membership too. Membership also grants management authority; it is not restricted to signing one pool.

**Primary — diagnose application-mode USB:**

```bash
lsusb -d 1209:4b45
sudo lsusb -v -d 1209:4b45
# Set this to the CURRENT device node reported by lsusb, not a saved address.
USB_DEVICE=/dev/bus/usb/001/001
udevadm info --query=all --name="$USB_DEVICE"
stat -c '%A %U %G %n' "$USB_DEVICE"
```

The application exposes `1209:4b45` and a 16-character chip-derived serial. Read the serial from the actual intended board's `iSerial`/udev information. Do not copy another workstation's serial, pin, or a BOOTSEL identifier. The rule grants group `pico2-kes-agent` mode `0660`; addresses change after reconnects. The daemon separately authenticates the pinned identity; permissions are not identity authentication.

### Enforce host memory policies first

The installer does not install the supplied node drop-in or policy acknowledgement file. **Commissioning and OTP provisioning may run on a development workstation without Cardano installed.** Their preflight uses `--commission` and checks only the agent service, not `cardano-node.service` or `NODE_MEMORY_POLICY`. Both modes still require no active swap, masked sleep targets, agent core/swap limits, and the snapshot/backup acknowledgements below. Normal operation additionally requires the real, literally named `cardano-node.service`; a dummy unit is not a substitute.

**Normal-operation host only — install node limits:**

```bash
sudo install -d -m 0755 /etc/systemd/system/cardano-node.service.d
sudo install -m 0644 deploy/cardano-node-memory-hardening.conf \
  /etc/systemd/system/cardano-node.service.d/pico2-kes-memory.conf
sudo systemctl daemon-reload
```

**Both modes:** before proceeding, disable active swap and its reboot activation, mask `sleep.target`, `suspend.target`, `hibernate.target`, and `hybrid-sleep.target`, and disable system/service core and kernel crash dumps. The supplied agent unit already sets `LimitCORE=0`, `MemorySwapMax=0`, and a 256-MiB memlock limit. On a normal-operation host, also apply the node drop-in via a controlled node restart before allowing it to hold new keys.

Also enforce snapshot policy at the actual host/hypervisor/provider layer: disable RAM-bearing snapshots/live migration, or ensure their encryption keys and recovery access remain off-host. Copying a policy file does not enforce this. Review backup software and administrative access as part of the same boundary.

**Normal-operation host:** only after those conditions are true:

```bash
sudo install -o root -g pico2-kes-agent -m 0640 deploy/host-security.env.example \
  /etc/pico2-kes-agent/host-security.env
systemctl show pico2-kes-agentd.service cardano-node.service \
  --property=LimitCORE --property=MemorySwapMax
systemctl is-enabled sleep.target suspend.target hibernate.target hybrid-sleep.target
cat /proc/swaps
sudo /usr/libexec/pico2-kes-agent-host-check
```

Exact acknowledgements in `host-security.env`:

| Literal | Operator assertion |
| --- | --- |
| `SNAPSHOT_POLICY=disabled-or-encrypted-off-host` | RAM snapshots are disabled or protected by encryption controlled off-host. |
| `NODE_MEMORY_POLICY=core-and-swap-disabled` | Normal mode only: node memory cannot enter core dumps or swap. |
| `BACKUP_PRIVATE_POLICY=off-primary` | Recipient private material is not on this host. |

For a **commissioning-only workstation**, do not assert a node policy for a nonexistent node. After actually enforcing the shared host policies, create the acknowledgement file only if one does not already exist:

```bash
if ! sudo test -e /etc/pico2-kes-agent/host-security.env; then
  printf '%s\n' \
    'SNAPSHOT_POLICY=disabled-or-encrypted-off-host' \
    'BACKUP_PRIVATE_POLICY=off-primary' \
    | sudo tee /etc/pico2-kes-agent/host-security.env >/dev/null
  sudo chown root:pico2-kes-agent /etc/pico2-kes-agent/host-security.env
  sudo chmod 0640 /etc/pico2-kes-agent/host-security.env
fi
sudo /usr/libexec/pico2-kes-agent-host-check --commission
```

Both preflight modes require no active swap, all four targets masked, and the agent unit reporting `LimitCORE=0` and `MemorySwapMax=0`. Normal mode additionally checks those limits on `cardano-node.service` and requires its policy acknowledgement. Neither mode can verify provider/snapshot promises. The commissioning override below explicitly selects `--commission` for both preflight and daemon; removing it restores the default normal-mode preflight.

Both `masked` (persistent) and `masked-runtime` (until reboot) satisfy the sleep-target checks. Runtime masks must be reapplied after reboot before provisioning; disabling swap manually also does not prevent its reboot activation.

The service keeps `ProcSubset=pid` and `ProtectProc=invisible`. Because that hides `/proc/swaps` inside its sandbox, the unit binds the live host file read-only at `/run/pico2-kes-agent/host-swaps` and directs preflight there. This is not a cached swap-status snapshot or a preflight bypass; do not remove the check or run it outside the service sandbox to work around a startup failure.

## Commission and configure

### Operator workspace and commissioning mode

**Primary — operator, not root:** use a private, owner-controlled directory for receipts, public inputs, and outputs. Never ask the CLI to publish into root-owned `/etc`.

```bash
set -euo pipefail
umask 077
OPS="$HOME/pico2-kes-ops"
install -d -m 0700 "$OPS"
USB_SERIAL=REPLACE_WITH_16_CHAR_SERIAL
```

Replace the serial before proceeding. Save the following complete **commissioning JSON template** as `$OPS/commission.json`, replacing its serial. Unknown fields are rejected; this version-1 configuration intentionally has no installed pin and no pools.

```json
{
  "version": 1,
  "device": {"usb_serial": "REPLACE_SERIAL16"},
  "socket_directory": "/run/pico2-kes-agent",
  "socket_group": "pico2-kes-agent",
  "socket_mode": "0660",
  "management_socket": "/run/pico2-kes-agent/management.sock",
  "state_directory": "/var/lib/pico2-kes-agent",
  "networks": {},
  "pools": []
}
```

**Primary — administrative service setup:** reuse the installed unit's UID, memlock limits, runtime/state directories, and USB confinement. Stop it before changing mode.

This is initial commissioning or explicitly selected fresh OTP conversion only—not a firmware update. Before replacing an existing operational configuration, stop/fence producers, preserve their public records and cleanly stopped journal, and archive the configuration without clobbering an earlier archive:

```bash
sudo systemctl stop pico2-kes-agentd
if sudo test -e /etc/pico2-kes-agent/config.json; then
  (set -C; umask 077; sudo cat /etc/pico2-kes-agent/config.json \
    > "$OPS/config.before-commissioning.json")
fi
```

Both the daemon and provisioner must use `/etc/pico2-kes-agent/config.json`; the tool has no configuration-path override. Keep `device` as exactly `{"usb_serial": "your actual serial"}` and `pools` empty through all OTP stages. Do not leave an old normal-mode pin at this path while running the daemon against a separate commissioning file.


```bash
sudo systemctl stop pico2-kes-agentd
sudo install -o root -g pico2-kes-agent -m 0640 "$OPS/commission.json" \
  /etc/pico2-kes-agent/config.json
sudo install -d -m 0755 /run/systemd/system/pico2-kes-agentd.service.d
sudo tee /run/systemd/system/pico2-kes-agentd.service.d/commission.conf >/dev/null <<'UNIT'
[Service]
ExecStartPre=
ExecStartPre=/usr/libexec/pico2-kes-agent-host-check --commission
ExecStart=
ExecStart=/usr/bin/pico2-kes-agentd --commission --config /etc/pico2-kes-agent/config.json
UNIT
sudo systemctl daemon-reload
sudo systemctl start pico2-kes-agentd
```

### Optional attended OTP provisioning

This is a **manual, irreversible initial conversion**, completed before `device commission`, never an update/recovery step. Commands alone do not establish physical qualification. A2/A4 are silicon steppings, not KES Service V2 versions; A4 remains physically unverified here. Locking cannot repair extracted secrets. Review the [security boundary](#purpose-and-security-boundary) first. You need the authenticated public release bundle, not any private firmware-signing key.

Prerequisites: installed verification tools, the helper included in the authenticated bundle, matching host binaries, passing existing host preflight and the commissioning service setup above using **`/etc/pico2-kes-agent/config.json`**. Preserve `ExecStartPre`, service UID, confinement, memory limits and identity handshake. The provisioner does not install tools, control services, mount volumes or change configuration.

Use **two local terminals**:

- **A:** run the firmware tool in the foreground with stdin **and stdout** attached to the terminal. No `tee`, redirection, background jobs or scripted prompt answers. Applying stages require typing the exact serial.
- **B:** control the existing service and perform physical BOOTSEL/power/mount transitions. Complete the requested transition before pressing Enter in A. Never perform a competing copy while the enable-stage tool copies its UF2.

In A, from the trusted checkout, set the actual absolute bundle path and pinned tool directory. Application udev permissions do not cover BOOTSEL; run offline provisioning with explicit root privileges/PATH and keep its records separate from operator CLI receipts:

```bash
BUNDLE=/absolute/path/to/verified-bundle
FIRMWARE_TOOL="$PWD/tools/firmware.py"
TOOL_BIN=/absolute/path/to/directory-containing-picotool-2.3.1
test -x "$TOOL_BIN/picotool"
PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" verify --bundle "$BUNDLE"
PROVISION_DIR="/var/lib/pico2-kes-provisioning/$USB_SERIAL"
sudo install -d -o root -g root -m 0700 "$PROVISION_DIR"
RECORD="$PROVISION_DIR/otp-provisioning.json"
ERASE_RECORD="$PROVISION_DIR/erase-state.json"
sudo test ! -e "$RECORD"
sudo test ! -e "$ERASE_RECORD"
```

`USB_SERIAL` must already be the intended board's 16-character lowercase application chip-derived serial—not its BOOTSEL serial or saved bus address. Attach exactly one board. Keep the same effective UID (root), exact picotool executable and loaded libusb identities, unchanged bundle and original record while advancing between successfully completed stages. Schema-2 records bind canonical paths, hashes, build ID and package/version details; identical `picotool version` text is not sufficient. Older records are rejected without migration. Records are mode 0600; do not chown or edit them between stages.

**Before the initial preview or erase invocation**, stop the daemon in B, disconnect the selected board and hold BOOTSEL while reconnecting it:

```bash
sudo systemctl stop pico2-kes-agentd
# Physically reconnect the intended board with BOOTSEL held.
```

Starting in BOOTSEL avoids depending on old application firmware that lacks `device security`. In A, inspect and preview without writes:

```bash
sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
  inspect --serial "$USB_SERIAL"
sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
  provision --stage prepare --serial "$USB_SERIAL" --bundle "$BUNDLE" --record "$RECORD"
```

A preview is **not OTP admission**. BOOTSEL cannot establish fitted flash. Before OTP programming, the installed verified application must report JEDEC `ef4016`, SFDP `534644500a0100ff00080117800000ff`, density-minus-one `0x01ffffff`, `storage_blank_at_boot: true`, and status `commissioning_state: blank` on the same serial. Blank/uncommissioned checks remain mandatory through enable and the lock cold boot. Do not commission, enroll pools, set recipients or generate keys between stages.

If the preview rejects unexpected OTP output, stop before any applying or erase command. Keep the complete diagnostic for troubleshooting; do not ignore extra rows or warnings. When using a corrected tool from an already-trusted checkout, leave the authenticated bundle unchanged—replacing its bundled `firmware.py` invalidates the signed manifest. Retry only the read-only preview before proceeding.

**Optional destructive erase—only for deliberately selected fresh conversion:** export required artifacts, archive public records and stop/fence producers first. Accept loss of the existing device identity and pool material; this is not secure erasure or revocation of copies. With the daemon stopped and the unlocked board already in BOOTSEL, use its **separate** erase record:

```bash
sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
  erase-state --serial "$USB_SERIAL" --record "$ERASE_RECORD" --apply
```

Only `[0x10100000,0x10308000)` is erased, not firmware/OTP. The tool requires secure boot disabled and all redundant CRIT1 rows still zero; partial or stricter prior programming is a stop, not permission to reset it. Never pass `$ERASE_RECORD` to provision, delete it to force preparation, or erase during an update/recovery. Leave `$RECORD` nonexistent for first prepare. The later fresh application report—not the erase command alone—must establish blankness.

Run stages **one at a time**, review each result, and stop on any error:

1. **Prepare**, starting in BOOTSEL with the daemon stopped:

   ```bash
   sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
     provision --stage prepare --serial "$USB_SERIAL" --bundle "$BUNDLE" --record "$RECORD" --apply
   ```

   The tool loads/readback-verifies the signed ELF and leaves BOOTSEL available for verification. At the application prompt, B physically reconnects **without BOOTSEL** and runs `sudo systemctl start pico2-kes-agentd`. Diagnose startup failure with `sudo systemctl status pico2-kes-agentd` and `sudo journalctl -u pico2-kes-agentd --no-pager -n 50`; do not continue A until startup/readiness is established. The tool obtains `device security` and `status` through the installed CLI; pasted assertions do not count. At the next prompt, stop the daemon in B and physically re-enter BOOTSEL. It then programs/readbacks the public slot-0 hash/key masks and runs the authenticated target-bound unsigned helper to close page-2/page-63 permissions with RMA clear. Never use `picotool otp permissions`. Successful prepare ends in **BOOTSEL**, not application mode.

2. **Enable**, retaining the prepared record and BOOTSEL state:

   ```bash
   sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
     provision --stage enable --serial "$USB_SERIAL" --bundle "$BUNDLE" --record "$RECORD"
   sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
     provision --stage enable --serial "$USB_SERIAL" --bundle "$BUNDLE" --record "$RECORD" --apply
   ```

   This enables secure boot only, reboots and pauses for the commissioning daemon. Later B must stop it, physically enter BOOTSEL and mount the board. Supply the **absolute mounted volume root**, never `/dev/sdX` or a guessed directory. The tool checks USB ancestry/`INFO_UF2.TXT`, then **copies and flushes the UF2 itself**. At the next prompt, re-enter BOOTSEL for installed-image verification. Then reconnect without BOOTSEL and restart the commissioning daemon in B before continuing A. Successful enable observes signed startup and verified reinstall before final interface/debug restrictions.

3. **Lock**, only after successful enable observations. First stop the daemon in B and physically enter BOOTSEL again:

   ```bash
   sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
     provision --stage lock --serial "$USB_SERIAL" --bundle "$BUNDLE" --record "$RECORD"
   sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
     provision --stage lock --serial "$USB_SERIAL" --bundle "$BUNDLE" --record "$RECORD" --apply
   ```

   The tool programs each physical copy of the restrictions/debug fuses separately, reads that row back before advancing, and independently verifies each complete redundant group. It stops at the first mismatch even if picotool reports success. At its prompt, cold-power-cycle **without holding BOOTSEL**, start the commissioning daemon in B and let A check the serial, authorized key, runtime debug locks and locked profile. The final prompt asks B to stop the daemon, enter BOOTSEL and mount MSD again. This check observes MSD present/PICOBOOT absent; **it does not copy another UF2 or prove post-lock recovery**.

After successful lock, reconnect **without BOOTSEL**, restart the commissioning daemon in B and [commission the blank device](#commission-the-blank-device) as the ordinary operator with fresh receipts. Do not run ordinary commissioning mutations as root merely because offline provisioning needed BOOTSEL privileges. No unsigned helper or picotool device access is available after lock.

**Failed/interrupted stages are not automatically resumable.** Ordinary prepare refuses an existing record; enable/lock require the exact preceding completed stage, and non-null `pending` is rejected. An uncertain write retains its intended physical postcondition, bounded subprocess diagnostics and any available readback. Preserve records/diagnostics unchanged; do not reset, retry or power-cycle until the state has been diagnosed. Do not edit `pending`/`completed_stage`, replay OTP, remove records or substitute keys to force advancement. A fully matching locked application may be confirmed read-only, but `already_provisioned` does not repair an interrupted record or establish missing MSD/qualification observations. If a locked application cannot boot, use verified full-UF2 [recovery](#firmware-upgrade), not provision or erase-state.

There is one explicit pre-OTP recovery checkpoint: if preparation installed the signed firmware but failed before recording blank-application admission, `--resume` may continue **only** when the original owner-only schema-2 record has exactly the public preparation preflight and completed signed-firmware installation, with both `pending` and `completed_stage` null. Use the same serial, exact tool/library identities, unchanged bundle and record. Start the commissioning daemon with the selected application connected, confirm fresh `device security` and `status` reports, then run in A:

```bash
sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
  provision --stage prepare --serial "$USB_SERIAL" --bundle "$BUNDLE" \
  --record "$RECORD" --apply --resume
```

This does not erase or reinstall firmware. It repeats the attended serial confirmation and application-transition pause, rechecks blank-at-boot/uncommissioned admission, then pauses for B to stop the daemon and physically enter BOOTSEL. Before any OTP write it requires fresh public OTP to equal the recorded preflight and verifies the installed signed ELF against the authenticated bundle. A mismatch stops; a pending operation, any OTP-write observation, or any other checkpoint is not resumable. Do not use a new record path to bypass these conditions.

If the **only** pending action has `step: page2_page63_permissions`, do not rerun the helper or use `--resume`. With the daemon stopped and the same board still available in BOOTSEL, the following command can assess the helper's postconditions from fresh observations:

```bash
sudo env PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" \
  reconcile-prepare --serial "$USB_SERIAL" --bundle "$BUNDLE" \
  --record "$RECORD" --apply
```

Here `--apply` authorizes attended **read-only observation**, not a record update or device write. The tool verifies schema-2 bundle/record/serial/tool bindings and preceding preparation observations, computes the helper's exact expected permission changes while retaining stricter locks, and requires two identical full public OTP snapshots around installed-image verification. It prints the assessment but leaves the original record byte-for-byte unchanged, including `pending` and `completed_stage`. Neither successful postconditions nor later repair establishes the cause of the failed operation or permits automatic advancement to enable.

### Commission the blank device

**Primary — operator, attended blank-device initialization:**

```bash
pico2-kes-agent-cli device commission --usb-serial "$USB_SERIAL" \
  --expected-revision 0 --receipt "$OPS/commission.receipt.json" --out "$OPS/device.json"
```

Physically trust the selected board and firmware. The record's self-signature is not independent hardware attestation. Archive the public `device.json` and original receipt separately from the machine. Nonblank, corrupt, or already-commissioned storage is not automatically reset.

If the outcome is uncertain, keep the receipt and use [reconciliation](#reconciliation) with an unused `--out` path to recover the public record; do not commission again. The exported record includes `kind`, `device_id`, `identity_public_key`, `identity_fingerprint`, `usb_serial`, protocol/storage versions, and `revision`.

### Normal configuration and trusted context

Create `$OPS/config.json` using the complete **normal-mode JSON template** below. Replace all synthetic identity, digest, network parameters, and paths. In `device`, set `id` from the record's `.device_id`, `identity_public_key` from `.identity_public_key`, and `usb_serial` from `.usb_serial`. The zero identity below is not a live device pin.

```json
{
  "version": 1,
  "device": {
    "id": "00000000000000000000000000000000",
    "identity_public_key": "0000000000000000000000000000000000000000000000000000000000000000",
    "usb_serial": "REPLACE_SERIAL16"
  },
  "socket_directory": "/run/pico2-kes-agent",
  "socket_group": "pico2-kes-agent",
  "socket_mode": "0660",
  "management_socket": "/run/pico2-kes-agent/management.sock",
  "state_directory": "/var/lib/pico2-kes-agent",
  "networks": {
    "pool-network": {
      "genesis_file": "/etc/cardano/pool-network/genesis.json",
      "genesis_digest": "0000000000000000000000000000000000000000000000000000000000000000",
      "network_magic": 42,
      "mainnet": false,
      "node_socket": "/run/cardano-node/node.socket",
      "cardano_cli": "/usr/local/bin/cardano-cli",
      "era_history": "/etc/pico2-kes-agent/pool-network-history.json",
      "slots_per_kes_period": 100,
      "kes_lifetime": 64,
      "max_context_age_ms": 30000,
      "query_timeout_ms": 5000
    }
  },
  "pools": []
}
```

The `42`/`100` values are illustrative, **not production defaults**. Use the selected network's trusted genesis for `networkMagic`, `slotsPerKESPeriod`, and `maxKESEvolutions`, and verify those values against its authoritative configuration. `mainnet=true` requires magic `764824073`. Compute the exact selected genesis file's SHA-256:

```bash
GENESIS=/etc/cardano/pool-network/genesis.json
sha256sum "$GENESIS"
DEVICE_RECORD="$OPS/device.json"
jq -e '{id: .device_id, identity_public_key: .identity_public_key, usb_serial: .usb_serial}' "$DEVICE_RECORD"
```

Use absolute paths visible inside the service sandbox, not `/home` or `/tmp`. Make public genesis/history files readable by the service. Give the daemon access to the node query socket **and traversal of each parent directory**, using the node's controlled group/ACL and, if necessary, a unit `SupplementaryGroups=` drop-in. Do not make sockets/directories world writable. This node-query access is distinct from the node's access to the agent's per-pool delivery sockets and from the operator's private receipts.

Era history is an operator-supplied JSON array of `{start_slot, start_time_us, slot_length_us}`. The first slot must be zero; times are **absolute Unix microseconds**, not offsets from Shelley genesis. Successive segments must satisfy:

`next.start_time_us = current.start_time_us + (next.start_slot - current.start_slot) * current.slot_length_us`

Obtain actual slot-length transitions from authoritative network history, including pre-Shelley history where applicable. A single-Shelley-genesis shortcut is not valid for all networks. There is no automatic history generator in this repository.

**Synthetic arithmetic example only — not mainnet or testnet history:** ten slots of two seconds end at Unix time `1700000020000000` microseconds, followed by one-second slots.

```json
[
  {"start_slot": 0, "start_time_us": 1700000000000000, "slot_length_us": 2000000},
  {"start_slot": 10, "start_time_us": 1700000020000000, "slot_length_us": 1000000}
]
```

The parser accepts 1–32 segments with positive slot lengths. `max_context_age_ms=30000` and `query_timeout_ms=5000` are example settings: maximum context age must be positive and at most 255000 ms; query timeout must be positive. A stale tip, failed query, bad genesis/history, or unrecognized synchronization state withholds fresh context/key delivery. Recheck the [clock-marker limitation](#requirements-and-compatibility) before relying on delivery; configuration validation does not test it.

Normal `pools` may initially be empty. Management enrollment and the durable public journal reconstruct bindings; **preserve the journal**. Default enrollment creates `<pool-id>.sock` directly under `socket_directory`. For migration/custom socket names, an optional explicit binding has this shape (replace IDs with returned values and insert into `pools`):

```json
{
  "pool_id": "00000000000000000000000000000000000000000000000000000000",
  "incarnation_id": "00000000000000000000000000000000",
  "socket_path": "/run/pico2-kes-agent/custom-pool.sock",
  "network": "pool-network"
}
```

### Switch to normal mode

**Primary — administrative setup:** stop commissioning, install the reviewed normal configuration, remove **only** the dedicated runtime override, and check as the service UID. Do not use `systemctl revert`, which could erase unrelated operator overrides. Runtime/state directories must already exist and belong to that UID; systemd's runtime directory may disappear when the service stops, so create it before a manual check.

```bash
sudo systemctl stop pico2-kes-agentd
sudo install -o root -g pico2-kes-agent -m 0640 "$OPS/config.json" /etc/pico2-kes-agent/config.json
sudo rm /run/systemd/system/pico2-kes-agentd.service.d/commission.conf
sudo systemctl daemon-reload
sudo install -d -o pico2-kes-agent -g pico2-kes-agent -m 0750 /run/pico2-kes-agent
sudo install -d -o pico2-kes-agent -g pico2-kes-agent -m 0700 /var/lib/pico2-kes-agent
sudo -u pico2-kes-agent /usr/bin/pico2-kes-agentd \
  --check-config --config /etc/pico2-kes-agent/config.json
sudo systemctl start pico2-kes-agentd
systemctl status pico2-kes-agentd
pico2-kes-agent-cli --json status
```

Device `ready` with no pools proves neither valid period context, key delivery, nor block production.

## Enroll and serve the first generation

### Shell and file conventions

All following primary commands run as the operator in a Bash session with `set -euo pipefail` and `umask 077`, using the private `OPS` directory above. Global `--socket` and `--json` precede command words. The default management socket is `/run/pico2-kes-agent/management.sock`; override it only with `pico2-kes-agent-cli --socket "$MANAGEMENT_SOCKET" --json ...` after defining that path.

Every mutation needs a **new, unique receipt file**; the example filenames below are for a first run only. `--operation-id` is optional; the CLI generates one. Capture successful JSON before extracting with `jq -e`; do not pipe a mutation into `jq`, hide its exit, or continue after nonzero exit. In an interactive shell, stop the sequence explicitly on any failure; do not rely solely on shell options in conditional contexts.

Refresh `.result.revision` from device `status` immediately before `recipient set` and `pool enroll`, and from `pool status --pool "$POOL"` before generation/certificate/discard/delete mutations. Concurrent operations can still cause `revision_conflict`: that is a rejection, unlike an uncertain submitted operation, which needs reconciliation with its original receipt.

File inputs and immediate parents must be owned by the invoking operator and not group/world writable. Copy transferred public files into the private workspace as that operator. Outputs are owner-only and no-clobber. A missing output after a successful mutation is not permission to repeat the mutation.

### 1. Create a backup recipient off-primary

**Backup-recipient host:** install the host CLI there, create a private directory, and retain the private file and passphrase securely.

```bash
set -euo pipefail
umask 077
BACKUP_OPS="$HOME/pico2-kes-backup"
install -d -m 0700 "$BACKUP_OPS"
RECIPIENT_KEY="$BACKUP_OPS/recipient.private"
RECIPIENT_PUBLIC="$BACKUP_OPS/recipient.public.json"
pico2-kes-agent-cli recipient create --out "$RECIPIENT_KEY" --public-out "$RECIPIENT_PUBLIC"
```

Terminal prompts handle passphrases. There is no argv/environment passphrase option. Transfer **only the public JSON** to the primary's `$OPS/recipient.public.json`.

### 2. Install the public recipient

**Primary:**

```bash
RECIPIENT_PUBLIC="$OPS/recipient.public.json"
DEVICE_STATUS=$(pico2-kes-agent-cli --json status)
DEVICE_REV=$(jq -er '.result.revision' <<<"$DEVICE_STATUS")
RECIPIENT_RESULT=$(pico2-kes-agent-cli --json recipient set --public-key "$RECIPIENT_PUBLIC" \
  --expected-revision "$DEVICE_REV" --receipt "$OPS/recipient-set.receipt.json")
printf '%s\n' "$RECIPIENT_RESULT"
```

### 3. Enroll the pool

Transfer the public cold verification key from the cold host to `$OPS/cold.vkey`; the cold signing key never follows it. Standard Cardano public cold-vkey envelopes are suitable. The generic public input reader does not validate arbitrary envelope type metadata; device certificate validation is the authority.

**Primary:**

```bash
NETWORK=pool-network
COLD_VKEY="$OPS/cold.vkey"
DEVICE_STATUS=$(pico2-kes-agent-cli --json status)
DEVICE_REV=$(jq -er '.result.revision' <<<"$DEVICE_STATUS")
ENROLL_RESULT=$(pico2-kes-agent-cli --json pool enroll --cold-vkey "$COLD_VKEY" --network "$NETWORK" \
  --expected-revision "$DEVICE_REV" --receipt "$OPS/enroll.receipt.json")
POOL=$(jq -er '.result.pool_id' <<<"$ENROLL_RESULT")
INCARNATION=$(jq -er '.result.incarnation_id' <<<"$ENROLL_RESULT")
pico2-kes-agent-cli --json pool status --pool "$POOL"
pico2-kes-agent-cli --json pool list --page-size 16
```

`POOL` is 56 lowercase hexadecimal characters, not Bech32 `pool1...`. Device, incarnation, and generation IDs are 32 hex characters. Save returned IDs with your records. Obtain `POOL_SOCKET` from the matching pool's returned list entry `socket_path`; follow pagination when necessary, rather than substituting the management socket.

### 4. Generate a staged key

**Primary:**

```bash
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
GENERATE_RESULT=$(pico2-kes-agent-cli --json key generate --pool "$POOL" --incarnation "$INCARNATION" \
  --expected-revision "$POOL_REV" --receipt "$OPS/generate.receipt.json")
GENERATION=$(jq -er '.result.generation_id' <<<"$GENERATE_RESULT")
```

Generation already commits the encrypted artifact and activation intent. There is no later backup-approval gate.

### 5. Retrieve verification key and encrypted backup

**Primary:**

```bash
KES_VKEY="$OPS/first-kes.vkey"
ARTIFACT="$OPS/first-kes.backup"
pico2-kes-agent-cli key verification-key --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --out "$KES_VKEY"
pico2-kes-agent-cli key export --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --out "$ARTIFACT"
```

The vkey uses the `KesVerificationKey_ed25519_kes_2^6` envelope. Export is read-only ciphertext, **not a signing-key file**. Retrieve it before replacement, expiry, discard, or pool deletion retires device-side retrieval. Archive it and the [restore bundle](#offline-restoration-and-failover) off-primary before certificate installation. Read-only exports may be repeated to fresh paths.

### 6. Issue the certificate offline

Determine and verify the **absolute** start KES period from the actual network's current slot and trusted `slotsPerKESPeriod`: integer division `current_slot / slotsPerKESPeriod` gives the current absolute period. Choose the intended valid start with enough commissioning time, not a wall-clock guess or a relative evolution number. Transfer the vkey and independently checked period information to the cold host.

**Offline cold-key host:** set paths to your existing protected key/counter, choose `ERA` supported by the installed matching CLI and network, and set `START_PERIOD` to the verified absolute value before running:

```bash
set -euo pipefail
umask 077
COLD_OPS="$HOME/pool-cold"
KES_VKEY="$COLD_OPS/first-kes.vkey"
COLD_SKEY="$COLD_OPS/cold.skey"
COUNTER="$COLD_OPS/cold.counter"
OPCERT="$COLD_OPS/first.opcert"
ERA=conway             # select for your installed CLI/network
: "${START_PERIOD:?Set the independently verified absolute start period}"
cardano-cli "$ERA" node issue-op-cert --kes-verification-key-file "$KES_VKEY" \
  --cold-signing-key-file "$COLD_SKEY" --operational-certificate-issue-counter-file "$COUNTER" \
  --kes-period "$START_PERIOD" --out-file "$OPCERT"
```

Preserve the updated issuance counter. Never reset it or repeatedly issue certificates to fix a transport timeout. Transfer only the certificate back to the primary's workspace, and include it in the off-primary backup bundle.

### 7. Install the certificate

**Primary:**

```bash
OPCERT="$OPS/first.opcert"
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
CERTIFICATE_RESULT=$(pico2-kes-agent-cli --json certificate install --pool "$POOL" \
  --incarnation "$INCARNATION" --generation "$GENERATION" --certificate "$OPCERT" \
  --expected-revision "$POOL_REV" --receipt "$OPS/certificate.receipt.json")
printf '%s\n' "$CERTIFICATE_RESULT"
pico2-kes-agent-cli --json pool status --pool "$POOL"
```

A valid future-start certificate waits staged. A currently valid eligible generation activates automatically after valid context and required cleanup. There is no activation command or backup-approval command. Inspect pool status and actual node consumption rather than treating certificate-command success as proof of forging.

## Connect cardano-node

**Primary — singleton producer example:** retain your normal config/topology/database/node-socket arguments. Set these paths for your deployment; get `POOL_SOCKET` from the matching returned `pool list` entry, not a receipt filename.

```bash
NODE_CONFIG=/etc/cardano/config.json
TOPOLOGY=/etc/cardano/topology.json
DATABASE=/var/lib/cardano-node/db
NODE_SOCKET=/run/cardano-node/node.socket
VRF_SKEY=/etc/cardano/vrf.skey
: "${POOL_SOCKET:?Set the socket_path returned for this pool}"
cardano-node run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --shelley-kes-agent-socket "$POOL_SOCKET" \
  --shelley-operational-certificate "$OPCERT" --shelley-vrf-key "$VRF_SKEY"
```

Replace the old `--shelley-kes-key` source; do not pass both sources. For a systemd producer, put the arguments and an accessible public startup-certificate path in its existing configuration, not the operator's protected home directory. Keep the cold key and recipient private key off this host.

Migration from a signing-key file or the original agent uses a **fresh device generation and new certificate**, not plaintext import. Keep the existing producer until the replacement is ready, then fence/stop it before enabling replacement forging. Avoid dual forging.

Ordinary evolution and generation rotation require neither node restart nor SIGHUP. Keep the node's startup certificate file current for future restarts. A change to startup configuration requires a controlled restart using your normal node-service procedure. A running node may retain already delivered state and evolve/sign independently; stopping the agent alone is not revocation.

## Operations and maintenance

### Command reference

These are all implemented CLI commands; global options are `--socket PATH` and `--json`. The CLI provides top-level help, not detailed subcommand help. Mutating service commands accept optional `--operation-id` alongside the target/revision/receipt flags shown in their walkthroughs.

| Command | Complete walkthrough |
| --- | --- |
| `status` | [Routine inspection](#routine-inspection) |
| `device commission` | [Commissioning](#operator-workspace-and-commissioning-mode) |
| `device security` | Read-only public OTP/flash/debug report, available in commissioning and normal modes; no command-specific flags |
| `pool list`, `pool status` | [Routine inspection](#routine-inspection) |
| `pool enroll` | [Enrollment](#3-enroll-the-pool) |
| `pool delete` | [Pool removal](#pool-removal-and-re-enrollment) |
| `key generate` | [Generation](#4-generate-a-staged-key) |
| `key verification-key`, `key export` | [Public key and backup](#5-retrieve-verification-key-and-encrypted-backup) |
| `key discard` | [Staged cancellation](#staged-slot-and-cancellation) |
| `certificate install` | [Certificate installation](#7-install-the-certificate) |
| `recipient create`, `recipient set` | [Recipient creation](#1-create-a-backup-recipient-off-primary), [installation](#2-install-the-public-recipient), [rotation](#recipient-rotation) |
| `operation reconcile` | [Reconciliation](#reconciliation) |
| `restore` | [Offline restoration](#offline-restoration-and-failover) |

### Routine inspection

**Primary — operator:**

```bash
pico2-kes-agent-cli status
pico2-kes-agent-cli --json pool status --pool "$POOL"
CURSOR=
while :; do
  if [[ -n "$CURSOR" ]]; then
    PAGE=$(pico2-kes-agent-cli --json pool list --page-size 16 --cursor "$CURSOR")
  else
    PAGE=$(pico2-kes-agent-cli --json pool list --page-size 16)
  fi
  jq -e '.result.pools' <<<"$PAGE"
  CURSOR=$(jq -r '.result.cursor // empty' <<<"$PAGE")
  [[ -n "$CURSOR" ]] || break
done
systemctl status pico2-kes-agentd
sudo journalctl -u pico2-kes-agentd --since '1 hour ago' --no-pager
```

Follow the returned cursor until absent/null. Inspect device identity, pool incarnation, active/staged state, validity and context, then check node logs/operational metrics for actual consumption and forging. Do not dump secret USB/socket traffic into logs or support bundles.

### Evolution, rotation, and expiry

Period evolution is automatic under trustworthy context; it does not issue a new certificate. Plan generation rotation before expiry. Repeat [generation through certificate installation](#4-generate-a-staged-key) with **new output and receipt names**. Export before installing the certificate, retain the active generation until replacement validity, and update the node's startup certificate file for future restarts. There is no additional backup-readiness gate.

Replenishment reuses the retired generation's public-object region, leaving the active generation's public tree and encrypted backup intact across repeated rotations and reboot. This allocation correction prevents new overwrites; it cannot restore an object already overwritten by affected firmware. Verification covers the software NOR fault model and CLI exports, not physical flash qualification or repair of an already-damaged pool.

On expiry or outage, first restore legitimate context and inspect pool state. If the generation is expired, create/certify a replacement. Do not roll back the clock/period or expect an expired signing key to become useful again.

### Staged slot and cancellation

There is only one staged slot per pool. Before destructive cancellation, export/copy any needed artifact and public records: discard ends retrieval on the device but does not revoke external copies. Confirm the exact staged generation from fresh status; do not assume the old shell variable still names it.

**Primary — deliberate cancellation:**

```bash
: "${GENERATION:?Set the exact staged generation to discard}"
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
DISCARD_RESULT=$(pico2-kes-agent-cli --json key discard --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --expected-revision "$POOL_REV" --receipt "$OPS/discard.receipt.json")
printf '%s\n' "$DISCARD_RESULT"
```

Type `yes` at the interactive confirmation, or append `--yes` only for deliberate automation. A late discard can return `target_not_staged` after activation; refresh status, do not target a different generation as a retry.

### Recipient rotation

Create a new recipient on the backup host using new paths, transfer only its public JSON, and repeat [recipient installation](#2-install-the-public-recipient) with a **fresh device revision and new receipt**. It affects only future generations, not existing artifacts. Keep old private files/passphrases while their artifacts are needed. A lost recipient/passphrase cannot decrypt old ciphertext; a fresh recipient and generation can protect future backups but cannot repair that loss.

### Reconciliation

After timeout, uncertain/pending status, or a lost response, retain the original receipt, operation ID, target, revision, and digest. Do not submit a new operation merely because the result is unknown.

**Primary — same original receipt:**

```bash
RECEIPT="$OPS/generate.receipt.json"  # choose the original uncertain operation
pico2-kes-agent-cli operation reconcile --receipt "$RECEIPT"
```

For commissioning-output recovery only, choose the commissioning receipt and a fresh output path:

```bash
RECEIPT="$OPS/commission.receipt.json"
pico2-kes-agent-cli operation reconcile --receipt "$RECEIPT" --out "$OPS/device-recovered.json"
```

A local output failure after device success still needs reconciliation, not another mutation. Read-only vkey/artifact exports can instead be repeated to fresh paths. Busy/recovering operations may require waiting for recovery before reconciling the same receipt.

### Host restart and device reconnect

Preserve pin/config/public journal and use the installed service. After restart/reconnect, check the **same** identity and each pool's readiness using [routine inspection](#routine-inspection). A running node may continue with its already received state; a reconnecting node requires fresh valid context. Disconnect is not revocation.

### Host software upgrade

**Primary — maintenance window:** stop the agent, preserve `/etc/pico2-kes-agent`, `/var/lib/pico2-kes-agent`, operator receipts and public identity, then rebuild/reinstall using [the build/install instructions](#build-flash-and-install). Make offline copies after clean shutdown; preserve ownership and permissions. Do not restore an older journal/flash image to force rollback.

There is no daemon configuration hot reload. Check configuration as the service UID with existing owned runtime/state directories, restart through systemd, then verify identity and pool readiness. The installer preserves an existing config; it does not merge new settings or install the optional hardening files automatically.

### Firmware upgrade

**Normal update or application-failure recovery — not provisioning:** authenticate and verify the complete bundle using the [bootstrap procedure](#authenticate-a-downloaded-bundle-before-executing-its-verifier), including its signed manifest, ELF and UF2 range checks. Keep the last known-good compatible signed bundle offline. The verified UF2 writes/erases only firmware `[0x10000000, 0x10100000)`; preserve all state `[0x10100000, 0x10308000)`, including configuration, pool and handoff sectors. The signed ELF and unsigned permission helper are not the update file.

Before planned maintenance, retain **public** identity, recipient-policy/installation records, pool/incarnation/generation bindings, active/staged verification keys and certificates, floors and comparison outcomes. Never save current secret KES bytes or their hashes as a maintenance record. Preserve normal configuration, pin and journal. Stop/fence producers as appropriate, stop the daemon, and physically hold BOOTSEL while reconnecting the one intended board.

There is no standalone updater command in `firmware.py`. For a normal update/recovery, the operator copies the verified UF2 manually. Select the **actual existing mounted RP2350 volume root**, not `/dev/sdX`, a guessed stale directory or an assumed volume label. Never `mkdir` a missing mount path and copy into it as a substitute for mounting the board. Inspect its mount/device and `INFO_UF2.TXT`; physically control the selected board because the BOOTSEL serial need not equal the application serial:

```bash
set -euo pipefail
MSD=/absolute/path/to/the/current/RP2350-mount
findmnt --mountpoint "$MSD" -o SOURCE,TARGET,FSTYPE
cat "$MSD/INFO_UF2.TXT"
# STOP unless this is the intended USB board and Board-ID identifies RP2350.
cp -- "$BUNDLE/pico2-kes-firmware.signed.uf2" "$MSD/"
sync -f "$MSD"
```

Wait for successful copy/flush completion and application reboot; a successful local file copy alone is not successful installation. Treat copy/flush errors or a vanished mount before confirmation as uncertain, not as success on the theory that reboot probably happened. Re-enter physical BOOTSEL and diagnose/repeat the complete verified UF2 as necessary; never repair an update by erasing state or programming OTP. Restart the daemon in its **existing normal configuration** and establish fresh valid context. Do not use picotool device access on a locked board, enter commissioning, run `provision`/`erase-state`, restore a whole-flash image, replace the pin/journal, export/reimport device keys, regenerate or recommission.

Check that the same pinned identity and recipient configuration remain, and compare every pool/incarnation/generation, active and staged verification key and certificate binding, period floor, and usable current KES state with the pre-update observations. At the same valid period, current KES state must be retained; when context later advances normally to the staged generation's start period, that same staged generation must become usable with its original bindings. Normal evolution, activation and expiry are distinct from update-induced loss. If a key, identity, floor or binding is missing or changed, stop and preserve diagnostics; do not make the comparison pass by resetting or replacing state.

Do not move real network periods backward or freeze live context to force byte equality: an update may span legitimate evolution/activation/expiry. Establish fresh context/session after reboot and distinguish those transitions from loss. Status/security alone do not expose every retained value; retain the original public certificate and recipient records. Lab preservation tests are maintainer procedures, not a required end-user upgrade step.

Any compatible project-signed release can boot: there is no automatic irreversible firmware anti-rollback. A downgrade is supported only when its storage format and interpretation are compatible. This release retains storage version 2 and the existing wrapping-root derivation and record bindings; preserved bytes alone would not suffice if those changed. Incompatible or corrupt state must fail closed without formatting or discarding generations. Restore the last known-good compatible signed UF2 to regain access; a future format change requires a separately designed key-preserving migration.

If a copy is interrupted or the application will not boot, repeat the verified **full** UF2 copy through physical BOOTSEL, then perform the same identity and state checks; never repeat OTP provisioning. This recovery promise is limited to supported generated images and qualified interruption scenarios. A2 erratum E22 can hang BOOTSEL on malformed metadata: arbitrary corruption or malicious images, OTP errors, damaged hardware, and a lost signing authority are not guaranteed recoverable. ROM signature enforcement rejects execution of an unauthorized image; it does not promise that the mass-storage interface refuses to write its bytes.

### Device loss or replacement

Either perform controlled [file-based failover](#offline-restoration-and-failover) from an existing artifact, or commission a new blank device and issue fresh pool generations/certificates. Restore does not import a key into a Pico2. Do not re-pin an unexpected replacement to conceal an identity failure. Fence existing producers and treat old device/node/backup copies as still capable within their certificate validity.

### Pool removal and re-enrollment

Export required artifacts and archive public records **before** deletion. Remove/fence the node's corresponding credential source first or alongside maintenance; deletion does not stop a node that already has keys. It removes all that pool's device-side keys/artifacts, not external copies.

If only a pool's public KES objects are damaged, `pool status` can still report its authenticated pool/incarnation, revision and publication with `storage_failure` health and no active/staged details. The same deletion command works when the committed metadata of all enrolled pools authenticates unambiguously; it does not require readable objects that will be destroyed. Key delivery, export and other pool mutations remain blocked for the damaged pool. Unauthenticated or conflicting snapshots still prevent deletion: do not substitute a state erase or recommissioning.

**Primary — deliberate deletion:**

```bash
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
DELETE_RESULT=$(pico2-kes-agent-cli --json pool delete --pool "$POOL" --incarnation "$INCARNATION" \
  --expected-revision "$POOL_REV" --receipt "$OPS/delete.receipt.json")
printf '%s\n' "$DELETE_RESULT"
```

Interactive confirmation requires `yes`; append `--yes` only for deliberate automation. Preserve receipts. Re-enrollment creates a new incarnation and needs fresh generations/certificates. Review any explicit configuration binding so an obsolete incarnation is not retained.

### Decommission and uninstall

Intentionally export needed artifacts, stop/fence producers, and deliberately delete chosen pools if required. Then, **primary, checkout root**:

```bash
sudo deploy/uninstall.sh
```

Uninstall preserves configuration, state, service account/group, and device storage. It is not secure device wiping. There is no supported device-wide reset/format command.

### Journal capacity or corruption

Preserve the public journal under `/var/lib/pico2-kes-agent`; it reconstructs management outcomes and pool bindings. Admission has a **64-MiB bound**, with no documented compaction CLI. Do not delete/truncate it to clear an error. Stop mutations, preserve diagnostics and cleanly stopped copies, and obtain a reviewed recovery procedure.

## Offline restoration and failover

Preserve a bundle containing:

- Encrypted artifact and matching recipient private file (protected off-primary).
- Independently trusted public device identity record; never infer the trusted identity from the artifact itself.
- Original exported KES verification-key envelope and matching OpCert.
- Device, pool, incarnation, and generation IDs, plus useful public receipts and certificate validity information.

**Backup-recipient host — local only:** set the IDs to the archived exact values before running. No daemon or connected device is needed.

```bash
set -euo pipefail
umask 077
BACKUP_OPS="$HOME/pico2-kes-backup"
ARTIFACT="$BACKUP_OPS/first-kes.backup"
RECIPIENT_KEY="$BACKUP_OPS/recipient.private"
DEVICE_RECORD="$BACKUP_OPS/device.json"
KES_VKEY="$BACKUP_OPS/first-kes.vkey"
OPCERT="$BACKUP_OPS/first.opcert"
RESTORED_SKEY="$BACKUP_OPS/restored-kes.skey"
DEVICE_ID=$(jq -er '.device_id' "$DEVICE_RECORD")
: "${POOL:?Set archived pool ID}"
: "${INCARNATION:?Set archived incarnation ID}"
: "${GENERATION:?Set archived generation ID}"
pico2-kes-agent-cli restore --artifact "$ARTIFACT" --recipient-key "$RECIPIENT_KEY" \
  --device-identity "$DEVICE_RECORD" --device "$DEVICE_ID" --pool "$POOL" \
  --incarnation "$INCARNATION" --generation "$GENERATION" \
  --verification-key "$KES_VKEY" --out "$RESTORED_SKEY"
```

The command prompts for the passphrase, verifies bindings/signature/recipient, and publishes a mode-0600 no-clobber conventional `KesSigningKey_ed25519_kes_2^6` file. Wrong recipient, tampering, identity mismatch, or output collision does not publish a replacement key. Keep the original public vkey envelope: restore's strict parser does not accept a raw hex file.

**Fence/stop the primary before backup forging.** There is no distributed fencing or automatic failback. Check certificate validity; restoring period zero cannot extend certificate lifetime. Plaintext now intentionally exists on the backup host, with the usual limitations of storage erasure.

**Backup producer — manual file-based node configuration:** use its ordinary config/topology/database/socket paths and matching VRF/certificate. Do not also supply an agent socket.

```bash
NODE_CONFIG=/etc/cardano/config.json
TOPOLOGY=/etc/cardano/topology.json
DATABASE=/var/lib/cardano-node/db
NODE_SOCKET=/run/cardano-node/node.socket
VRF_SKEY=/etc/cardano/vrf.skey
cardano-node run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --shelley-kes-key "$RESTORED_SKEY" \
  --shelley-operational-certificate "$OPCERT" --shelley-vrf-key "$VRF_SKEY"
```

For a managed service, securely stage the restored key at a service-readable location with owner-only access and use its normal controlled startup procedure, rather than weakening the backup workspace's permissions.

## Troubleshooting and references

Read-only diagnosis first. No blanket chmod, journal deletion, pin reset, reformat, artificial time markers, or default destructive retries.

| Symptom | Action |
| --- | --- |
| Missing socket / service preflight failure | Inspect `systemctl status` and journal; verify policy file, actual no-swap policy, four masked targets and both units' memory limits. |
| Permission / new membership / sandbox / node query failure | New login and controlled node restart for group changes; inspect ownership and parent traversal. Check sandbox-visible absolute paths and daemon node-query access separately from management/delivery sockets. |
| USB renumbered / denied / BOOTSEL | Rediscover with `lsusb`/udev; expect `1209:4b45` and group mode `0660` only in application mode. Unlocked pre-lock maintenance may use attended privileged picotool; locked devices use physical BOOTSEL mass storage. |
| Wrong pin / identity failure | Stop; compare trusted original record and physical device. Do not silently re-pin. |
| Busy / recovering / uncertain receipt | Preserve original receipt and reconcile after recovery. Do not create a replacement mutation. |
| `revision_conflict` | Rejected, not success. Refresh correct device/pool status; reconsider intent before a new operation with a new receipt. |
| Staged slot occupied | Inspect staged state; finish its certificate workflow or deliberately discard the exact target after exporting required materials. |
| `target_not_staged` | Refresh state; it may have activated. Never redirect a destructive retry to another generation. |
| Period unavailable / clock / genesis / history / stale tip | Verify genuine recognized sync-marker content, trusted digest/history and synchronized node tip. Correct context; never roll time back or create markers. |
| Expired generation | Create and certify a replacement; an expired key/restore cannot extend validity. |
| Artifact retired | Use an already archived copy; retrieval ends at replacement, expiry, discard or deletion. |
| Recipient / passphrase / binding error | Verify original bundle IDs, trusted device record, recipient and original vkey envelope; do not substitute identity from ciphertext. Lost credentials cannot decrypt old backups. |
| No-clobber / input ownership failure | Use an unused output path and operator-owned, non-group/world-writable input and immediate parent. Reconcile mutation success separately from publication. |
| Node lacks standard agent-socket option | Obtain a compatible upstream node release and matching CLI before cutover. Do not substitute undocumented credential formats. |
| Storage / entropy failure | Stop mutations; preserve diagnostics and state. Do not erase/format or force a rollback. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Invalid invocation/input |
| `3` | Permission |
| `4` | Pre-admission unavailable |
| `5` | Rejected lifecycle/identity/certificate |
| `6` | Uncertain/pending |
| `7` | Local I/O/crypto/storage |

Some device errors are coarsely mapped; not every failure has a unique fine-grained exit code. Retain diagnostics and receipts, not just the numeric code.

### Context failure evidence

Context rejections from diagnostic-capable firmware include the failing phase, first storage substage/error, and any latched entropy-health cause. For example, `CatchUp / TransactionNonce / Entropy` distinguishes nonce acquisition from `CatchUp / RecoveryScan / Flash(Io)`; neither changes quarantine or authorizes a retry. A latched entropy cause describes device state, not necessarily the cause of an unrelated rejection. Older firmware replies can omit these details. Upgrade host tools before diagnostic-capable firmware: older hosts reject the extended failure response.

The daemon reports these public rejection details on stderr (the service journal under systemd). Attended `qualification physical-context` records an owner-only, no-clobber JSONL sidecar beside its input: `<input>.context-<session>-<sequence>.jsonl`. The `--preserve-update` path records `<output>.context-<offset>-<session>-<sequence>.jsonl` beside its configured output. Each sidecar fsyncs intent before sending, then retains the complete Context payload and decoded response or transport/parse failure before returning an error. Payloads of other response kinds, especially `Current`, are never recorded. Preserve sidecars and attempt markers; an existing sidecar prevents dispatch, and a failed attempt is not automatically resumed.

Diagnostics do not establish key loss or repair: a pool may be quarantined after an otherwise durable commit. Stop and inspect the recorded failure before another context, reset, or firmware transfer. Offline fault-injection and firmware compilation validate diagnostic reporting, not the board's entropy/flash health or upgrade preservation.

### Deep contracts and evidence scope

Repository-root-relative references:

- [Management CLI contract](specs/001-pico2-kes-agent/contracts/management-cli.md)
- [Backup contract](specs/001-pico2-kes-agent/contracts/backup.md)
- [Device-storage contract](specs/001-pico2-kes-agent/contracts/device-storage.md)
- [Node-service contract](specs/001-pico2-kes-agent/contracts/node-service.md)
- [Current configuration parser](src/config.rs) and [context acquisition](src/daemon/context.rs)
- [Original KES agent](https://github.com/IntersectMBO/kes-agent), [FAQ](https://github.com/IntersectMBO/kes-agent/blob/master/doc/faq.markdown), and [guide](https://github.com/IntersectMBO/kes-agent/blob/master/doc/guide.markdown)
- [Standard Cardano node installation](https://developers.cardano.org/docs/get-started/infrastructure/node/installing-cardano-node/)
- [RP2350 datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf), secure boot/OTP and A2 errata; [A4 compatibility and residual extraction limitation](https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/)

Builds, configuration checks, firmware flashing, device status, and socket connection are different evidence from live network forging and peer-accepted blocks. This handbook makes no production-certification or invasive physical-security claim.

### Before leaving the producer unattended

- [ ] Physical board/firmware trusted; original device pin independently archived and verified.
- [ ] Service and host policies ready, with genuine recognized clock synchronization.
- [ ] Recipient private file/passphrase secured off-primary; old recipients retained when needed.
- [ ] Current pool active with trustworthy network context and certificate validity.
- [ ] Actual node consumption checked; production-forging claims require actual network evidence.
- [ ] Rotation planned before expiry; startup certificate kept current.
- [ ] Restore bundle, public identity, receipts and cleanly stopped journal copies archived.
- [ ] Threat model accepted: no HSM, physical-extraction, rollback, external-copy revocation, or unsupported production-security guarantee.
