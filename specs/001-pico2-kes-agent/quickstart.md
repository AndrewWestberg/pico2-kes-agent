# Quickstart validation guide

## Execution status

These commands validate the implemented firmware, daemon, CLI, host packaging, fixed Cardano compatibility vectors, and qualification runners. Functional results must still be tied to the current revision and dirty-source digest; an older report is evidence only for its recorded candidate.

Use only disposable credentials on an isolated controlled network for destructive scenarios. Mainnet, live cold keys and production backup recipients must not enter qualification fixtures. The backup host need not run a producer.

## 1. Prerequisites and setup

Required validation uses a Pico2 A2 with its fitted flash, Linux with USB access, and Rust 1.99.1. Hosted PR/release compatibility checks consume committed Haskell-generated vectors; GHC/Cabal are needed only for maintainer regeneration, not candidate CI. Use trusted host time and fresh local-node state when exercising period advancement. A recipient host is needed for restore interoperability. Controlled leadership windows and laboratory power equipment are optional, not acceptance prerequisites.

### Host-only foundation phase

Once implemented under the recorded approval, run:

```sh
cargo run --locked -p qualification -- foundation
```

This planned command exercises the actual bounded decoders on malformed and oversized inputs, the protection initializer in a subprocess with deterministic OS memory-lock denial, and the actual fixture parser against locally generated invalid public input before side effects. Inspect `evidence/<candidate>/foundation/report.json` for structured nonsecret execution and outcome evidence; missing execution or an incorrect outcome must produce a nonzero exit. This phase fits the G2 30-minute host budget, does not need a fixture, hardware or daemon, and is neither a full G2 pass nor a firmware pass.

On the implementation checkout:

```sh
rustup target add --toolchain 1.99.1 thumbv8m.main-none-eabihf
cargo +1.99.1 build --locked --release --bin pico2-kes-agentd --bin pico2-kes-agent-cli
cargo +1.99.1 build --locked --release -p pico2-kes-firmware --target thumbv8m.main-none-eabihf
cargo +1.99.1 build --locked --release -p qualification
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo clippy --locked -p pico2-kes-firmware --release --target thumbv8m.main-none-eabihf -- -D warnings
```

Actual changes in external node/consensus integration repositories still require their native builds/tests, source identities and interoperability evidence; unchanged provider candidates do not build cardano-node or a live Haskell oracle. Attended firmware installation must preserve the state partition; never perform an unreviewed whole-flash erase on an enrolled device. Inspect actual A2/flash identity and firmware/RAM bounds before commissioning.

Build and install both host binaries, the systemd unit, host check, and production udev rule:

```sh
cargo build --locked --release --bin pico2-kes-agentd --bin pico2-kes-agent-cli
sudo deploy/install.sh
sudo usermod -aG pico2-kes-agent "$USER"
```

The installer preserves an existing `/etc/pico2-kes-agent/config.json` and `/var/lib/pico2-kes-agent`, and does not start the daemon before the device pin is configured. `sudo deploy/uninstall.sh` removes installed binaries/unit/rule while preserving configuration, host state, account/group, and enrolled device storage. Re-login after adding an operator or node account to the group. Disable core dumps, swap/hibernation and persistent host snapshots for secret-bearing daemon/node memory; do not count daemon-only protection as sufficient. Obtain the initial public device pin through the following attended procedure, not discovery during normal startup.

### First-device commissioning

With the intended board physically identified and trusted firmware installed, stop the normal service. Prepare an owner-controlled commissioning config according to [management-cli.md](contracts/management-cli.md#attended-commissioning): the selected USB serial only in `device`, empty `pools`, and the same runtime/state directories and socket policy used for normal service. Set `DAEMON_USER`, `SOCKET_GROUP`, `COMMISSION_CONFIG`, `USB_SERIAL`, `RECEIPTS` and `DEVICE_RECORD` to actual deployment values; receipt and public output paths must be unused. The serial selects the attended device; it is not independent attestation.

```sh
sudo systemctl stop pico2-kes-agentd
sudo install -d -m 0750 -o "$DAEMON_USER" -g "$SOCKET_GROUP" /run/pico2-kes-agent
sudo -u "$DAEMON_USER" pico2-kes-agentd --commission --config "$COMMISSION_CONFIG" --check-config
sudo -u "$DAEMON_USER" pico2-kes-agentd --commission --config "$COMMISSION_CONFIG"
```

Leave that foreground daemon running. From a second authorized terminal:

```sh
pico2-kes-agent-cli --json status
pico2-kes-agent-cli device commission --usb-serial "$USB_SERIAL" \
  --expected-revision 0 --receipt "$RECEIPTS/device-commission.json" --out "$DEVICE_RECORD"
```

Expected: only wholly verified blank state initializes; success publishes one public device ID/key/fingerprint/serial record after durable commit, cleanup and journal handoff. No pool sockets or operational keys are available in this mode. Trust the record only through the attended physical/firmware ceremony, not its self-signature alone.

If the reply or public-file publication is lost, retain the original receipt and use the following recovery command with an unused output path; do not issue another commissioning operation:

```sh
pico2-kes-agent-cli operation reconcile \
  --receipt "$RECEIPTS/device-commission.json" --out "$DEVICE_RECORD"
```

A valid committed first identity must recover unchanged; nonblank partial/corrupt first writes must fail closed with no reset. A different operation on an enrolled device must reject. On success, archive the public record, copy its `device_id`, `identity_public_key` and `usb_serial` into the normal configuration's `device: {id, identity_public_key, usb_serial}`, and configure node/genesis context and sockets. Stop the commissioning daemon with SIGINT before starting the normal unit below. Normal startup must verify a fresh challenge against that pin and must not learn or replace it.

### Normal pinned service

```sh
pico2-kes-agentd --config /etc/pico2-kes-agent/config.json --check-config
sudo systemctl daemon-reload
sudo systemctl enable --now pico2-kes-agentd
systemctl is-active pico2-kes-agentd
pico2-kes-agent-cli --json status
```

Expected: active service, enrolled intended device identity, public capacity 64, common socket permissions, and no plaintext operational key outputs. Wrong device, occupied live socket or unsupported storage must report a non-success/actionable condition, not takeover/reset.

### Focused U1/U2/I1 validation

Use disposable fixtures for destructive focused scenarios. The deterministic recovery suite, `qualification hardware`, `qualification load`, and fixed compatibility tests are implemented; optional long-running diagnostics remain separate.

For `qualification hardware`, retain fresh `flash-identity.json` and `production-usb.json` beside the report under `evidence/<revision>-<dirty-sha256>/hardware/`; historical `evidence/physical/` records are not candidate evidence. The USB observation records the local ELF `firmware.sha256`, verified release directory `firmware.bundle`, `firmware.signed_uf2_sha256`, `firmware.transfer_method: "signed-msd"`, observed `firmware.transfer_flushed: true`, and `startup.identity_authenticated: true` with ready production USB status. The runner independently verifies the signed bundle and requires its source commit and UF2 hash to match. Locked MSD installation does not provide flash readback or firmware attestation.

- **U1:** begin on qualified blank state, then interrupt before first write, during a partial first write, after valid COMMIT before CLEAN, after CLEAN before reply, and before host pin installation. Observe the specified blank retry, explicit unavailable diagnosis, or same-identity recovery—not automatic formatting. Reject wrong serial, a second commissioning ID and corrupt/nonblank state; normal mode never initializes. Preserve public evidence and keep device-private identity/storage keys off the host.
- **U2:** observe the stored public descriptor and actual V2 timestamp. Cut after publication COMMIT, after CLEAN before USB reply, and after send before confirmation. Repeated committed delivery must use the identical timestamp and bundle; a later visible state must be newer. Equal-period refresh, status polling and reconnect must not create publications. Exercise expiry Drop, direct replacement, explicit deletion without fresh period context, same-pool re-enrollment after restart with a lower valid host-time sample, different-pool slot reuse, and overflow rejection. Verify terminal deletion timestamp recovery from public receipts without retaining old key state.
- **I1:** enroll two pools on the same network; persist different accepted floors, reboot, and submit a fresh but regressive context to each target. Each rejects below its own floor, independently of the other's health. Expiry/rotation/discard retain the floor; equal-period refresh does not write flash. Quarantine one pool and prove the other proceeds. Delete the last pool for the network and re-enroll: a new incarnation requires fresh context but inherits no period floor or old secret from the slot. Reconcile old operations without recreating a generation.

These are required real-interface/fault scenarios, not checks performed by this planning command. T043/T093 include the additional floor, commissioning, and deletion writes in maximum-size and capacity qualification.

## 2. Shared recipient and one-pool lifecycle

On the **backup host**, in an owner-only directory:

```sh
umask 077
pico2-kes-agent-cli recipient create --out recipient.key --public-out recipient.pub
```

Enter the passphrase interactively. Copy only `recipient.pub` to the primary. Keep the private file/passphrase off primary and device.

On primary set environment paths to the fixture's **public** recipient/cold-vkey files and protected operator receipt directory. `REV` is the current relevant policy/device/pool revision from status; refresh before each new mutation, not while reconciling an old one. `NETWORK` names the configured trusted network.

```sh
pico2-kes-agent-cli --json status
pico2-kes-agent-cli recipient set --public-key "$RECIPIENT_PUBLIC" \
  --expected-revision "$REV" --receipt "$RECEIPTS/recipient-set.json"
pico2-kes-agent-cli pool enroll --cold-vkey "$COLD_VKEY" --network "$NETWORK" \
  --expected-revision "$DIRECTORY_REV" --receipt "$RECEIPTS/enroll.json"
pico2-kes-agent-cli --json pool list
pico2-kes-agent-cli --json pool status --pool "$POOL"
pico2-kes-agent-cli key generate --pool "$POOL" --incarnation "$INCARNATION" \
  --expected-revision "$POOL_REV" --receipt "$RECEIPTS/generate.json"
pico2-kes-agent-cli key verification-key --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --out "$KES_VKEY"
pico2-kes-agent-cli key export --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --out "$ARTIFACT"
```

Read `POOL`, `INCARNATION`, `GENERATION` and revisions from actual returned public results; do not fabricate identities. Each receipt path must be new for a new mutation. Export must disclose artifact loss on retirement. A second generate while staged is occupied must return `staged_occupied` without changing either generation.

Transfer the public KES verification key to the offline cold-signing workflow. Using the fixture's pinned unmodified CLI and chosen era, issue the certificate with its real counter and start period:

```sh
cardano-cli "$ERA" node issue-op-cert \
  --kes-verification-key-file "$KES_VKEY" \
  --cold-signing-key-file "$COLD_SKEY" \
  --operational-certificate-issue-counter-file "$COUNTER" \
  --kes-period "$START_PERIOD" --out-file "$OPCERT"
```

Run that command only in the external cold-key environment. Return only certificate/public inputs to primary. Install with the current pool revision:

```sh
pico2-kes-agent-cli certificate install --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --certificate "$OPCERT" \
  --expected-revision "$POOL_REV" --receipt "$RECEIPTS/certificate.json"
pico2-kes-agent-cli --json pool status --pool "$POOL"
```

Expected: future certificate remains staged; currently valid certificate activates automatically after cleanup. No activation approval command or backup receipt exists. Wrong-pool/vkey/signature, expired/regressive certificate and unavailable/regressive period context reject safely.

## 3. Native node and offline-backup rotation

Construct bulk JSON from complete certificate/VRF text envelopes using the [bulk grammar](contracts/node-service.md). An agent entry uses `kesSource: {"type":"kes-agent","socketPath":"/run/pico2-kes-agent/<pool-id>.sock"}` and contains no KES signing-key file.

Run the hosted-compatible Cardano gate:

```sh
cargo test --locked -p kes-core --features qualification --test crypto_compatibility
cargo test --locked --test backup_restore
cargo test --locked --test node_service
```

The crypto command must execute four tests, comparing all 64 periods and certificate cases against the pinned Haskell-derived fixture. Running without the feature selects no crypto tests and is not evidence. `backup_restore` compares the actual published envelope and restored state/key to Haskell's period-zero reference while retaining authentication, mode-0600 and no-clobber checks. `node_service` retains the existing Rust V2 regressions. Artifact retention is checked against the persistent lifecycle in `recovery`.

The quality host job combines these in `cargo test --locked --workspace --exclude pico2-kes-firmware --features kes-core/qualification`; the unsigned release build explicitly runs crypto compatibility and backup restore before its dependent signing job. Production builds do not enable qualification signing. Until observed, hosted execution is unverified; require logs showing four passing crypto tests and passing restore tests, with no queued `native` job.

These SO-002b fixed examples cover one seed/message, not new random inputs on each candidate. SO-005c applies to offline independent reference generation. The corpus does not establish native receiver cancellation, bulk loading, live forging, device behavior or complete Service V2 serialization. Live SIGHUP and peer-accepted-block campaigns remain optional.

### Maintainer-only vector regeneration

Regenerate only when pinned reference semantics, formats or vector cases deliberately change. The sole committed secret-shaped fixture is public synthetic data: **PUBLIC SYNTHETIC TEST KEYS - NEVER USE FOR FUNDS**. The generator accepts no arguments or input files and uses only KES seed bytes `00..1f`, cold seed bytes `20..3f`, and ASCII `disposable Sum6KES interoperability`. Never supply operational/device-generated keys, random qualification secrets or credentials.

From the repository root, use GHC 9.12.4 and cabal-install 3.16.1.0 with the existing secure repository index states, versions and archive hashes. Cabal may fetch missing pinned packages; offline generation means outside candidate CI, not necessarily disconnected. Keep build logs separate from generator stdout:

```bash
set -eu
tmp=$(mktemp -d)
(
  cd qualification/native
  test "$(ghc --numeric-version)" = "9.12.4"
  test "$(cabal --numeric-version)" = "3.16.1.0"
  cabal build exe:native-oracle
  python3 -I - <<'PY'
import json
from pathlib import Path
pins = json.loads(Path("pins.json").read_text())
plan = json.loads(Path("dist-newstyle/cache/plan.json").read_text())
assert plan["compiler-id"] == pins["compiler"], "compiler mismatch"
for name, pin in pins["packages"].items():
    entries = [e for e in plan["install-plan"] if e.get("pkg-name") == name]
    assert entries, f"missing package: {name}"
    for entry in entries:
        assert entry["pkg-version"] == pin["version"], f"version mismatch: {name}"
        if "sha256" in pin:
            assert entry.get("pkg-src-sha256") == pin["sha256"], f"archive mismatch: {name}"
PY
  exe="$(cabal list-bin exe:native-oracle)"
  "$exe" > "$tmp/first.json"
  "$exe" > "$tmp/second.json"
  cmp "$tmp/first.json" "$tmp/second.json"
)
python3 -I -m json.tool --sort-keys "$tmp/first.json" > "$tmp/cardano-kes.json"
```

Only after successful self-checks, pin validation and identical repeated output, install `$tmp/cardano-kes.json` at `crates/kes-core/tests/fixtures/cardano-kes.json` and remove the temporary directory. Tool, pin or generation failure stops publication; never redirect a possibly failing command over the committed fixture. The generator/configuration/pins describe the reference; do not embed source hashes or machine-specific build plans in the fixture. Tests never regenerate expectations, and Rust output is never an expected-byte source. Resolve mismatches against the governing format/reference rather than overwriting expectations to make CI green.

Before production backup/foundation checks, retain no-swap, disabled core dumps and adequate locked-memory limits. Where needed, use the established release-shell setup (`ulimit -c 0`, verify `/proc/swaps` is empty, and `sudo prlimit --pid "$$" --memlock=268435456:268435456`); never bypass memory validation. Public vector generation itself needs no system-wide memory changes.

### Continue the lifecycle scenario

Exercise discard with exact generation ID and expected revision. Observe the warning, then confirm deliberately (`--yes` only for automated disposable qualification):

```sh
pico2-kes-agent-cli key discard --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$STAGED_GENERATION" --expected-revision "$POOL_REV" \
  --receipt "$RECEIPTS/discard.json" --yes
pico2-kes-agent-cli operation reconcile --receipt "$RECEIPTS/discard.json"
```

If activation won, discard rejects without touching active state. If discard won, repeated reconciliation returns the original result even after a later staged generation exists. Deliberately lose generation/discard replies and restart daemon/device: reconcile the existing receipt, never issue a new operation ID to make a timeout disappear. Recipient-policy change must alter only later artifacts. Pool deletion warns and removes its operational state/artifacts; re-enrollment cannot inherit old incarnation or secrets.

## 4. Offline restoration fidelity

Move the encrypted artifact and independently trusted public device/pool/generation/vkey bindings to backup host. With daemon/device/producer absent:

```sh
umask 077
pico2-kes-agent-cli restore --artifact "$ARTIFACT" --recipient-key "$RECIPIENT_PRIVATE" \
  --device-identity "$DEVICE_IDENTITY" --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --verification-key "$KES_VKEY" --out "$RESTORED_KES_SKEY"
cardano-cli key verification-key --signing-key-file "$RESTORED_KES_SKEY" \
  --verification-key-file "$RESTORED_KES_VKEY"
```

Compare the derived public key with the expected KES vkey. This optional CLI conversion alone does **not** prove byte fidelity: recovered state must match the protected disposable generation-time reference byte-for-byte, per [backup contract](contracts/backup.md). Standard-format compatibility is checked by the production restore test against the offline independent Haskell envelope, not by rerunning Haskell on each restored file. Wrong recipient/tampered/identity mismatch and output collision must publish no usable destination key. Check mode 0600 and no symlink overwrite. Do not run a backup producer or introduce its availability as an activation condition.

## 5. Full qualification campaigns

Use owner-controlled disposable qualification inputs for physical and optional external integration scenarios. Secrets are referenced only by protected paths and never copied into evidence; the deliberately public synthetic compatibility corpus is the sole committed-fixture exception.

Build and validate the production firmware, then run the full-capacity software scenario:

```sh
cargo run --locked -p qualification -- hardware
cargo run --locked -p qualification -- load
cargo test --locked -p kes-core --test recovery
```

Preserve the state partition and install the production image. On the accepted Pico2 A2 with identified fitted storage, use disposable credentials to generate and certify a pool, advance it, remove power from both host and device, restore both, and demonstrate valid signing with the recovered generation and unchanged verification key and certificate. Verify the pinned identity returns ready without re-enrollment or state reconstruction. USB reset alone is not a substitute; repeated attended cut campaigns are not required.

The hosted compatibility commands in section 3 are required on every candidate. Native receiver/finalizer checks belong to actual changes in the external integration repositories, not the fixed-vector provider gate.

| Scenario | Required observed outcome |
|---|---|
| SC-001 capacity | All 64 pools correctly bound with 64 active+64 staged; 65th enrollment changes no existing pool |
| SC-002/SC-009 faults/cleanup | Every modeled persistent boundary passes; obsolete regions are read-verified erased; one complete host/device power-loss recovery smoke preserves the certified generation and proves valid signing on the accepted A2 with identified fitted storage |
| SC-003 recovery | All 64 valid pools ready <=60 s after device, daemon, valid context and requesting nodes are available |
| SC-004 normal burst | Every one of 64 concurrent requests usable <=10 s under stalled/malformed-client pressure; zero cross-pool results |
| SC-005 rotation | Offline backup does not block activation; lost replies/restart create no duplicate or superseded resurrection; an unrelated pool is unchanged |
| SC-006 fidelity | One device-generated key0 artifact restores byte-exactly; the real restore test matches the offline Haskell envelope/state/vkey; tamper/recipient/identity failures publish no key |
| SC-007 Cardano compatibility | All 64 fixed Haskell-derived periods, certificate cases, real restored envelope and existing Rust V2 node-service regressions pass |
| SC-008 operator | Installed CLI covers lifecycle/recipient/restore/reconciliation/restart paths; denied, unavailable, rejected and uncertain exits are distinct |
| P1 capacity | One full 64-active+64-staged run meets <=10-second requests and <=60-second recovery |

Also exercise stale/missing/future/regressive context, expired active and staged generations, failed entropy/erase, wrong USB device, live socket collision, startup/reconnect, deleted-pool slot reuse, 64-way boundary catch-up, 64 future-certified staged replacements, and uncertified staged keys remaining at period zero. Pause/disconnect one agent pool and prove healthy file/other pools keep operating; no implicit file fallback. Temporary USB loss must not emit key deletion or stop the node.

### Optional diagnostics

Performance measurements, mutation scores and coverage percentages are diagnostics, not functional acceptance gates. No benchmark runner or baseline is supplied.

Run all functional commands selected in [quality-gates.md](contracts/quality-gates.md). Retain revision-linked public evidence; never add a production plaintext-export interface to simplify qualification.
