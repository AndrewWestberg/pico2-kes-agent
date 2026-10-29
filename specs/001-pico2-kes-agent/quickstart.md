# Quickstart validation guide

## Execution status

These commands validate the implemented firmware, daemon, CLI, host packaging, native integration, and qualification runners. Functional results must still be tied to the current revision and dirty-source digest; an older report is evidence only for its recorded candidate.

Use only disposable credentials on an isolated controlled network for destructive scenarios. Mainnet, live cold keys and production backup recipients must not enter qualification fixtures. The backup host need not run a producer.

## 1. Prerequisites and setup

Required validation uses a Pico2 A2 with its fitted flash, Linux with USB access, Rust 1.99.1, and the pinned GHC/Cabal native-node environment. Use trusted host time and fresh local-node state when exercising period advancement. A recipient host and independent Cardano decoder are needed only for restore interoperability. Controlled leadership windows and laboratory power equipment are optional, not acceptance prerequisites.

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

Build the integrated node with its native `cabal build cardano-node`; separately build the unmodified pinned CLI/oracle. Capture all source/tool hashes and resolved native plans. Attended firmware installation must preserve the state partition; never perform an unreviewed whole-flash erase on an enrolled device. Inspect actual A2/flash identity and firmware/RAM bounds before commissioning.

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

Use disposable fixtures for destructive focused scenarios. The deterministic recovery suite, `qualification hardware`, `qualification load`, and `qualification native-regression` are implemented; optional long-running diagnostics remain separate.

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

Run the pinned native compatibility gate:

```sh
cargo run --locked -p qualification -- native-regression
```

This builds the pinned node source and runs the exact node-service protocol regressions. Live SIGHUP and peer-accepted-block campaigns are optional integration diagnostics, not release gates.


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

Compare derived public key with the expected KES vkey. This CLI conversion alone does **not** prove byte fidelity: the independent Haskell qualification decoder must also extract exactly the 608-byte key0 state and compare it to the protected disposable generation-time reference, per [backup contract](contracts/backup.md). Wrong recipient/tampered/identity mismatch and output collision must publish no usable destination key. Check mode 0600 and no symlink overwrite. Do not run a backup producer or introduce its availability as an activation condition.

## 5. Full qualification campaigns

`FIXTURE` is an owner-controlled disposable qualification document for native and independent interoperability checks. Secrets are referenced only by protected paths and never copied into evidence.

Build and validate the production firmware, then run the full-capacity software scenario:

```sh
cargo run --locked -p qualification -- hardware
cargo run --locked -p qualification -- load
cargo test --locked -p kes-core --test recovery
```

After firmware changes, preserve the state partition, install the production image, power-cycle the board once, and verify the pinned identity returns ready. Repeated attended cut campaigns are not required.

When the pinned native fixture is available, run its receiver/finalizer compatibility regression:

```sh
cargo run --locked -p qualification -- native-regression
```

| Scenario | Required observed outcome |
|---|---|
| SC-001 capacity | All 64 pools correctly bound with 64 active+64 staged; 65th enrollment changes no existing pool |
| SC-002/SC-009 faults/cleanup | Every modeled persistent boundary passes; obsolete regions are read-verified erased; one production-device power cycle returns the pinned identity ready |
| SC-003 recovery | All 64 valid pools ready <=60 s after device, daemon, valid context and requesting nodes are available |
| SC-004 normal burst | Every one of 64 concurrent requests usable <=10 s under stalled/malformed-client pressure; zero cross-pool results |
| SC-005 rotation | Offline backup does not block activation; lost replies/restart create no duplicate or superseded resurrection; an unrelated pool is unchanged |
| SC-006 fidelity | One device-generated key0 artifact restores byte-exactly through an independent decoder; tamper/recipient/identity failures publish no key |
| SC-007 native compatibility | Pinned integrated native node builds and exact V2 node-service protocol regressions pass |
| SC-008 operator | Installed CLI covers lifecycle/recipient/restore/reconciliation/restart paths; denied, unavailable, rejected and uncertain exits are distinct |
| P1 capacity | One full 64-active+64-staged run meets <=10-second requests and <=60-second recovery |

Also exercise stale/missing/future/regressive context, expired active and staged generations, failed entropy/erase, wrong USB device, live socket collision, startup/reconnect, deleted-pool slot reuse, 64-way boundary catch-up, 64 future-certified staged replacements, and uncertified staged keys remaining at period zero. Pause/disconnect one agent pool and prove healthy file/other pools keep operating; no implicit file fallback. Temporary USB loss must not emit key deletion or stop the node.

### Optional performance diagnostics

When a separately approved baseline is available, run:

```sh
cargo run --locked -p qualification -- benchmarks --baseline "$BASELINE_REV"
```

Retain raw samples and environment details. Benchmark ratios, mutation scores and coverage percentages are diagnostics, not functional acceptance gates.

Run all functional commands selected in [quality-gates.md](contracts/quality-gates.md). Retain revision-linked public evidence; never add a production plaintext-export interface to simplify qualification.
