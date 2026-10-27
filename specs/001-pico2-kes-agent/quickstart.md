# Quickstart validation guide

## Execution status

These commands define validation of the completed implementation. The repository currently contains only its initial Rust package and planning documents; the planned binaries, firmware, native changes and qualification targets do not yet exist here. The refined gate definition is explicitly maintainer-approved; its current approval record satisfies the definition-approval prerequisite for T001–T100 and supersedes proposal-time status labels in the unchanged definition. Do not report these planned commands as executed by this workflow. This guide is a run/validation contract, not implementation code or a substitute for the [quality gates](contracts/quality-gates.md).

Use only disposable credentials on an isolated controlled network for destructive scenarios. Mainnet, live cold keys and production backup recipients must not enter qualification fixtures. The backup host need not run a producer.

## 1. Prerequisites and setup

Full campaigns require: accepted Pico2 A2 with identified qualified flash; controllable device/host power; Linux primary with systemd/USB access; a separate recipient host; offline cold-certificate workflow; independent Cardano decoder and validating peer; controlled network with predeclared leadership opportunities for all 64 pools within the G9 budget. Trusted host time and fresh local-node state are required for period advancement. Install Rust 1.99.1, pinned gate tools, GHC/Cabal for the research pins, and `jq`. The separately scoped foundation phase below needs no fixture, hardware or daemon. Verify the recorded definition approval and demonstrate gate sensitivity before accepting results.

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

Install the two host binaries, supplied systemd unit and udev rule through the implementation's packaging. Create the daemon account/group and authorize the test operator/node under that common group. Disable core dumps, swap/hibernation and persistent host snapshots for secret-bearing daemon/node memory; do not count daemon-only protection as sufficient. Obtain the initial public device pin through the following attended procedure, not discovery during normal startup.

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

Use disposable fixtures and the existing `smoke`, `power-loss`, `node` and `operator` qualification commands below:

- **U1:** begin on qualified blank state, then interrupt before first write, during a partial first write, after valid COMMIT before CLEAN, after CLEAN before reply, and before host pin installation. Observe the specified blank retry, explicit unavailable diagnosis, or same-identity recovery—not automatic formatting. Reject wrong serial, a second commissioning ID and corrupt/nonblank state; normal mode never initializes. Preserve public evidence and keep device-private identity/storage keys off the host.
- **U2:** observe the stored public descriptor and actual V2 timestamp. Cut after publication COMMIT, after CLEAN before USB reply, and after send before confirmation. Repeated committed delivery must use the identical timestamp and bundle; a later visible state must be newer. Equal-period refresh, status polling and reconnect must not create publications. Exercise expiry Drop, direct replacement, explicit deletion without fresh period context, same-pool re-enrollment after restart with a lower valid host-time sample, different-pool slot reuse, and overflow rejection. Verify terminal deletion timestamp recovery from public receipts without retaining old key state.
- **I1:** enroll two pools on the same network; persist different accepted floors, reboot, and submit a fresh but regressive context to each target. Each rejects below its own floor, independently of the other's health. Expiry/rotation/discard retain the floor; equal-period refresh does not write flash. Quarantine one pool and prove the other proceeds. Delete the last pool for the network and re-enroll: a new incarnation requires fresh context but inherits no period floor or old secret from the slot. Reconcile old operations without recreating a generation.

These are required real-interface/fault scenarios, not checks performed by this planning command. T043/T093 must include any additional floor/commissioning/deletion writes in maximum-size and per-sector endurance qualification.

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

## 3. Bulk node and offline-backup rotation

Construct actual bulk JSON from complete certificate/VRF text envelopes, using the exact [bulk grammar](contracts/node-service.md). An agent entry uses `kesSource: {"type":"kes-agent","socketPath":"/run/pico2-kes-agent/<pool-id>.sock"}`. Do not put a KES signing-key file in that entry. Configure 64 independently enrolled/certified pools with unique identities/sockets, then a separate mixed-source scenario containing legacy files, versioned files and agent entries. The user removed predecessor forge changes from the consensus baseline; do not restore them for qualification. Test other source compatibility only if independently supported by the selected baseline; otherwise verify unsupported-source rejection. Do not reuse one pool identity across source kinds to fake coverage.

```sh
"$NODE_BIN" run --config "$NODE_CONFIG" --topology "$TOPOLOGY" \
  --database-path "$DATABASE" --socket-path "$NODE_SOCKET" \
  --bulk-credentials-file "$BULK_CREDENTIALS"
```

Provide the fixture's leadership opportunities and observe peer-accepted blocks, not merely a successful launch. Stop the backup host; generate/export/certify a replacement while the active generation continues. At valid start it must publish automatically, with unchanged node process and other 63 generations. Export before retirement; retrieve twice across evolution/reboot and compare byte-identical ciphertext. Retire through replacement/expiry/discard/delete and verify retrieval now reports `artifact_retired`, with unrelated retained artifacts unchanged.

### Controlled SIGHUP reload validation

After T047 registers the actual native regression cases, and before T054's fix, execute the following to retain the expected failing-before result; repeat after the fix for corrected behavior. A missing native runner or unregistered case is unavailable, not a behavioral failure or pass:

```sh
cargo run --locked -p qualification -- native-regression --fixture "$FIXTURE"
```

Use only the isolated disposable fixture and a node it launched; establish `NODE_PID` from that fixture's process record and verify its live PID, executable and command line against the fixture's node, configuration and bulk paths before signaling. Verify from fixture/node initialization evidence that the SIGHUP handler is installed and consensus initialization is complete; also confirm valid context and the applicable agents are ready for the post-initialization cases. Never signal an arbitrary or production process. Then:

```sh
kill -HUP "$NODE_PID"
```

The signal command alone proves only signal delivery, not completed reload. Observe the reload completion, unchanged PID, old receiver and socket retirement, replacement readiness and fresh pool-correct agent delivery, unchanged file-key bytes, current-period file signing, and independently peer-accepted blocks. For the early-initialization case, use a controlled fixture pause after handler installation but before consensus initialization, verify both states and the same disposable PID before sending SIGHUP, and observe the handler's not-effective result; never use an unverified generic process kill.

Run the native receiver/finalizer cancellation regression with actual blocked service I/O and reconnect delay; prove awaited cancellation completes and cannot retry afterward. Run actual post-init reloads on the 64-agent topology and separate mixed file/agent and singleton topologies, with unchanged and changed valid credential contents; complete ten sequential reloads per valid topology, without crediting coalesced signals, alternating I/O and reconnect-delay cancellation cases where applicable. Exercise file-key catch-up, future-start and expired keys, malformed and missing credential files with the baseline-prescribed distinct outcomes, and an unavailable agent that returns while healthy pools continue. Use predeclared leadership windows within G9's unchanged eight-hour budget; missing leadership is inconclusive. Apply the approved bounds and retain nonsecret evidence as specified in the [SIGHUP qualification contract](contracts/quality-gates.md#sighup-reload-qualification); approval does not establish measured results.


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

`FIXTURE` is an owner-controlled qualification JSON document naming the actual device pin, fitted-part qualification record, firmware/binary paths and hashes, 64 disposable pool/public identities, existing protected cold/VRF fixture locations, trusted network/genesis/node sockets, independent decoder/peer executables, recipient-host endpoint, power controller and evidence directory. For reload qualification it also identifies the disposable node PID/configuration, initialization and receiver/socket observations, mixed and singleton topologies, and predeclared leadership windows; retain observed timestamps, pool outcomes, public file immutability and peer-accepted block evidence without raw keys. Secrets are referenced only where the trusted fixture needs them, never embedded into reports. The runner validates readiness and refuses production networks/credentials or missing hardware. It must implement the exact fixture schema before use; absent runner/fixture is unavailable, not pass.

For the endurance projection, also provide public intended-deployment network/era profiles, the fitted part's guaranteed endurance rating and operating conditions, and a documented per-sector prior-wear bound. Keep deployment timing separate from any accelerated disposable test-network timing; no production credentials or production-node connection are needed for this input. Record the actual test-network schedule and count its physical campaign wear separately.

```sh
cargo run --locked -p qualification -- smoke --fixture "$FIXTURE"
cargo run --locked -p qualification -- native-regression --fixture "$FIXTURE"
cargo run --locked -p qualification -- interop --fixture "$FIXTURE"
cargo run --locked -p qualification -- load --fixture "$FIXTURE" --rounds 1000
cargo run --locked -p qualification -- power-loss --fixture "$FIXTURE" --cuts 1000
cargo run --locked -p qualification -- node --fixture "$FIXTURE"
cargo run --locked -p qualification -- operator --fixture "$FIXTURE"
```

| Scenario | Required observed outcome |
|---|---|
| SC-001 capacity | All 64 pools correctly bound with 64 active+64 staged; 65th enrollment changes no existing pool |
| SC-002/SC-009 faults/cleanup | >=1,000 physical cuts plus every modeled persistent boundary; no acknowledged/released rollback; obsolete regions erased/read-verified; corrupt pool unavailable without reset; no primary plaintext persistent outputs |
| SC-003 recovery | All 64 valid pools ready <=60 s after device, daemon, valid context and requesting nodes are available; period 5 outage resumes at 8 without a new certificate |
| SC-004 normal burst | Every one of 64 concurrent requests usable <=10 s, including stalled/malformed-client pressure; zero cross-pool results |
| SC-005 rotation | Offline backup does not block activation; lost replies/restart create no duplicate generation or superseded-key resurrection; other 63 pools unaffected |
| SC-006 fidelity | Exact generation-time key0 equality and independent standard file decoding for each qualified generation across pools; all tamper/recipient/identity cases publish zero keys |
| SC-007 primary producer | Independent peer accepts pool-correct blocks before/after evolution, real SIGHUP reload, rotation and complete power recovery; 64-agent, separate mixed and singleton reloads demonstrate fresh delivery, file catch-up, healthy operation during agent outage and recovery, and no receiver accumulation or cancellation hang. Missing leadership is inconclusive |
| SC-008 operator | Installed CLI covers all required lifecycle/recipient/restore/reconciliation operations through daemon; denied, unavailable, rejected and uncertain outcomes have correct non-success exits |
| P1 endurance | Five-year/1,827-day projection with the selected monthly maintenance workload and actual network timing; every sector satisfies `2 * (prior wear + projected service erases) <= guaranteed rating`. Record fitted-part rating/conditions, campaign wear, measured costs, workload counts and the limiting sector under the [storage endurance policy](contracts/device-storage.md#endurance-acceptance-policy); missing inputs are inconclusive |

Also exercise stale/missing/future/regressive context, expired active and staged generations, failed entropy/erase, wrong USB device, live socket collision, startup/reconnect, deleted-pool slot reuse, 64-way boundary catch-up, 64 future-certified staged replacements, and uncertified staged keys remaining at period zero. Pause/disconnect one agent pool and prove healthy file/other pools keep operating; no implicit file fallback. Temporary USB loss must not emit key deletion or stop the node.

### P0 microbenchmarks

After implementation, select the separately approved baseline revision and run the aggregate comparison under the recorded gate-definition approval:

```sh
cargo run --locked -p qualification -- benchmarks --baseline "$BASELINE_REV"
```

The runner measures both the `kes-core` lifecycle target (generation, evolution, certificate and artifact workloads) and the host target (framing and real public journal fsync/reconcile workloads), for baseline and candidate. It retains three separate runs with 100 samples, 5-second warmup and 10-second measurement per workload. A per-workload 95% runtime-ratio confidence interval wholly at or below 1.05 passes, wholly above fails, and one crossing the threshold is inconclusive; all workloads must fit the combined 30-minute budget. The individual measurements below are not an aggregate P0 verdict:

```sh
cargo bench --locked -p kes-core --bench lifecycle -- --save-baseline "$RUN_LABEL"
cargo bench --locked -p pico2-kes-agent --bench host -- --save-baseline "$RUN_LABEL"
```

Retain baseline/candidate revisions, raw samples and per-workload verdicts under the [quality-gate contract](contracts/quality-gates.md); missing workloads or evidence cannot pass.

Finally run all selected sensor and benchmark commands in [quality-gates.md](contracts/quality-gates.md), including activation defect probes. Retain revision-linked public evidence with actual counts/measurements and exclusions. Incomplete/failed/inconclusive campaigns block acceptance; do not weaken deadlines, omit a pool or replace physical trials with simulations. No new production plaintext-export interface may be added to simplify qualification.
