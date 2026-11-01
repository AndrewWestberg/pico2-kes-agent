# Bounded Pico2 qualification — 2026-11-01

## Result

The approved three-pool lifecycle and signed rc9→rc11 preservation campaign completed. The device retains exactly three disposable pools, each with its original start-32 generation active at relative period 1 (absolute lab period 33), and a certified replacement staged for absolute period 64. Original commissioned identity and boot authority are unchanged. No OTP write, state-partition erase, recommissioning, journal reset, identity re-pin or authority rotation occurred.

**Accepted evidence exception:** all six original device pools already had journal bindings. No pre-existing physical orphan was present. The real-core CLI/daemon smoke exercised unbound discovery and normal deletion; physical inventory found and deleted all six existing pools. The operator explicitly accepted documenting this physical limitation rather than manufacturing lost journal metadata.

This is **not** a pass of the full `qualification security` gate or a production physical-security endorsement.

Machine-readable provenance, public observations and file digests: [acceptance-index.json](acceptance-index.json). Protected-memory preservation report: [preservation-result.json](preservation-result.json).

This is the state observed at campaign close, not a live device inventory. See the [repository handoff](README.md) before further work. Original absolute paths in raw records are provenance, not portable commands or permission to replay operations.

## Changes delivered

- `d442b636043162e185d2ba4e9a4ee80fb7ed41da`: authoritative, read-only `device inventory` through authenticated pool headers, bounded USB Kind 12, daemon management, installed CLI and emulator. At most 64 entries; worst-case USB response is 4000 bytes. Host `pool list` remains the binding/socket view. Corruption, unsupported firmware and wrong identity do not become empty success. Behavior tests and operating documentation updated.
- `84df698978d37256de1bdf85cec940022d32ceaa`: release workflow establishes no-core/no-swap/locked-memory prerequisites before protected operations. Published rc11; failed rc10 history was preserved.
- Current-source daemon and CLI installed through the existing installer. Original `/etc/pico2-kes-agent/config.json` retained. The installer refreshed the ordinary systemd unit, removing the `adjtimex clock_adjtime clock_adjtime64` exception while retaining `SystemCallFilter=~@clock`; see [installed-unit.diff](installed-unit.diff).

## Authenticated firmware provenance

Both complete eleven-asset bundles were independently authenticated using the trusted checkout verifier and patched picotool. Same authorized signing key, storage version 2 and wrapping-root interpretation; distinct commits, tags, manifests and signed images. UF2 writes were confined to firmware `[0x10000000,0x10100000)`; state `[0x10100000,0x10308000)` was preserved.

| Artifact | BASE | CANDIDATE |
|---|---|---|
| Tag | `v0.1.0-rc.9` | `v0.1.0-rc.11` |
| Commit | `2e22f818e15d1824f88c9eed365aaffc29dff803` | `84df698978d37256de1bdf85cec940022d32ceaa` |
| Manifest SHA-256 | `d025e97236fbe449352b501e67dec994ac771ec68b6f3effe3edac61a633a0b5` | `3be123b16e36e6fcd8fd7992b4a40372ae284935b9e97b2831d079a98a9d96c8` |
| Signed UF2 SHA-256 | `eaf511c1e5e3ab5fba1f7f37c21e46ba5839c4fb0ae9e387ea0c88a812f40b77` | `55fc5f7e461c0249a0360a3ea826f12477426ab7ef1b6d46d5e0a79b0f0cb2bb` |

Successful publication: [rc11 workflow 41348318775](https://github.com/AndrewWestberg/pico2-kes-agent/actions/runs/41348318775). The preservation harness records source commit `84df698…` and dirty-state fingerprint `2593f2817f21af96923ca5693f5f776a1bd1d93c63d9c8b50e25249f06cfb92b`.

The transferred firmware version is operationally inferred from authenticated artifacts, successful complete copy/flush, cold reboot and application behavior. The device does not independently attest its executing image digest.

## Physical observations

Target: serial `00afd9003906a634`, device ID `f39127e9e0ab25f8341401048acf629d`, identity key `a3cd5edfccee6bef4b640a591e80afd47a69ef1970b9abe0de63514df56b6e7f`; stable USB parent `1-3.4.2`.

Authority SHA-256: `be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0`. Public security remained `rp2350-signed-msd-v1`, A2/ROM2, redundancy consistent. Full before/after fields are retained.

1. Preliminary rc11 installation enabled authoritative inventory. Six normal deletions committed at sequences 49–54 using fresh revisions and unique retained receipts. Authenticated inventory became `[]` at device revision 22. No new historical-secret backups were made for those deleted pools.
2. On the empty board, each validated negative image was copied and flushed through the verified RP2350 mount. The operator unplugged/reconnected without BOOTSEL. Monitoring began before reconnect and captured USB events; each subsequent observation sampled the same connected board 121 times over a full 30 seconds. Only ROM mass-storage descriptors were observed, with no PICOBOOT interface and no application/diagnostic enumeration. No diagnostic or PICOBOOT write commands were sent.

| Negative image | Connected-ROM observation | Signed recovery |
|---|---:|---|
| Unsigned | 30.0676 seconds | Original identity/security; empty inventory |
| Valid signature under unrelated key | 30.0611 seconds | Original identity/security; empty inventory |
| Payload modified inside signed coverage, metadata unchanged | 30.0686 seconds | Original identity/security; empty inventory |

3. Authenticated rc9 was installed only after the last empty proof. Exactly three cold-key-derived pools were enrolled using the current installed host binaries and existing journal. Each received an active start-0 certificate and future-staged start-32 certificate. Public keys and encrypted period-zero backups were exported before certificate installation; cold counters were retained throughout issuance.
4. Actual Service V2 socket-delivered states signed `pico2-kes-qualification` at absolute periods 0, 1, 2 and repeated 2. Each signature passed the local verifier and independent native oracle, and the oracle rejected the altered message. Active/staged generation IDs and artifact digests remained unchanged.
5. The attended preservation harness exited 0. It compared actual current state bytes in protected memory across rc9→rc11, alongside public keys, certificates, encrypted-artifact bindings, recipient, period floors and security policy. It then activated all three original staged generations at 32. Each pool was replenished with a newly exported, certified generation starting at 64, using the same recipient and continuously maintained cold counter.
6. All three activated keys passed actual socket-state signature proofs at absolute periods 32/33, relative periods 0/1. Across the six observation points there are 18 public proofs, each with positive independent verification and altered-message rejection.
7. Final authoritative inventory contains exactly the three expected incarnations, pool revisions 17 and device revision 26. Final status is ready with no pending receipt. The journal preserves the original 62,964-byte prefix; final length 99,088 bytes, SHA-256 `0ab93c69110682dfe5c76ff5f08c42478c13f6d433face9b341c3b59c17ccdec`. Last successful management sequence: 76.

All full target IDs, generation IDs, certificates, public snapshots, receipts, transfer/flush timestamps and boot traces are indexed. Current KES state bytes and their hashes were never persisted in evidence.

## Software verification and failures retained

Retained execution logs: [first source run](source-first-run.log), [second source run](source-second-run.log), [protected checks](protected-source-checks.log), [release gates](release-workflow-gates.log), [picotool/BASE verification](baseline-verification.log), and [node loader tests](node-loader-tests.log). The [firmware compatibility review](firmware-compatibility-review.txt) and [host safety review](host-safety-review.txt) are source-review evidence only. The index maps historical session artifact handles to these repository files.

- `kes-core` tests passed. `kes-protocol`: 30 passed after correcting an existing unknown-kind fixture from newly assigned Kind 12 to `u16::MAX`.
- Selected host integration suites: 49 initially passed; one recipient-rotation test failed under active swap. That exact test passed after the operator disabled swap. This is combined coverage of all 50 cases, not a claim of an initial clean run.
- Host library: 42 passed; qualification software: 23 passed; remaining release integration gates: 7 passed; isolated firmware/release Python tests: 61 passed. Python mock OTP traces were software fixtures, not physical OTP operations.
- Current release host/ARM builds passed. Real release CLI→daemon management→USB codec→real-core inventory/delete smoke passed, including the unbound-pool case. The temporary protected signature probe also passed its deterministic fixture self-check before physical use.
- Patched picotool signature-boundary regression: 4096 cases passed. Independent BASE and CANDIDATE verification logs are included.
- rc10 [workflow 41323068497](https://github.com/AndrewWestberg/pico2-kes-agent/actions/runs/41323068497) failed before signing on missing runner memory prerequisites. Its tag/history was not moved or overwritten. The corrected rc11 workflow completed publication.
- Two read-only reviews of the existing committed rc9→initial-HEAD firmware/host changes found no concrete blockers; this is review evidence, not physical proof.
- Local `cardano-node-test` passed at node commit `d248299eb7db5e448ce688bfda52b1ba86be4377`, including bulk-credential and independent leader-credential loader tests. No live node or forging process was launched for this campaign.
- Two read-only CLI invocations used unsupported syntax (`device status`, then `pool status --incarnation`). They were rejected locally; supported syntax was then used. No mutation was retried or receipt replaced because of these invocation errors.

Tool provenance is in the index and cloud `tool-versions.txt`: Rust/Cargo 1.99.1; patched picotool 2.3.1; SDK and patch hashes; `cardano-cli` 11.6.0.0; native GHC 9.12.4. Executed native dependencies were **kes-agent 1.3.0.0 / kes-agent-crypto 1.1.0.0**. Inspected 1.4 source compatibility is not an executed 1.4 test.

## Host restoration and retained material

Restoration was executed and independently observed:

- `/swap.img` active again: 8,589,930,496 bytes, original priority -1.
- All four sleep targets restored to their original static/inactive state; only this run's runtime masks removed.
- Lab daemon, preservation harness, oracle/probe and credential-generation processes stopped before policy restoration. Temporary runtime directory, signature-probe build/source and one-off host scripts removed.
- Ordinary service remains **inactive/enabled**. Original config unchanged. Do not start it under the restored swap/sleep policy and expect protected-operation admission to pass.
- Installed daemon SHA-256: `59d9ee06fc89c7c9c263e982c289b58a673ceaf6be11b0992e9c820e105e2cbb`.
- Installed CLI SHA-256: `cd30d0e7424e721d77b38605da410dfd8aeba5482021a04647b0594a24574dd4`.
- The device remains on signed rc11 with the three dummy pools. Original host backups and the continued journal are retained, not restored over newer state.

The original owner-only operational workspace is `/home/westbam/pico2-qualification-2p9qdufn`. At handoff it retained disposable keys/counters and the encrypted recipient file under `private/`, and encrypted backups under `pool-1/`, `pool-2/`, `pool-3/`. Those are external workspace paths, **not directories in this repository**. None of that private/recovery material is included here. Do not publish the entire operational workspace. The private recipient plus an encrypted period-zero backup can reconstruct historical KES states; deletion or recipient replacement does not revoke external copies.

## Limits and unexercised checks

- No pre-existing physical orphan was available; the operator accepted the documented source-smoke substitute for that one scenario.
- No live-node/forging, interrupted-copy, populated-key downgrade, endurance, A4, external SWD-denial or invasive-extraction campaign. Successful empty-board installation of an older authorized image is not populated downgrade qualification.
- The selected node consensus pin is `a337d69f4946d5a1b20ecaaeae635dd47822e3d2`, not the sibling checkout with extra delivered-bundle validation. Do not attribute that sibling's cold-key/counter checks to this node build.
- Cold/recipient credentials were disposable and local; physical air-gap practice was not exercised. Current KES states reach daemon/node memory; this is not an HSM signing boundary.
- This A2 board's OTP-repair history and earlier context/OTP incidents remain historical limitations. The bounded new observations do not close them or establish exhaustive alternate-path resistance.
