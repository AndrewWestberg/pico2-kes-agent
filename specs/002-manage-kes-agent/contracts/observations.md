# Public observations and version contracts

Status: implemented additive observation interfaces; packaged and physical acceptance remains pending. Existing [management contract](../../001-pico2-kes-agent/contracts/management-cli.md), mutation receipts, storage and node-service bytes remain unchanged.

## Host command versions

All three host executables gain `--version` and `--version --json`, requiring no config, daemon or device. JSON is `{ "schema_version": 1, "component": string, "version": string, "build_id": string, "source_commit": string }`; human output is not parsed. Release builds embed immutable build IDs and commit identity; development builds are explicitly development/unqualified, not silently the release corresponding to Cargo's package version.

The manager, daemon and CLI implement these standalone forms. Build-time
`P2KES_BUILD_VERSION`, `P2KES_BUILD_ID` and `P2KES_SOURCE_COMMIT` must be supplied
together; partial metadata fails the build. Version/build IDs are nonempty ASCII
graphical strings of at most 64 bytes, and the source commit is 40 or 64 ASCII
hex characters. Without these inputs, all three values are
`development-unqualified`. Supplying metadata does not establish qualification:
release packaging must authenticate and bind it to the selected payloads.

Installed versions come from authenticated ownership metadata matched to file digests, or an explicitly trusted executable's version output. Do not execute arbitrary PATH candidates merely to inventory them. Record PATH candidates, systemd ExecStart, `/proc/<MainPID>/exe` when permitted, and the manager's own executable independently. The live daemon self-report is running evidence; a symlink target is not proof that an old running inode was replaced. Inaccessible paths are unknown, not absent.

## Management transport

Retain version-1 request/response envelopes, 4-byte length framing, 16,384-byte maximum and existing outcomes/errors. Add only read-only actions:

The CLI's optional global `--expected-peer-pid PID --expected-peer-uid UID` must be supplied together. When an independently authenticated caller supplies them, the connected Linux peer is checked before request bytes; these flags neither authenticate their own values nor alter management frames. Manager lifecycle admission binds the caller and normal or restricted commissioning authority and expires; original commissioning recovery uses restricted authority without a blank-state or normal-pin prerequisite.

| Action / CLI spelling | Arguments | Result |
|---|---|---|
| `host.observe` / `host observe` | optional `cursor`, `snapshot_id`, `page_size` (1–16) | Running daemon build/PID, config identity, registry snapshot and one page of configured/effective bindings |
| `device.info` / `device info` | none | Firmware build, protocol/storage/security profile and supported observation fields |
| `pool.observe` / `pool observe` | exact `pool_id`, `incarnation_id` | Public pool/generation/certificate/context observation |

Each new result begins with `schema_version: 1`. Existing `device.inventory` supplies complete device membership (≤64); no extra all-pools JSON envelope is introduced. Frame-budget-aware page packing may return fewer than 16 bindings. A single overlarge record is rejected explicitly, never truncated into another identity. Clients never derive absence from a failed, unsupported or incomplete request.

`host.observe` includes `snapshot_id`, `bindings`, `next_cursor` (null at end), `total` and `observed_at_unix_us`. Bindings identify whether they are configured, effective through the journal, retired/tombstoned, or conflicting; show raw configured bindings even if reconstruction suppresses them. Snapshot identity binds the loaded config and completed journal position. Later pages must name the same snapshot; a changed snapshot rejects with `revision_conflict`, discards that partial scan and permits a new read-only scan within the deadline. Repeated conflicts show incomplete data. Compute registry once per snapshot rather than rebuilding it for every pool. Runtime service state remains a separate local systemd observation, not a daemon claim.

`device.info` fields: device ID (null only for explicitly blank commissioning state), USB serial, firmware `version`, `build_id`, `source_commit`, `protocol_major`, `storage_version`, `capacity`, security profile and supported-observation bitmap. Bind results to the authenticated session/pin before accepting commissioned-device information. The build ID is an embedded manifest-bound build identifier, not a self-referential hash of its own complete image. No independent attestation is implied.

`pool.observe` does not require a host binding. It returns the exact target and revision, pool health, active/staged generation details, publication descriptor, accepted period floor, daemon context validity/source/age and public blocking diagnostics. A missing host binding yields unavailable network-derived context, not a missing device pool. Device storage errors remain scoped to the affected pool unless shared state is invalid.

Generation fields: generation ID/revision/role, artifact digest, certificate presence, start period, exclusive expiry period, lifetime, current absolute period, relative period, remaining valid periods, health and publication state. An absent certificate has null bounds and an explanation. Arithmetic is checked: expiry = start + lifetime; remaining = max(expiry − current, 0); relative is unavailable before start, otherwise current − start. Readiness still comes from lifecycle/context/publication checks, never from remaining > 0 alone. Time estimates additionally require validated network timing and fresh context; missing authority suppresses estimates.

## USB additions

Keep `PKA1`, protocol major 1, canonical CBOR, 4,096-byte payload bound, CRC, request matching and existing kinds 1–12 unchanged. Reserve kind 13 for `FirmwareInfo`, kind 14 for `PoolObservation`. Both are read-only and allocation-free on device.

Each request and response uses a definite canonical integer-keyed map with schema key `0 = 1`. FirmwareInfo request has only key 0. Response keys: 0 schema; 1 device ID or null if blank; 2 serial; 3 release version (bounded UTF-8 ≤64 bytes); 4 build ID (32-byte identifier); 5 source commit (ASCII hex, 40 or 64 bytes); 6 protocol major; 7 storage version; 8 capacity; 9 security profile (≤64 UTF-8 bytes); 10 supported observation bitmap (u64). Never include arbitrary release text or unbounded strings.

Bitmap bit 0 denotes FirmwareInfo and bit 1 PoolObservation. Development firmware
uses `development-unqualified`, a zero 32-byte build ID and a 40-character zero
hex source value, explicitly unavailable identity rather than a qualified release.
Firmware release builds require the same three metadata inputs as the host,
with `P2KES_BUILD_ID` exactly 64 hexadecimal characters for its 32 bytes.

PoolObservation request keys: 0 schema; 1 pool ID; 2 incarnation ID. Response keys: 0 schema; 1 device ID; 2 target (existing PoolTarget encoding); 3 pool revision; 4 health; 5 active generation or null; 6 staged generation or null; 7 existing Publication encoding; 8 accepted absolute period floor or null; 9 public failure code or null. Generation maps use: 0 generation ID; 1 revision; 2 role; 3 period; 4 health; 5 artifact digest; 6 certificate start or null; 7 lifetime or null. ID widths and unsigned integer bounds reuse existing types. Certificate start/lifetime must be both present or both absent. Derive expiry/relative/remaining on host with checked arithmetic. Context-source/age are host fields, not fabricated device facts. All optional absence has a host-visible reason.

An inaccessible pool uses the target-error form `{0: 1, 1: device, 2: target,
9: failure_code}`. It does not invent a revision, generation or publication.
Successful observations use the full keys 0–9 above.

Use the existing firmware status/target-error envelope conventions rather than inventing a mutation receipt for reads. Wire fixtures must specify missing/duplicate/extra keys, invalid types/widths, arithmetic overflow and maximum-size responses. Public generation accessors read existing lifecycle metadata; this extension does not change persistent layout or release operational secrets.

On older firmware, probe extension support at most once per authenticated connection identity. Unsupported kind/schema, timeout or poisoned framing yields unavailable capability, followed by bounded transport reconnect/reauthentication where needed. Do not repeatedly poison a connection on every UI refresh. Existing status/inventory remain available where supported; no new legacy codec or mutation shim is added. If support cannot be safely established, advanced observations remain unavailable and dependent maintenance is blocked. Never downgrade an identity failure to unsupported capability.

## Freshness and partial snapshots

For each source retain `observed_at`, monotonic age, last successful public value and last error. States are fresh, stale, unavailable, unsupported, unknown. Freshness is per source and per pool, not a global green check. Wall-clock jumps must not reset monotonic freshness. Inventory becomes complete only when validation of the full response succeeds; cross-source observations are not claimed atomic. Maintain membership revision and per-pool revisions; detect changes during scans and label partial results rather than inventing consistency.

Initial local overview ≤5 seconds; all responsive 64-pool observations ≤10 seconds; loss becomes visible ≤10 seconds. Publish partial progress while scanning. At most one outstanding management request and one queued refresh; mutations supersede queued refresh but never cancel an admitted operation as though it were not sent. Existing daemon scheduling must continue giving healthy pools service under monitoring load.

Manager public diagnostic history retains at most 256 entries, each truncated at 4096 escaped bytes plus a truncation marker; individual text fields are limited to 256 characters before escaping. It contains selected public observation metadata, never raw socket/subprocess streams, keys or passphrases. Service → **Export public diagnostics to a new protected file** requires an absolute destination, publishes mode 0600 without clobber, and can still disclose sensitive public identities and paths; review before sharing.

## Required cutover

The additive observations and peer-binding options do not change existing lifecycle mutation envelopes or receipts, node-service bytes, device storage, backup or OTP wire/persistence formats. Older component combinations without these observations remain inspectable with explicit limitations, but are not advertised as full-feature qualified combinations. The unpublished internal host service action now uses `operation: start|stop|restart`, not `start: bool`; no automatic migration of old internal payloads is implied.
