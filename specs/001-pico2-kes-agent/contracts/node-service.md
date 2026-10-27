# Node-service and bulk credentials contract

## Compatibility baseline

Normative source is the pinned `kes-agent 1.3.0.0` archive and `kes-agent-crypto 1.1.0.0` in [research](../research.md), specifically `Protocols/VersionHandshake/{Driver,Peers}.hs`, `Protocols/Service/V2/{Driver,Protocol}.hs`, `Serialization/{DirectCodec,RawUtil}.hs` and `KES/Bundle.hs`. Rust implements negotiated Service V2. Existing pinned singleton and bulk clients offer V2; unsupported-only clients receive negotiation rejection. No pool field is added to this protocol.

Each Unix stream socket has exactly one pool/incarnation mapping. Connecting selects that pool. All pool sockets and the management socket share owner, group, mode 0660 and directory traversal policy. A node may hold one subscription for each of 64 pools. The daemon must not replace unrelated live endpoints. Startup locks the runtime directory, validates every configured mapping and treats an occupied live endpoint as conflict; only an owned stale endpoint under that lock may be removed.

## Wire contract

All integral fields are unsigned, fixed-width, big-endian unless the pinned codec says otherwise. This is a raw stream, not CBOR, JSON, Ouroboros mux framing or a new length-framed protocol. Handle partial reads/writes and EOF. The version handshake sends a count and identifiers directly; its `VersionHandshake:0.1` type identifier is not an extra on-wire preamble.

| Step / message | Bytes |
|---|---|
| Server version offer | u32 count (=1), then 32-byte identifier `Service:2.0` padded with NUL to 32 bytes |
| Client choice | Boolean byte 0 (reject) or 1 followed by the selected 32-byte identifier; reject any unoffered choice |
| Service initialization | Server sends the selected 32-byte `Service:2.0` identifier again |
| Key publication | u8 tag 0, u64 POSIX-microsecond publication timestamp, Bundle |
| Drop publication | u8 tag 1, u64 POSIX-microsecond publication timestamp |
| Client confirmation | **u32** result: 0 OK, 1 outdated, 2 invalid certificate, 3 no key, 4 unsupported, 0xFFFF unknown; other values decode as unknown |

Bundle concatenates raw Sum6KES signing-key direct serialization, relative period u32, then certificate hot verification key (32 bytes), certificate issuance counter u64, certificate start KES period u64, and Ed25519 cold signature (64 bytes). Use the pinned `DirectSerialise` representation for key state; the canonical 608-byte key must be compared byte-for-byte to Haskell's direct codec during interoperability qualification, not assumed from a self-roundtrip. No text envelope/CBOR wrapper or length prefix is added to the fixed-sized key/certificate fields.

Do not confuse the generic DirectCodec enum instance with `RawUtil.sendRecvResult`: V2 explicitly calls the latter, which sends **four bytes** and maps unknown to 0xFFFF, not enum ordinal 5. Timestamp conversion in `kes-agent-crypto/KES/Bundle.hs` is floor(POSIX seconds*1,000,000); use microseconds despite a stale millisecond comment elsewhere.

Server sends one key/drop, then waits for its confirmation before sending another. There is no client get-key request. An accepted subscription receives current eligible state and later updates. Coalesce superseded pending notifications, but never mix one generation's state with another's certificate. Slow confirmation times out that connection only; zeroize its pending secret buffer. Bound handshake and write/confirmation waits to 5 seconds and message storage to 2 KiB per connection. Reconnect gets the latest durable publication, not queued historical state.

Publication timestamps are device-owned durable ordering metadata, not period authority. The [storage publication contract](device-storage.md#device-owned-publication-ordering) defines host time samples, checked assignment, COMMIT/CLEAN and deletion handoff. The device commits `(pool_id, incarnation_id, publication_revision, kind, generation/bundle binding, timestamp_us)` atomically with a node-visible change; USB `current` returns that descriptor with the matching state. The daemon sends `timestamp_us` verbatim, never assigns a second timestamp or persists a competing publication record. Repeated delivery, reconnect and multiple subscribers reuse the same descriptor/time; metadata-only pool revisions do not cause a publication.

Expiry or explicit deletion with no replacement commits a Drop; rotation commits only the replacement bundle. The terminal deletion descriptor/high-water survives in the device receipt until the daemon has fsynced it. Old-incarnation connections close rather than switch bindings. Re-enrollment of the same pool starts above the timestamp floor derived from its retained public deletion receipts; a different pool reusing the slot inherits nothing. This public ordering continuity is needed because V2 carries no incarnation field; it does not preserve old KES secrets or retired network period floors. Increasing timestamps never permits evolution or delivery without valid period context.

Qualification cuts before COMMIT, between COMMIT/CLEAN, after CLEAN but before USB reply, and after node send but before confirmation. Verify identical timestamp/bundle on a repeated committed publication, strictly newer timestamps on later publications, safe overflow rejection, and no false Drop on unavailable context/USB. Also exercise same-pool deletion/re-enrollment after daemon restart with a lower valid host-time sample and distinct-pool slot reuse. Keep the existing V2 bytes and microsecond units unchanged.

Socket/USB loss closes or stalls a subscription without sending Drop. The node retains its current valid key and continues local signing. Explicit durable expiry/deletion with no replacement can send Drop. Rotation sends the new bundle directly after cleanup. If a pool has no certified generation yet, keep the connection pending/status not-ready; do not falsely claim deletion of a previously held key because time/device information is unavailable.

## Bulk grammar and migration

The inspected node loader in `Cardano/Node/Protocol/Shelley.hs` supports legacy embedded-envelope triples. The user has removed old cardano-kes-forge changes from the consensus baseline. The predecessor's version-1 object envelope is reused as a schema convention only; its external-signing branch is not recreated. The cited `Shelley/Credentials.hs` is a planned module, absent from the inspected node checkout. Add the following file/agent source union:

```text
Bulk = [LegacyTriple | VersionedEntry, ...]
LegacyTriple = [operationalCertificate, vrfSigningKey, kesSigningKey]
VersionedEntry = {
  "version": 1,
  "operationalCertificate": TextEnvelope<NodeOperationalCertificate>,
  "vrfSigningKey": TextEnvelope<VrfSigningKey>,
  "kesSource": FileSource | AgentSource
}
FileSource = {"type":"file", "signingKey":TextEnvelope<KesSigningKey>}
AgentSource = {"type":"kes-agent", "socketPath":FilePath}
```

The new discriminator is `kes-agent`, not `agent`. Preserve legacy triples, singleton `--shelley-kes-key` and singleton `--shelley-kes-agent-socket`. Bulk arrays may mix file and agent sources. Do not restore the removed `cardano-kes-forge` source or reinterpret its unsupported configuration as current-key delivery; an unsupported source fails explicitly. If an integration baseline independently supports other sources, preserve their semantics under FR-004 rather than replacing them. Relative agent socket paths resolve relative to the bulk file directory; absolute paths are normalized, not rebased. Duplicate JSON keys are rejected before Aeson object normalization. Unknown version/source, conflicting fields, missing/empty paths, malformed envelopes, duplicate normalized agent sockets and duplicate cold pool identities across singleton+bulk inputs fail with entry/path context. Legacy file validation remains unchanged except required key/certificate identity checks.

Static loading must not require an available daemon/device. It constructs an independent credential state per pool, preserving healthy file/agent entries when another configured agent cannot connect. Malformed configuration still fails explicitly rather than silently dropping entries. Agent failure never opens a fallback KES key file. VRF/cold certificate inputs remain node/external-process responsibilities; device does not custody VRF or cold secrets.

For each agent subscription the node retains expected cold identity from the bootstrap certificate. Validate every incoming hot-key/certificate pair: current key's derived vkey equals certificate hot key; signature verifies under expected cold key; counter does not regress; period/start/lifetime are valid for this node network. The delivered certificate may legitimately replace the bootstrap certificate during rotation. Never insist on bootstrap hot-key equality forever, and never accept another pool's correctly signed certificate. Reject invalid bundles before replacing the hot-key state and report the affected entry. This strengthens the inspected singleton TODO as well as bulk routing; all callers must migrate together without changing the wire.

## SIGHUP credential reload

Reuse `Cardano/Node/Run.hs`'s `installSigHUPHandler` and `updateBlockForging`: after consensus initialization, SIGHUP reconstructs protocol and forging credentials from the existing configured paths and calls `setBlockForging`. Before initialization the installed handler reports forging reload as not effective. Startup-only paths do not change; this is neither a new daemon command nor a protocol extension. The common strict singleton/bulk source selection applies on startup and reload.

File credentials construct a hot key from the reread key and certificate; the slot-driven forging callback invokes `HotKey.evolve` to catch up within network and certificate validity. The handler does not evolve the key or rewrite its file; future-start and expired keys cannot sign outside their validity. Agent credentials construct a keyless dynamic hot key and a new receiver after the forging controller cancels the old workers. A new subscription receives the provider's latest eligible bundle using unchanged V2 bytes and the durable publication descriptor. Explicit reload can leave an unavailable agent pool unable to forge until fresh delivery, while healthy pools continue. Ordinary disconnect instead preserves the existing worker's valid key; neither a key-transfer cache, file fallback, nor mandatory reload for automatic rotation is introduced.

Preserve the corrected native baseline's reload errors: ordinary parse/validation errors are reported without installing a new forging set; missing credential-file errors handled by `updateBlockForging` can disable the entire forging set. An asynchronous agent connection failure is not a missing credential-file error. Inventory the exact baseline cases before integration.

`HotKey.mkHotKeyWith` finalizes with `cancel keyThreadAsync >> unset`. The inspected receiver catches `AsyncCancelled` within its retry loop and also has a broad `SomeException` handler. Cancellation must escape both handlers, while genuine recoverable service errors retain reconnect behavior. Reproduce the native receiver/finalizer failure before fixing it; prove termination, socket/resource and key cleanup before replacement, without detached old receivers or suppressed errors.

The [SIGHUP qualification contract](quality-gates.md#sighup-reload-qualification) defines native cancellation regression and real reload scenarios, budgets and evidence; explicit maintainer approval is recorded in its approval section against the unchanged reviewed bytes. It does not claim measured results, zero-gap replacement, or change existing steady delivery and recovery targets. Provider notifications alone are not reload evidence.

## Native implementation boundaries

- Node `Cardano/Node/Run.hs`: preserve the installed SIGHUP handler and `updateBlockForging` initialization and error boundaries while applying the shared credential loader.
- Node `Cardano/Node/Protocol/Shelley.hs`: common singleton/bulk identity validation and construction of file/agent credentials.
- Node `Cardano/Node/Protocol/Shelley/Credentials.hs`: create/reconcile the documented strict bulk decoder; this path is a planned module, not a currently observed file.
- Node `Cardano/Node/Types.hs`, `Parsers.hs`, `Orphans.hs`: retain source selection/serialization semantics; do not make agent credentials serializable as secret file credentials.
- Consensus `Ouroboros/Consensus/Protocol/Praos/AgentClient.hs`, `Praos/Common.hs`, and `Ledger/HotKey.hs`: thread expected cold identity/network context to receive validation and preserve reconnect, key replacement and explicit-drop behavior against the corrected baseline. Do not reapply removed predecessor external-signing patches.
- Native Cabal manifests/project pins: pin agent 1.3.0.0/crypto 1.1.0.0 and the exact integrated consensus source; record the resulting resolved graph and dirty-source digest. Follow native test/build conventions.

Before exported-symbol changes, inspect language-server references and migrate all consumers. Native regression tests cover legacy/versioned/file/agent/singleton compatibility, unsupported-source rejection, wrong socket, wrong certificate, duplicate/malformed selection, unavailable entry isolation, rotation without restart, and disconnect without key revocation. Exercise other source compatibility only where the selected baseline supports it; do not rebuild removed functionality to manufacture a test fixture. Actual 64-socket Haskell/Rust exchange plus independently accepted primary blocks is required; source inspection is not interoperability evidence.
