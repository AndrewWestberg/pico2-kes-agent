# Data model: local KES management

Status: design. Existing device storage, configuration v1, encrypted backup format, CLI receipt v1 and OTP record schema 2 are reused, not replaced. New records contain public data only; no database is needed.

## Entities and relationships

| Entity | Fields / identity | Authority and validation |
|---|---|---|
| Managed installation | host OS/architecture/libc, role, paths, component ownership, selected tuple, account/group, service identity, config path | Local observations plus authenticated installation registry; unknown ownership is external, never silently adopted |
| Component observation | component, installed version/build/digest/path, running version/build/PID/path, selected release, provenance | Keep installed/running/selected separate; do not execute untrusted binaries for discovery |
| Observation<T> | source, value or null, observed wall time, monotonic age, fresh/stale/unavailable/unsupported/unknown, public error | Retain last success on failure; null is not zero/empty/healthy; not all observations are simultaneous |
| Device observation | pin, observed device ID/key/serial, application/bootloader/absent/ambiguous mode, firmware/build, protocol/storage/capabilities, security report | Application identity bound to daemon session; physical bootloader association requires attendance; security report is not attestation |
| Membership snapshot | device ID, device revision, complete flag, ≤64 pool/incarnation/revision entries | Existing authenticated inventory, duplicate rejection; unavailable is never an empty complete snapshot |
| Host binding snapshot | snapshot ID, config identity/journal position, configured and effective bindings, source, retirement/conflict flags, cursor | Config and reconstructed journal registry remain distinct from device membership; full paging required before absence claims |
| Pool observation | device/pool/incarnation, revision, membership/binding comparison, active/staged, publication, context, failure | Exact composite identity; unmatched pools remain visible and queryable; no automatic repair |
| Generation observation | generation ID/revision/role, artifact digest, certificate start/lifetime/exclusive expiry, absolute/relative/remaining periods, readiness | Existing lifecycle data; checked arithmetic; missing certificate or context yields explicit unknown fields |
| Supplied pool inputs | entered fields or public file paths/digests, network identity/genesis inputs, provenance, validation result | Validate with current config/core parsers; no node lookups, guessed network defaults or silent conflict resolution |
| Release manifest | schema/purpose, tag/channel/commit, signed qualification `candidate` or `qualified`, platform, components/digests, authorized compatibility tuples, required artifacts/tools, signatures | Exact authenticated bytes; authorization is not qualification; unknown schema/compatibility blocks install; cache age is not authenticity |
| Installation registry | schema 1, managed file paths/hash/mode/owner, immutable components, current tuple, preserved data/drop-ins | Root-owned mode 0644 public metadata; no-clobber initial creation, atomic durable update; paths confined to approved roots |
| Maintenance record | schema 1, random operation ID, action, plan digest, selected identities/versions, approved scope, previous service state, pre-observations, checkpoints, post-observations, outcome | Public durable intent before mutation; first-install binds bundle/image digest and attended physical selection without inventing an application pin; no rewriting prior confirmed evidence to force success; privileged side revalidates plan |
| Lifecycle receipt | existing version-1 request, operation ID/revision/target, response or null, reconciliation result | Existing CLI receipt/journal authority; no second manager mutation ID; retain before submit and on uncertain exit |
| Operator artifact | kind, path/digest, device/pool/incarnation/generation/recipient bindings, destination ownership | Public inputs or encrypted outputs on primary; no-clobber output; plaintext restore only in backup-host child |
| Provisioning record | existing schema-2 device/bundle/tool/qualification bindings, stages, pending actions, physical observations | Existing firmware tool owns semantics and persistence; manager retains path/reference, never rewrites record |

## Storage and bounds

- Preserve `/etc/pico2-kes-agent`, `/var/lib/pico2-kes-agent`, public journal, receipts, pin and service account/group. New installation metadata lives under root-owned `/var/lib/p2kesup/` (0755), separate from the daemon's private state directory. Public ownership metadata is readable without root. Host-maintenance records are root-owned, group-readable (0640) in a protected (0750) subdirectory using the existing authorized operator group; no new socket role is introduced. Backup-local records remain in the invoking user's protected XDG state. Do not loosen existing daemon-directory or receipt permissions.
- The concrete schema-1 installation registry path is `/var/lib/p2kesup/installation.json`, root-owned mode 0644 and bounded to 1 MiB. Discovery validates protected ancestry and component hashes; authenticated host installation owns publication.
- User release metadata/cache and public UI operation references use XDG cache/state directories under `p2kesup`, owner-only directories (0700) and files (0600). Default fallback follows XDG conventions. Root actions never trust writable user paths without revalidation and safe copying into their own protected staging directory.
- Current selection is an atomic symlink to an immutable generation of per-component links; see [distribution](contracts/distribution.md). Config/service/udev updates are separate durable checkpoints, not falsely claimed part of that atomic switch.
- Observation memory is bounded to 64 device entries, 64 configured and 64 effective host identities, and 128 device generation slots, plus bounded pages. A full join can display up to 192 distinct source identities; never truncate unmatched bindings to the device's 64-pool capacity. Generation details remain bounded by 64 device pools. UI logs are a bounded public ring, not raw subprocess/socket traffic.
- New maintenance records: maximum 1 MiB each, maximum 64 MiB retained per record store. At capacity, block new mutation with explicit export/archive guidance; never silently delete unresolved records. Existing lifecycle receipt and OTP record limits remain unchanged. Release cache admission is ≤1 GiB and must check filesystem free space before download/staging; authenticated manifest limits apply separately. Explicit cache removal never removes receipts or operational state.
- Public record writes use existing protected file primitives where applicable: exclusive creation, owner/mode checks, bounded reads, atomic replace and fsync of file plus parent. Validate symlink ancestry at privileged destinations. Configuration edits validate in a sibling candidate before replacing the working file; a failed check leaves working bytes/mode/owner unchanged.
- No daemon, manager or primary cache stores raw current KES traffic, cold keys, recipient private keys, passphrases or restored plaintext keys. Foreground backup children enforce their own protected-memory rules and do not return private contents to the TUI.

## State transitions

### Observations

Unknown → fresh after successful source validation. Fresh → stale after a deadline, source failure or disconnect; preserve value/time. No previous value → unavailable. Unsupported capability → unsupported until reconnect/build change provides new evidence. Reconnection never implicitly trusts a different identity.

### Setup and configuration

Observe → missing prerequisites → reviewed changes → approved apply → independently observe result. Cancellation before apply changes nothing. Restart after interruption reconstructs state from files, service, receipts and device; it does not replay a scripted install sequence. For an already-running uncommissioned application, the sole restricted commissioning daemon must observe the intended compatible application and its blank state before separate commissioning. Blank-device commissioning publishes the public identity once and requires explicit normal-mode pin/config installation; an already commissioned unexpected board is refused, not erased.

### First firmware installation

Factory/BOOTSEL-only board → authenticated bundle and attended unambiguous physical target reviewed → durable first-install intent → firmware-only verified transfer/flush → sole commissioning-daemon observation of selected compatible application → confirmed blank admission → separate commissioning → reviewed normal-mode pin/config. No application serial or pin exists at bootloader selection, and the bootloader identifier is never promoted to a pin. Transfer alone is not blank admission or commissioning. Nonblank, ambiguous, wrong or unknown application state blocks commissioning and pinning. Interruption or uncertain transfer retains the original record and blocks new-work treatment, automatic reflash and silent recommissioning; recovery observes actual state against that record. Applicable image/tool/hardware and OTP prerequisites remain in force; first installation never erases state or performs OTP.

### Release admission and promotion

Signed candidate metadata authorizes exact component digest tuples for explicitly reviewed, attended `--version TAG` or offline `--bundle` acceptance on a disposable host, subject to the normal trust, schema, state, hardware and applicable security checks. Default discovery offers only signed qualified stable releases. Acceptance evidence for the exact tuple and supported targets permits re-signing metadata as `qualified` with identical component payload digests and source commit; changed source or payload requires a new candidate and acceptance. Compatibility authorization alone never proves qualification.

### Lifecycle mutation

Prepared existing receipt → submitted → success/rejected/pending/uncertain. Admission uncertainty remains pending/uncertain until original-operation reconciliation supplies authoritative outcome. Reopening the UI locates the original receipt. A changed revision requires a new review, not automatic retry with a new operation ID. Export preserves existing activation-intent semantics; no archival/restore approval gate is added.

### Host maintenance

Planned → approved → staged/authenticated → intent durable → service quiesced if needed → files/tuple activated → post-check → completed. Before side effects, cancellation may yield cancelled. After side effects, failure is failed-known or uncertain with last confirmed checkpoint. Previous service state is retained; stopped services stay stopped unless explicitly approved to run. Recovery re-observes actual state and proposes only compatible actions. Binary fallback is permitted only if current data remain readable; snapshots are never rolled back.

### Firmware maintenance

Reviewed pre-state → approved service stop → attended bootloader target → verified transfer/flush → awaiting application → post-state comparison → completed or uncertain. Completion requires the same pin and selected live build, not transfer success. Maintenance begun with a stopped service may temporarily start the daemon for explicitly approved validation and return it to stopped afterward. Never run a second operational USB owner.

### Forward lifecycle comparison

Pool/incarnation identity must remain constant unless a separately recorded authorized mutation explains a change. Generation identity may remain active/staged or move staged→active under its certificate and valid period context. Active/staged disappearance requires evidence of permitted expiry or an independently reconciled authorized deletion/discard; missing data alone never proves expiry. Period floors do not decrease. Publication/recipient and journal continuity must match accounted-for transitions. Unexpected concurrent changes yield uncertainty, not automatic normalization.

### OTP and backup roles

OTP state is owned by the existing stage record; the manager offers only currently admitted preview/apply/recovery. A pending uncertain write blocks advancement/replay. Backup role admission precedes private-path reads and passphrase prompts; contradictory primary evidence or unverifiable role blocks. Local restoration validates every binding and memory prerequisite before no-clobber publication. No restoration changes device state or contacts a node.

## Version/migration decision

New manager records use schema 1. Unknown schemas are read-only diagnostics and block mutation. Compatibility metadata must explicitly allow older managers/daemons to read the current installation/config/journal/receipt state. This feature performs no schema downgrade or device-state migration. Existing public contracts remain authoritative; changes to them require synchronized caller/fixture/documentation updates before acceptance.
