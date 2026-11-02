# Authenticated distribution and maintenance contract

Status: proposed. No host bundle/bootstrap/first-install/normal firmware-update command described here currently exists. Existing firmware schema-1 bundles and schema-2 OTP records remain unchanged.

## Bootstrap and trust root

Publish one `install.sh` entry point with detached `install.sh.asc`. Before executing it, obtain it through an independently authenticated channel or verify it using a locally trusted project authority keyring. Do not advertise unauthenticated `curl | sh` as verification. The script carries a small initial verifier using trusted system tools; a fetched manager or firmware verifier never establishes its own authority.

Trust pins: primary OpenPGP fingerprint `9FF957E79B5D853544805F4725491F18087931B6`, authorized signer `78C0F32094CD02A4BAFA444C684E37A210480F82`. Compare verified signature status, not a key ID printed in downloaded metadata. Key replacement requires separately authenticated authority, never an automatically imported replacement from the bundle. Firmware key delegation remains limited to the current firmware purpose.

Installer interface: `sh install.sh [--bundle DIRECTORY] [--role primary|backup]`. Defaults: primary role and interactive stable-release selection. `--bundle` is offline selection, not verification bypass. `--help` does not mutate. No `--yes`, skip-verification or force-compatibility flag. Non-interactive input exits without mutation. Bootstrap completion explains `p2kesup` and, for backup-only installs, `p2kesup --role backup`.

Before installation: detect host, current components and ownership; display destinations, required packages, privilege use, selected components and proposed changes. Missing tools on supported hosts are offered through approved exact `apt-get` argument vectors, then availability is rechecked. Decline/failure blocks only dependent operations. If the operator cannot authenticate the script because no trusted verification tool/key is available, installing that prerequisite through the OS trusted package path precedes script execution; never run an unauthenticated script to fix its own trust root.

Initial support targets: Debian 12 and Ubuntu 24.04 x86-64 with systemd/udev and glibc ≥2.36. Qualify both before publishing either as supported. Distro packages include required CA/download/archive/signature/runtime libraries and Python/OpenSSL for tool handoffs; actual manifest package lists are exact per distro and scoped per selected operation. No source toolchain or node/Cardano CLI installation. Patched picotool 2.3.1 is a signed project distribution artifact with its shared-library dependencies and license notices, not replaced by an incompatible OS version.

## Distribution manifest schema 1

`distribution.json` is signed byte-for-byte with detached OpenPGP `distribution.json.asc`. Reject duplicate/unknown keys, invalid encodings, unsupported schema/purpose, malformed identities and missing entries before use. Purpose: `pico2-kes-agent-distribution-v1`.

| Field | Required content |
|---|---|
| `schema_version`, `purpose` | 1 and exact purpose above |
| `release` | tag, version, full source commit, build ID, stable/prerelease classification, publication timestamp |
| `platform` | x86_64-unknown-linux-gnu, glibc minimum, exact supported OS ID/version pairs, systemd/udev requirement |
| `components` | manager/daemon/CLI/firmware/tool/deployment versions, artifact references and embedded build identifiers |
| `artifacts` | unique confined relative path, exact bytes, lowercase SHA-256, installation class and mode |
| `compatibility` | authorized complete component tuples by exact digests; readable config/journal/receipt/installation schema sets; management actions, USB/storage/security profiles and hardware constraints |
| `qualification` | signed release status, exactly `candidate` or `qualified`, independent of stable/prerelease classification |
| `prerequisites` | operation-specific tools, required capability/version, supported-distro package list or bundled artifact reference |
| `preservation` | firmware/state address bounds, no-data-migration policy, config/state/identity/receipt retention |

No semantic-version heuristic substitutes for an explicit compatible tuple. A cross-release mix is admitted only when a trusted manifest explicitly authorizes that exact tuple and all referenced manifests/artifacts verify. Current data-schema and hardware observations must fit the selected tuple. Missing observations or unknown compatibility block changes. Authorization establishes compatibility for review; it is not evidence of release qualification.

An authenticated `candidate` may be selected only through an explicit offline `--bundle` in an attended acceptance session on a disposable host, after the operator reviews its candidate status, exact tuple and consequences. This is not a verification bypass: signatures, authority, schema, state, hardware, image/tool qualification and any applicable OTP prerequisites remain mandatory. Normal discovery and ordinary installation offer only `qualified` releases, irrespective of channel; `qualified` offline bundles remain subject to all normal checks.

After acceptance evidence establishes all release qualification gates for the exact candidate tuple and supported targets, promotion publishes re-signed metadata marking it `qualified` and binding the identical component payload digests and source commit. Publish candidate and promoted metadata at distinct immutable locations; never overwrite historical candidate bytes. Promotion is not a rebuild or a way to conceal post-test source modifications: changed source or payload requires a new candidate and acceptance. Preserve the evidence and linkage to the candidate metadata; verify promoted signatures, status admission and payload equality before release completion. These final metadata checks do not require a second full payload qualification. Do not infer qualification from compatibility authorization alone.

Limits: manifest ≤1 MiB; ≤256 artifact entries; each path ≤240 bytes; each artifact ≤256 MiB; total uncompressed ≤1 GiB. Paths are unique normalized relative paths, never absolute, `..`, symlinks, hardlinks, device files or control characters. Reject archive members outside the declared set, duplicate extraction paths, inconsistent sizes and compressed expansion exceeding bounds. Download to protected staging, authenticate before extraction/use, verify every extracted file, then install. Recheck at privileged use to defeat cache substitution.

Place the existing firmware bundle under a dedicated `firmware/` directory with exactly its existing allowed files. Its `release.json`, signature, authority chain, signed ELF/UF2 and OTP helper remain independently verified by the authenticated existing verifier. Do not insert host manifests, evidence or logs into that directory. The outer signature binds all of its bytes but does not waive inner image/range/key checks.

## Discovery and offline operation

GitHub release API at `https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases` is discovery only. Bound metadata fetches, restrict project release origins, prevent credential forwarding on redirects, and treat all remote strings as untrusted terminal content. Only signed manifests determine authenticity/compatibility. Escape control sequences in displayed diagnostics and filenames.

Cache publication/fetch times and verification provenance; label cached age. Local navigation continues during network failure. Offline selection verifies signatures, current available authority evidence, manifest completeness, hashes and compatibility again, and applies the qualification admission rules above. If any required verifier/key/revocation prerequisite is unavailable, block maintenance. Offline success claims authenticity under available trust evidence, not current global revocation freshness or latest-release status. Explicit downgrade is allowed only by compatible signed selection.

## Host transaction and ownership

- Immutable components: `/usr/lib/pico2-kes-agent/components/<component>/<sha256>/`.
- Selected tuple: `/usr/lib/pico2-kes-agent/generations/<id>/`, containing links to selected component directories.
- Active tuple: atomic `/usr/lib/pico2-kes-agent/current` symlink; stable `/usr/bin/p2kesup`, `/usr/bin/pico2-kes-agent-cli` and `/usr/bin/pico2-kes-agentd` resolve through it.
- Manager registry/maintenance records: `/var/lib/p2kesup/`, with public ownership metadata and protected operator-group-readable maintenance records as specified in the [data model](../data-model.md); existing daemon config/state permissions and service identities are preserved.

Acquire one host-maintenance lock. Revalidate privileged input, platform, path ancestry, ownership, installed hashes and current compatibility; user-writable plan bytes are not privileged authority. Never execute an operator-provided command string or program path as root. A finite `host-apply --plan FILE` mode of the verified installed manager performs only enumerated install/config/service/hardening/uninstall actions after displaying and confirming their digest-bound scope. Initial bootstrap stages the authenticated manager to a protected location before privilege handoff. This is an internal invocation, not a general privileged command runner or new socket role.

Stage/fsync immutable components and tuple on the destination filesystem. Persist intent and prior service state before stopping the daemon. Validate proposed configuration with candidate `pico2-kes-agentd --config FILE --check-config` as the service user; run existing deployment preflight without bypass. Apply separately recorded service/udev/config changes, atomically switch tuple, reload changed service/device configuration, then restore the approved service state. Verify installed and running builds independently. Previously stopped services stay stopped unless temporary validation/start is explicitly approved; after temporary checks restore stopped state.

A process termination leaves the original record with last confirmed checkpoints. Reopen reads actual pointer/files/service state before recovery. If the previous binary tuple remains compatible with current persistent data, explicit binary fallback is permitted. No old config/journal/flash snapshot is restored. Self-update uses the same switch; the old manager remains running until explicit re-exec, and its version is shown separately from the installed selection.

Manual/external installations are inspectable but never silently adopted. A collision blocks affected replacement and identifies the owner/path. Modified manager-owned files require a new explicit review; the approval of an earlier hash does not authorize replacing current bytes. Uninstall removes only selected ownership-proven files; stops only the managed service if needed and approved; preserves config, journal, receipts, identities, service user/group, all device storage and producer drop-ins. List retained paths. It is not erasure or revocation.

## Attended first firmware installation

A factory/BOOTSEL-only board has no application serial or pin to supply. For a source-free first install, use the authenticated bundled tool and firmware: `python3 -I firmware.py first-install --bundle DIR --record FILE [--apply]`. Without `--apply`, verify and preview only; applying requires foreground terminal confirmation. Reuse the existing firmware verifier and board, mount, image-range and copy helpers, and the same image/tool/hardware evidence and applicable security prerequisites as other firmware operations. The selected image may write only `[0x10000000, 0x10100000)`; preserve `[0x10100000, 0x10308000)`. No state erase or OTP operation is implied or permitted.

Before transfer, persist a public maintenance intent binding the authenticated bundle/image digest, attended physical selection and checkpoints; do not invent an application identity or promote a bootloader identifier to a pin. Require physical attendance and one unambiguous BOOTSEL target associated with the operator's selected board; ambiguity or an unverified mount blocks transfer, not a guess based on a volume label or changed USB address. Verify the actual mount, available space, full UF2 copy and flush as for maintenance. Transfer is not commissioning or proof of blank state.

First-install eligibility must be reviewed independently of missing application contact: an existing pin, installation record or known commissioned target excludes this route even if the pin file has disappeared or the application will not boot. Such devices retain the existing maintenance/recovery authority. A factory-board declaration does not override contradictory evidence.

After transfer, observe the selected compatible live application through the sole existing restricted commissioning daemon, with no competing USB owner. Only an unambiguous, observed blank application is admitted to the separate existing commissioning workflow; a nonblank, ambiguous, wrong-build or unknown post-state blocks commissioning and pinning. Commissioning publishes the identity and installs a reviewed normal-mode pin/config separately. An already-running uncommissioned application follows that blank-admission and commissioning path without a first-install transfer; an already pinned device follows maintenance below. An interrupted or uncertain first install retains its original record and blocks treating the board as new work or silently reflashing, recommissioning or pinning; reopen the record and observe actual state for explicit recovery.

## Attended firmware update

New trusted tool interface: `python3 -I firmware.py update --bundle DIR --serial SERIAL --record FILE [--apply]`. Without `--apply`, validate and preview only. Applying requires foreground terminal confirmation and the existing qualified image/tool/hardware evidence; optional physical-security provisioning is never implied. The update record is a distinct public maintenance record, not an OTP record.

The manager records complete public pre-state and verifies compatibility before stopping the daemon. Reuse the first-install tool's verified board/mount, range and copy helpers; do not guess a destination by volume label or a changed USB address. Multiple/ambiguous boards block until attended disambiguation. Verify the actual mount belongs to the selected physical transition, check space, copy full verified UF2, flush, and record the transfer result. The image may write only `[0x10000000, 0x10100000)`; retained state is `[0x10100000, 0x10308000)`. No erase-state/OTP commands are used.

Tool completion means transfer checkpoint only. Manager completion requires daemon reconnection to the same pin, selected live build and compatible storage, followed by retained membership/generation/recipient/period/journal comparison according to [data model](../data-model.md). Do not claim success when a stopped daemon or missing context prevents post-check; offer explicit temporary validation or leave incomplete. Interruption, unknown destination, failed flush/reboot or unexplained state change remains failed/uncertain. Recovery never automatically reflashes, erases, changes pins, recommissions or replays OTP.
