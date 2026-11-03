# Authenticated distribution and maintenance contract

Status: implementation contract. Existing firmware schema-1 bundles and schema-2 OTP records remain unchanged.

## Bootstrap and trust root

Publish one `install.sh` entry point with detached `install.sh.sig`. The documented `curl -fsSL https://raw.githubusercontent.com/AndrewWestberg/pico2-kes-agent/master/install.sh | sh` path explicitly trusts the initial launcher from HTTPS hosting. Independent pre-execution verification remains available through the trusted local publisher. Downloaded distribution payloads MUST be authenticated through the separately PGP-authorized secp256k1 distribution key before execution; a fetched manager or firmware verifier never establishes its own authority.

Trust pins: primary OpenPGP fingerprint `9FF957E79B5D853544805F4725491F18087931B6`, authorized signer `78C0F32094CD02A4BAFA444C684E37A210480F82`. Compare verified signature status, not an asserted key ID. The existing firmware boot delegation remains unchanged and insufficient for host distributions. A separate locally PGP-signed distribution authorization grants the existing secp256k1 key distribution authority; no PGP private key goes to CI. Key replacement requires separately authenticated authority.

`distribution-authority.json` has exactly `schema_version` (integer 1, not boolean), `purpose` (`pico2-kes-agent-distribution-authority-v1`), `project` (`https://github.com/AndrewWestberg/pico2-kes-agent`), `algorithm` (`secp256k1`) and `public_key_pem` (the authorized public PEM). Reject duplicate/unknown keys, wrong scope/project/algorithm and non-secp256k1 public keys. Authenticate its exact bytes using `distribution-authority.json.asc` and the pinned OpenPGP authority before trusting the embedded key. Both authorization files are public, committed under `security/`, and included in the manifest inventory.

Release signatures are detached DER ECDSA-SHA256. The signed input is the ASCII signing purpose, one LF byte, then the exact file bytes: `pico2-kes-agent-distribution-v1` for `distribution.json.sig`, `pico2-kes-agent-bootstrap-v1` for `install.sh.sig`. The two contexts are not interchangeable, and neither is the unprefixed firmware-signature format. Do not accept legacy PGP release signatures or infer authority from the old firmware-only statement. All verification uses trusted OS tools before downloaded helpers.

Installer interface: `sh install.sh [--version TAG | --bundle DIRECTORY] [--role primary|backup]`. Defaults: primary role and latest qualified stable release. Explicit tag or offline bundle selection can admit a reviewed candidate only for attended disposable-host acceptance. `--bundle` is not a verification bypass. `--help` does not mutate. No `--yes`, skip-verification or force-compatibility flag. Read confirmations from `/dev/tty` when stdin is a pipe; no interactive terminal means refusal without mutation. The bootstrap directly installs the persistent command after review, then explains reopening `p2kesup` and separate hardware setup.

Before installation: detect host, current components and ownership; display destinations, required packages, privilege use, selected components and proposed changes. Missing tools on supported hosts are offered through approved exact trusted-OS `apt-get` argument vectors, then availability is rechecked. Decline/failure blocks dependent operations. Initial HTTPS launcher trust is distinct from the pinned signature checks on downloaded payloads.

Support targets: Debian 12, Ubuntu 24.04 and Ubuntu 26.04 x86-64 with systemd/udev and glibc ≥2.36. Qualify each image before claiming release qualification on it. Distro packages include required CA/download/archive/signature/runtime libraries and Python/OpenSSL for tool handoffs; actual manifest package lists are exact per distro and scoped per selected operation. No source toolchain or node/Cardano CLI installation. Patched picotool 2.3.1 is a signed project distribution artifact with its shared-library dependencies and license notices, not replaced by an incompatible OS version.

## Distribution manifest schema 1

`distribution.json` is authenticated by the delegated `distribution.json.sig` with the exact distribution signing prefix above. Reject duplicate/unknown keys, invalid encodings, unsupported schema/purpose, malformed identities and missing entries before use. Its JSON purpose remains `pico2-kes-agent-distribution-v1`.

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

Schema 1 uses the following exact nested keys (objects reject all other keys):

- `release`: `tag`, `version`, `source_commit`, `build_id`, `channel` (`stable` or `prerelease`), `published_at` (UTC RFC 3339).
- `platform`: `target`, `glibc_min`, `os` (array of `{id, version}`), `systemd`, `udev`.

  New manifests declare all three OS ID/version pairs above. Readers also accept the exact historical Debian 12/Ubuntu 24.04 pair without widening its authorization: the actual host must appear in the authenticated manifest. Duplicate/unknown OS entries are rejected. Build provenance remains Debian 12. RC.13 and earlier cannot be made Ubuntu 26.04-compatible by substituting only the launcher; publish a new authenticated release containing the updated launcher, manager and manifest.

- `components`: array of `{name, version, build_id, artifact, digest}`; `artifact` is a declared entrypoint and `digest` binds the complete component inventory described below.
- `artifacts`: array of `{path, size_bytes, sha256, class, mode}`; `mode` is an integer permission mask.
- `compatibility`: `tuples` (array of objects mapping every component name to its exact lowercase SHA-256), `readable_schemas` (`config`, `journal`, `receipt`, `installation`, each an array of integer versions), `management_actions`, `usb_profiles`, `storage_versions`, `security_profiles`, `hardware`.
- `qualification`: the string `candidate` or `qualified`.
- `promotion`: null for a candidate; for a qualified release `{candidate_sha256, approval_sha256}` binds the candidate manifest bytes and signed approval bytes.
- `prerequisites`: array of `{operation, tool, version, packages, artifact}`, where `packages` is an array of `{id, version, names}` OS/package-list objects and `artifact` is a declared path or null.
- `preservation`: `firmware_start`, `firmware_end`, `state_start`, `state_end`, `migration` (exactly `none`), `retained` (array of retained categories).

The bundle contains only declared artifact files plus `distribution.json` and `distribution.json.sig`. Mandatory declared trust files include root `distribution-authority.json` and `distribution-authority.json.asc`, and `firmware/release-authority.asc`. The authenticated firmware verifier and patched tool remain `tools/firmware.py` and `tools/picotool`; neither executes until the outer payloads have been authenticated.

Admission runs each system signature command with a 30-second deadline and the authenticated firmware verifier with a 180-second deadline. Subprocess stdin is closed, stderr is discarded, stdout is limited to 64 KiB, and timeout or overflow kills the subprocess group and rejects the bundle. Both GPG and the firmware verifier use isolated private temporary homes, not the invoking account's GPG home or the authenticated snapshot.

Bootstrap's dearmor, signature verification and package metadata subprocesses are likewise bounded to 30 seconds and 64 KiB stdout, with closed stdin, discarded stderr and process-group termination on timeout/overflow. These limits do not authenticate the initial HTTPS launcher.

The six components are `manager` → `bin/p2kesup`, `daemon` → `bin/pico2-kes-agentd`, `cli` → `bin/pico2-kes-agent-cli`, `firmware` → `firmware/pico2-kes-firmware.signed.uf2`, `tool` → `tools/picotool`, and `deployment` → `deploy/install.sh`. Artifact classes are `bin`, `firmware`, `tool`, `deployment`, `license`, `runtime`, and `bootstrap`; modes are 0644 or 0755. `usb-protocol-1` denotes protocol major 1, independently of firmware security profile `rp2350-signed-msd-v1`.

Each component digest is SHA-256 of its inventory sorted by relative path. For each entry append UTF-8 path, NUL, decimal byte count, NUL, lowercase artifact SHA-256, NUL, decimal mode and newline. Manager, daemon and CLI inventories each contain their entrypoint; firmware contains every `firmware/` file; tool contains every `tools/`, `runtime/` and `licenses/` file; deployment contains every `deploy/` file and `install.sh`. The detached `install.sh.sig` and two root distribution authorization files are declared bootstrap artifacts, outside component inventories. Tuples bind inventory digests, not just entrypoint bytes. Each selected component records its entrypoint digest and independently verified source commit and manifest digest.

`prepare --compatible-tuples FILE` accepts at most 255 additional explicit six-component maps in JSON, with each value either a lowercase 64-digit inventory digest or `current`, expanded to the prepared component's digest. The optional repository-root `release-compatible-tuples.json` supplies this input to the release workflow. The signed manifest always contains concrete digests, including its own tuple; duplicate, incomplete or malformed tuples are rejected. No historical published manager schema compatibility is implied.

The published tuple permits application-reported `unlocked` and `rp2350-signed-msd-v1` security profiles; `incomplete` is not admitted. These reports are not independent attestation and do not waive image, tool, hardware or applicable OTP qualification.

The patched tool carries signed `runtime/libusb-1.0.so.0`, `runtime/libudev.so.1`, `runtime/libstdc++.so.6`, and `runtime/libgcc_s.so.1` plus their license notices and the picotool/mbedTLS notices. It uses the host's qualified glibc and dynamic loader; do not substitute an OS picotool. The installed tool component keeps these libraries under its own `runtime/` directory.

The outer manifest also authenticates `runtime/provenance.json`: exactly `schema_version: 1`, `os: {id: "debian", version: "12"}`, and `libraries`, an array of exactly four `{path, package, package_version, sha256}` entries, one for each runtime library above. Package names and versions come from the Debian build's package database; each digest must equal its separately signed artifact digest. Reject duplicates, unknown fields, missing libraries and mismatches. On the target, these are signed build provenance, not a claim that the copied library belongs to an installed host package. GNU `readelf` from the approved `binutils` package supplies the real tool build ID; no compiler or source build is required.

Approved privileged host actions use `/usr/bin/pkexec` with the protected registry-authenticated manager and finite `host-apply --plan FILE`; the `pkexec` package and a functioning polkit authentication agent are installation prerequisites on all target OS versions. Root invokes the same protected helper directly.

Published assets are `distribution.json`, `distribution.json.sig`, `distribution-authority.json`, `distribution-authority.json.asc`, `release-authority.asc`, `install.sh`, `install.sh.sig` and `distribution.tar`. The tar contains exactly manifest-declared artifacts. Before extraction, a trusted unpacker authenticates the delegation and manifest signature, then rejects undeclared, duplicate, linked, special, oversized or hash-mismatched archive members. Standalone and archived authorization/certificate bytes must agree. Publisher round-trip verification repeats the trust chain, both release signatures, exact outer hashes and independent inner firmware verification.

Before candidate signing, the trusted build publisher runs each staged host binary's `--version --json` with a 10-second deadline and 4 KiB output bound, requiring exact schema-1 component, version, build ID and source commit. Stale or mismatched binaries block publication. Consumer admission never executes downloaded host binaries to establish their identity.

Identity inspection and inner firmware verification run in a no-signing-secret staging job. A fresh signing runner disables swap before receiving `PICO2_FIRMWARE_SIGNING_KEY_PEM`, disables core dumps and confines its temporary private file to `/dev/shm` with unconditional cleanup. It revalidates the public distribution authorization, key identity, prepared schema, source/build identity and inventory without executing bundled code; it signs the installer and manifest with `--key-file` and verifies the result. Publication runs separately without the secret. Promotion likewise verifies existing human approval before delegated metadata signing; no PGP private-key secret is needed by either signing job.

Promotion approval is `approval.json`, detached signed by the pinned project signer, with exactly `schema_version`, `candidate_sha256`, `source_commit`, `payloads`, `evidence`, `approved`. Version is 1; `approved` is true; `payloads` maps every candidate artifact path to its SHA-256; `evidence` maps `Q1.md`–`Q11.md`, `developer-checks.md`, `performance.md`, `security-review.md`, and `acceptance.md` to SHA-256 of the retained files. Each named evidence file and the signed approval are published alongside qualified metadata, and the approval identifies the exact candidate metadata and source. The approval is an authority's assertion of completed T070 review, not a substitute for actually performing it.

No semantic-version heuristic substitutes for an explicit compatible tuple. A cross-release mix is admitted only when a trusted manifest explicitly authorizes that exact tuple and all referenced manifests/artifacts verify. Current data-schema and hardware observations must fit the selected tuple. Missing observations or unknown compatibility block changes. Authorization establishes compatibility for review; it is not evidence of release qualification.

An authenticated `candidate` may be selected only through an explicit `--version TAG` or offline `--bundle` in an attended acceptance session on a disposable host, after the operator reviews its candidate status, exact tuple and consequences. This is not a verification bypass: signatures, authority, schema, state, hardware, image/tool qualification and any applicable OTP prerequisites remain mandatory. Default discovery and ordinary installation offer only qualified stable releases; qualified offline bundles remain subject to all normal checks.

After acceptance evidence establishes all release qualification gates for the exact candidate tuple and supported targets, promotion publishes re-signed metadata marking it `qualified` and binding the identical component payload digests and source commit. Publish candidate and promoted metadata at distinct immutable locations; never overwrite historical candidate bytes. Promotion is not a rebuild or a way to conceal post-test source modifications: changed source or payload requires a new candidate and acceptance. Preserve the evidence and linkage to the candidate metadata; verify promoted signatures, status admission and payload equality before release completion. These final metadata checks do not require a second full payload qualification. Do not infer qualification from compatibility authorization alone.

Qualified stable publication uses the exact GitHub tag `qualified-<signed release.tag>`, prerelease false and latest true; candidates use the plain signed tag and all candidates and prerelease channels remain prerelease and not latest.

Limits: manifest ≤1 MiB; ≤256 artifact entries; each path ≤240 bytes; each artifact ≤256 MiB; total uncompressed ≤1 GiB. Paths are unique normalized relative paths, never absolute, `..`, symlinks, hardlinks, device files or control characters. Reject archive members outside the declared set, duplicate extraction paths, inconsistent sizes and compressed expansion exceeding bounds. Download to protected staging, authenticate before extraction/use, verify every extracted file, then install. Recheck at privileged use to defeat cache substitution.

Place the existing firmware bundle under a dedicated `firmware/` directory with exactly its existing allowed files. Its `release.json`, signature, authority chain, signed ELF/UF2 and OTP helper remain independently verified by the authenticated existing verifier. Do not insert host manifests, evidence or logs into that directory. The outer signature binds all of its bytes but does not waive inner image/range/key checks.

## Discovery and offline operation

GitHub release API at `https://api.github.com/repos/AndrewWestberg/pico2-kes-agent/releases` is discovery only. Bound metadata fetches, restrict project release origins, prevent credential forwarding on redirects, and treat all remote strings as untrusted terminal content. Only signed manifests determine authenticity/compatibility. Escape control sequences in displayed diagnostics and filenames.

Cache publication/fetch times and verification provenance; label cached age. Local navigation continues during network failure. Offline selection verifies signatures, current available authority evidence, manifest completeness, hashes and compatibility again, and applies the qualification admission rules above. If any required verifier/key/revocation prerequisite is unavailable, block maintenance. Offline success claims authenticity under available trust evidence, not current global revocation freshness or latest-release status. Explicit downgrade is allowed only by compatible signed selection.

## Host transaction and ownership

The schema-1 ownership registry is `/var/lib/p2kesup/installation.json`, root-owned
mode 0644 and bounded to 1 MiB. Observation reads this protected registry and
verifies component hashes; the authenticated privileged installer publishes it.
User-cache metadata cannot substitute for this authority. Unknown schemas or
inaccessible ownership evidence remain unknown and cannot authorize mutation.

- Immutable components: `/usr/lib/pico2-kes-agent/components/<component>/<sha256>/`.
- Selected tuple: `/usr/lib/pico2-kes-agent/generations/<id>/`, containing links to selected component directories.
- Active tuple: atomic `/usr/lib/pico2-kes-agent/current` symlink; stable `/usr/bin/p2kesup`, `/usr/bin/pico2-kes-agent-cli` and `/usr/bin/pico2-kes-agentd` resolve through it.
- Manager registry/maintenance records: `/var/lib/p2kesup/`, with public ownership metadata and protected operator-group-readable maintenance records as specified in the [data model](../data-model.md); existing daemon config/state permissions and service identities are preserved.

Acquire one host-maintenance lock. Revalidate privileged input, platform, path ancestry, ownership, installed hashes and current compatibility; user-writable plan bytes are not privileged authority. Never execute an operator-provided command string or program path as root. A finite `host-apply --plan FILE` mode of the verified installed manager performs only enumerated install/config/service/hardening/uninstall actions after displaying and confirming their digest-bound scope. Initial bootstrap stages the authenticated manager to a protected location before privilege handoff. This is an internal invocation, not a general privileged command runner or new socket role.

Privileged confirmation reads at most 257 bytes and rejects a line over 256 bytes; approval must match the displayed digest. Physical same-board confirmation is likewise bounded and requires the exact serial.

Each approval includes a random plan identity; changing scope requires a new
review. Reopening an original plan uses read-only `host-inspect --plan FILE`,
not another apply. `host-admit --plan FILE` performs finite privileged commissioning
admission and authenticates the connected daemon's PID/UID before sending public
observation requests; it does not mutate a device or replace lifecycle receipts.
An uncertain first-install permits only explicitly reviewed prerequisites and
same-board reconciliation bound to its original operation. Successful transfer
alone is never commissioning admission.

`host-lifecycle-admit` uses a caller-bound, mode-bound expiring public authority record; normal authority binds the pinned identity, restricted authority binds the commissioning serial, and connected CLI streams check the approved peer PID/UID before bytes. Original commissioning recovery selects restricted authority by the original receipt even when the device is committed and no normal pin exists. New commissioning still requires live compatible blank admission.

Service readback includes `InvocationID` and pending job state; an unchanged active invocation is not proof of completed restart and pending jobs block reconciliation. The unpublished internal service action payload is `operation: start|stop|restart`, replacing `start: bool` without silent migration of earlier internal plans.

Stage/fsync immutable components and tuple on the destination filesystem. Persist intent and prior service state before stopping the daemon. Validate proposed configuration with candidate `pico2-kes-agentd --config FILE --check-config` as the service user; run existing deployment preflight without bypass. Apply separately recorded service/udev/config changes, atomically switch tuple, reload changed service/device configuration, then restore the approved service state. Verify installed and running builds independently. Previously stopped services stay stopped unless temporary validation/start is explicitly approved; after temporary checks restore stopped state.

A process termination leaves the original record with last confirmed checkpoints. Reopen reads actual pointer/files/service state before recovery. If the previous binary tuple remains compatible with current persistent data, explicit binary fallback is permitted. No old config/journal/flash snapshot is restored. Self-update uses the same switch; the old manager remains running until explicit re-exec, and its version is shown separately from the installed selection.

The complete `p2kesup upgrade` transaction adds an original-plan-bound persistent service mask before firmware transfer/publication, preventing a reboot from starting a mismatched host/firmware pair. Target firmware executes using the authenticated executable tool component, not a non-executable staging copy. Immutable transfer image identity is recorded before durable intent. Resume reauthenticates retained sources and original/target ownership, never reflashes, and completes forward only after exact flush evidence. Only proven no-transfer cancellation with unchanged original files can restore the old service; ambiguous handoffs remain blocked. Manual unmasking is not recovery.

Manual/external installations are inspectable but never silently adopted. A collision blocks affected replacement and identifies the owner/path. Modified manager-owned files require a new explicit review; the approval of an earlier hash does not authorize replacing current bytes. Uninstall removes only selected ownership-proven files; stops only the managed service if needed and approved; preserves config, journal, receipts, identities, service user/group, all device storage and producer drop-ins. List retained paths. It is not erasure or revocation.

Selected uninstall approval hashes the registry and exact selected file/link inventory. Recovery binds fresh public readback to the original operation and plan digest, refuses changed observations, and does not stop services. Full removal retains the registry tombstone/provenance and `/usr/lib/pico2-kes-agent/sources` cache, not merely operational state. After completed full removal initial Install can restore the exact prior single-bundle tuple; it does not reinterpret mixed tuples. Producer recovery likewise binds fresh readback to the original operation/digest and requires fresh approval of original reload/try-restart scope only, never starting stopped units.

## Attended first firmware installation

A factory/BOOTSEL-only board has no application serial or pin to supply. For a source-free first install, use the authenticated bundled tool and firmware: `python3 -I firmware.py first-install --bundle DIR --record FILE [--apply]`. Without `--apply`, verify and preview only; applying requires foreground terminal confirmation. Reuse the existing firmware verifier and board, mount, image-range and copy helpers, and the same image/tool/hardware evidence and applicable security prerequisites as other firmware operations. The selected image may write only `[0x10000000, 0x10100000)`; preserve `[0x10100000, 0x10308000)`. No state erase or OTP operation is implied or permitted.

Before transfer, persist a public maintenance intent binding the authenticated bundle/image digest, attended physical selection and checkpoints; do not invent an application identity or promote a bootloader identifier to a pin. Require physical attendance and one unambiguous BOOTSEL target associated with the operator's selected board; ambiguity or an unverified mount blocks transfer, not a guess based on a volume label or changed USB address. Verify the actual mount, available space, full UF2 copy and flush as for maintenance. Transfer is not commissioning or proof of blank state.

New first-install records are root-owned `/var/lib/p2kesup/firmware/<32 lowercase hex>.json`. Before new work, root rechecks protected configuration and identity, journal, and prior firmware/maintenance records. Reopening the original record is read-only; selecting a replacement filename cannot bypass historical admission or an interrupted operation.

First-install eligibility must be reviewed independently of missing application contact: an existing pin, installation record or known commissioned target excludes this route even if the pin file has disappeared or the application will not boot. Such devices retain the existing maintenance/recovery authority. A factory-board declaration does not override contradictory evidence.

After transfer, observe the selected compatible live application through the sole existing restricted commissioning daemon, with no competing USB owner. Only an unambiguous, observed blank application is admitted to the separate existing commissioning workflow; a nonblank, ambiguous, wrong-build or unknown post-state blocks commissioning and pinning. Commissioning publishes the identity and installs a reviewed normal-mode pin/config separately. An already-running uncommissioned application follows that blank-admission and commissioning path without a first-install transfer; an already pinned device follows maintenance below. An interrupted or uncertain first install retains its original record and blocks treating the board as new work or silently reflashing, recommissioning or pinning; reopen the record and observe actual state for explicit recovery.

## Attended firmware update

New trusted tool interface: `python3 -I firmware.py update --bundle DIR --serial SERIAL --record FILE [--apply]`. Without `--apply`, validate and preview only. Applying requires foreground terminal confirmation and the existing qualified image/tool/hardware evidence; optional physical-security provisioning is never implied. The update record is a distinct public maintenance record, not an OTP record.

The manager records complete public pre-state and verifies compatibility before stopping the daemon. Reuse the first-install tool's verified board/mount, range and copy helpers; do not guess a destination by volume label or a changed USB address. Multiple/ambiguous boards block until attended disambiguation. Verify the actual mount belongs to the selected physical transition, check space, copy full verified UF2, flush, and record the transfer result. The image may write only `[0x10000000, 0x10100000)`; retained state is `[0x10100000, 0x10308000)`. No erase-state/OTP commands are used.

Tool completion means transfer checkpoint only. Manager completion requires daemon reconnection to the same pin, selected live build and compatible storage, followed by retained membership/generation/recipient/period/journal comparison according to [data model](../data-model.md). Do not claim success when a stopped daemon or missing context prevents post-check; offer explicit temporary validation or leave incomplete. Interruption, unknown destination, failed flush/reboot or unexplained state change remains failed/uncertain. Recovery never automatically reflashes, erases, changes pins, recommissions or replays OTP.

Packaged OTP provisioning and `reconcile-prepare` invoke the authenticated tool with `--distribution`, binding its signed runtime. The tool only uses the default management socket; a configured nondefault socket is refused before service stops or tool handoff. Only existing original-tool-record recovery is permitted. These additions do not migrate or change mutation, node-service, device-storage, backup or OTP wire/persistence formats.
