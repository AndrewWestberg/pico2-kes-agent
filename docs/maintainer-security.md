# Maintainer security and release guide

For project maintainers only. These procedures manage the firmware-signing authority, build release artifacts and collect lab evidence. End users do not generate, recover, upload or receive a private firmware-signing key.

Run shell commands from the repository root, not from `docs/`. End-user installation, public verification, provisioning, updates and recovery are in the [README](../README.md). Physical procedures are performed manually; no hardware or cloud result is implied by this guide.

## Maintainer procedures

### Build the pinned security tools

Use a native C/C++ toolchain, `arm-none-eabi-gcc`, CMake, pkg-config and libusb development headers. Install prerequisites explicitly using the host's package manager; the firmware utility never installs packages. Build picotool with the SDK's pinned mbedTLS submodule so native signing and USB support are both present.

```bash
set -euo pipefail
TOOL_ROOT="$HOME/.local/share/pico2-kes-tools"
mkdir -p "$TOOL_ROOT"
git clone https://github.com/raspberrypi/pico-sdk.git "$TOOL_ROOT/pico-sdk"
git -C "$TOOL_ROOT/pico-sdk" checkout 079c6f39023649b154152db30f1d781e884879bc
git -C "$TOOL_ROOT/pico-sdk" submodule update --init lib/mbedtls
git clone https://github.com/raspberrypi/picotool.git "$TOOL_ROOT/picotool"
git -C "$TOOL_ROOT/picotool" checkout 2041936441b48a3cc53ae3da9e805229fe8f4e18
cmake -S "$TOOL_ROOT/picotool" -B "$TOOL_ROOT/picotool-build" \
  -DPICO_SDK_PATH="$TOOL_ROOT/pico-sdk" -DPICOTOOL_NO_LIBUSB=0 \
  -DCMAKE_INSTALL_PREFIX="$TOOL_ROOT/install"
cmake --build "$TOOL_ROOT/picotool-build" --parallel
cmake --install "$TOOL_ROOT/picotool-build"
export PATH="$TOOL_ROOT/install/bin:$PATH"
picotool version
cmake -S tools/otp_permissions -B target/otp-permissions \
  -DPICO_SDK_PATH="$TOOL_ROOT/pico-sdk" -DPICO_BOARD=pico2
cmake --build target/otp-permissions --parallel
```

The permission helper is **unsigned preparation code**, not a firmware update. It runs entirely in XIP-SRAM before secure boot, accepts only the two expected CHIPID words, and can only close page-2/page-63 permissions. Authenticate its bundle digest before making a target-bound private copy. Never use stock `picotool otp permissions`: its page-63 omission does not satisfy this profile.

### Attended OTP evidence and uncertainty

Use the hardened schema-2 provisioner for new boards. Historical schema-1 records are evidence, not inputs to an automatic migration. Do not replace the tool inside an authenticated bundle; that would invalidate its manifest. A separately trusted checkout tool may verify/use the unchanged bundle.

Before attended provisioning, retain the exact tool identity in the private lab directory:

```bash
umask 077
PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I - <<'PY'
import json, runpy
tool = runpy.run_path("tools/firmware.py")
print(json.dumps(tool["tool_identity"](), indent=2))
PY
```

This probes the actual glibc-loaded libusb, not a guessed library or version banner. The approved Linux host needs `readelf` and `dpkg-query` as well as the existing prerequisites. Identity binds canonical executable/library paths, SHA-256, GNU build ID, full version output, libusb package/version, provisioner hash and any selected trace-hook hash. Missing provenance or a changed identity stops applying/resume before another write.

CRIT1 and both BOOT_FLAGS groups are programmed as explicit raw physical rows. Each command has an immediate same-row readback; the next copy is not attempted after a mismatch. Independent full-group checks compare every copy and the vote (CRIT1 three-of-eight, boot flags two-of-three). A majority/voted policy alone is insufficient. The record contains each intended row/value/payload, expected and observed postcondition, timestamps and bounded subprocess evidence.

An action is durable `pending` before dispatch. Completed subprocess evidence is checkpointed before subsequent observation or operator prompts. Each stream retains at most 4 KiB with explicit truncation indicators; parser output is separately limited to 64 KiB. Records have an 8 MiB limit and reserve evidence capacity before an action. Timeout/interruption terminates the subprocess group, including a supervising trace wrapper's children, before retaining its available diagnostics and marking the action uncertain. These bounds do not make OTP transactional or recover evidence from an unobserved in-flight crash.

After any uncertain OTP operation: stop, retain immutable/protected copies and hashes of the original record and tool/bundle inputs, append subsequent evidence separately, and do not reset/retry until the physical state has been diagnosed. `reconcile-prepare` is now a read-only assessment: it neither clears pending nor promotes preparation. Never manually edit a record or use a new record path to bypass uncertainty. A later repair cannot turn a failed lock-stage attempt into qualification.

`provision` and `erase-state` optionally accept `--trace-hook /absolute/executable`. The hook receives `PICOTOOL ARG...` as separate arguments, without a shell, including a provenance `version` probe. It must execute/supervise that exact command, preserve its exit status and stdout, and store packet traces in an owner-only location. Its hash and the libusb loaded through it are bound into identity. Device `info --device --debug` is deliberately excluded from retained stdout and transport wrapping because it contains RANDID. Do not broaden captures to secret pages, signing stdin, operational USB traffic or private key files.

The hook is an integration point, **not** a PICOBOOT packet decoder or an added command-status query. A future PICOBOOT incident reproduction still needs an audited instrumented binary and USB trace retaining the command header, payload, transfer counts, ACK and `GET_COMMAND_STATUS`; ordinary provisioning has no packet-capture dependency.

The [CRIT1 incident report](crit1-7-5-otp-bug-report.md) records the sacrificial-board protocol, physical results and upstream disposition. Keep that board out of production qualification. Qualification requires exact tool/library provenance, all physical redundant copies, cold-boot policy observations and the complete acceptance procedure; repaired physical values alone are not a pass.

The standalone `tools/otp_diagnostic` target is lab-only, excluded from releases and normal firmware. It runs Secure code from RAM, has no USB auto-reset facility, and admits only the hard-bound A2 board/key and four fixed, blank user-row ranges. It is not the unsigned permissions helper or a generic OTP programmer.

```bash
git -C "$TOOL_ROOT/pico-sdk" submodule update --init lib/tinyusb
cmake -S tools/otp_diagnostic -B target/otp-diagnostic \
  -DPICO_SDK_PATH="$TOOL_ROOT/pico-sdk" -DPICO_BOARD=pico2 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build target/otp-diagnostic --parallel
```

Building does not sign or install it. Any installation requires a separately reviewed experiment protocol, authenticated image, checked ELF/UF2 firmware-only load ranges, exact device identity and captured public transcripts. All four existing ranges on the incident board are now nonblank and must not be retried. Changing the board/ranges is a new destructive experiment, not a recovery flag. Preserve failures before deciding any reset or further test.


### Maintainer boot authority

GPG authorizes one dedicated secp256k1 public boot authority; automated releases are not individually OpenPGP-signed. The pinned primary is `9FF957E79B5D853544805F4725491F18087931B6`, signing subkey `78C0F32094CD02A4BAFA444C684E37A210480F82!`. Email-only selection and the revoked older identity are not acceptable. The ROM fingerprint is SHA-256 of 64-byte big-endian `X || Y`, not the PEM digest or GPG fingerprint.

Before first creation, inspect both `gh secret list --repo AndrewWestberg/pico2-kes-agent` and `$HOME/.local/share/pico2-kes-signing`. An existing secret/backup is a recovery requirement, not permission to rotate. GitHub secrets cannot be read back as backups. Reuse only after recovering the same key and comparing its public identity with the authorized statement. The personal GPG private key stays local; devices receive only the public boot-key hash.

Every pushed `v*` tag on any commit triggers the release-signing workflow; there is no branch, signed-tag, or protected-environment approval gate. Access to the repository, workflow, tags, or signing secret is therefore firmware-signing authority. Protect and review that access accordingly. This is a single lifetime authority: the unused boot-key slots are invalidated during provisioning, so there is no independent emergency key or transparent rotation. Loss of the key and its protected backups prevents new signed releases for locked devices; compromise permits malicious authorized firmware. A GitHub secret is not a recoverable backup. Publication or physical qualification must not be inferred from the workflow's existence.

**Maintainer, once only, trusted checkout:** the following deliberately refuses an existing authority. Local GPG pinentry interaction may be required. Do not put PEM contents in shell arguments, logs, build outputs, or the checkout.

```bash
(
  set -euo pipefail
  set +x
  umask 077
  export GPG_TTY="$(tty)"
  gpg-connect-agent updatestartuptty /bye
  SIGNING_HOME="$HOME/.local/share/pico2-kes-signing"
  install -d -m 0700 "$SIGNING_HOME"
  BACKUP="$SIGNING_HOME/firmware-signing-key.pem.gpg"
  test ! -e "$BACKUP"
  test ! -e "$SIGNING_HOME/firmware-signing-public.pem"
  test ! -e security/firmware-key.json
  test "$(gh secret list --repo AndrewWestberg/pico2-kes-agent --json name \
    | jq '[.[] | select(.name == "PICO2_FIRMWARE_SIGNING_KEY_PEM")] | length')" = 0
  PRIVATE_DIR="$(mktemp -d /dev/shm/pico2-signing.XXXXXXXX)"
  trap 'rm -rf -- "$PRIVATE_DIR"' EXIT
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 \
    -out "$PRIVATE_DIR/key.pem"
  chmod 0600 "$PRIVATE_DIR/key.pem"
  openssl pkey -in "$PRIVATE_DIR/key.pem" -pubout -out "$PRIVATE_DIR/public.pem"
  gpg --encrypt --recipient 9FF957E79B5D853544805F4725491F18087931B6 \
    --output "$BACKUP" "$PRIVATE_DIR/key.pem"
  chmod 0600 "$BACKUP"
  # Retain the public key even if decryption/signing needs another attempt.
  cp -n "$PRIVATE_DIR/public.pem" "$SIGNING_HOME/firmware-signing-public.pem"
  gpg --decrypt --output "$PRIVATE_DIR/recovered.pem" "$BACKUP"
  openssl pkey -in "$PRIVATE_DIR/recovered.pem" -pubout \
    -out "$PRIVATE_DIR/recovered-public.pem"
  cmp "$PRIVATE_DIR/public.pem" "$PRIVATE_DIR/recovered-public.pem"
  python3 tools/firmware.py authorize --public-key "$PRIVATE_DIR/public.pem" --out-dir security
  gh secret set PICO2_FIRMWARE_SIGNING_KEY_PEM \
    --repo AndrewWestberg/pico2-kes-agent < "$PRIVATE_DIR/key.pem"
)
```

`authorize` validates a public secp256k1 key and publishes the public PEM, exact signed JSON statement, detached armored signature and public GPG certificate without clobber. It never generates or uploads a private key. If pinentry/decryption/signing fails, preserve the encrypted backup and recover that authority; never rerun key generation to conceal the failure. Preserve a separate protected offline backup before provisioning. Invalidating unused boot slots makes this a single-authority lifetime commitment: loss prevents new releases; compromise permits malicious signed code. There is no second emergency authority or automatic key rotation.

**An authority already exists:** do not run the first-creation block again. The encrypted backup is `$HOME/.local/share/pico2-kes-signing/firmware-signing-key.pem.gpg`; its public key is `firmware-signing-public.pem` in that directory and in `security/`. The public authorization is `security/firmware-key.json`, its detached `.asc` signature and `security/release-authority.asc`. All four repository assets are public and commit-safe; a decrypted private PEM is not.

If first creation stopped before authorization, decrypt the **existing** backup in a private `/dev/shm` directory, derive its public key with `openssl pkey -pubout`, and compare DER public keys with the saved PEM using `openssl pkey -pubin -outform DER` and `cmp`. Run `authorize` with that recovered public key only if the repository authorization assets do not already exist. Existing assets must be verified and compared, not deleted to bypass no-clobber protection. The local build below recovers the same encrypted key and checks it against an existing authorized authority; it never generates a replacement.

For terminal pinentry, run `export GPG_TTY="$(tty)"` and `gpg-connect-agent updatestartuptty /bye` in your own terminal. Enter a passphrase only into GPG's prompt. An `encrypted with … 495C1BB52A776BE8` message identifies the encryption subkey, not the authorization signer; `authorize` forces the pinned signing subkey and its verifier checks both primary and signing fingerprints.

Preserve separate protected copies of the encrypted backup, public PEM and authorization files, and preserve your personal GPG recovery material separately. To make a text-only copy **without decrypting**, use `gpg --enarmor --output NEW.asc ORIGINAL.gpg`. Restore its original encrypted bytes with `gpg --dearmor --output NEW.gpg NEW.asc` and `cmp` them against the original before relying on the copy. `PGP ARMORED FILE` from `--enarmor` is an outer text wrapper; dearmor it before supplying it as the encrypted backup. Never display, email or commit a decrypted private PEM.

#### Upload an existing authority when the GitHub secret is missing

Use this after successful public authorization if upload was not completed. It authenticates the public authority, recovers the same backup, compares canonical public keys and sends only the dedicated boot private PEM through stdin. It refuses an existing secret: GitHub cannot reveal that secret for comparison, and its existence is not proof of a match. Do not rotate or overwrite it blindly. An explicit restoration of an existing secret must use this same recovered authorized authority.

```bash
(
  set -euo pipefail
  set +x
  umask 077
  export GPG_TTY="$(tty)"
  gpg-connect-agent updatestartuptty /bye
  python3 -I - <<'PY'
import runpy
runpy.run_path("tools/firmware.py")["verify_authority"]("security")
PY
  test "$(gh secret list --repo AndrewWestberg/pico2-kes-agent --json name \
    | jq '[.[] | select(.name == "PICO2_FIRMWARE_SIGNING_KEY_PEM")] | length')" = 0
  PRIVATE_DIR="$(mktemp -d /dev/shm/pico2-signing.XXXXXXXX)"
  trap 'rm -rf -- "$PRIVATE_DIR"' EXIT
  gpg --decrypt --output "$PRIVATE_DIR/key.pem" \
    "$HOME/.local/share/pico2-kes-signing/firmware-signing-key.pem.gpg"
  chmod 0600 "$PRIVATE_DIR/key.pem"
  openssl pkey -in "$PRIVATE_DIR/key.pem" -pubout -outform DER \
    -out "$PRIVATE_DIR/recovered.der"
  openssl pkey -pubin -in security/firmware-signing-public.pem -outform DER \
    -out "$PRIVATE_DIR/authorized.der"
  cmp "$PRIVATE_DIR/recovered.der" "$PRIVATE_DIR/authorized.der"
  gh secret set PICO2_FIRMWARE_SIGNING_KEY_PEM \
    --repo AndrewWestberg/pico2-kes-agent < "$PRIVATE_DIR/key.pem"
)
```

The personal GPG private key never leaves the local host. The signing workflow separately verifies that the uploaded boot key matches the authorization before publishing. Neither this upload nor a local bundle proves a cloud release ran.

### Build and sign a local manual-qualification bundle

Use a trusted checkout containing the four public authorization files, the pinned tools above and the existing encrypted boot-key backup. Commit the intended firmware/tool/public-authority changes first: `release.json.commit` identifies an exact source commit, not an uncommitted worktree. No private key belongs in that commit. The following creates a **local tag label only**; it does not create/push a Git tag, contact a device or publish a Release.

```bash
(
  set -euo pipefail
  set +x
  umask 077
  export GPG_TTY="$(tty)"
  gpg-connect-agent updatestartuptty /bye
  export PATH="$HOME/.local/share/pico2-kes-tools/install/bin:$PATH"
  git diff --quiet
  git diff --cached --quiet
  COMMIT="$(git rev-parse --verify HEAD)"
  OUT_DIR="$PWD/target/security-bundles/$COMMIT"
  test ! -e "$OUT_DIR"
  python3 - <<'PY'
import runpy
runpy.run_path("tools/firmware.py")["verify_authority"]("security")
PY
  PICO2_REQUIRE_FIRMWARE_AUTHORITY=1 cargo build --locked --release \
    --bin pico2-kes-agentd --bin pico2-kes-agent-cli
  PICO2_REQUIRE_FIRMWARE_AUTHORITY=1 cargo build --locked --release \
    -p pico2-kes-firmware --target thumbv8m.main-none-eabihf
  test -f target/otp-permissions/pico2-otp-permissions.elf
  PRIVATE_DIR="$(mktemp -d /dev/shm/pico2-signing.XXXXXXXX)"
  trap 'rm -rf -- "$PRIVATE_DIR"' EXIT
  gpg --decrypt --output "$PRIVATE_DIR/key.pem" \
    "$HOME/.local/share/pico2-kes-signing/firmware-signing-key.pem.gpg"
  chmod 0600 "$PRIVATE_DIR/key.pem"
  python3 tools/firmware.py seal \
    --elf target/thumbv8m.main-none-eabihf/release/pico2-kes-firmware \
    --permissions-helper target/otp-permissions/pico2-otp-permissions.elf \
    --tag "vqualification-$COMMIT" --commit "$COMMIT" \
    --key-file "$PRIVATE_DIR/key.pem" --out-dir "$OUT_DIR"
  python3 tools/firmware.py verify --bundle "$OUT_DIR"
  printf 'Verified local bundle: %s\n' "$OUT_DIR"
)
```

Build the permission helper with the preceding pinned-SDK recipe before running this block. If the output directory already exists, verify and reuse it or select a new output directory; never overwrite an existing qualification bundle or silently rotate the key. Keep the bundle intact when transferring it to the manual provisioning host. Verification requires Python, GPG/GPGV, OpenSSL and pinned picotool 2.3.1; it does not require USB device access. The runtime permission helper remains unsigned preparation-only code even though its digest is authenticated by the signed bundle.


### Release publication and provenance

The [release workflow](../.github/workflows/release.yml) builds without the production secret, then signs/publishes on a fresh runner. Both jobs check out the triggering event's exact `github.sha`. Only the signing step receives the dedicated private boot key; cleanup removes its temporary plaintext file. The [publisher](../tools/publish_release.py) checks the triggering tag/commit and resolves the tag again before publishing its verified uploaded draft.

`verify` authenticates manifest metadata but does not resolve GitHub tags. `seal --commit` accepts a supplied commit identifier and cannot independently prove which source produced an ELF. Establish the source-to-build-to-manifest relationship; do not label an uncommitted build with an unrelated commit. A local tag label does not create a Git tag or establish cloud publication.

Publication does not overwrite history. Identical completed releases are a no-op; different/partial assets or an existing draft require explicit maintainer handling. A failed upload may leave an unpublished draft. The publisher checks the triggering tag/commit and rechecks tag resolution before publishing; a locally verified bundle or checked-in workflow is not evidence that a cloud run succeeded.

### Secure-boot qualification

Secure-boot evidence is separate from `qualification/hardware.json`. A2 storage/USB qualification does not prove ROM signature enforcement; A4 must not inherit an A2 result. Until the attended measurements exist, secure-boot, negative-boot and key-preserving-update checks are **not observed**, not passed. Observed debug fuses and volatile locks are not an external SWD-denial test.

Software verification, without USB or production secrets:

```bash
PICO2_PERMISSIONS_HELPER="$PWD/target/otp-permissions/pico2-otp-permissions.elf" \
  python3 -m unittest discover -s tools/tests -p 'test_firmware.py'
cargo test --locked -p kes-protocol
cargo test --locked --test operator_cli --test service_lifecycle --test backup_restore
cargo test --locked -p qualification --bin qualification
```

**Disposable A2 hardware only, attended:** first prove correct signed UF2 boot/reinstall before final restrictions. Negative images must have valid bounded metadata: use a different ephemeral signing authority, then a payload bit changed after signing. Observe non-execution and restore the authorized full UF2 via physical MSD; do not claim that MSD refused its bytes. Never burn another boot key or rollback counter. Test interrupted beginning/middle/end copies separately, recover each with the complete verified UF2, and stop irreversible work if recovery fails.

For each actual firmware-version upgrade, compatible downgrade and interrupted-transfer/full-reflash scenario, populate at least two disposable pools, each with active and certified staged generations. Keep the same valid comparison period across the reboot, then advance only forward to activate the original staged generations. Stop the daemon before direct USB ownership. Do not use real cold keys, recipients, certificates, or signing periods.

Use the [operator workflow](../README.md#commission-and-configure) to prepare only disposable pool material. Set `OPS` to the private lab directory containing your actual public input files; create it outside the checkout and prepare the inputs described below before invoking a hardware fixture:

```bash
OPS="$HOME/pico2-kes-security-lab"
install -d -m 0700 "$OPS"
```

```bash
cargo run --locked -p qualification -- physical-context --preserve-update --input "$OPS/preservation-input.json"
cargo run --locked -p qualification -- security --input "$OPS/security-observations.json"
```

The preservation fixture input contains the original `device_id`, `identity_public_key`, `usb_serial`, `recipient_public_key`; `genesis_digest`, `network_magic`, `slots_per_period`, `lifetime`, `period`, `session`, `sequence`, `lease_seconds`, `publication_time_us`; `scenario` (`upgrade`, `downgrade`, `interrupted_beginning`, `interrupted_middle`, or `interrupted_end`); `before_bundle`, `after_bundle`, a distinct public `output` path; and `pools`, each with `pool_id`, `incarnation_id`, `active_certificate`, and `staged_certificate` paths. Certificate inputs are canonical CBOR operational-certificate bytes, not a private cold key or the 112-byte direct encoding. Use the original public certificate objects and installation records from the operator workflow.

Run from the repository root, with absolute bundle/input/certificate/output paths. Keep operator inputs/outputs outside the checkout (or generated evidence under `evidence/`); untracked files elsewhere contribute to the candidate dirty digest. Input requires **2–16 distinct pools**, each with an active generation and a certified staged generation whose start follows the comparison period. Hex fields are lowercase: device/incarnation/generation IDs 32 characters, pool IDs 56, public keys/genesis digest 64, serial 16. Use fresh context session/sequence values and valid lease/publication data from the controlled disposable fixture, not synthetic values on a real pool.

The CLI's public certificate JSON envelope or textual hex is **not** the fixture's binary certificate input. Convert each original public certificate's CBOR hex into a separate no-clobber binary file; the fixture subsequently checks canonical encoding, cold-key/pool binding and signature. This conversion creates no certificate or private key:

```bash
umask 077
python3 -I - "$OPS/active.opcert" "$OPS/active.opcert.cbor" <<'PY'
import json, pathlib, sys
source, destination = map(pathlib.Path, sys.argv[1:])
if source.stat().st_size > 16384:
    raise SystemExit("public certificate input too large")
text = source.read_text().strip()
encoded = json.loads(text)["cborHex"] if text.startswith("{") else text
data = bytes.fromhex(encoded)
if not 0 < len(data) <= 154:
    raise SystemExit("invalid operational-certificate byte length")
with destination.open("xb") as output:
    output.write(data)
PY
```

Repeat for both active/staged certificates of each pool, using distinct output names. Pass these binary CBOR files—not the JSON envelope, ASCII hex, installation receipt or 112-byte direct encoding—to the fixture.

The fixture verifies both bundles and requires distinct source commits/tags/image digests. It retains current KES bytes only in locked, zeroized process memory; it never logs or persists their plaintext or hashes. It checks nonce-pinned identity, same-period byte equality, public pool/generation/key/artifact/certificate bindings and floors, then exercises original staged activation. When prompted, use the existing operator workflow to replenish disposable staged generations without changing the recipient; the fixture verifies the newly generated signed artifact's recipient binding. The fixture does not generate keys, erase storage, recommission, or replace pins/journals. Installed-image identification is an attended operational observation of the verified UF2 transfer and native single-image boot, not independent hardware attestation.

Every scenario, **including interrupted-copy recovery**, requires distinct verified before/after manifests, source commits, tags and UF2 digests; a same-image reinstall is rejected. The fixture pauses while you perform the specified transfer; it does not perform or independently attest that transfer. On completion, each pool has advanced to the original staged start and must have an operator-replenished staged generation. Update certificate inputs and choose forward-only periods for the next scenario; never reuse the old comparison period after activation.

The `security` validator performs no device operations. Its strict version-1 input binds `candidate` commit/dirty identity, actual `chip` revision/ROM/serial, `tools`, public `artifacts` hashes, `pre_device`/`post_device`, and `checks`. The nine required names are `signed_boot`, `wrong_key_rejected`, `tampered_image_rejected`, `picoboot_disabled`, `debug_fuses_and_runtime_locks`, `msd_recovery`, `state_preserving_update`, `compatible_downgrade`, and `interrupted_update_recovery`. Each has an `outcome` (`pass`, `fail`, `not-observed`) and typed `observations`; a global success assertion is insufficient. Not-observed entries have no invented observations. Preservation observations include per-pool comparisons and activation records; interrupted recovery needs all three positions individually. Use the fixture's public observation, not guessed booleans. Input schemas are in [the validator](../qualification/src/security.rs) and [the attended fixture](../qualification/src/physical_security.rs).

The preservation output is a wrapper: put **its `.observation` member**, not the entire file, into the relevant check's `observations` array. Upgrade/downgrade require one observation each; interrupted recovery requires the beginning, middle and end observations individually. `before_security`/`after_security` are not drop-in `pre_device`/`post_device` values: the latter use a different strict schema including persistent identity and `bootkey_sha256`, and reject unknown fields. Assemble those values from actual public device/enrollment records using the schema linked above.

`candidate.commit` and `candidate.dirty` must be the checkout identity/digest from `evidence::candidate`, not `"clean"`, a boolean or ordinary Git status. The preservation wrapper provides `candidate_commit`/`candidate_dirty`; reuse them only if candidate source stayed unchanged. The validator checks supplied public observations and internal consistency and labels the report with that checkout identity. **It does not independently authenticate all physical claims, reopen signed bundles, or establish that measured image commits equal that candidate.** Separately retain the verified manifests, hashes, build provenance and actual transfer/boot observations tying the firmware being qualified to its intended source commit.

`security` exits 0 for accepted all-pass input. Exit 1 means either a valid nonpassing report or an error: inspect the report/diagnostics, not merely a printed pathname. Reports are atomically replaced at `evidence/<commit>-<dirty>/security/report.json`, not appended; archive earlier public reports separately. A2 observations leave A4 not observed. Keep `external_swd_denial_observed` false unless an actual external test occurred; the debug-fuses/runtime-locks check does not itself prove SWD denial. Missing observations and unsuccessful recovery remain blockers, never inferred passes.

