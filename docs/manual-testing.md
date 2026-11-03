# Manual RC-to-lifecycle test runbook

Use this in order, stopping at the first unexpected result. It covers publishing an RC, installing `p2kesup`, commissioning, every KES lifecycle command, and the remaining manager workflows. The [Q1–Q11 acceptance procedure](../specs/002-manage-kes-agent/quickstart.md#q1--bootstrap-reopen-and-absentpartial-inventory) defines the larger acceptance matrix; this guide supplies the concrete operator sequence.

**An authenticated RC is not a qualified release.** These are attended tests on disposable hosts and keys. Do not use production pools, erase an existing device to make it eligible, bypass a refusal, or promote this candidate merely because the happy path works. The previous [development acceptance report](../evidence/p2kesup/development-f23486803f9d2c730a4c943d6c32cdead361bfe9/acceptance.md) records outstanding gates, not evidence for a newly built RC.

## 0. Prepare the hosts, inputs and evidence

| Location | What belongs there |
|---|---|
| Maintainer workstation | Trusted source checkout and Git/GitHub CLI for tagging and release review |
| Disposable primary | Debian 12, Ubuntu 24.04 or Ubuntu 26.04 **x86-64**, systemd/udev, attended terminal, sole attached test device, public inputs, encrypted artifacts and receipts |
| Isolated backup host | Same supported installation platform; no primary configuration/state, daemon or device; recipient private material and restored test key |
| Offline cold-key host | Disposable pool cold signing key, authoritative issuance counter, matching Cardano CLI; never transfer those private inputs to primary |

The maintainer workstation is not required to be the primary. **Ubuntu 26.04 is an installation target for releases containing the Ubuntu 26.04 support change.** RC.13 and earlier retain their original installer and signed-manifest restrictions: publish a new RC containing this change, then use that tag instead of the older examples below. Updating only the launcher cannot authorize an old bundle for a new OS. Existing unregistered files, service accounts/groups and state can still intentionally block a managed install; use a clean disposable host or a separately reviewed migration, not blind deletion/adoption.

Before beginning, obtain:

- For optional independent/offline verification, an independently authenticated project OpenPGP certificate/keyring. The normal one-command installer needs no manually obtained assets or keyring.
- An eligible disposable Pico 2 and the hardware/tool/image evidence required by its selected operation. The accepted A2/storage record is in [qualification/hardware.json](../qualification/hardware.json); it is not blanket qualification for another board. A4 remains physically unverified. Use a genuinely blank compatible board for commissioning. A populated board must retain its existing identity and use the maintenance path.
- An existing disposable pool's **public** cold verification-key envelope, trusted Byron and Shelley genesis files, their actual network transition count, and correct UTC time. Keep the cold signing key/counter offline.
- For normal mode, the actual `cardano-node.service` deployment and unchanged host-memory policy. A dummy unit is not a substitute. Commissioning alone can run without Cardano, but normal-mode lifecycle testing cannot bypass that preflight. Keep a standby/test producer fenced from production forging.
- For whole-release acceptance, a second explicitly compatible authenticated bundle, a separate approved performance baseline, and the additional physical/cohort prerequisites in the quality contract. These are not prerequisites to simply publishing an unqualified RC.

Use Bash for the command blocks. Run them individually in the stated location; this document is **not** one unattended script. Stop on a nonzero exit unless the step explicitly expects a rejection. Never capture a complete terminal session containing recipient passphrases or private outputs. Public evidence can include versions, public status, receipt paths, hashes, expected/actual results and timings.

## 1. Check GitHub release signing before creating the tag

**Maintainer workstation, trusted checkout root.** The workflow is [release.yml](../.github/workflows/release.yml), named `signed-firmware-release`. Pushing a `v*` tag builds both host executables and firmware; a firmware-only historical release is not a manager distribution.

```bash
REPO=AndrewWestberg/pico2-kes-agent
gh auth status
gh secret list --repo "$REPO"
gh secret list --repo "$REPO" --env release-signing
```

Inspect **Settings → Environments → release-signing** and the applicable tag rules. Confirm authorized reviewers, tag deployment restrictions and these existing capabilities:

| Secret | Used for |
|---|---|
| `PICO2_FIRMWARE_SIGNING_KEY_PEM` | Existing secp256k1 key, in firmware sealing, distribution signing and later metadata promotion |

No PGP private-key secret belongs in GitHub. Before tagging, ensure the separately authorized public `security/distribution-authority.json` and its `.asc` signature are committed; see [local distribution authorization](maintainer-security.md#authorize-distribution-signing-locally). Routine releases reuse that authorization. The signing jobs validate it and use the existing protected PEM; human qualification approval remains separately locally PGP-signed. Do not paste private keys into logs, upload a personal/cold key, rotate the firmware authority or weaken verification to make a job green. Secret-list output proves only that a named secret exists.

The workflow source does not prove GitHub environment/ruleset settings. Publication jobs need `contents: write`; build jobs do not need production secrets. Keep both approval boundaries intact.

The original `v0.1.0-rc.12` workflow required a missing PGP secret and cannot gain this source-level signing change by rerunning. Commit the authorization and verifier/workflow cutover, then use a new immutable RC tag (for example `v0.1.0-rc.13` if unused); do not move `v0.1.0-rc.12`. Substitute that actual new tag in the examples below.

## 2. Commit the intended source and create a new immutable RC tag

**Maintainer workstation.** Commit all intended implementation and documentation changes before tagging; do not commit recipient keys, restored keys, cold keys or private signing backups. The installer/upgrade changes must be in the tagged source, not merely the runbook. Publish the reviewed launcher to the repository's default branch before advertising the default-branch curl URL.

Then check the source and remote tags:

```bash
set -euo pipefail
REPO=AndrewWestberg/pico2-kes-agent
git status --short
test -z "$(git status --porcelain)"
git tag --list 'v*' --sort=-version:refname
git ls-remote --tags origin 'refs/tags/v0.1.0-rc.*'
```

At the time this guide was written, the latest **local** tag was `v0.1.0-rc.11`. Choose the next unused tag after checking the remote; the following is an example, not a reservation:

```bash
RC_TAG=v0.1.0-rc.12
SOURCE_COMMIT=$(git rev-parse --verify HEAD)
printf 'RC=%s\nSOURCE=%s\n' "$RC_TAG" "$SOURCE_COMMIT"
git tag -a "$RC_TAG" "$SOURCE_COMMIT" -m "$RC_TAG"
git push origin "refs/tags/$RC_TAG"
```

Never force-push or reuse an existing tag. The workflow triggers on `v*`; use conventional `v<version>-rc.<number>` spelling. A hyphen makes the signed release channel `prerelease`; candidate distribution publication is a GitHub prerelease, not latest. Keep the full source commit with your test evidence.

If code must change after a failure, commit the fix and choose a new RC. Do not relabel an old build with a new source commit or overwrite partial historical assets.

## 3. Watch the correct build and approve its signing jobs

```bash
gh run list --repo "$REPO" --workflow release.yml --event push \
  --branch "$RC_TAG" --json databaseId,headSha,status,conclusion,url
```

Select the run whose `headSha` equals `SOURCE_COMMIT`. If the tag filter shows nothing, inspect the workflow's Actions page/list without that filter; do not choose an unrelated successful run.

```bash
: "${RUN_ID:?Set the numeric workflow run ID for this tag and source commit}"
gh run watch "$RUN_ID" --repo "$REPO" --exit-status
gh run view "$RUN_ID" --repo "$REPO" \
  --json headSha,status,conclusion,jobs,url
```

Approve the `release-signing` environment when its reviewed job waits for you. Expected progression:

1. `host-build`: Debian 12 host binaries, patched picotool and runtime inventory.
2. `build`: firmware/host checks, native tool checks and unsigned firmware.
3. `seal-firmware`: firmware signing with the existing delegated authority.
4. `prepare-distribution`: combine authenticated firmware, host binaries, tools and deployment assets.
5. `sign-distribution`: verify the public delegation and sign exact metadata and bootstrap with the existing secp256k1 key.
6. `publish-candidate`: verify, publish and download/compare the immutable assets.

A green firmware build alone is insufficient. Require successful `publish-candidate`, correct source identity and a published, non-draft RC. If a run fails, inspect its actual error, preserve its URL and stop. A failed upload may leave a draft that requires explicit maintainer handling; do not delete/recreate it or repeatedly rerun signing as a generic repair.

## 4. Confirm the complete candidate publication

**Maintainer workstation.** Confirm the intended immutable RC and source commit in the release and workflow; the candidate is a GitHub prerelease and not latest. Do not use it on production hosts. Normal installation downloads the required assets itself; independent verification and offline preparation remain optional maintainer procedures in the [security guide](maintainer-security.md).

The launcher is trusted from the project's HTTPS-hosted default branch. This initial trust is separate from the pinned OpenPGP distribution delegation and domain-separated secp256k1 signatures on downloaded payloads. A signed candidate is not release qualification.

## 5. Run the authenticated installer on the disposable primary

**Primary, ordinary operator account, real terminal at least 80×24.** No project source checkout or build toolchain is needed. Replace the example with the actual tag from step 2:

```bash
curl -fsSL https://raw.githubusercontent.com/AndrewWestberg/pico2-kes-agent/master/install.sh | sh -s -- --version v0.1.0-rc.12
```

Default installation without `--version` selects the latest qualified stable release, not this RC. Review the candidate status, exact tuple, dependencies, paths, privilege and service effects; approve only on the disposable host. The installer offers reviewed missing packages via the trusted OS apt channel. Declining or failed installation blocks the dependent action. Confirmations use `/dev/tty` despite the pipe; without an interactive terminal mutation must be refused. Non-root privilege handoffs use `sudo` in that terminal, including over SSH with a terminal allocated; no GUI or polkit agent is required. The account needs sudo authorization. If sudo is absent, have an administrator install it or run the installer from a root terminal. Do not run the ordinary TUI as root or pipe passwords.

Sudo may reuse its normal terminal authorization cache; expiry or site policy can require another terminal password prompt. Typed package, candidate and exact-plan approvals remain separate and mandatory. The manager suspends its TUI for authentication and resumes afterward; it does not capture passwords, enable askpass, alter sudoers or keep credentials alive. Select a new release containing this terminal-authentication change: replacing only the launcher does not change an older bundled manager's authentication behavior.

The installer directly installs the persistent host command after approval; hardware setup is separate. Retain the displayed original operation/plan record for interruption recovery. Reopen the normal manager and check installed versions:

```bash
command -v p2kesup pico2-kes-agent-cli pico2-kes-agentd
p2kesup --version --json
pico2-kes-agent-cli --version --json
pico2-kes-agentd --version --json
p2kesup
```

Versions/source/build IDs must match the signed candidate, not `development-unqualified`. Installed version and running process version are separate observations.

Navigation: Tab/Shift-Tab changes screens; arrows or j/k select; Enter opens/reviews; Esc backs out; `r` refreshes; `?` helps. In a field, Tab changes field, Enter advances, Backspace edits; fields are not shell-expanded, so paste `/home/operator/...`, **not** `$OPS/...` or `~/...`. Review all text before typing confirmation. `q` inside a text field is a character, not a general cancel key.

## 6. Grant access and enforce host policy

After managed installation creates its account/group, grant only intended operators full lifecycle authority:

```bash
sudo usermod -aG pico2-kes-agent "$(id -un)"
```

Start a **new login session**, check `id`, and reopen with `p2kesup`. Existing shells do not acquire new supplementary groups automatically. Do not make sockets world writable or run ordinary operations as root. The real producer service account also needs controlled group access and a controlled restart to pick it up; follow [host access](../README.md#host-access-and-usb-inspection).

Before commissioning, follow [host memory policies](../README.md#enforce-host-memory-policies-first): no active swap or reboot reactivation; all four sleep targets masked; agent core/swap limits; OS crash-dump prevention; actual hypervisor/snapshot policy; private backup material off-primary. Review RAM capacity before disabling swap. A checkbox or acknowledgement file does not enforce these settings.

Use the README's guarded commissioning acknowledgement-file procedure, then check:

```bash
cat /proc/swaps
systemctl is-enabled sleep.target suspend.target hibernate.target hybrid-sleep.target
systemctl show pico2-kes-agentd.service --property=LimitCORE --property=MemorySwapMax
sudo /usr/libexec/pico2-kes-agent-host-check --commission
```

For normal operation, apply the supplied drop-in to the actual `cardano-node.service` through **Producer hardening → Install producer memory hardening**, review the restart/disruption, and follow the normal-mode acknowledgements/preflight in the README. Other unit names do not change the literal preflight constraint. Never create a dummy node unit or weaken preflight to make this test pass. Host-wide security-policy edits are deliberate administrator actions, not automatic setup behavior.

## 7. Install firmware, or retain an existing compatible blank application

**Primary, one intended physical board.** Keep all unrelated boards disconnected during target selection.

Setup preselects the installed release's retained authenticated source directory. Accept that default; no separate asset download or unpack is needed. RC source reuse still requires deliberate candidate acceptance and signature verification.

- **Factory/BOOTSEL-only board:** Setup → **Factory-only firmware install / original record (skip compatible blank app)**. Review the new original record, authenticated image and exact physical BOOTSEL/mount association. Preview first; then follow the foreground tool's attended apply/physical instructions. It may write firmware only in `[0x10000000,0x10100000)` and must preserve `[0x10100000,0x10308000)`. Do not manually copy a different UF2, select by volume label alone, erase flash or run a competing USB tool.
- **Already running compatible blank application:** skip transfer and proceed to its restricted-daemon blank/build observation.
- **Already commissioned/populated device:** do not use either blank setup path. Retain the original pin/config/journal and use a separately authorized compatible maintenance operation. Missing identity files do not make a device factory-new.

Retain the original first-install tool record and manager plan. A completed copy/flush alone does not prove application readiness. On interruption choose **Reconcile original first install with attended blank-application evidence**, after restoring the admitted observation setup below; never start a new record to hide uncertainty.

Obtain the actual application's 16-character lowercase serial through the documented [USB inspection](../README.md#host-access-and-usb-inspection). A BOOTSEL identifier is not an application identity. Required qualification/admission failures are stop conditions, not reasons to fall back to raw copying.

**Optional OTP branch goes here, before commissioning.** The normal lifecycle test leaves OTP declined. See step 20 for the separately qualified irreversible procedure; it cannot be added after populating the board without destroying the premises of that procedure.

## 8. Start restricted commissioning and commission exactly once

**Primary, ordinary operator.** Create a new private workspace; keep it across terminal sessions:

```bash
set -euo pipefail
umask 077
OPS="$HOME/pico2-kes-ops-$RC_TAG"
mkdir -m 0700 "$OPS"
: "${USB_SERIAL:?Set the intended application serial: 16 lowercase characters}"
```

Save the complete [commissioning configuration template](../README.md#operator-workspace-and-commissioning-mode) as `$OPS/commission.json`, replacing its serial. It has no pin, networks or pools. In `p2kesup`:

1. **Setup → Review/install explicit commissioning configuration**; select that absolute file and inspect the exact diff.
2. **Start restricted commissioning service**; require the intended compatible blank application through the sole daemon.
3. If needed, resolve the **original** first-install record with the fresh blank/build evidence.
4. **Commission intended blank application**; review serial, blank admission, receipt and unused public output path such as `$OPS/device.json`; confirm once.
5. Archive the public enrollment record and original receipt off-primary. It is a pin obtained through attended trust, not independent hardware attestation.

**Interface rule for the rest of this guide:** the recommended pass uses the named TUI action. The CLI blocks are equivalent standalone command tests, **not commands to run again after doing the same mutation in the TUI**. Choose one interface per mutation. For TUI results, set shell variables from the observed public IDs/receipts, or recover them with read-only status; do not repeat a mutation merely to populate a shell variable. A later independent CLI pass needs new disposable identities and unique receipts.

Equivalent commission, only if it has **not** already been submitted:

```bash
pico2-kes-agent-cli --json device commission --usb-serial "$USB_SERIAL" \
  --expected-revision 0 --receipt "$OPS/commission.receipt.json" \
  --out "$OPS/device.json"
```

On lost output/uncertainty, preserve that receipt and use **Operations → Reconcile an original receipt** in the same restricted serial-bound mode, with an unused output path if the public record needs recovery. Do not require the now-commissioned board to become blank again or submit a second commission.

## 9. Install the normal pin/network configuration

Read public identity from the enrollment record:

```bash
DEVICE_ID=$(jq -er '.device_id' "$OPS/device.json")
IDENTITY_PUBLIC_KEY=$(jq -er '.identity_public_key' "$OPS/device.json")
USB_SERIAL=$(jq -er '.usb_serial' "$OPS/device.json")
```

Create `$OPS/config.json` using the complete [normal configuration template](../README.md#normal-configuration-and-trusted-context): insert the returned identity/key/serial, actual network alias, trusted absolute Byron/Shelley genesis paths, actual transition epoch count, SHA-256 of the **exact Shelley file bytes**, and context lease. Initially `pools: []` is valid. Do not copy zero IDs, mainnet transition `208`, or a sample network's magic into another network. Genesis files must be service-readable outside `/home`/`/tmp`; keep the candidate itself in your private workspace for manager review.

Check correct UTC and independently trusted network timing before exposing keys to context. Advancing a test host clock or supplying incorrect genesis can irreversibly evolve/expire keys; never accelerate production time to shorten a test.

Through Setup:

1. **Stop restricted commissioning service**.
2. **Review/install explicit normal configuration and pin**; inspect the exact candidate/diff.
3. Complete the real normal-mode node/host policy prerequisites from step 6.
4. **Start normal service (existing preflight still applies)**.

Use manager configuration actions rather than manually replacing managed files or deleting systemd overrides. Check:

```bash
systemctl status pico2-kes-agentd.service
pico2-kes-agent-cli --json status
pico2-kes-agent-cli --json host observe
pico2-kes-agent-cli --json device info
pico2-kes-agent-cli --json device security
pico2-kes-agent-cli --json device inventory
pico2-kes-agent-cli --json pool list --page-size 16
```

Expected: exact pinned identity and selected firmware; normal-mode observations; truthful empty membership only if the authenticated complete inventory is empty. Host `pool list` alone is not authoritative device absence. `host observe` and `pool list` are paged: follow their returned cursor (and host snapshot ID) until completion; use **Operations → List complete device inventory and host bindings** for the manager's complete join.

## 10. Install the backup-role manager and create a recipient off-primary

**Isolated backup host.** Repeat steps 4–5's public verification/installation, but execute the verified installer with:

```bash
curl -fsSL https://raw.githubusercontent.com/AndrewWestberg/pico2-kes-agent/master/install.sh | sh -s -- --version v0.1.0-rc.12 --role backup
```

Review the candidate and direct backup-role installation on this disposable host, then reopen:

```bash
p2kesup --role backup
```

No daemon/device or configured primary state may be present. Disable swap and process dumps before secret handling; keep protections in effect throughout. The role check also refuses inaccessible evidence, not just detected primary state. Local admission cannot prove this host's history.

Create a new protected backup workspace:

```bash
set -euo pipefail
umask 077
BACKUP_OPS="$HOME/pico2-kes-backup-$RC_TAG"
mkdir -m 0700 "$BACKUP_OPS"
RECIPIENT_KEY="$BACKUP_OPS/recipient.private"
RECIPIENT_PUBLIC="$BACKUP_OPS/recipient.public.json"
```

Select **Backup host → Create protected backup recipient**. Approve the finite local privileged role/process inspection before private-path forms and again before the child; it does not connect to the primary/daemon/device. Enter the two absolute output paths. The foreground CLI, not a TUI field, asks for the passphrase. Do not record, pipe, tee or put it in argv/environment.

Equivalent **backup-host-only** CLI test:

```bash
pico2-kes-agent-cli recipient create \
  --out "$RECIPIENT_KEY" --public-out "$RECIPIENT_PUBLIC"
```

Expected: new protected private file and public JSON, no overwrite. Transfer **only `recipient.public.json`** to primary `$OPS/recipient.public.json`. Keep the private file/passphrase off-primary even for disposable tests.

## 11. Install the public recipient and enroll a pool

**Primary.** Public inputs and their immediate parent must be operator-owned and not group/world writable. Copy transferred files into `$OPS` as the operator. Do not ask the CLI to publish into root-owned `/etc`.

TUI: **Operations → Install / rotate public recipient**. Supply the public file and new receipt path. Review fresh device identity/revision. Equivalent:

```bash
RECIPIENT_PUBLIC="$OPS/recipient.public.json"
DEVICE_STATUS=$(pico2-kes-agent-cli --json status)
DEVICE_REV=$(jq -er '.result.revision' <<<"$DEVICE_STATUS")
RECIPIENT_RESULT=$(pico2-kes-agent-cli --json recipient set \
  --public-key "$RECIPIENT_PUBLIC" --expected-revision "$DEVICE_REV" \
  --receipt "$OPS/recipient-set.receipt.json")
printf '%s\n' "$RECIPIENT_RESULT"
```

TUI: **Enroll supplied public cold verification key**. Supply the disposable pool's public cold-vkey envelope and the exact configured network alias. Equivalent:

```bash
NETWORK=pool-network    # must be the actual alias in your normal configuration
COLD_VKEY="$OPS/cold.vkey"
DEVICE_STATUS=$(pico2-kes-agent-cli --json status)
DEVICE_REV=$(jq -er '.result.revision' <<<"$DEVICE_STATUS")
ENROLL_RESULT=$(pico2-kes-agent-cli --json pool enroll \
  --cold-vkey "$COLD_VKEY" --network "$NETWORK" \
  --expected-revision "$DEVICE_REV" --receipt "$OPS/enroll.receipt.json")
printf '%s\n' "$ENROLL_RESULT"
POOL=$(jq -er '.result.pool_id' <<<"$ENROLL_RESULT")
INCARNATION=$(jq -er '.result.incarnation_id' <<<"$ENROLL_RESULT")
pico2-kes-agent-cli --json pool status --pool "$POOL"
pico2-kes-agent-cli --json pool list --page-size 16
```

Do not pipe a mutation into `jq` or hide its exit status. Every mutation gets a new receipt; uncertainty reuses the original receipt, not a new request. IDs: pool is 56 lowercase hex characters, not `pool1...`; device/incarnation/generation IDs are 32 hex characters. Save exact returned IDs.

**Required before readiness:** obtain this pool's `socket_path` from the complete list; add `{pool_id, incarnation_id, socket_path, network}` to a normal configuration candidate. Use **Service → Review/validate supplied configuration candidate**, review/cancel once, then validate/apply and separately **Restart managed agent**. Enrollment/journal reconstruction alone does **not** start a context poller for a pool absent from startup configuration. Never substitute the management socket for the pool delivery socket.

## 12. Generate, inspect and export the first generation

TUI: **Operations → Create staged generation**. Review exact pool/incarnation and fresh pool revision. Equivalent:

```bash
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
GENERATE_RESULT=$(pico2-kes-agent-cli --json key generate \
  --pool "$POOL" --incarnation "$INCARNATION" \
  --expected-revision "$POOL_REV" --receipt "$OPS/generate.receipt.json")
printf '%s\n' "$GENERATE_RESULT"
GENERATION=$(jq -er '.result.generation_id' <<<"$GENERATE_RESULT")
pico2-kes-agent-cli --json pool observe --pool "$POOL" --incarnation "$INCARNATION"
```

Expect one staged generation with encrypted backup/activation intent durably created. It may be awaiting certificate/context; generation success is not readiness. A second generation cannot overwrite an occupied staged slot.

TUI: **Export public verification key**, then **Export encrypted artifact**, each with the same exact generation and a new absolute destination. Equivalent:

```bash
KES_VKEY="$OPS/first-kes.vkey"
ARTIFACT="$OPS/first-kes.backup"
pico2-kes-agent-cli key verification-key --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --out "$KES_VKEY"
pico2-kes-agent-cli key export --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --out "$ARTIFACT"
stat -c '%a %U %n' "$KES_VKEY" "$ARTIFACT"
```

Expect owner-only, no-clobber outputs; the vkey is a Cardano `KesVerificationKey_ed25519_kes_2^6` envelope, the backup is encrypted ciphertext. Export/archive before activation/replacement/expiry/discard/delete can retire retrieval. Keep the original vkey envelope, not just extracted hex. Archive the artifact, public device record, pool/incarnation/generation IDs, receipts and eventual certificate off-primary, associated with the correct recipient.

## 13. Issue the operational certificate offline and install it

Obtain and independently verify the intended **absolute** start KES period from actual network slot/genesis information: integer `current_slot / slotsPerKESPeriod`. Do not use relative evolution age or guess from wall time. Transfer only the public vkey and checked period information to the cold host.

**Offline cold-key host**, existing disposable key/counter, matching CLI/era:

```bash
set -euo pipefail
umask 077
COLD_OPS="$HOME/pool-cold"
KES_VKEY="$COLD_OPS/first-kes.vkey"
COLD_SKEY="$COLD_OPS/cold.skey"
COUNTER="$COLD_OPS/cold.counter"
OPCERT="$COLD_OPS/first.opcert"
ERA=conway             # select the era supported by your actual CLI/network
: "${START_PERIOD:?Set the independently verified absolute start period}"
cardano-cli "$ERA" node issue-op-cert --kes-verification-key-file "$KES_VKEY" \
  --cold-signing-key-file "$COLD_SKEY" \
  --operational-certificate-issue-counter-file "$COUNTER" \
  --kes-period "$START_PERIOD" --out-file "$OPCERT"
```

Preserve the updated authoritative counter. Do not reset it or issue another certificate merely because a transfer timed out. Transfer only the resulting public certificate back to primary `$OPS/first.opcert`, and add it to the off-primary archive.

**Primary**, TUI **Operations → Install matching public certificate**; equivalent:

```bash
OPCERT="$OPS/first.opcert"
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
CERTIFICATE_RESULT=$(pico2-kes-agent-cli --json certificate install \
  --pool "$POOL" --incarnation "$INCARNATION" --generation "$GENERATION" \
  --certificate "$OPCERT" --expected-revision "$POOL_REV" \
  --receipt "$OPS/certificate.receipt.json")
printf '%s\n' "$CERTIFICATE_RESULT"
pico2-kes-agent-cli --json pool status --pool "$POOL"
pico2-kes-agent-cli --json pool observe --pool "$POOL" --incarnation "$INCARNATION"
```

Expect signature/binding/counter/timing validation. A future certificate remains staged until eligible. With valid context and timing, activation is automatic after required cleanup. There is **no `activate` command, backup-approval command, plaintext export or device key-import command**.

For actual producer delivery, use the separate existing [Cardano-node connection procedure](../README.md#connect-cardano-node) with the returned per-pool socket and certificate, replacing—not combining with—an old `--shelley-kes-key` source. Fence any previous producer before cutover. `p2kesup` does not discover/configure/connect to nodes. A ready pool or successful command does not prove peer-accepted blocks.

## 14. Observe evolution, rotate generations and discard a staged generation

In **Pools**, inspect both slots, certificate start/expiry, absolute/relative period, remaining validity and context source/age; compare with `pool status` and `pool observe`. Wait for a real network KES boundary to observe forward evolution. Do not alter the host clock, genesis or durable floors to speed it up. Evolution is automatic, not another CLI mutation.

Before active expiry, repeat steps 12–13 with **new receipt and output filenames**, a fresh generation ID and the next properly issued certificate. Keep the old and new archive identities separate. The active generation must remain until a valid replacement can activate; future staging must not replace it early. Keep the producer's startup certificate current for future restarts; ordinary evolution/rotation is not a reason to send SIGHUP or restart a node.

To test discard safely, generate a further disposable **uncertified staged** generation once the staged slot is free; archive it first. Cancel **Discard exact staged generation** once and verify unchanged state. Then approve the exact staged target. Set `STAGED_GENERATION` to that generation, not your active one. Equivalent:

```bash
: "${STAGED_GENERATION:?Set the exact disposable staged generation ID}"
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
pico2-kes-agent-cli --json key discard --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$STAGED_GENERATION" --expected-revision "$POOL_REV" \
  --receipt "$OPS/discard.receipt.json"
```

Answer the actual interactive confirmation; do not add `--yes` for this manual test. Active state must remain unchanged. If activation raced the request, `target_not_staged` is a reason to inspect the original target, not redirect the destructive operation. Discard ends device retrieval and does not revoke exported copies.

## 15. Rotate the public backup recipient

On the **backup host**, create another recipient with new private/public paths, such as `recipient-2.private` / `recipient-2.public.json`. Never overwrite the old private file. Transfer only the new public record to primary.

Use **Install / rotate public recipient** or step 11's `recipient set`, with the new public file, a freshly observed **device** revision and a new receipt. Generate a future generation only after the change. Verify its artifact's public recipient binding in the operation/review evidence. Existing ciphertext remains bound to the old recipient; it is not re-encrypted or revoked. The restore tests below should retain both recipients and their matching artifacts.

## 16. Exercise receipt discovery and reconciliation

First rehearse read-only discovery: **Operations → Discover and inspect original operation receipts**. Record the exact original path, operation ID, request digest, target and result. A manager reference is not a substitute for the CLI receipt.

For a qualification-controlled interrupted **non-OTP** lifecycle submission on disposable state, terminate only the manager after submission but before final display. Do not kill the daemon or unplug storage merely to test a lost UI response. The result may already be committed; reopening must not invent a retry.

TUI: **Reconcile an original receipt**. Equivalent:

```bash
: "${RECEIPT:?Set the absolute original receipt file path}"
pico2-kes-agent-cli --json operation reconcile --receipt "$RECEIPT"
```

For original commissioning-record output recovery only, use an unused destination:

```bash
pico2-kes-agent-cli --json operation reconcile \
  --receipt "$OPS/commission.receipt.json" --out "$OPS/device-recovered.json"
```

Commissioning recovery uses the original restricted serial-bound authority even if the mutation committed and no normal pin was installed. It does not require another blank admission. For normal operations retain normal pinned authority.

| Exit | Meaning / next step |
|---|---|
| 0 | Observe the successful result; still distinguish pool readiness from command success |
| 2 | Fix invalid invocation/input before a fresh intended operation |
| 3 | Resolve permissions without broadening access indiscriminately |
| 4 | Establish actual daemon/device availability; inspect whether a receipt exists |
| 5 | Inspect the authoritative rejection and refresh target/revision |
| 6 | Pending/uncertain: retain and reconcile the **original** receipt |
| 7 | Local failure: inspect receipt and output state; absence of an output does not undo a committed mutation |

A genuine storage-uncertainty recovery is different from a lost UI response. Follow the owning [reconciliation procedure](../README.md#reconciliation) and retained record's device-recovery instructions; do not apply a generic power-cycle/reset to OTP or every error. Never edit a receipt, reuse an operation ID with changed arguments, truncate the journal or restore old flash/journal snapshots.

## 17. Restore locally on the isolated backup host

Transfer only the encrypted artifact and its public verification bundle from primary. Verify the independently archived device identity and exact archived pool/incarnation/generation/vkey/recipient association; do not obtain a replacement identity from an untrusted artifact alone.

TUI: **Backup host → Restore encrypted backup locally**; approve local role admission and enter the exact evidence/private-file **paths**, never private contents. Equivalent backup-host-only CLI:

```bash
DEVICE_RECORD="$BACKUP_OPS/device.json"
DEVICE_ID=$(jq -er '.device_id' "$DEVICE_RECORD")
: "${POOL:?Set archived pool ID}"
: "${INCARNATION:?Set archived incarnation ID}"
: "${GENERATION:?Set the archived generation ID, not a later rotated generation}"
pico2-kes-agent-cli restore --artifact "$BACKUP_OPS/first-kes.backup" \
  --recipient-key "$BACKUP_OPS/recipient.private" --device-identity "$DEVICE_RECORD" \
  --device "$DEVICE_ID" --pool "$POOL" --incarnation "$INCARNATION" \
  --generation "$GENERATION" --verification-key "$BACKUP_OPS/first-kes.vkey" \
  --out "$BACKUP_OPS/restored-kes.skey"
stat -c '%a %U %n' "$BACKUP_OPS/restored-kes.skey"
```

Expect a new mode-0600 conventional `KesSigningKey_ed25519_kes_2^6` file. Do not print or attach its contents. No daemon, device or primary connection is needed. Repeat with wrong recipient/passphrase, tampered artifact, missing/mismatched public identity and an existing output path: none may publish/replace a key. Use separate disposable input copies and new output destinations, preserving original evidence. Do not deliberately enable swap while private material is in memory; perform unsafe-policy refusal checks in a separate clean session before any private input.

Restoration reconstructs generation-time state; it neither extends the certificate lifetime nor revokes other copies. It never imports a key into Pico2. Actual backup producer failover requires separate fencing and the [existing failover procedure](../README.md#offline-restoration-and-failover); do not start a second producer as part of a restore smoke.

Format/permissions alone do not satisfy the inherited [independent backup-fidelity gate](../specs/001-pico2-kes-agent/contracts/backup.md). That gate compares disposable generation-time state using the pinned independent decoder; retain its real qualification result separately, never extract production plaintext just to manufacture a reference.

## 18. Exercise remaining host/manager behavior before deletion

Use the actual UI, not just CLI success, for these cases:

1. **Overview/Pools:** compare installed vs running builds and complete inventory; inspect the last pool/unmatched bindings. Temporarily deny/disconnect only under the disposable scenario; stale/unavailable must appear with last-success evidence within 10 seconds, not healthy/zero. Local navigation must work without release networking.
2. **Service:** cancel then perform reviewed start/stop/restart; observe the exact service state and running build. Uptime is not delivery/forging. Test an invalid configuration candidate and verify working bytes/mode/owner remain unchanged; apply a valid candidate only after exact diff/service-identity validation, then separately approve restart.
3. **Diagnostics:** inspect bounded public history; export to a new absolute protected path. Check mode 0600, inspect public-only content, record its hash, then request the same destination and verify no-clobber refusal/unchanged hash. Do not include private child traffic in a report.
4. **Original host recovery:** after an admitted interrupted service/config operation, use **Inspect original host operation and actual state** then **Reconcile original service/configuration outcome without replay** with the original operation ID/digest. It must not silently repeat a restart/configuration write.
5. **Producer hardening:** operator supplies one actual disposable concrete `.service` name; inspect `/etc/systemd/system/<unit>.d/pico2-kes-memory.conf`, reload result and separately approved restart or deferral. Stopped services must not start. Test invalid `../escape.service` and cancellation before any changes. Preserve unrelated drop-ins. Recovery uses **Recover original producer batch**, the original ID/digest and fresh review; never a new batch to hide partial results.
6. **Keyboard/terminal:** rerun the applicable selection/review/error paths with `NO_COLOR=1 p2kesup`; resize below/above 80×24, cancel fields, complete/fail/cancel foreground handoffs, and inspect restored echo/cursor/terminal state. Nonterminal invocation must refuse interactive mutation. Never repeat OTP writes or record passphrase sessions merely for accessibility.

For performance/capacity acceptance, repeat the setup with 64 distinct disposable pools and the required 64 active/64 staged workload, then verify enrollment 65 is rejected without eviction. Measure the 5-second overview/10-second full inventory/10-second loss bounds with the approved instrument. A single-pool run or host model is not that reading. Follow the existing [baseline and sensitivity procedure](../specs/002-manage-kes-agent/contracts/quality.md#required-project-performance-gate); do not invent a zero baseline or accelerate clocks. Your own manual pass does not substitute for the fixed five-person uncoached cohort.

## 19. Test host and firmware maintenance with explicitly compatible bundles

One fresh RC is enough for initial setup/lifecycle testing, **not proof of upgrade/downgrade**. Keep the original authenticated bundle, pin, configuration, journal and operation records. Record complete public pre-state before changes.

1. With a second authenticated RC, run `p2kesup upgrade --version v0.1.0-rc.12`, replacing the example with its actual tag. Review candidate admission on the disposable host. The default `p2kesup upgrade` selects latest qualified stable; `p2kesup upgrade --bundle /absolute/new-RC-bundle` selects an offline bundle. The installed role is inferred.
2. Review the complete signed host and firmware tuple, service disruption, physical prerequisites and pre-state. The coordinated update does not authorize arbitrary mixed tuples. Preserve stopped service state unless explicitly approving temporary validation.
3. Attend any firmware transfer on the exact pinned board, following the foreground BOOTSEL, verified mount, flush and reconnect instructions. Require the selected live build, original identity and retained state; copy success alone is incomplete. Compare config, pin, journal, recipients and pool/generation continuity, allowing only explained forward lifecycle transitions.
4. Repeat the selected upgrade and verify the already-installed tuple is a no-op. For an admitted interruption, retain the original plan's absolute path and resume only that forward-only operation with `p2kesup upgrade --resume ORIGINAL_PLAN_PATH`; never erase, re-pin, recommission, restore old state or create a replacement operation to hide uncertainty.
   The primary service remains persistently masked across an incomplete firmware/host transition. Do not manually unmask it. Original-plan recovery verifies the retained evidence before restoring a proven pre-transfer cancellation or completing the target tuple forward.
5. Test compatible downgrade only when signed compatibility and current state permit it. Missing authorization or physical evidence blocks the test; do not edit signed manifests or treat host fallback as firmware rollback.

After collecting pre-state, ordinary supported host/device recovery may be tested only on the identified disposable setup according to the [inherited qualification procedure](../specs/002-manage-kes-agent/contracts/quality.md#inherited-release-qualification). USB reset alone is not host/device power-loss evidence. Random power cuts during flash or OTP are not part of this introductory walkthrough; use the separately controlled scenarios and preserve uncertainty.

## 20. Optional OTP branch — separate board, before step 8

**Skip applying OTP for the normal test.** To test it, use an eligible blank sacrificial target and the existing hardware/tool/image qualification, before commissioning. Signed software or successful preview does not grant that qualification. If it is absent, record the branch blocked.

1. Complete authenticated install, host policy and the appropriate restricted blank-application observation setup, without commissioning.
2. **Device security → Read-only security preview**. Review exact serial, tool/bundle, supported stepping/flash, blank status, evidence and irreversibility. Nondefault management sockets are unsupported by the owning tool and must refuse before service stops/writes.
3. Review/apply **Prepare one stage** only. Use the foreground tool's exact physical transitions and direct prompts; preserve its original protected record/readbacks.
4. Reopen/read the same record. If preparation is proven complete and fresh restricted blank admission is available, separately review/apply **Enable one stage**.
5. After its required evidence, separately review/apply **Lock one stage**. Cancel between stages once; completed stages remain and the next must not start automatically.
6. A pending uncertain write blocks replay/advancement. Use only the existing admitted pre-OTP resume or read-only `reconcile-prepare` assessment. In that assessment `--apply` permits observation, not a repair write. Never edit the record, change its filename, reset/erase to convert eligibility or feed confirmation automatically.
7. Preserve final observations and their limits, then separately perform step 8 commissioning if admitted. Application security reports are not independent ROM/SWD attestation.

The detailed physical authority remains the [maintainer security procedure](maintainer-security.md#attended-otp-evidence-and-uncertainty) and the authenticated tool, not a shortened set of generic power-cycle instructions here.

## 21. Delete the disposable pool last

Only after required exports, restore testing and maintenance observations, fence/remove any producer use of this test credential. Retain its archived public/backup evidence. Cancel **Operations → Delete exact pool incarnation (irreversible)** once and verify no change; then review and confirm the exact disposable incarnation.

Equivalent CLI, freshly observed pool revision:

```bash
POOL_STATUS=$(pico2-kes-agent-cli --json pool status --pool "$POOL")
POOL_REV=$(jq -er '.result.revision' <<<"$POOL_STATUS")
pico2-kes-agent-cli --json pool delete --pool "$POOL" --incarnation "$INCARNATION" \
  --expected-revision "$POOL_REV" --receipt "$OPS/delete.receipt.json"
pico2-kes-agent-cli --json device inventory
pico2-kes-agent-cli --json pool list --page-size 16
```

Answer the interactive confirmation rather than adding `--yes`. Verify unrelated pools are unchanged and cleanup completes before slot reuse. Remove the stale explicit binding through reviewed configuration. If re-enrolling, require a **new incarnation**, generation/certificate and matching configuration; never resurrect it from a saved journal/config snapshot.

Deletion does not revoke exported backup copies or state already delivered to a node. Stopping the agent, disconnecting USB and uninstalling it are also not revocation.

## 22. Uninstall selected managed components and close the evidence

Do this last on the disposable host:

1. Open **Uninstall**, choose `new`, enter the exact comma-separated installed component names (`manager,daemon,cli,firmware,tool,deployment` as applicable), and explicitly decide whether stopping the affected managed daemon is permitted.
2. Review every removal and retained path. Cancel once; then reopen and approve only the intended selection. Modified/external files must block, not be silently removed.
3. Verify retained configuration, journal, receipts, public pin/identity, maintenance/OTP records, accounts/groups, producer drop-ins and all device state. No producer restart or wipe/revocation claim is allowed. Removing the host `firmware` component removes its managed host files, not device flash.
4. If an admitted interruption occurred, choose `recover`, provide original operation ID/digest and review fresh evidence. Recovery does not stop a newly changed service. If the command itself was removed, reopen through the independently verified retained bootstrap/bundle, then recover the original record rather than reinstalling blindly.
5. Full removal retains registry provenance and authenticated source cache. Exact prior **single-bundle** restoration may be admitted afterward; mixed-tuple reinstall is not silently inferred.

Keep public-only results outside authenticated bundle directories. For each Q1–Q11 report record RC tag, exact source/build/manifest/payload identity, host OS/kernel, identified board/profile, actual command/UI action, expected and observed result, timing if required, original record references and pass/fail/blocked disposition. Do not mark an unchecked requirements-quality checklist as implementation completion.

Manual testing is complete only for the paths actually exercised. Release acceptance additionally requires the [quality contract](../specs/002-manage-kes-agent/contracts/quality.md), missing calibration/performance/physical/decoder evidence and operator cohort. Do **not** invoke the workflow's promotion `workflow_dispatch` inputs or rewrite `qualification` to pass. Metadata-only promotion is a later separately approved step after all gates pass for unchanged tested payloads.

## Failure triage: stop at the authority that refused

| Symptom | Next action, without bypass |
|---|---|
| Unsupported OS/architecture | Use Debian 12, Ubuntu 24.04 or Ubuntu 26.04 x86-64 with a release whose installer and signed manifest support that host; Ubuntu 26.04 requires a new release after RC.13. Do not patch downloaded assets or the support check |
| Missing secret or signing failure | Review the exact job and existing authority capability; do not generate a replacement key |
| Signature/hash/inventory mismatch | Preserve assets/error; obtain a newly authenticated complete candidate; never run the disputed code |
| Candidate absent from discovery | Expected: select its exact `--version TAG`, or an optional offline `--bundle`, with deliberate candidate admission |
| Existing external files/account/group | Use a clean disposable managed host or an explicitly reviewed owner migration; no blind deletion/adoption |
| RC.15 fresh install reports `No such file or directory` after plan approval, with the service group absent | RC.15 incorrectly treats NSS `ENOENT` for an absent group as fatal. Use a newly signed release containing the group-lookup fix; do not pre-create the group, alter NSS configuration or patch authenticated release files |
| Socket permission denied after group change | New login/session, verify ownership/membership; no chmod 777 |
| Config valid but pool lacks context | Add the exact live binding to startup config, validate/restart; verify trusted genesis/time |
| Active swap / MemoryProtection | Correct the actual dedicated-host policy before secret interaction; never disable the check |
| Missing output after mutation | Inspect/reconcile the original receipt; do not submit another mutation |
| Unsupported compatible tuple | Obtain explicit signed authorization and actual source artifacts; version similarity is not compatibility |
| Physical/OTP qualification missing | Record blocked and retain uncertainty; no erase/retry/record rewrite |

For that RC.15 group-lookup failure, retain the original plan and bundle. Confirm that no service account, installation registry, account-intent file or maintenance record was created before starting a new installation with the fixed release. In the observed failure, `/var/lib/p2kesup` contained only the authenticated bootstrap manager: staging and account creation had not begun, so no further legacy cleanup was needed. The old plan remains bound to RC.15 and cannot authorize a replacement manager; use the new release's own reviewed plan. Other missing-path errors require their own diagnosis rather than this workaround.

### Documentation verification boundary

Delegated-signing verification: 94 Python tests, 109 Rust library tests, 15 operator CLI tests and the bootstrap subprocess-bound regression passed. The new public distribution authorization was signed locally and verified against the pinned signer and existing firmware public key; the unchanged firmware authorization also verified. The unmodified installer helper accepted that real authorization. A disposable-key publisher-to-installer smoke accepted the correct ECDSA context and rejected cross-purpose replay; the actual manager under a PTY rejected a signature from the wrong delegated key before creating an install plan. The local authorization CLI refused to overwrite existing public files. Workflow YAML, all 17 workflow shell steps, documented maintainer/runbook shell blocks and 101 local documentation links passed checks.

No tag, release, GitHub secret/environment, installed service or hardware was changed. The sole production-key operation was local PGP signing of the public distribution delegation; the private key was not exported. Supported-host positive installation, physical upgrade/recovery and cloud publication still require their actual environments and a new signed RC. The full host-security suite was not repeated: its earlier passphrase-prompt failure came from this workstation's active swap, and that protection remains intact. Source checks and instructions are not release qualification.
