# Quickstart validation: management TUI

This is a run/acceptance guide for the proposed implementation, not a claim that the manager or host bundle already exists. Manager, host/device info observations, bootstrap and the firmware tool's `first-install`/`update` commands are new deliverables. Existing CLI commands and Cargo/Python gates are identified in their contracts. Do not run destructive scenarios against production pools.

## Prerequisites

- Signed source-free candidate bundle and authenticated bootstrap with independently trusted project OpenPGP keyring. The manifest must authorize the exact compatible tuple and declare `qualification: candidate`; admit it only through explicit local `--bundle` acceptance on disposable targets, not normal release discovery. Have a second explicitly compatible signed bundle, admitted under the same rules if unqualified, and incompatible/untrusted test inputs. Final qualification follows acceptance; it is not a prerequisite to testing the candidate.
- Disposable Debian 12 and Ubuntu 24.04 x86-64 systemd/udev machines, plus an isolated backup host. Package installation and service changes require administrative approval. Ordinary TUI inspection runs unprivileged.
- An accepted Pico2 A2 with required hardware/tool/image evidence and disposable pool generations for maintenance scenarios; a factory/BOOTSEL-only board for first installation, a compatible running blank application for the alternate setup path, and an eligible sacrificial target with required qualification for OTP. Never erase a populated device to satisfy a scenario. First-install does not require a pre-existing application pin.
- Operator-supplied public network/genesis/pool inputs, trusted device identity, public recipient records and disposable encrypted artifacts. Cold signing remains offline. Recipient private keys/passphrases exist only on the backup host.
- Existing host-memory/security requirements from [README](../../README.md). The existing agent preflight still references `cardano-node.service`; this guide does not add node discovery, configuration or integration checks. Custom-unit drop-in installation does not change that constraint.
- One actual terminal at least 80×24, keyboard-only/no-color runs, and a way to exercise resize. For SC-003, fix the five-person operator cohort and record eligibility as specified in [SC-003](spec.md#measurable-outcomes).
- For performance acceptance, approve the baseline-selection procedure, actual comparable baseline/build identity, environment, measurement tool/version and bounded comparison rules in the [quality contract](contracts/quality.md#required-project-performance-gate) before candidate evaluation. Freeze a separate first comparable implementation if no earlier manager exists; missing behavior is not a zero baseline. Retain approval, sensitivity evidence, raw timings and verdicts in `evidence/p2kesup/<candidate>/performance.md`.
- Before trusting behavioral readings, complete the [behavioral tool calibration](contracts/quality.md#behavioral-tool-calibration) approved in T001 and exercised in T067. Retain passing → known-defect failure → restored passing evidence in `evidence/p2kesup/<candidate>/behavioral-calibration.md`; missing or invalid calibration blocks acceptance independently of performance calibration.

Set `INSTALLER`, `BUNDLE`, and `TRUSTED_KEYRING` to actual absolute local paths supplied by the release/acceptance setup. `INSTALLER.asc` is the corresponding detached signature. These paths must contain the candidate release, not a fabricated fixture advertised as published software. Keep acceptance reports public-only; do not record terminal passphrase sessions or secret outputs.

## Q1 — Bootstrap, reopen and absent/partial inventory

Authenticate the script and check both [distribution trust pins](contracts/distribution.md) before running it. Use trusted OS `gpgv` and `awk`; obtain any missing verifier/key through an independently trusted channel first. Keep the installer, signature and keyring in a protected local directory that untrusted users cannot replace or modify during verification/execution. Run the complete block; the subshell stops before execution on any verification or pin failure:

```sh
(
    signature_status=$(gpgv --status-fd 1 --keyring "$TRUSTED_KEYRING" "$INSTALLER.asc" "$INSTALLER") || exit 1
    printf '%s\n' "$signature_status" | awk \
        -v signer=78C0F32094CD02A4BAFA444C684E37A210480F82 \
        -v primary=9FF957E79B5D853544805F4725491F18087931B6 '
        $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
            signatures++
            if ($3 == signer && $12 == primary) authorized++
        }
        END { exit !(signatures == 1 && authorized == 1) }
    ' || { printf '%s\n' 'Installer signer/primary fingerprint verification failed' >&2; exit 1; }
    sh "$INSTALLER" --bundle "$BUNDLE" || exit 1
    p2kesup --version --json && p2kesup
)
```

The block requires a successful `gpgv` exit and exactly one `VALIDSIG` matching both independently trusted fingerprints; a “good signature” from another key is insufficient. Review the signed candidate status and explicitly confirm disposable-host acceptance; declining it must cause no installation. Candidate admission must not bypass any signature, compatibility, state or hardware prerequisite. Then decline package/host changes once and verify nothing was installed, approve manager installation without daemon/device, and reopen using the printed command. Overview must distinguish missing components, unavailable device and unknown versions; a candidate is never labelled qualified.

Repeat with partial state, denied service/socket/file permissions, multiple executable copies and an external/manual installation. The effective service executable, PATH candidates, installed/running/selected versions and provenance remain distinct. External files are not overwritten/adopted. Unsupported architecture/distribution is rejected before mutation; missing compatible tools block dependent steps, not status navigation. No source checkout/build is required.

Expected: SC-001 inventory correctness, local overview ≤5 seconds, no unexpected package/service/config/device change merely by viewing.

## Q2 — Guided prerequisites and setup

In Setup, inspect exact packages/privileges/paths, decline once, then approve prerequisites using the supported OS package path. Inject one package-install failure; setup remains blocked with the failing command/tool and no bypass. Complete clean installation of selected manager/daemon/CLI/deployment files. Supply network/public pool inputs and host-policy declarations; missing/malformed/conflicting files must not replace working config or trigger node lookups.

Review and cancel a configuration change, then accept a valid one. Independent existing validator:

```sh
sudo -u pico2-kes-agent pico2-kes-agentd --config /etc/pico2-kes-agent/config.json --check-config
```

Interrupt setup between confirmed host steps and reopen. Completed ownership/state must be recognized and preserved. Rerun setup with existing config, journal, receipts and pin; compare their public digests, permissions and identity bindings with the approved expected change set. Do not snapshot/restore operational device state.

Expected: reviewed agent-only configuration, exact unmet prerequisites, resumable non-destructive behavior; no hidden host-wide policy change.

## Q3 — Complete observation and freshness

Start with the supported daemon/device combination and 64 disposable pools, each with active and staged slots where the scenario admits them. Open Overview and Pools; inspect the last pool and both generations. Reference the [observation contract](contracts/observations.md), not UI labels, for authority and period arithmetic.

Independent public commands:

```sh
pico2-kes-agent-cli --json status
pico2-kes-agent-cli --json host observe
pico2-kes-agent-cli --json device info
pico2-kes-agent-cli --json device inventory
pico2-kes-agent-cli --json pool list
```

Page all host bindings; compare complete device membership independently. Include device-only pools, config-only bindings, incarnation mismatch and retired journal bindings. A pagination revision change produces incomplete/restarted read evidence, never silent loss. Corrupt/unavailable one pool context without fabricating readiness for it or hiding healthy pools.

Disconnect device or deny access while viewing. Within 10 seconds, affected values become stale/unavailable with last observed time. Failed/unsupported inventory never displays zero pools. With trusted context missing, expiry estimates disappear with a reason. Older unsupported firmware reports limitations, not guessed live version. For responsive local components, all 64 pools are inspectable within 10 seconds of launch. Record actual latencies and delivery-isolation evidence, then apply the bounded baseline/candidate comparison and sensitivity procedure from the [quality contract](contracts/quality.md#required-project-performance-gate). Absolute timing success does not replace a passing regression reading.

## Q4 — Commissioning and every ordinary lifecycle action

Exercise both initial states with OTP declined. For a factory/BOOTSEL-only board, use Setup's authenticated `first-install` foreground handoff: preview without writes, confirm the unambiguous physical target and firmware-only range, retain intent and copy/flush checkpoints, then observe the selected compatible blank application through the sole restricted commissioning daemon. No source build, fabricated application serial/pin, erasure or OTP is permitted. For an already-running compatible blank application, skip flashing and perform the same blank admission.

Cancel before transfer, try ambiguous targets, and exercise a qualified interrupted transfer/reopen: retain the original record and uncertain state rather than automatically reflashing or treating the board as new. Missing/wrong build, nonblank, mismatched or unavailable application evidence must block commissioning and pinning. Do not treat a missing pin on an existing installation as first-install eligibility.

Only after blank admission, review board identity/security limits, separately confirm commissioning, retain original receipt and public enrollment output, review normal pin/network config, then transition to the normal daemon. Try an unexpected commissioned board: it must not be reset or automatically trusted. Record first-install and alternate setup results with Q2, and ordinary lifecycle results with Q4.

Through the manager, on disposable identities:

1. Install a public recipient record; enroll a pool with explicit supplied inputs; inspect its incarnation/binding.
2. Create a staged generation; export public verification key and encrypted initial artifact to new explicit destinations. Output collisions do not overwrite files.
3. Transfer public verification material for offline certificate signing; install the matching public certificate. No cold/private-recipient key is requested and no extra activation approval or archival gate appears.
4. Observe scheduled activation/evolution and readiness; create a future staged generation. Occupied-stage, stale-revision, invalid-context and mismatched-certificate cases preserve established rejection semantics.
5. Cancel a staged discard and pool deletion; verify unchanged state. Then perform each with exact target confirmation and retained receipts; unrelated active/pool state remains intact.
6. Rotate the public recipient; future artifacts bind the new recipient, older artifacts remain bound to the original private key.
7. Exercise 64-pool capacity and rejected 65th enrollment without eviction.
8. Terminate the manager after a mutation is submitted but before its outcome is displayed. Reopen Operations and reconcile the original receipt; never resubmit under a new identity.

Existing independent reconciliation command, with `RECEIPT` set to the original file:

```sh
pico2-kes-agent-cli --json operation reconcile --receipt "$RECEIPT"
```

Expected: every FR-016 lifecycle action completable via TUI or explicit offline handoff; all receipt/revision/uncertain outcomes preserved. No node connection or configuration.

## Q5 — Host release selection, offline mode and self-update

Select versions separately for manager, daemon and CLI; inspect the signed authorized compatible tuple, qualification status, schemas, ownership, affected pools, interruption and recovery prerequisites before approval. Normal discovery remains qualified/stable-only; prerelease opt-in must not admit unqualified candidates. Use explicit local-bundle acceptance for candidate version-change exercises. Attempt tampered content, missing signature, incomplete bundle, unknown schema/qualification, incompatible tuple and unreadable-current-journal downgrade; all block before execution/installation. Test candidate refusal outside explicit acceptance. Promotion rejection and digest binding use T020's disposable-authority cases before acceptance; final production metadata promotion and qualified-status discovery checks occur only in T070 after required candidate evidence passes, without rebuilding payloads.

Perform compatible host upgrade and downgrade. Compare preserved config/pin/journal/receipts, permissions and pool/generation identities allowing only independently explained forward transitions. Check installed versions separately from the daemon's running build using the Q3 commands and executable `--version --json`. A stopped service remains stopped unless explicitly approved temporary validation was selected; restore stopped state afterward.

Interrupt staging, tuple switch and service restart in separate disposable runs. Reopening shows the last confirmed step and actual/uncertain state. Only state-compatible binary fallback is offered; no journal/flash snapshot rollback. Update the manager alone: old running manager remains identified until explicit re-exec, and the selected daemon/firmware do not change implicitly.

Disconnect release networking, reopen the TUI, inspect local state and cached age, then select the obtained local bundle:

```sh
p2kesup --bundle "$BUNDLE"
```

Offline maintenance still verifies authority/integrity/compatibility; missing verification prerequisites block it. Cached metadata is not claimed fresh.

## Q6 — Attended firmware upgrade, downgrade and interruption

Use signed compatible firmware admitted through the candidate/qualified distribution rules, with all separately required hardware/tool/image qualification and complete pre-state. From Releases, review the exact pinned device, firmware build, affected pools and disruption; approve daemon shutdown. Follow the trusted foreground tool's physical BOOTSEL/destination instructions. Do not pick a mount solely by label or USB address. A second/ambiguous board must block guessing. This existing-installation path never substitutes unpinned first-install admission.

After transfer/flush, manager reconnects through the daemon and verifies selected live build, unchanged pin, retained memberships/recipient and allowed generation/period transitions. A file copy alone must leave validation pending. Repeat compatible downgrade; select an incompatible storage/boot-key profile and verify rejection.

Only on the designated disposable hardware and admitted procedure, exercise removal during transfer, missing/changed mount, failed flush/reboot and reconnection to a wrong identity. Preserve original records; no auto-reflash/reset/erase/re-pin/recommission/OTP. Span an evolution/activation/expiry boundary and verify that [forward comparison](data-model.md) distinguishes allowed transition from unexplained loss. Unsupported older firmware that cannot supply required pre-state blocks maintenance rather than weakening checks.

Expected: success only after verified application/post-state; otherwise accurate failed/uncertain result with a compatible, explicitly attended next action.

## Q7 — Optional OTP, separately qualified

On an eligible blank sacrificial device with the required hardware/tool/bundle qualification, open Device security. Verify optional status and cancellation; normal install on an unlocked device must not force provisioning. Nonblank/unsupported/wrong-device/mismatched-evidence cases block before writes.

Preview then apply one stage at a time using the foreground handoff: prepare, enable, lock. Confirm exact target in the trusted tool and follow existing physical transitions/readbacks. Check original protected record after each stage. Cancel between stages; reopening offers only the next admitted step, never implicit advance.

Interrupted writes are tested only under the existing qualification-controlled procedure. Preserve uncertainty and original record; only admitted pre-OTP resume or read-only assessment is offered. Never generic reset, automatic retry, new record to bypass a pending write, or erase-to-convert. Completion states observations and limits, then offers separate ordinary commissioning. Host simulation is not an OTP acceptance result.

## Q8 — Isolated backup role

On the separate backup host, with no daemon/device and no active swap:

```sh
p2kesup --role backup
```

Create a recipient to new protected destinations; export only the public record for transfer. Restore a disposable encrypted artifact using independently trusted device identity and exact pool/incarnation/generation/vkey evidence to a nonexisting owner-only local output. Do not capture the foreground passphrase terminal. Verify resulting key format/identity with the existing independent qualification procedure without placing secret contents in a report.

Try wrong recipient/passphrase, tampered artifact, missing/mismatched public evidence, active swap and destination collision. None publishes/replaces a signing-key file. On a detected/configured primary, selecting backup role refuses before private-file access or a passphrase prompt; inaccessible role evidence also blocks. CLI binaries alone do not make an isolated backup host a primary.

Expected: no daemon/device/node contact, no key import, no changed certificate lifetime or revoked external copy claim; clear operator fencing/custody responsibility.

## Q9 — Service, diagnostics and uninstall

Through Service, start/stop/restart the managed daemon with reviewed disruption/privileges. Inject invalid configuration; working config remains intact and failed start is not healthy. Service running, device connected and pool ready remain distinct. Diagnostics show useful public identities/errors without secret/raw traffic.

Select uninstall and cancel once, then confirm only manager-owned components. Modified/external paths are not silently removed. Inspect retained config, journal, receipts, public identities, maintenance records, service user/group, producer drop-ins and device state. No producer restart occurs. Remaining data are listed, and uninstall is not presented as erasure or revocation.

## Q10 — Actual terminal and operator acceptance

Exercise Q1–Q9 and Q11 with keyboard-only navigation and `NO_COLOR=1`, including Service/configuration/diagnostics/Uninstall, Producer hardening and backup/OTP selection, confirmation and error screens—not only return from their children. Resize below/above minimum while selecting and reviewing; confirm text identifies targets, state and failures without color. Record per-flow results, including declined/deferred actions and safe cancellation. Reuse qualifying manual scenario runs and schedule irreversible OTP stages once on their eligible target; never replay writes merely to repeat an accessibility check. Return from failed/cancelled/complete foreground handoffs with echo/cursor/raw mode restored and no passphrase in UI history/diagnostics. Nonterminal manager/bootstrap input must not cause unattended mutation.

Evaluate the fixed cohort under [SC-003](spec.md#measurable-outcomes), recording each participant's result for each of the three actions and whether at least four distinct participants complete all three. Supplementary runs do not alter the cohort or its results. No production secret recording or node integration checks are needed.

## Q11 — Minimal producer hardening acceptance

Supply an operator-selected local `.service` name (custom concrete instances are supported), review the exact drop-in destination and approve administrative installation. Observe file-install result and `systemctl daemon-reload` result. Approve restart for a selected running service once; defer once. Stopped services must not be started. Failed file/systemd operations must be reported, and unrelated files remain untouched.

This is a manual file/command acceptance action, not a dedicated test suite, multi-producer setup or runtime-policy audit. Do not inspect node connections or re-test systemd. Drop-ins remain on uninstall; existing agent preflight is unchanged.

## End-user acceptance and existing developer checks

Q1–Q11 are operator-executed acceptance scenarios, not requirements to build automated suites. Test packaged `p2kesup` and real dependencies, including refusal/interruption paths, and record expected versus observed outcomes. SC-002 timing and the bounded constitutional performance comparison/calibration use these workflows and existing tooling; no coverage percentage/report, microbenchmark framework or mandatory new unit/integration/property/mutation/fuzz campaign applies.

For implementation developers only, run the [existing quality commands](contracts/quality.md) once after integrated changes; end users never need source builds. Maintain affected shared-component tests and add only small checks for new critical logic. Retain candidate/config/environment/tool identity and observed results, with failures or unavailable prerequisites explicit. No new test framework, dedicated manager suite or benchmark executable is a prerequisite.

This planning session validates these documents' structure, links and source facts only. It does not execute Q1–Q11, sign a release, access hardware or claim any acceptance reading.
