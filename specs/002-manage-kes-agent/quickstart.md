# Quickstart validation: management TUI

This is a run/acceptance guide for the integrated development implementation, not a qualified release or a claim of packaged, physical or operator acceptance. Q1–Q11 remain to be executed against an authenticated candidate with the prerequisites below. Do not run destructive scenarios against production pools.

Start with the [manual RC-to-lifecycle runbook](../../docs/manual-testing.md) for concrete publication, installation and command/UI steps. Return here for the full Q1–Q11 rejection, interruption, performance and operator-acceptance matrix; neither document supplies an unperformed result.

## Prerequisites

- Signed source-free candidate bundle or published RC tag, with pinned project OpenPGP authority for downloaded payload verification. The manifest must authorize the exact compatible tuple and declare `qualification: candidate`; admit it only through explicit `--version TAG` or local `--bundle` acceptance on disposable targets, not default release discovery. Have a second explicitly compatible signed bundle, admitted under the same rules if unqualified, and incompatible/untrusted test inputs. Final qualification follows acceptance; it is not a prerequisite to testing the candidate.
- Disposable Debian 12 and Ubuntu 24.04 x86-64 systemd/udev machines, plus an isolated backup host. Package installation and service changes require administrative approval. Ordinary TUI inspection runs unprivileged.
- An accepted Pico2 A2 with required hardware/tool/image evidence and disposable pool generations for maintenance scenarios; a factory/BOOTSEL-only board for first installation, a compatible running blank application for the alternate setup path, and an eligible sacrificial target with required qualification for OTP. Never erase a populated device to satisfy a scenario. First-install does not require a pre-existing application pin.
- Operator-supplied public network/genesis/pool inputs, trusted device identity, public recipient records and disposable encrypted artifacts. Cold signing remains offline. Recipient private keys/passphrases exist only on the backup host.
- Existing host-memory/security requirements from [README](../../README.md). The existing agent preflight still references `cardano-node.service`; this guide does not add node discovery, configuration or integration checks. Custom-unit drop-in installation does not change that constraint.
- One actual terminal at least 80×24, keyboard-only/no-color runs, and a way to exercise resize. For SC-003, fix the five-person operator cohort and record eligibility as specified in [SC-003](spec.md#measurable-outcomes).
- For performance acceptance, approve the baseline-selection procedure, actual comparable baseline/build identity, environment, measurement tool/version and bounded comparison rules in the [quality contract](contracts/quality.md#required-project-performance-gate) before candidate evaluation. Freeze a separate first comparable implementation if no earlier manager exists; missing behavior is not a zero baseline. Retain approval, sensitivity evidence, raw timings and verdicts in `evidence/p2kesup/<candidate>/performance.md`.
- Before trusting behavioral readings, complete the [behavioral tool calibration](contracts/quality.md#behavioral-tool-calibration) approved in T001 and exercised in T067. Retain passing → known-defect failure → restored passing evidence in `evidence/p2kesup/<candidate>/behavioral-calibration.md`; missing or invalid calibration blocks acceptance independently of performance calibration.

Normal installation and upgrade require no manually supplied assets. Only for independent/offline acceptance scenarios, set `INSTALLER`, `BUNDLE`, and `TRUSTED_KEYRING` to actual absolute local paths; `INSTALLER.asc` is the corresponding detached signature. Never advertise fabricated fixtures as published software. Keep reports public-only; do not record passphrase sessions or secret outputs.

## T001 gate approval

On 2026-11-02, the maintainer selected **Approve existing gate** during implementation:
the definition in [quality.md](contracts/quality.md) is approved without weakening its
checks, thresholds or exclusions. SO-002b, SO-002c and SO-006e full entries were
reconsulted through the Software Observatory MCP; the existing mapping remains applicable.
This approves the procedure, not any measurement or release.

- Baseline: identify a comparable Q1/Q3 implementation, or freeze a separately identified
  initial comparable implementation before evaluating the candidate. Never use absent
  behavior, zero time or the candidate itself as the baseline.
- Environment/tools: use the same otherwise idle supported Debian 12 or Ubuntu 24.04
  x86-64 host, real service/device, 64 active/64 staged generations, terminal, power
  policy and starting state for both builds. Record exact identities and approve the
  monotonic instrument/version (resolution at least 0.1 seconds) before measurement.
  Development inventory observed Rust/Cargo 1.99.1 and Python 3.14.4; this does not
  establish the supported acceptance hosts' installed package versions.
- Performance: one warmup each, then five pairs in AB/BA/AB/BA/AB order within
  30 minutes. Every candidate sample must meet the 5/10/10-second absolute limits.
  A range above 0.5 seconds is inconclusive; use the contract's
  `max(0.5 seconds, 20% of baseline median)` regression limit and 0.25-second
  uncertainty. Demonstrate detection of the separate 2-second Overview slowdown first.
- Behavioral calibration: the exact
  `cargo test --locked --lib manager::observe::tests::stale_after_observation_failure -- --exact`
  check and Q3 must detect deliberately retained `fresh` status after observation
  failure, then pass after restoration, preserving last-success evidence. Use Rust/Cargo
  1.99.1, at most 30 minutes per build and 30 minutes for the three runs after setup.
  Other runners require applicable retained calibration or a separately approved
  single-defect demonstration. Reuse requires unchanged applicable runner/version,
  invariant, detection path and environment.
- Evidence: retain public-only reports under `evidence/p2kesup/<candidate>/`, with
  the full candidate commit and dirty-source digest when applicable; use
  `performance.md` and `behavioral-calibration.md` for the independent calibrations.
  Record every sample, failure, identity and restoration result.

The concrete baseline/build, instrument/environment approval, signing authorization,
compatible signed bundles, qualified physical targets, calibration results and fixed
five-operator cohort are not established by this approval. Missing prerequisites block
their dependent evaluation and acceptance; they are not passing readings.

## T002 dependency review

The requested exact Ratatui 0.29.0/Crossterm 0.28.1 graph resolves with
Rust/Cargo 1.99.1. Both crates declare MIT licenses and minimum Rust versions
below the pinned compiler. `cargo fetch` and `cargo tree --locked -e features
-p ratatui` succeeded; only the requested Ratatui Crossterm backend is enabled.

`cargo deny check` exited 1: Ratatui introduces `paste` 1.0.15 into the host
graph, rejected under [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436).
Licenses, bans and sources passed with warnings. `cargo audit` exited successfully
but reported five allowed warnings, including `lru` 0.12.5 through Ratatui:
[RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002) and
[RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253).
The latter requires unwinding/catch-unwind and a potentially panicking key
destructor; this is not evidence of an exploitable manager path. The audit also
reported unmaintained firmware dependencies `bare-metal`, `paste` and
`proc-macro-error2`.

No advisory suppression or policy weakening was added. Sequential implementation
stopped at that failed check. The maintainer selected **Revise Ratatui pin**,
approving Ratatui 0.30.2 (MIT, Rust 1.88 minimum). That graph passed
`cargo check --locked` and `cargo deny check`; `cargo audit` retained only the
three existing firmware maintenance warnings, with `lru` updated to 0.18.5.

Inspection found that Ratatui's backend enables Crossterm 0.29 by default and
chooses the highest enabled version, even when `crossterm_0_28` is requested.
The maintainer therefore selected **Align on Crossterm 0.29.0**. Final pins are
Ratatui 0.30.2 with default features disabled and only `crossterm`, plus
Crossterm 0.29.0. The plan, research, task and Cargo manifest are synchronized.
The aligned graph resolved and passed `cargo deny check` (advisories, licenses,
bans and sources) and host compilation through `cargo test --locked --test
operator_cli`. Remaining duplicate-version warnings are unrelated to Crossterm.
The first version-test filter selected zero tests; it is not behavioral evidence.

## Foundation implementation checks

T003–T007 developer checks passed: five manager library checks covering schema
admission, protected records, interrupted receipt recovery and terminal error
propagation; the exact `host_versions_are_standalone_and_share_build_identity`
operator CLI test executed once and passed. Both built host executables were
also invoked directly with human and JSON version forms, without configuration
or device access, and reported `development-unqualified`.

A temporary executable exercised terminal drawing, an unsuccessful foreground
child, spawn failure, resume, normal close and an aborting panic in a 100×24
pseudoterminal. Both normal and panic exits restored the original termios
settings and emitted cursor-show/alternate-screen-exit controls. The first harness
lacked cursor-position replies and failed; adding normal terminal DSR replies
allowed both scenarios to pass. The temporary source was removed. This checks
the helper, not complete Q10 accessibility or physical-device behavior; actual
manager navigation/restoration remains part of T019 and final acceptance.

## US1 internal integration checkpoint

The development build implements read-only Overview/Pools/details, host discovery,
and additive host/device/pool observations. This is internal integration work,
not the complete packaged feature or an acceptance result.

- `cargo check --locked` passed.
- `cargo test --locked --workspace --exclude pico2-kes-firmware` initially stopped
  on four `backup_restore` cases with `MemoryProtection`: `/swap.img` was active.
  The protection was unchanged. After explicit maintainer approval and graphical
  `pkexec /usr/sbin/swapoff /swap.img` authentication, `/proc/swaps` contained only
  its header and the complete host run passed 275 tests across 26 suites.
  `pkexec /usr/sbin/swapon /swap.img` restored the original file and priority -1;
  persistent swap configuration was not changed.
- Core/protocol `--no-default-features` checks and firmware target check, release
  build and Clippy `-- -D warnings` passed for `thumbv8m.main-none-eabihf`.
  Rust reports the existing `proc-macro-error2` future-incompatibility warning.
- Following separate configuration access/ownership presentation, the manager
  binary built and `cargo test --locked --lib manager::` passed 11 checks.
  `cargo check --locked --manifest-path fuzz/Cargo.toml --bins` passed.
- Actual `p2kesup` primary and backup PTY runs exercised Overview, Pools where
  applicable, help, `NO_COLOR=1`, resizing from 120×32 to 60×20, safe quit and exact
  termios/cursor/alternate-screen restoration. The runs took 3.066 and 2.810 seconds
  including deliberate harness pauses; these are not SC-002 workload timings.
  A temporary pyte 0.8.2 screen decoder handled differential terminal rendering;
  initial raw-stream text assertions were invalid harness checks, not UI failures.
  Nonterminal invocation refused with exit 4; standalone help/version succeeded.

The inspected host is Ubuntu 26.04, not either supported installation target.
The UI correctly labels it unsupported for installation, reports the sysfs USB
candidate as application mode without claiming authentication, and keeps
external installation ownership distinct from authenticated registry evidence.
The installed daemon was inactive; no agent service, pin, device state, flash
or OTP was changed. At this checkpoint host Clippy and authenticated installation
integration were still pending; the US2 checkpoint below records later checks.

T019 remains blocked for actual 64-active/64-staged Q3, supported packaged hosts,
mixed/disconnected/denied physical observations and healthy-delivery isolation.
No synthetic workload or terminal smoke substitutes for that evidence, the
independent calibrations, or the five-operator cohort.



## US2 internal integration checkpoint

Authenticated distribution admission, isolated publication/promotion stages,
immutable host installation, configuration review, attended first-install and
commissioning handoffs are implemented. These are development results, not Q1/Q2
or commissioning acceptance on packaged supported targets.

- `cargo check --locked` and host-workspace Clippy with `--all-targets -- -D warnings`
  passed. The current `p2kesup` development binary built.
- `python3 -I -m unittest discover -s tools/tests` passed 76 tests, using disposable
  test authorities rather than production signing material.
- Manager library checks passed 17 tests; connected-stream peer-identity/deadline
  checks passed two; `service_lifecycle` passed three.
- `host_security` passed ten tests and failed its recipient-prompt memory-protection
  case with swap active. Two graphical swap-disable authentication attempts did
  not complete; `/swap.img` remained active, unused, priority -1. The protection was
  not weakened. The earlier US1 full-suite result is not a current full-suite pass.
- Shell syntax checks passed for bootstrap and deployment scripts. Actual bootstrap
  help succeeded; nonterminal and unsupported Ubuntu 26.04 invocations refused
  before installation.
- Actual primary/backup PTY runs exercised Setup, cancellation, invalid public
  configuration, minimum-size blocking, uninstall review and terminal restoration.
  Invalid configuration bytes and mode remained unchanged. Internal privileged
  modes refused nonroot execution; an actual foreground failure remained visible
  until acknowledgement and restored terminal settings.
- Actual first-install preview refused an incomplete bundle without creating a
  record. All six distribution subcommand help entrypoints executed; `prepare`
  refused an incomplete payload without publishing output. The release workflow
  parsed, but its CI/signing/publication jobs were not executed.

No installation, service change, firmware transfer, commissioning or OTP write was
performed. T023 signed staging and T030 supported-host/physical acceptance remain
blocked by missing authorized signing, disposable supported hosts and qualified
hardware. Development fixtures do not establish those results.

## US3 internal integration checkpoint

T031–T038 implementation checks passed; T039 Q5/Q6 release acceptance remains
blocked by the signed compatible bundles, supported disposable hosts and qualified
physical targets listed above. No host installation, service change, firmware
transfer or OTP write was performed.

- Host-workspace Clippy passed with all targets and warnings denied; 36 manager
  and seven journal library checks passed. The firmware-tool Python suite passed
  81 checks. These exercise development fixtures, not physical preservation.
- A real Unix management-socket scenario accepted forward period evolution,
  rejected reversed evidence and refused a disconnected device. Eight management
  recovery and ten operator-CLI checks passed. The legacy emulator's selected
  serial now matches its security report; its explicit context observation models
  the runtime cache after device acceptance.
- The shared single-pool run passed 23 checks; recipient restoration was refused
  by `MemoryProtection` with swap enabled. Attempts to obtain swapoff authorization
  timed out; swap remained unchanged. This is not a current full-suite pass.
- Actual primary/backup PTY runs exercised Releases navigation, offline selection,
  safe refusal/cancellation, minimum-size and no-color behavior, and terminal
  restoration. An acknowledged foreground child preserved output until Enter.
- The independent release worker's deadline killed a deliberately stalled process
  group after 10.022 seconds; explicit cancellation took 15.766 milliseconds.
  These controlled scenarios are not performance calibration or a baseline.
  Offline discovery returned no offers; a symlink cache was refused. Cache cleanup
  regression failed before its fix and passed afterward.
- Signed inventory digests cover complete component payloads. Selection requires
  an exact authorized tuple; installed provenance is retained. Firmware copy is
  not completion: post-checks and original-record recovery remain mandatory.
  Originally stopped services require explicit temporary validation approval.
  Binary fallback restores no configuration, journal, period or flash snapshot.

No positive signed-bundle publication/installation, capacity-limited qualified
cache reuse, physical update or supported-host recovery result is claimed here.
The temporary terminal/worker smoke executables were removed.

These US1–US3 checkpoints are historical observations of their respective development builds, not final acceptance. Later integrated evidence is retained separately under `evidence/p2kesup/development-f23486803f9d2c730a4c943d6c32cdead361bfe9/`, with exact source/build identities and observed failures; do not infer a current full-suite pass from an earlier checkpoint.

## Navigation and recovery

Use Tab/Shift-Tab to change views and up/down to select actions, Enter to review and Esc to cancel. In **Setup**, select **Install authenticated host bundle**, **Factory-only firmware install / original record**, **Review/install explicit commissioning configuration**, **Start restricted commissioning service**, **Commission intended blank application**, **Stop restricted commissioning service**, and **Review/install explicit normal configuration and pin** as applicable. An interrupted first install uses **Reconcile original first install with attended blank-application evidence**, not a new transfer.

**Operations** contains the lifecycle actions and **Discover and inspect original operation receipts** / **Reconcile an original receipt**. Original commissioning reconciliation uses the saved serial and restricted daemon authority even if committed and no normal pin exists; it does not require a second blank admission. Normal actions use normal pinned authority. Both use caller-bound expiring root admission and paired CLI peer PID/UID checks before bytes; changed authority requires a fresh review.

**Releases** offers independent host component selection, firmware preview/update, original-plan inspection, original firmware reconciliation, compatible binary fallback and explicit re-exec. **Service** offers start/stop/restart, configuration review/edit, public diagnostics/export and original service/configuration reconciliation. **Device security** offers preview, individual stages, original-record reopen, admitted pre-OTP resume and read-only permission reconciliation. **Backup host** offers recipient creation, local restore and public-transfer guidance. **Producer hardening** offers installation or original-batch recovery; **Uninstall** asks `new` or `recover`.

## Q1 — Bootstrap, reopen and absent/partial inventory

The standard pipeline explicitly trusts the HTTPS-hosted launcher; this is distinct from pinned OpenPGP verification of downloaded payloads. On an attended disposable host, exercise the default qualified-stable pipeline and explicit RC selection:

```sh
curl -fsSL https://raw.githubusercontent.com/AndrewWestberg/pico2-kes-agent/master/install.sh | sh
curl -fsSL https://raw.githubusercontent.com/AndrewWestberg/pico2-kes-agent/master/install.sh | sh -s -- --version v0.1.0-rc.12
```

Use separate clean hosts or runs as appropriate, and substitute the actual RC tag. Review the signed candidate status and explicitly confirm disposable-host acceptance; declining must cause no installation. Candidate admission must not bypass signature, compatibility, state or hardware prerequisites. Decline package/host changes once and verify nothing was installed; approve reviewed trusted-apt prerequisites and direct persistent installation, then reopen with `p2kesup` for later device setup. Exercise `--role backup` on an isolated backup host, `/dev/tty` prompts under the pipe and noninteractive refusal. Overview must distinguish missing components, unavailable device and unknown versions; a candidate is never labelled qualified.

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

For an interrupted original commissioning, retain its reference/receipt and use **Operations → Reconcile an original receipt** with its original public output destination when needed. The restricted daemon must correspond to the saved serial; do not demand blank state or a normal pin for this recovery and do not submit a new commission.

Existing independent reconciliation command, with `RECEIPT` set to the original file:

```sh
pico2-kes-agent-cli --json operation reconcile --receipt "$RECEIPT"
```

Expected: every FR-016 lifecycle action completable via TUI or explicit offline handoff; all receipt/revision/uncertain outcomes preserved. No node connection or configuration.

## Q5 — Host release selection, offline mode and self-update

Run `p2kesup upgrade` for default qualified-stable discovery, `p2kesup upgrade --version TAG` for explicit reviewed candidate acceptance on a disposable host, and `p2kesup upgrade --bundle DIRECTORY` for offline selection. Verify the installed role is inferred, the signed complete host/firmware tuple and service disruption are reviewed, and an identical tuple is a no-op. Attempt tampered content, missing signature, incomplete bundle, unknown schema/qualification, incompatible tuple and unreadable-current-journal downgrade; all block before execution/installation. Candidate acceptance does not establish qualification. Promotion rejection and digest binding use T020's disposable-authority cases before acceptance; production promotion occurs only in T070 after required evidence passes, without rebuilding payloads.

Perform compatible coordinated upgrade and downgrade with attended firmware actions. Compare preserved config/pin/journal/receipts, permissions and pool/generation identities allowing only independently explained forward transitions. Check installed versions separately from the daemon's running build using the Q3 commands and executable `--version --json`. A stopped service remains stopped unless explicitly approved temporary validation was selected; restore stopped state afterward.

Interrupt staging, tuple switch and service restart in separate disposable runs. Resume the original operation with `p2kesup upgrade --resume ORIGINAL_PLAN_PATH`, reviewing last confirmed and actual/uncertain state; recovery is forward-only and does not authorize an arbitrary mixed tuple or journal/flash snapshot rollback. The old running manager remains identified until explicit re-exec.

Disconnect release networking, reopen the TUI, inspect local state and cached age, then select the obtained local bundle:

```sh
p2kesup upgrade --bundle "$BUNDLE"
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

The packaged handoff uses `provision --distribution`; read-only permission assessment uses `reconcile-prepare --distribution ... --apply`, where `--apply` authorizes observation only. It uses the authenticated distribution runtime and original record. The tool supports the default management socket only: test that a configured nondefault socket refuses before service stops or tool handoff. Enable/lock require fresh restricted-daemon blank admission; this is separate from recovering an original commissioning receipt.

Interrupted writes are tested only under the existing qualification-controlled procedure. Preserve uncertainty and original record; only admitted pre-OTP resume or read-only assessment is offered. Never generic reset, automatic retry, new record to bypass a pending write, or erase-to-convert. Completion states observations and limits, then offers separate ordinary commissioning. Host simulation is not an OTP acceptance result.

## Q8 — Isolated backup role

On the separate backup host, with no daemon/device and no active swap:

```sh
p2kesup --role backup
```

Create a recipient to new protected destinations; export only the public record for transfer. Restore a disposable encrypted artifact using independently trusted device identity and exact pool/incarnation/generation/vkey evidence to a nonexisting owner-only local output. Do not capture the foreground passphrase terminal. Verify resulting key format/identity with the existing independent qualification procedure without placing secret contents in a report.

Select **Backup host → Create protected backup recipient** or **Restore encrypted backup locally**. Explicitly approve the finite elevated local `/proc`/role inspection before entering private paths and again before the inherited-terminal CLI handoff; refusal or inaccessible evidence blocks. It neither reads private paths nor contacts daemon/device/node.

Try wrong recipient/passphrase, tampered artifact, missing/mismatched public evidence, active swap and destination collision. None publishes/replaces a signing-key file. On a detected/configured primary, selecting backup role refuses before private-file access or a passphrase prompt; inaccessible role evidence also blocks. CLI binaries alone do not make an isolated backup host a primary.

Expected: no daemon/device/node contact, no key import, no changed certificate lifetime or revoked external copy claim; clear operator fencing/custody responsibility.

## Q9 — Service, diagnostics and uninstall

Through Service, start/stop/restart the managed daemon with reviewed disruption/privileges. Inject invalid configuration; working config remains intact and failed start is not healthy. Service running, device connected and pool ready remain distinct. Diagnostics show useful public identities/errors without secret/raw traffic.

Inspect **Service → Inspect bounded public diagnostic history** and export through **Export public diagnostics to a new protected file** to an absolute protected path. Verify mode 0600 and refusal of an existing destination; public identities and paths may still be sensitive. For interrupted service work use **Reconcile original service/configuration outcome without replay**; pending systemd jobs block, and the same active `InvocationID` does not establish a restart.

Select uninstall and cancel once, then confirm only manager-owned components. Modified/external paths are not silently removed. Inspect retained config, journal, receipts, public identities, maintenance records, service user/group, producer drop-ins and device state. No producer restart occurs. Remaining data are listed, and uninstall is not presented as erasure or revocation.

Review the selected inventory digest including registered files/links, not only registry bytes. On a disposable interrupted removal choose **Uninstall → recover**, supply the original operation ID and plan digest, review fresh readback and cancel once; approved recovery refuses changed evidence and does not stop services. After completed full removal verify retained registry provenance/source cache and the other listed state; initial Install may restore the exact prior single-bundle tuple, not silently reinterpret mixed tuples. Do not call removal secure erasure or revocation.

## Q10 — Actual terminal and operator acceptance

Exercise Q1–Q9 and Q11 with keyboard-only navigation and `NO_COLOR=1`, including Service/configuration/diagnostics/Uninstall, Producer hardening and backup/OTP selection, confirmation and error screens—not only return from their children. Resize below/above minimum while selecting and reviewing; confirm text identifies targets, state and failures without color. Record per-flow results, including declined/deferred actions and safe cancellation. Reuse qualifying manual scenario runs and schedule irreversible OTP stages once on their eligible target; never replay writes merely to repeat an accessibility check. Return from failed/cancelled/complete foreground handoffs with echo/cursor/raw mode restored and no passphrase in UI history/diagnostics. Nonterminal manager/bootstrap input must not cause unattended mutation.

Evaluate the fixed cohort under [SC-003](spec.md#measurable-outcomes), recording each participant's result for each of the three actions and whether at least four distinct participants complete all three. Supplementary runs do not alter the cohort or its results. No production secret recording or node integration checks are needed.

## Q11 — Minimal producer hardening acceptance

Supply an operator-selected local `.service` name (custom concrete instances are supported), review the exact drop-in destination and approve administrative installation. Observe file-install result and `systemctl daemon-reload` result. Approve restart for a selected running service once; defer once. Stopped services must not be started. Failed file/systemd operations must be reported, and unrelated files remain untouched.

For a disposable interrupted batch select **Producer hardening → Recover original producer batch**, supply the original operation ID and approved plan digest, inspect fresh public readback and cancel once. An approved recovery reauthorizes only the original reload/try-restarts, refuses changed readback and never adds scope or starts a stopped unit.

This is a manual file/command acceptance action, not a dedicated test suite, multi-producer setup or runtime-policy audit. Do not inspect node connections or re-test systemd. Drop-ins remain on uninstall; existing agent preflight is unchanged.

## End-user acceptance and existing developer checks

Q1–Q11 are operator-executed acceptance scenarios, not requirements to build automated suites. Test packaged `p2kesup` and real dependencies, including refusal/interruption paths, and record expected versus observed outcomes. SC-002 timing and the bounded constitutional performance comparison/calibration use these workflows and existing tooling; no coverage percentage/report, microbenchmark framework or mandatory new unit/integration/property/mutation/fuzz campaign applies.

For implementation developers only, run the [existing quality commands](contracts/quality.md) once after integrated changes; end users never need source builds. Maintain affected shared-component tests and add only small checks for new critical logic. Retain candidate/config/environment/tool identity and observed results, with failures or unavailable prerequisites explicit. No new test framework, dedicated manager suite or benchmark executable is a prerequisite.

The internal checkpoints above record development checks only. Q1–Q11 packaged
acceptance, release signing, physical qualification and cohort/performance evidence
remain separate gates; no unexecuted scenario is claimed passed.
