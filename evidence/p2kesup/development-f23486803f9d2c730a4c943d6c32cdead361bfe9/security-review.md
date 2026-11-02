# Integrated boundary review

Status: source review completed with fixes and scoped executable checks; **not hardware or release qualification**. Identity: [source-identity.json](source-identity.json). This is the requested manual review, not a new SO-014/SAST reading.

Reviewed `release.rs`, `host.rs`, `producer.rs`, `uninstall.rs`, `backup.rs`, `provisioning.rs`, `lifecycle.rs`, their UI handoffs, `terminal.rs`, connected CLI peers/receipts, `install.sh` and `tools/firmware.py`. Two independent read-only reviews covered privileged installation/recovery and lifecycle/backup/OTP handoffs. Parent integrated corrections and ran the checks in [developer-checks.md](developer-checks.md).

## Findings and disposition

| Finding | Correction and observed verification |
|---|---|
| Bootstrap signature output/deadline limits applied only after process completion | Shared streaming bounded subprocess helper: 30 seconds, 64 KiB verification output, closed stdin, discarded stderr, process-group kill/reap. Also used for dearmor and package metadata; apt simulation has a 1 MiB output cap. Real subprocess boundary/deadline tests passed; shell and all embedded Python syntax passed. Attended apt installation retains direct terminal streams rather than a captured buffer. |
| Active service alone falsely proved a completed restart | Reviews/readbacks now include systemd InvocationID and refuse pending jobs. Same active invocation resolves as failed-known, not completed restart; missing invocation remains unproven. Unit regression passed; actual read-only systemd property syntax exercised. No service restart was performed. |
| Uncertain producer operation blocked all host work without original recovery | Fresh exact readback authorizes only original unit/file/policy/restart scope. Recovery retains the original record/checkpoints, handles already-approved installed files and reapproves repeated reload/try-restart explicitly. No new-ID bypass; stopped units are not started. Classification guard tests passed; actual privileged partial-recovery acceptance remains Q11. |
| Original commissioning recovery incorrectly required a normal pinned daemon | Inspect the reviewed original method/serial first; commissioning receipts use explicit restricted authority without a blank-state or pre-existing-pin requirement. Normal operations still require normal pinned authority. Receipt/mode/peer regressions passed; physical lost-response recovery remains Q4. |
| Commissioning authenticated an observation connection but not the actual submission connection | Caller-bound, expiring protected admission includes restricted mode/serial and daemon PID/UID. The actual CLI connection checks expected peer credentials before sending bytes. Fresh commissioning still separately requires blank/compatible evidence. Connected-peer and mode tests passed. |
| Provisioning admitted custom sockets unsupported by its owning firmware tool | Protected installed configuration must resolve to the tool's documented default endpoint before service stops or tool handoff. Custom-socket regression passed. No config rewrite or tool semantic bypass. |
| Configuration/public-genesis special files could block before regular-file validation | Nonblocking opens and regular-file checks; manager parses the exact reviewed bytes. FIFO regression passed and actual daemon command returned promptly. Intended daemon symlink semantics for public inputs remain distinct from stricter manager candidate admission. |
| Privileged typed confirmations had unbounded line reads | Shared 256-byte confirmation boundary, used by host/provisioning prompts; overlong and invalid UTF-8 regression passed. Bootstrap approval input is bounded too. |
| Producer rollback/publication and policy identity races | Approved policy hash reauthenticated against selected deployment; protected owner/group/mode; unproven displaced files retained rather than deleted. Boundary/rollback/ownership tests passed. |
| Receipt/artifact attribution and backup process-identity weaknesses | Reviewed receipt/reference snapshots retained; actual reconciliation evidence separate; artifact recipient authenticated through existing backup authority. Backup's finite privileged read-only process inspection uses executable identity, not process-name fallback. Role/custody boundaries tested; current-host backup UI refused before private forms. |
| Root dispatcher observation argument mismatch and lint defects | Corrected tuple argument and exhaustive new action routing; final check/all-target Clippy passed. |

## Surviving controls

- Exact signed component/source inventory, independent bootstrap authority, reauthentication at use; cache symlinks/substitution fail closed.
- Fixed privileged actions/paths and argv, not arbitrary shell/user commands. Producer scope is only selected unit drop-ins plus approved systemd commands; no node discovery, connection or policy audit.
- Original receipt, maintenance and firmware-tool records remain authoritative. Unknown schemas/ownership or conflicting evidence block mutation; uncertain state is not hidden by a new operation ID.
- Selected uninstall retains configuration, pin/identity, journal, receipts/OTP/maintenance records, accounts, device state and producer files. Full removal retains source/provenance evidence; no wipe or revocation claim.
- Public diagnostic ring is bounded and field-selected, with terminal escaping. Private backup child streams are inherited, never captured. Real backup-mode socket sentinel observed zero connections before denial; no private form or passphrase prompt opened.
- Foreground child output survives until acknowledgement where required, then terminal ownership resumes; success, failure, explicit child cancellation and spawn failure were exercised in a disposable real-PTY helper.

Runtime limits: no supported-host privileged installation/removal/recovery, qualified firmware/OTP operation, isolated positive backup restore, producer restart, power-loss smoke or five-person exercise occurred. Manual review is not proof against all races or defects. Exact single-bundle retained reinstall is intentionally conservative; mixed-tuple reinstall is not silently inferred from an Install request.
