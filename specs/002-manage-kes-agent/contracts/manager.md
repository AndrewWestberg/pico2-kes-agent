# Manager operator and handoff contract

## Entry points and UI

Proposed command: `p2kesup [--role primary|backup] [--socket PATH] [--bundle DIRECTORY]`. Default role is primary; socket default matches `/run/pico2-kes-agent/management.sock`. Bundle selection remains verified/compatible/interactive. Normal discovery offers qualified releases only; an authenticated candidate is admitted only by explicit `--bundle` for attended acceptance on a disposable host, after review, under the [distribution contract](distribution.md). `--help`, `--version`, `--version --json` are non-mutating. Invalid arguments exit 2. Nonterminal invocation refuses interactive work without mutation. Fatal availability/permission/local errors use the existing CLI classes 3/4/7; graceful quit is 0. A mutation failure is reported inside the UI and in its durable record, never hidden by a subsequent normal quit.

Screens: Overview; Pools/details; Setup; Releases/maintenance; Operations/receipts; Service/configuration/diagnostics; optional Device security; Backup host; Producer hardening; Uninstall. They are views over the existing authorities, not separate services. Up/down or j/k selects; Tab/Shift-Tab changes focus; Enter opens/reviews; Esc cancels/back; r refreshes; ? displays help; q quits from a nonapplying screen. Destructive confirmation names exact targets and consequences; Enter on an overview never applies maintenance. Text labels carry health without color. Resize preserves selection; below 80×24 show minimum-size instructions and permit quit, not hidden confirmation. Escape untrusted terminal controls.

Opening any screen, navigation and refresh perform observations only. Confirmations expire on target/revision change. Mutations are serialized locally but concurrency elsewhere is handled by existing revision/operation checks, not assumed away. Busy/unavailable/incomplete status is distinct from empty/healthy. Redacted diagnostics contain public identities and error classes only, never node-service payloads, raw USB frames, private keys or passphrases.

## Workflows and authority

| Workflow | Existing surface / planned orchestration | Completion rule |
|---|---|---|
| Discovery/monitoring | Existing inventory/status plus [new observations](observations.md), local service/file inventory | Per-source age/evidence; all device pools and configured/effective bindings visible |
| First firmware installation | `python3 -I firmware.py first-install --bundle DIR --record FILE [--apply]` on an attended unambiguous BOOTSEL board | Authenticated firmware transfer and sole commissioning-daemon observation of selected compatible blank application; separate commission and pin |
| Commissioning | `device commission` in existing attended commissioning daemon mode | Explicit intended blank board, original receipt and no-clobber public enrollment record, reviewed pin/network/service configuration, normal-mode checks |
| Enrollment | `pool enroll` with supplied validated public pool/network inputs | New incarnation from authoritative receipt; review binding, no node lookup; 65th pool rejected |
| List/detail | `device inventory`, `pool list`, `pool observe` | Complete-vs-partial distinguished; unmatched device pools not hidden |
| Delete | `pool delete` | Exact pool/incarnation/revision confirmation, irreversible/fencing warning, original receipt; no unrelated target changes |
| Generate/discard | `key generate`, `key discard` | Exact generation/revision/preconditions; occupied stage or activation race preserves established rejection |
| Public key/backup export | `key verification-key`, `key export` | Explicit no-clobber destinations; encrypted artifact and public bindings retained; no primary plaintext key |
| Certificate | `certificate install` after off-primary signing | Matching public certificate validated; existing automatic activation rules, no new approval/archive gate |
| Recipient policy | `recipient set` with public record | Show recipient identity; result retained; only future artifacts change recipient |
| Reconciliation | `operation reconcile` with original receipt | Reuse original operation identity; never new-ID retry after uncertain submission |
| Service/config | Local approved host actions and existing daemon config parser/check | Working config preserved on invalid edit; observed service result, no implied node/pool readiness |
| Release/install/remove | [Distribution contract](distribution.md) | Authenticated compatible selection, reviewed ownership, retained data and post-checks |
| OTP | Foreground existing firmware tool, below | Original stage/readbacks/evidence, no inferred attestation |
| Backup role | Foreground existing local CLI, below | Restricted local output only after all evidence and memory checks |
| Producer hardening | Supplied drop-in plus approved systemd commands, below | Actual file install and command results; no runtime-policy audit |

For mutating CLI invocations, use structured argv with exact targets/revision and a new owner-protected receipt path; request `--json` for public results. The existing CLI owns receipt creation before submission, request identity and exit classes: 0 success, 2 invocation, 3 permission, 4 unavailable, 5 rejected, 6 uncertain, 7 local failure. If a subprocess disappears after its receipt is created, read/reconcile that receipt, even when no final stdout arrived. Never reconstruct a new request from a partial screen. Host maintenance records are separate because they track filesystem/service/firmware actions rather than device lifecycle operations.

## Setup inputs and service boundaries

Use existing config validation for explicit operator network/genesis inputs, paths, pool IDs, socket ownership and host policy. Show source paths/digests and exact agent-only diff. Do not discover node configuration, contact nodes, install Cardano CLI or infer forging. A missing public input is an actionable blocker. Existing normal-mode agent preflight still expects `cardano-node.service` and host swap/sleep/dump/snapshot policy; do not silently change or bypass it. Display that deployment constraint and supplied instructions, without adding node probes outside the producer exception.

For factory/BOOTSEL-only boards, offer the source-free first-install handoff in the [distribution contract](distribution.md) before commissioning; no unavailable application serial/pin is required or inferred from the bootloader. An already-running uncommissioned application goes directly to blank admission, not a flash. Observe the selected compatible application and blank state through one existing restricted commissioning daemon; nonblank, ambiguous, wrong or unknown post-state blocks commissioning. An interrupted first-install record remains the recovery authority and is not retried as new work. Commissioning is a separate explicit action on the intended blank board, followed by reviewed normal-mode pin/config installation. Stop restricted mode before normal service startup; never start a second USB owner. Unexpected commissioned devices require deliberate identity handling outside automatic setup, never reset or auto-pin. Restarting setup observes what completed; protected enrollment/receipts and existing config are not clobbered.

## Secret-bearing backup handoff

`--role backup` is an explicit local role, not a remote mode or proof of host history. Before opening any private path or asking a passphrase, check the managed installation role, agent service/runtime/socket and known primary config/state evidence. Active or configured primary evidence refuses; inaccessible evidence blocks rather than being interpreted absent. Binaries without primary state are allowed. No operator override of contradictory evidence. Explain that the operator must use a separate host and that unregistered historical primary use cannot be proven absent.

Suspend raw mode and alternate screen; invoke the authenticated CLI in the foreground with inherited terminal stdin/stdout/stderr, never captured/teed. Existing command forms are `recipient create --out PRIVATE --public-out PUBLIC` and `restore --artifact FILE --recipient-key PRIVATE --device-identity PUBLIC --device ID --pool ID --incarnation ID --generation ID --verification-key PUBLIC --out NEW_FILE`. Passphrase is entered only by the CLI's existing secure interaction, never argv/environment/TUI history. Restore terminal UI after child exit and retain only public outcome/path metadata. Memory-policy rejection, wrong recipient, tamper, missing identity/binding evidence or output collision publishes no key.

Explain plaintext output custody, original certificate lifetime, no revocation of other copies and operator fencing obligations. Do not contact a daemon/device/node, import keys into Pico2, or transfer private material. Only the recipient public record is offered for explicit primary transfer. Diagnostics must not read restored output or private recipient bytes.

## OTP handoff

Use authenticated `python3 -I firmware.py` in the foreground. Available surfaces: `verify --bundle DIR`; `inspect --serial SERIAL`; `provision --stage prepare|enable|lock --serial SERIAL --bundle DIR --record FILE` (preview); same with `--apply` for one explicitly approved stage. Preserve physical transitions and direct tool prompts; never feed confirmations programmatically. A daemon-mediated application observation may be required by the existing procedure: retain its foreground/two-terminal handoff without competing USB owners.

Require eligible blank target, exact serial/tool/bundle binding, supported hardware and required qualification before applying. Retain original protected record. Cancellation between stages preserves completed state and starts no next stage. An uncertain write blocks replay/advancement. Only original admitted pre-OTP `--resume` and read-only `reconcile-prepare --serial SERIAL --bundle DIR --record FILE --apply` are exposed as the existing tool permits; the latter flag does not authorize a repair write. Never expose `erase-state`, arbitrary record edits, generic reset instructions, signing-key prompts or automatic OTP in update recovery. After locking, offer ordinary commissioning as a separate action and state qualification limits.

## Producer drop-in exception

Operator supplies local concrete service unit names; do not discover producer nodes. Accept systemd escaped names and concrete instances, reject slash/traversal/control bytes, leading option syntax, empty template instances, non-service suffixes and names beyond systemd's unit-name limit. Validate before deriving paths or argv; do not shell-expand a name. Limit a single reviewed batch to 64 units.

After administrative approval, install the authenticated supplied `deploy/cardano-node-memory-hardening.conf` as `/etc/systemd/system/<unit>.d/pico2-kes-memory.conf`, using the same destination on repeats, preserving unrelated files. A pre-existing different file at that destination needs explicit replacement review. Use safe path ancestry and atomic file publication. Run `systemctl daemon-reload`. Query only selected units' running state to offer explicitly approved restarts; never start a stopped unit. If restart is deferred explain next-start/restart effect. File/command failure is reported accurately, including partial completion.

No new policy, runtime-policy inspection, dedicated test suite or multi-producer fixture. Acceptance is the installed file and requested command outcomes; rely on systemd semantics. Existing agent preflight remains unchanged. Uninstall retains/lists these drop-ins and does not restart producers.
