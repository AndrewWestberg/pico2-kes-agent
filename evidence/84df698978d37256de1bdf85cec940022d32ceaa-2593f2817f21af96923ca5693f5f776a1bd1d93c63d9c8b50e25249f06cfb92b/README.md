# 2026-11-01 qualification: start here

This directory is the durable public record of the completed, attended **rc9→rc11 three-pool campaign**, measured at source commit `84df698978d37256de1bdf85cec940022d32ceaa`. The later documentation commit does not identify a new firmware build or a rerun. Do not repeat destructive qualification steps merely because these records exist.

## Read and verify

- [Qualification report](qualification-report.md): observed results, implementation/release commits, failed checks and retries, accepted exception, tool provenance, host restoration and security limits.
- [Acceptance index](acceptance-index.json): relative archive paths, byte counts/SHA-256, full identities, final pool state and public signature evidence. Historical session artifact handles are mapped to committed test logs; no session transcript is needed to inspect those results.
- [Preservation result](preservation-result.json): actual protected-memory state comparison, public bindings and activation/replenishment observations. Its adjacent attempt and nine context sidecars preserve the attended execution trail.
- [Final device inventory](final-device-inventory.jsonl), [security](final-device-security.jsonl) and [status](final-device-status.jsonl): authenticated observations at campaign close, **not current live state**.
- `public-proofs/`: 18 public socket-state signature proofs, including repeated period 2. `pool-1/`, `pool-2/`, `pool-3/`: public keys, certificates and original operation receipts. Together with deletion and recipient receipts, mutation sequences 49–76 are complete.
- Negative-image transfer records, 30-second connected-ROM observations, USB event traces and signed-recovery records are included for unsigned, wrong-key and tampered images.

Raw records retain original absolute command paths, socket names and timestamps to preserve provenance. They are **not portable replay instructions**. Release subdirectories contain public manifests only, not complete flashable bundles; obtain and authenticate all eleven release assets before any future transfer. Config/genesis snapshots describe a disposable synthetic network, not a production deployment.

## State left for the next operator

At campaign close:

- Device serial `00afd9003906a634`, ID `f39127e9e0ab25f8341401048acf629d`, original identity/authority, signed rc11; exactly three expected dummy pool incarnations.
- Absolute disposable period **33**, active relative period **1**; original start-32 generations active, replacements certified for **64**. Do not rewind these pools to the earlier period-0/1/2 fixtures.
- Existing management journal `/var/lib/kes-lab-dafa3a76/operations.journal` continued without reset; final successful sequence **76**, no pending receipt. Do not use an empty journal or assume 77 is still next without inspecting actual current state.
- Installed current-source daemon/CLI retained. Ordinary service **inactive/enabled**, original config unchanged. Swap and sleep policy restored; the temporary runtime directory and lab scripts/probe were removed. Do not start the agent without re-establishing its real protection prerequisites and a valid current config/context.

Before new physical work, reauthenticate the pinned board, inspect current policy/state and journal/receipts, fence any producer, and establish a new attended protected window. Never re-pin, erase state, program OTP, reset counters or replace the journal to make a fixture run.

## Evidence boundaries

All six original pools had host journal bindings. The operator explicitly accepted documenting the unavailable physical-orphan scenario; real-core host smoke covered unbound discovery/deletion. This archive does **not** establish full `qualification security`, live forging, interrupted-update recovery, populated downgrade, A4 behavior, external SWD denial or invasive-extraction resistance. Historical OTP-repair/context incidents remain limitations. Executed native verification used kes-agent **1.3.0.0**, not the separately inspected 1.4 sources.

The original owner-only workspace `/home/westbam/pico2-qualification-2p9qdufn` retains private disposable credentials/counters, encrypted backups and original host-state archives. These remain **outside Git**; they are not needed to read the public record. Do not copy that workspace wholesale into the repository. No private keys, passphrases, current KES states/state hashes, backup payloads, complete host journals or firmware binaries are included here.
