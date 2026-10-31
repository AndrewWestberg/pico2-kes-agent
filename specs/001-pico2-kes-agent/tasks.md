---
description: "Completed implementation tasks for the persistent Pico2 multi-pool KES agent"
---

# Tasks: Persistent Pico2 Multi-Pool KES Agent

The maintainer-approved pragmatic software/device scope supersedes the earlier laboratory, repeated-manual-campaign, fixed coverage/mutation/benchmark, and supplied-leadership task breakdown. The completed convergence tasks below are the current implementation plan. Optional diagnostics remain documented in `contracts/quality-gates.md`; they are not unfinished product tasks.

## Runtime and lifecycle

- [X] T101 Wire bounded device-current polling and publish each committed bundle or terminal Drop through the exact pool subscription without converting temporary unavailability into revocation.
- [X] T102 Supply fresh exact-target period context, recover/catch up before delivery, and create a fresh context session after reconnect without guessed or regressive state.
- [X] T103 Integrate mixed file/agent native credential loading, identity validation, and cancellation-safe receiver replacement while preserving supported baseline source semantics.
- [X] T104 Implement durable staged evolution, eligibility, automatic activation, predecessor retirement, restart reconciliation, and direct node notification without backup-readiness gates.
- [X] T105 Implement protected recipient custody and fully offline authenticated restoration to a no-clobber owner-only conventional KES key file.
- [X] T106 Enforce 64-pool/128-generation capacity, bounded device/host scheduling, fair progress, and unchanged enrollment-65 rejection.
- [X] T107 Reconcile dynamic pool sockets with stable pool/incarnation bindings and the management socket's identical access policy.
- [X] T108 Read-verify obsolete-secret cleanup across generation, evolution, activation, discard, deletion, expiry, interruption, and recovery.
- [X] T109 Enforce terminal retirement and artifact retention/removal for replacement, expiry, discard, and pool deletion, including precise retired retries and warnings.
- [X] T110 Reconnect only the pinned device, reconcile pending operations, refresh period sessions, resume subscriptions, and shut down without false Drop.
- [X] T111 Harden deployment and host boundaries for locked memory, core dumps, swap/hibernation/snapshots, persistent outputs, and off-primary backup secrets.
- [X] T112 Bound management/node connections and deadlines, isolate pool failures, and expose required nonsecret device/pool health states.
- [X] T113 Apply shared recipient changes only to future generations while preserving existing artifact bytes and keeping private recipient material off the primary/device.

## Device and operator surfaces

- [X] T114 Build and qualify production firmware on the accepted Pico2 A2 using fitted JEDEC/SFDP geometry, assigned USB identity/stable serial, signed-image provenance (operational inference, not firmware readback or attestation), image/RAM fit, ready startup, and honest threat exclusions.
- [X] T115 Complete the daemon-only CLI lifecycle, status, warnings, receipts/reconciliation, recipient, local restore, stable JSON, and exit-code surface with no direct-USB escape path.
- [X] T116 Serialize exact staged discard against activation, preserve active/later-staged generations, retain retry outcomes, return `target_not_staged` precisely, and cover both orderings plus reboot cuts.

## Pragmatic acceptance

- [X] T117 Execute full-capacity qualification for 64 active plus 64 staged generations, pool-correct concurrent delivery, enrollment-65 rejection, stalled/malformed-client isolation, requests under 10 seconds, and recovery under 60 seconds.
- [X] T118 Execute deterministic persistent-transition cut regressions and production-device reset/reconnect recovery, with no rollback, primary plaintext persistence, or unverified cleanup.
- [X] T119 Exercise offline-backup rotation, lost generation/activation replies, stable export retry, restart, no superseded resurrection, and unchanged unrelated-pool state.
- [X] T120 Exercise exact key0 restoration and rejection of wrong-recipient, tampered, and identity-mismatched artifacts without publishing an output key.
- [X] T121 Build the pinned integrated native node and execute exact V2 node-service compatibility regressions; live repeated-SIGHUP/accepted-block campaigns remain optional integration evidence.
- [X] T122 Build and stage-install systemd/udev/operator artifacts, smoke installed binaries with valid configuration and the actual device, and cover denied/unavailable/rejected/uncertain outcomes.
- [X] T123 Execute bounded semantic fuzz smoke for every registered parser and deterministic production-core lifecycle fault-model scenarios; mutation, percentage coverage, and benchmark comparisons are optional diagnostics.
- [X] T124 Reconcile the specification, plan, quickstart, contracts, task plan, qualification manifest, and measured commands with the implemented pragmatic acceptance scope.

## Execution record

- Production device: Pico2 A2, USB `1209:4b45`, stable serial `00afd9003906a634`; persistent udev matching makes changing `/dev/bus/usb/001/0XX` addresses irrelevant.
- Implemented commands: `qualification foundation`, `hardware`, `load`, `native-regression`, `physical-context`, and `security`; host and firmware checks run directly. No aggregate gate dispatcher or benchmark runner is supplied.
- Current-source changes invalidate older candidate digests. Final verification MUST regenerate reports for the final dirty-source digest rather than treating an older report as current.
