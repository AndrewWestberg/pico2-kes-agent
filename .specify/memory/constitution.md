<!--
Sync Impact Report — temporary review material; remove before committing.
Version change: unversioned → 1.0.0 (initial project adoption).
Basis: cardano-kes-forge constitution v1.1.0; its version and ratification date are
not inherited. Direct adaptation authorized in place of the unavailable resolver.
Modified principles relative to the source (titles retained):
- I. Explicit Scope and Correctness: bind scope to the project's KES-agent specification.
- II. Verifiable Behavior: distinguish host checks from device and node qualification.
- III. Stable and Explicit Interfaces: include USB, sockets, storage, and backup contracts.
- IV. Security at Trust Boundaries: define accepted authority, custody, and A2 claim limits.
- V. Simple, Maintainable Rust: require bounded device resources and failure isolation.
- VI. Software Observatory Quality Gate: retain the source gate without weakening it.
Added sections: all sections are new locally; no heading sections added to the source structure.
Adapted sections: Technical Constraints, Development Workflow, Governance.
Removed sections: none.
Dependent templates, commands, specifications, and application files: unchanged.
Deferred placeholders and follow-up TODOs: none.
-->

# pico2-kes-agent Constitution

## Core Principles

### I. Explicit Scope and Correctness

Every change MUST state its intended behavior, acceptance criteria, and relevant failure cases.
Implementation MUST remain within that scope; the project name alone does not establish product
requirements. Incorrect results and unsupported operations MUST produce explicit failures rather
than fabricated success. Correctness takes precedence over performance and convenience.

The accepted product scope is a persistent, multi-pool Cardano KES current-key provider, as
specified in `specs/001-pico2-kes-agent/spec.md`. The device manages KES state; authorized nodes
receive current keys and sign locally. General HSM functions, device-side block signing, cold-key
custody, and plaintext secret import into the device MUST NOT be introduced without an explicit
scope amendment. Prior projects supply reusable evidence and designs, not inherited requirements.

### II. Verifiable Behavior

Behavioral changes MUST be exercised through the affected executable or public interface before
acceptance. Bug fixes MUST demonstrate the reported failure before the fix when reproducible and
verify the corrected behavior afterward. Permanent tests MUST cover consumer-visible behavior,
boundaries, or failure modes rather than implementation details. Verification reports MUST name
the checks run, their results, and any unverified behavior; tests alone do not replace a smoke run.

Host tests and simulations MUST NOT be presented as proof of device durability, physical storage
cleanup, hardware capacity, or node interoperability. Qualification MUST exercise the accepted
Pico2 A2 and its identified fitted storage, including power interruption and recovery at persistent
transition boundaries. End-to-end acceptance MUST demonstrate the specified 64-pool workload and
accepted primary-producer blocks across evolution, rotation, and power recovery. Backup fidelity
MUST be checked against disposable generation-time state and an independent standard-format
decoder; running a backup producer is not a required acceptance gate. Evidence MUST distinguish
qualification targets from measured results.

### III. Stable and Explicit Interfaces

Changes to public commands, arguments, output formats, Rust APIs, USB messages, Unix-socket
protocols, persistent storage, or encrypted backup formats MUST document their input, output,
versioning, and error contracts. Breaking changes MUST identify affected consumers and provide a
migration decision before acceptance. All repository-owned callers and associated contract
documentation MUST be updated together. Cross-repository node changes MUST identify the matching
revisions and demonstrate interoperability before the combined behavior is accepted. Diagnostic
output MUST remain distinguishable from machine-consumed results.

Pool, generation, certificate, and operation identities MUST remain explicit wherever needed to
prevent substitution or duplicate mutation. Retry contracts MUST distinguish a rejected operation
from an uncertain outcome and reconcile the original operation rather than repeat a mutation.
Node integration MUST preserve existing file, singleton-agent, and external-signing credential
semantics and the existing KES-agent node-service behavior. Agent unavailability MUST NOT cause
an implicit file fallback.

### IV. Security at Trust Boundaries

External input MUST be validated before it controls sensitive operations. Secrets MUST NOT appear
in logs, diagnostics, version control, or committed fixtures. Cryptographic and encoding changes
MUST identify their governing specifications and demonstrate compatibility using authoritative
vectors or an independent implementation. Custom cryptographic primitives MUST NOT be introduced
when a maintained, compatible implementation is available.

Socket access is the accepted authorization boundary and grants full management and key access
across all pools. Pool and management sockets MUST share the same access policy; implementations
MUST NOT add per-pool credentials or a stronger administrator role. Certificate signatures,
lifecycle preconditions, and integrity checks remain mandatory. Failure isolation MUST NOT be
represented as protection against valid destructive commands from an authorized client.

Operational keys on the primary host MUST remain transient and MUST NOT persist through files,
logs, swap, dumps, or diagnostic traffic. Deployment review MUST address node memory, hibernation,
and snapshots. The shared backup recipient private key MUST remain on the backup host, never on
the primary or device. Local restoration on the backup host is the explicit exception permitting
publication of a conventional owner-restricted plaintext KES key file after validation.

Security claims MUST distinguish ordinary power-loss recovery and qualified operational erasure
from physical extraction, invasive remanence, malicious firmware, captured-storage rollback, and
copies retained by recipients or authorized hosts. The accepted A2 target MUST NOT acquire an A4
upgrade requirement by inheritance. Full-system forward security MUST NOT be claimed while
initial-key backups remain recoverable. Key delivery does not provide producer fencing.

### V. Simple, Maintainable Rust

Implementations MUST use the smallest design that satisfies the accepted requirements. New
abstractions and dependencies MUST have a concrete use case and a reviewable benefit. Changes MUST
remove code made obsolete by their replacement, not retain unused compatibility layers. Avoidable
allocation, copying, and repeated computation MUST be eliminated from changed execution paths.
Unsafe Rust MUST document its safety invariants and why safe alternatives do not meet the need.

Firmware memory, nonvolatile storage, flash endurance, and host client queues MUST have explicit
bounds justified against the full supported workload. Capacity evidence MUST include one active
and one staged generation for each of 64 pools; an older 32-pool layout is not evidence of fit.
Malformed or slow clients and isolated pool failures MUST NOT starve healthy pools. Shared-state
failures MUST be reported explicitly rather than hidden behind unsafe partial recovery.

### VI. Software Observatory Quality Gate

The Software Observatory MCP and its sensor catalog MUST guide the project's mandatory quality
gate. Before implementation, plans MUST consult the MCP to select applicable sensors, inspect
their full entries, and record their IDs, relevance, limitations, and coverage gaps. Keyword
suggestions are discovery aids, not proof of suitability. Catalog guidance MUST be translated
into executable project checks; consulting the MCP alone is not a passing sensor reading.

Before a code change or release is accepted, every applicable required sensor MUST have a valid,
passing reading for the candidate revision under a maintainer-approved gate definition. Missing,
stale, failed, or inconclusive readings MUST block acceptance. An unavailable MCP MUST block
sensor selection or revalidation; a previously approved, recorded selection MAY be executed
without a live MCP connection. Sensor definitions MUST be revalidated when their applicability
or tooling changes.

Each gate definition MUST record its sensor mapping, command, tool version, measured scope,
oracle or invariant, pass/fail rule, execution budget, and evidence artifact. Evidence MUST identify
the candidate revision, configuration, environment, exclusions, and result. An empty workload,
unexercised behavior, or a successful tool exit without the required measurement MUST NOT count
as a valid reading. Coverage measures execution, not correctness or test sensitivity.

The project MUST select, configure, and exercise Rust-compatible testing and benchmark tools
that produce the evidence required by the selected sensors and performance gates. Tools MUST
demonstrate relevant defect detection or controlled regression detection before their readings
are trusted. Thresholds, scope, and exclusions MUST be approved before evaluating the candidate;
they MUST NOT be weakened merely to make a failing candidate pass. This makes the gate evidence
of quality rather than a checklist of installed tools.

## Technical Constraints

- The established Cargo package is `pico2-kes-agent`, using Rust edition 2024. Firmware, the
  systemd service `pico2-kes-agentd`, and the utility `pico2-kes-agent-cli` MUST be implemented in
  Rust. Changes to this baseline MUST include an explicit compatibility rationale.
- One daemon MUST manage one accepted Pico2 A2 device over USB and remain its sole USB owner.
  Service-connected CLI operations MUST use the management socket, not bypass the daemon.
  Per-pool node-service sockets MUST retain stable pool bindings and common access permissions.
  Backup-host local restoration MUST work without a daemon or device connection.
- Successful persistent mutations MUST survive ordinary complete host/device power loss.
  Recovery MUST NOT precede an acknowledged transition or released successor. Required
  obsolete-secret cleanup and period catch-up MUST finish before affected key delivery.
  Ambiguous state or unverifiable erasure MUST make the affected pool unavailable, not trigger
  silent reset. Erasure claims MUST use qualified fitted-storage behavior, not file deletion
  or encryption alone, and MUST exclude external backups and already delivered host copies.
- KES evolution MUST be forward-only, based on validated per-pool network context, certificate
  start, and lifetime. Invalid, unavailable, or regressive period information MUST prevent unsafe
  delivery or mutation. Expiry MUST remove operational state without generating a replacement.
  New secrets MUST originate on-device with suitable entropy; entropy failure MUST fail closed.
- Each of 64 pools MUST retain an independent active and staged-generation slot. A new generation
  MUST NOT overwrite an occupied staged slot. Explicit discard MUST identify its generation,
  preserve the active key, and remain safe under activation races and retries. A 65th enrollment
  MUST fail without eviction or mutation of existing pools.
- Each generation MUST durably commit one immutable, recipient-encrypted, origin-authenticated
  initial-key artifact before generation success. The artifact MUST bind device, pool, generation,
  verification key, and recipient. Recipient changes MUST affect only future generations.
  Export MUST durably commit automatic activation intent; activation MUST wait for matching valid
  certification, timing, and cleanup, but MUST NOT wait for backup availability, archival,
  restoration, or separate approval. Retried operations MUST recover the same committed result.
- Dependencies MUST be declared through Cargo for Rust components and reviewed for maintenance,
  license compatibility, and security implications before adoption. Integration changes in other
  repositories MUST follow those repositories' build and dependency conventions.
- New requirements for storage layout, cryptographic suite, firmware framework, USB class,
  deployment services, or update mechanisms MUST come from an accepted specification or plan.
  Cloud management, distributed fencing, remote firmware updates, and mandatory irreversible
  device provisioning MUST NOT be inferred from predecessor projects.
- Build failures, failed checks, and unsupported environments MUST be reported explicitly;
  acceptance MUST NOT imply verification that was not performed.
- The quality-tooling selection MUST address behavioral tests, property-based tests, mutation
  testing, coverage, and reproducible performance benchmarks. It MUST assess fuzzing and other
  catalog sensors against actual project risks and document non-applicability rather than
  silently omit them. Tool choices MUST satisfy the selected sensor entries; catalog examples
  are not exclusive tool mandates.
- Rust tooling MUST integrate with Cargo and the supported Rust toolchain. Selection MUST record
  host and firmware targets, pinned versions, reproducible commands, runtime cost, and retained
  report formats. Required tools MUST be configured and verified before gates are declared active.
  Host-only tooling MUST state its firmware exclusions and the checks covering those gaps.
- Benchmark gates MUST define representative workloads, a baseline revision, environment controls,
  measured metrics, and noise-aware regression thresholds before candidate comparison. Results
  MUST distinguish a measured regression from an inconclusive comparison; neither may silently
  pass. A benchmark MUST NOT be assigned an invented Software Observatory sensor ID when the
  catalog has no matching entry; it remains an explicit project performance gate.

## Development Workflow

1. Define the change's scope, observable acceptance criteria, and affected contracts before coding.
   Identify relevant lifecycle, trust-boundary, resource, and power-loss invariants.
2. Review existing implementation and conventions; record any constitutional conflict before
   proceeding with an incompatible design. Consult the Software Observatory MCP, record the
   selected sensors and coverage gaps, and approve applicable gate definitions before coding.
3. Implement the scoped change and update affected callers, behavior tests, and documentation.
   Record cross-repository integration revisions when node or consensus behavior is affected.
4. Before acceptance, run `cargo fmt --check`, `cargo check`, `cargo test`, and
   `cargo clippy --all-targets -- -D warnings` for affected host Rust packages. For firmware,
   record and run the supported target-specific Cargo check/build and Clippy commands and the
   applicable host-model or on-device tests; a host-only pass does not cover firmware. Run the
   native checks of affected non-Rust integration repositories. Exercise changed behavior
   directly, including relevant failure paths and hardware-dependent paths on the target.
   Documentation-only changes instead MUST validate structure, internal consistency, and
   referenced project facts. Execute applicable sensor and benchmark gates and retain
   revision-linked evidence. Full product acceptance MUST meet the specification's qualification
   criteria; a narrower change smoke run MUST NOT be represented as full qualification.
5. Review evidence against acceptance criteria and each applicable principle. The Software
   Observatory quality gate MUST pass before code or release acceptance; unavailable or invalid
   required readings MUST NOT be waived as passing by a maintainer decision. Non-applicability
   MUST be justified in the approved gate definition, not asserted after a failure. Other
   unavailable checks MUST be recorded with their reason and require an explicit maintainer
   decision rather than a claim of success. Unresolved failures MUST block acceptance.

## Governance

This constitution governs project specifications, implementation plans, reviews, and acceptance.
Conflicting subordinate guidance MUST be amended or the proposed change MUST be rejected until a
constitutional amendment is approved. The initial project requirements are recorded in
`specs/001-pico2-kes-agent/spec.md`; that specification does not override this constitution.

Amendments MUST describe the proposed text, rationale, affected principles, compatibility impact,
and required migrations. A project maintainer MUST approve the amendment before it is treated as
ratified. Approval MUST be recorded in the change review or repository history. The original
ratification date MUST be preserved once established; the last-amended date MUST change whenever
governance content changes.

Constitution versions follow semantic versioning: MAJOR for incompatible principle removals or
redefinitions, MINOR for new principles or materially expanded guidance, and PATCH for
non-semantic clarifications or corrections. Version 1.0.0 establishes this project's initial
baseline, not a claim about the application's release maturity. This constitution is adapted
from `cardano-kes-forge` constitution v1.1.0; subsequent sibling amendments MUST NOT apply
implicitly and require this project's amendment procedure.

Every change review MUST check compliance with applicable principles and record unresolved
conflicts. Amendments MUST assess dependent guidance for inconsistency; changes to that guidance
require a separate scoped change. The Sync Impact Report is temporary review material and MUST be
removed before committing the amended constitution; it is not part of the governance rules.

**Version**: 1.0.0 | **Ratified**: 2026-10-27 | **Last Amended**: 2026-10-27
