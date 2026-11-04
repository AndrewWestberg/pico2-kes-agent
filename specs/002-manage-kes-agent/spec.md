# Feature Specification: Pico2 KES Agent Management TUI

**Feature Branch**: Not created; no branch-creation hook is configured.

**Created**: 2026-11-01

**Status**: Ready for planning — scope clarified 2026-11-02

**Input**: User description: "Create a new spec for a shell-script-installed tui for installing, setup, managing, upgrading, downgrading, monitoring, and managing the pico2 kes-agent system. This single script should work similarly to things like rustup, ghcup (ghcup tui). It should be smart enough to determine what pieces are installed on the system, what is currently running on the pico2 device which includes the firmware version and the pools and their kes status. It should have a tui for displaying all information as well as downloading and installing new firmware, updating any daemons or cli executables. Basically, a management system for this entire project. Grill me with any questions for things that are unclear."

## Clarifications

### Session 2026-11-02

- Q: Which host CPU architectures must the first release support? → A: x86-64 Linux only.
- Q: When required host tools are missing, should the installer offer to install them or leave installation to the operator? → A: Offer installation after showing the required tools and proposed changes and obtaining operator approval.
- Acceptance scope: End-user testing of the actual `p2kesup` workflows is the primary quality gate. No high-code-coverage target or elaborate new unit/integration/property/mutation/fuzz/benchmark program is required for this feature. Retain existing affected regression/build checks, small checks for new critical logic, the constitution-required bounded performance comparison and sensitivity check using existing tooling, and all specified rejection, preservation and physical-device acceptance behavior.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Discover and monitor the actual installation (Priority: P1)

An operator opens one terminal management interface and sees what is installed, what is running, which Pico2 is connected, and whether each pool can supply valid KES state. Inspection works even when installation or configuration is incomplete.

**Why this priority**: Every installation, maintenance, and recovery decision depends on distinguishing observed state from assumptions.

**Independent Test**: Open the manager against absent, partial, healthy, disconnected, and mismatched installations; compare its inventory with independently established host and device state without making changes.

**Acceptance Scenarios**:

1. **Given** no agent software is installed, **When** the operator launches the manager, **Then** it identifies the host support status and missing components, offers installation, and does not require a running daemon or connected device to open.
2. **Given** installed executables differ from the running service or firmware, **When** inventory completes, **Then** installed, running, and selected release versions are shown separately with their locations and evidence source; unknown versions are explicitly unknown.
3. **Given** a device has pools absent from host configuration, **When** inspection completes, **Then** all device pools and all host bindings are visible, unmatched entries are identified, and no binding or device state is silently changed.
4. **Given** active and staged generations across up to 64 pools, **When** the operator opens pool details, **Then** each pool shows its identity, generation identities, certificate validity, current KES period, remaining periods, readiness, and any context or storage failure; unavailable fields carry an explanation.
5. **Given** a previously healthy device disconnects or access is denied, **When** refresh occurs, **Then** affected observations become stale or unavailable with their last observation time; an unsuccessful inventory is never displayed as zero pools.
6. **Given** monitoring is open, **When** an operator navigates by keyboard, resizes the terminal, or inspects a failure, **Then** navigation remains usable, health is understandable without color, and relevant diagnostics contain no secret key material. No maintenance or pool mutation is initiated merely by viewing status.

---

### User Story 2 - Install and set up a usable system (Priority: P1)

An operator starts with one published shell-script entry point and is guided from a bare or partially configured host to an installed agent, a verified device identity, and a correctly configured service.

**Why this priority**: The requested manager must replace fragmented installation and setup work, not only present existing status.

**Independent Test**: Complete source-free installation and commissioning on a supported disposable host, both from a factory/BOOTSEL-only board without application firmware and from compatible application firmware with blank/uncommissioned storage; decline optional OTP in both cases. Repeat setup against an existing configured installation and verify its state is preserved.

**Acceptance Scenarios**:

1. **Given** a supported host and access to trusted releases, **When** the operator runs the published HTTPS curl pipeline, **Then** it reviews dependencies and changes and directly installs the persistent command without a source checkout or menu installation, explains how to reopen the TUI, and leaves hardware setup for later. Explicit `--version TAG` selects an RC for reviewed disposable-host acceptance; `--role backup` selects the isolated backup role.
2. **Given** missing required host tools on a supported host, **When** preflight runs, **Then** the manager shows the tools and proposed changes, offers installation with explicit approval, and continues the affected setup step only after those prerequisites are available. Declined or failed installation leaves that step blocked with an actionable explanation. Unsupported hosts or unavailable compatible tools are reported without bypassing prerequisites.
3. **Given** an existing configuration, public journal, receipts, and device pin, **When** setup is rerun, **Then** these remain intact unless a specific reviewed change is approved; manually installed or externally managed components are not silently adopted or overwritten.
4. **Given** a supported factory/BOOTSEL-only board without application firmware, or a board already running compatible firmware with blank/uncommissioned storage, **When** attended setup is chosen, **Then** the first case receives authenticated firmware through an explicitly selected physical target before application-based blank admission; the second proceeds directly to that admission. Both paths separately confirm commissioning, establish and retain the public identity, validate network and host-policy inputs, and produce a usable normal-mode configuration. First installation requires neither a pre-existing application pin nor OTP, never writes operational storage or erases an unexpected device, and must refuse commissioning if the resulting application state is nonblank, mismatched, or unknown.
5. **Given** a setup step is cancelled, denied permission, or interrupted, **When** the manager is reopened, **Then** completed steps and unmet prerequisites are accurately identified and existing state is preserved rather than setup restarting destructively.
6. **Given** public network inputs supplied or discovered from local systemd node configuration, **When** setup validates them, **Then** it identifies their source, rejects missing, malformed, or inconsistent inputs, and previews agent-only configuration changes without contacting or changing a node. Existing device membership is discovered independently.

---

### User Story 3 - Select, install, upgrade, and downgrade releases safely (Priority: P1)

An operator sees available releases and compatibility, chooses versions of the manager, daemon, CLI, and device firmware, reviews the maintenance impact, and installs the chosen compatible combination.

**Why this priority**: Software maintenance is a core request and risks both service availability and irreplaceable KES state.

**Independent Test**: Change host and firmware versions on a commissioned test system with active and staged generations, including a compatible downgrade, an incompatible selection, an unauthenticated download, and an interrupted firmware transfer.

**Acceptance Scenarios**:

1. **Given** installed versions and trusted release information, **When** a release is selected, **Then** the operator sees current and proposed versions, compatibility with the host/device and persistent state, prerequisites, and expected service interruption before approving changes. Prereleases require deliberate selection.
2. **Given** missing authenticity evidence, altered content, unknown compatibility, or an incompatible target, **When** installation is attempted, **Then** execution or flashing of that content is blocked without weakening verification or modifying persistent KES state.
3. **Given** a compatible host upgrade or downgrade, **When** maintenance completes, **Then** the selected host components are installed, the intended service state is restored after checks, and configuration, permissions, device pin, public journal, and receipts remain intact. Running and installed versions are independently rechecked.
4. **Given** a compatible signed firmware release and the intended device, **When** the operator follows attended bootloader instructions and installs it, **Then** success requires reconnection to the same pinned application identity, observation of the selected firmware, and checks of retained pool and generation bindings; a completed file copy alone is not success.
5. **Given** maintenance spans legitimate KES evolution, activation, or expiry, **When** pre/post observations are compared, **Then** those forward transitions are distinguished from loss, and no clock, period floor, journal, or device state is rolled back to make the comparison pass.
6. **Given** transfer interruption, reboot failure, or partial host replacement, **When** recovery is offered, **Then** the actual or uncertain outcome is shown with the last confirmed step and a compatible recovery path; the manager never erases state, recommissions, changes device pins, or repeats irreversible provisioning to repair an update.
7. **Given** an installed role and a selected release, **When** the operator runs `p2kesup upgrade`, `p2kesup upgrade --version TAG`, or `p2kesup upgrade --bundle DIRECTORY`, **Then** the role is inferred and the complete signed host and firmware tuple is reviewed and coordinated; an already installed tuple is a no-op. Attended firmware action remains required. An interrupted operation is resumed forward only with `p2kesup upgrade --resume ORIGINAL_PLAN_PATH`, without authorizing arbitrary mixed tuples or restoring old KES state.
8. **Given** release discovery is unavailable, **When** the TUI opens, **Then** local inspection remains usable, cached release information is labelled with its age, and a previously obtained authentic compatible bundle can be selected for offline maintenance if all verification prerequisites are available.

---

### User Story 4 - Perform day-to-day pool and KES management (Priority: P2)

An operator completes the full pool lifecycle through guided workflows with explicit targets, clear prerequisites, and retained results, rather than assembling fragile command sequences.

**Why this priority**: Project-wide management must cover operational tasks beyond software installation while preserving the existing custody and mutation rules.

**Independent Test**: On a disposable pool, exercise every agent-side lifecycle action listed in FR-016, including cancellation and uncertain-result reconciliation, without placing cold or backup-recipient private keys on the primary host.

**Acceptance Scenarios**:

1. **Given** an authorized operator and a supported lifecycle action, **When** it is selected, **Then** the TUI shows the exact device, pool incarnation, generation where applicable, prerequisites, and consequences before submission; unavailable actions explain why they are unavailable.
2. **Given** a new or rotating pool, **When** its generation and certificate workflow is followed, **Then** public verification material and encrypted backup artifacts can be exported to explicit operator destinations, offline certificate signing remains off-primary, and the matching public certificate can be installed without an extra activation-approval gate.
3. **Given** an occupied staged slot, stale revision, expired generation, or invalid context, **When** an action is attempted, **Then** the established lifecycle rejection is preserved and no unrelated pool or active generation is replaced.
4. **Given** deletion or staged-generation discard is requested, **When** the operator reviews it, **Then** the affected identities and irreversible consequences are shown, preservation/fencing guidance is provided, and explicit confirmation is required. Cancellation leaves state unchanged.
5. **Given** an operation times out or the TUI closes after submission, **When** it is reopened, **Then** the original operation receipt remains available and the operator can reconcile that operation instead of blindly submitting a new mutation.
6. **Given** a public recipient record, **When** the operator installs or rotates the recipient, **Then** the selected public identity is confirmed, the result is retained, and the interface explains that only future artifacts use the new recipient and old artifacts still require their original private keys.
7. **Given** valid public pool inputs and an available device slot, **When** enrollment is confirmed, **Then** the new pool incarnation is reported and its agent binding is reviewed. A 65th enrollment is rejected without evicting an existing pool.

---

### User Story 5 - Operate, diagnose, and remove host components (Priority: P2)

An operator starts, stops, restarts, diagnoses, and uninstalls the agent components from the same interface. Agent health is reported without inspecting node connections or controlling a Cardano node outside the explicit producer memory-hardening workflow.

**Why this priority**: A management tool must handle ordinary maintenance and failed systems, not just the successful first installation.

**Independent Test**: Exercise service actions and diagnostics on an existing installation, inject a configuration failure, then uninstall and confirm retained operator/device data.

**Acceptance Scenarios**:

1. **Given** a configured installation, **When** start, stop, or restart is requested, **Then** service permissions and prerequisites are checked, disruption is explained, and the observed result is reported; a failed start is not reported as healthy.
2. **Given** configuration changes are proposed, **When** validation fails, **Then** the working configuration remains in place with an actionable explanation; when accepted, only reviewed settings change and required restart is explicit.
3. **Given** the daemon is running but a pool is not ready, **When** health is shown, **Then** host service, device connection, and pool readiness are separate indicators. Node connection, consumption, and forging are neither checked nor inferred; agent health remains inspectable without a node connection.
4. **Given** uninstall is selected, **When** removal is confirmed, **Then** the operator sees exactly which managed host components will be removed; configuration, journal, receipts, identities, service identity, and device state are preserved, and remaining data is listed. Uninstall is not presented as secure wiping.
5. **Given** diagnostic information is viewed or saved, **When** a sensitive operation or failure has occurred, **Then** useful public identities and failure reasons remain available without current KES secrets, cold keys, recipient private keys, passphrases, or raw secret-bearing traffic.

---

### User Story 6 - Provision optional device security deliberately (Priority: P2)

An operator elects to perform the existing irreversible device-locking procedure on an eligible blank device before commissioning, with guided preparation, enablement, and locking stages.

**Why this priority**: The selected full-management scope includes OTP provisioning, but accidental locking or unsafe retries can make a device unusable.

**Independent Test**: On a supported sacrificial device with the required hardware qualification, complete the attended stages and verify their recorded observations. Exercise refusal and cancellation paths, and qualification-controlled interrupted-stage cases; simulations alone do not establish safe OTP behavior.

**Acceptance Scenarios**:

1. **Given** normal installation or an already commissioned device, **When** setup opens, **Then** irreversible provisioning is not selected or run automatically; the nonblank device is refused without erasure. The operator may use an unlocked supported device without being forced to provision.
2. **Given** one eligible intended device and an authenticated release bundle, **When** provisioning is explicitly selected, **Then** the manager presents the irreversible effects, recovery limitations, target identity, prerequisite evidence, and read-only preview; no write occurs before exact target confirmation.
3. **Given** preparation, enablement, or locking is ready, **When** the operator confirms that stage and performs the required physical transitions, **Then** only that stage proceeds, its required readbacks and application observations are checked, and the original protected record is retained before advancing. No secret firmware-signing key is requested.
4. **Given** unsupported hardware, missing qualification, mismatched identity/tool/bundle evidence, nonblank storage, or unexpected prior OTP programming, **When** admission is checked, **Then** applying the stage is blocked with the specific reason; no bypass or weaker verification is offered.
5. **Given** an OTP write or observation fails or is interrupted, **When** the manager is reopened, **Then** it preserves the record and uncertainty, blocks automatic replay or advancement, and provides only the recovery or read-only assessment admitted by the existing procedure. It does not edit records or recommend a generic reset/power-cycle.
6. **Given** final locking observations pass, **When** completion is displayed, **Then** it states exactly what was observed and any remaining qualification limits, distinguishes application reports from independent attestation, and offers ordinary blank-device commissioning as a separate action.

---

### User Story 7 - Manage backup-recipient and restoration work off-primary (Priority: P2)

An operator uses the same manager on a separate backup host to create recipient material and restore a verified encrypted artifact, without connecting a device, contacting the primary, or configuring a producer node.

**Why this priority**: Full lifecycle management includes recovery while retaining the project's separate-host private-key custody boundary.

**Independent Test**: On an isolated backup host without a daemon or device, create a recipient, restore a valid disposable artifact, and reject wrong-recipient, tampered, identity-mismatched, and output-collision cases.

**Acceptance Scenarios**:

1. **Given** an explicitly selected backup-host workflow, **When** the operator creates a recipient, **Then** private material is kept in a protected local destination and only its public record is offered for transfer to the primary; existing output files are not overwritten.
2. **Given** an encrypted artifact, its matching private recipient, independently trusted public device identity, and matching public pool/generation/verification records, **When** restoration succeeds, **Then** the conventional signing-key file is published only to the selected owner-restricted nonexisting local destination. Secrets and passphrases never appear in the TUI history or diagnostics.
3. **Given** missing evidence, active swap, wrong recipient, tampering, identity mismatch, or output collision, **When** restoration is attempted, **Then** it fails without publishing or replacing a signing-key file.
4. **Given** a restoration is requested, **When** its consequences are reviewed, **Then** the manager explains plaintext-key custody, original certificate validity, and the operator's responsibility for producer fencing. It does not contact, check, configure, start, or stop any node, and restoration does not import keys into a Pico2.
5. **Given** the manager is operating on the primary host, **When** private-recipient creation or restoration is requested, **Then** it directs the operator to the separate backup-host workflow rather than accepting private recipient material on the primary.

---

### User Story 8 - Memory-harden local block-producer services (Priority: P2)

An operator supplies the local block-producer service names and installs the project's existing systemd memory-hardening drop-in for those services.

**Why this priority**: Producers retain delivered KES material in memory; hardening only the agent leaves the producer's memory exposure unaddressed.

**Independent Test**: No dedicated test suite, multi-producer test setup, or runtime-policy audit is required. Acceptance is successful file installation and completion of the requested systemd commands; systemd's drop-in behavior is relied upon, not re-tested.

**Acceptance Scenarios**:

1. **Given** operator-selected producer service names and administrative approval, **When** hardening is requested, **Then** the manager installs `deploy/cardano-node-memory-hardening.conf` as `/etc/systemd/system/<unit>.d/pico2-kes-memory.conf` for each selected unit and runs `systemctl daemon-reload`, leaving unrelated files and services unchanged.
2. **Given** the drop-in is installed, **When** the operator approves a producer restart, **Then** the manager runs the restart and reports the command result; otherwise it explains that the policy will apply on the next start/restart. It does not start stopped producers automatically.
3. **Given** a file operation or systemd command fails, **When** the action finishes, **Then** the manager reports the failure rather than claiming successful completion.

### Edge Cases

- Multiple attached boards, a replaced board, changing USB addresses, or bootloader identifiers that cannot be safely associated with the pinned application identity: require explicit attended target selection; never guess a flash destination.
- Stopped or missing daemon, inaccessible device, denied management access, unsupported older firmware, and unreadable device inventory: distinguish each from an empty or healthy installation.
- Multiple executable copies, changed executable search paths, custom service paths, and mixed-version components: identify the effective service executable and avoid overwriting an unrelated installation.
- Device pools missing host bindings, host bindings missing device pools, and per-pool corruption: show discrepancies without automatic enrollment, deletion, binding repair, or device-wide failure claims.
- Missing or stale trusted context: do not invent period or expiry estimates; display the missing authority and block operations already prohibited by the agent.
- Concurrent management activity, revision changes during a confirmation, and TUI closure after submission: revalidate targets and preserve original operation reconciliation.
- Insufficient disk space, permission denial, interrupted downloads, invalid release metadata, or unavailable verification tools: fail before destructive replacement wherever possible and report any partial change precisely.
- Device removal during flashing, stale or nonexistent bootloader mount, failed flush, and failed reboot: report uncertainty and require safe target re-identification before recovery.
- Host rollback that cannot interpret current configuration/journal, or firmware rollback that cannot interpret current stored state: block the rollback rather than reverting data.
- Expiry or activation during maintenance: compare identities and legitimate lifecycle transitions rather than assuming unchanged period values.
- Network loss, small terminals, non-color terminals, and non-interactive input: retain useful local diagnostics, readable keyboard navigation or a clear terminal-size requirement, and do not perform unattended mutations in place of interactive confirmation.
- Partially programmed OTP, pending provisioning records, mismatched provisioning tools, and cancellation between stages: preserve the original evidence; only explicitly admitted checkpoints may resume, never uncertain writes.
- Backup-host restoration with missing public identity records, an existing output file, or unsafe host memory policy: refuse publication without weakening custody or overwriting a key.
- Operator-supplied pool files that disappear, conflict with existing bindings, or contain invalid network parameters: preserve working configuration and report the exact input problem; never query a node to fill gaps.
- Invalid producer unit names, insufficient permissions, or failed systemd commands: report the error without modifying unrelated files or services.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The product MUST provide one published shell bootstrap script usable as the documented HTTPS curl pipeline, directly installing a persistent terminal management executable and selected project components after review, with a documented way to reopen the TUI. It MUST read attended prompts from `/dev/tty` when piped and refuse noninteractive mutation. Installation and privileged manager actions MUST work entirely in a local terminal or SSH session with a terminal allocated, without a desktop or GUI authentication agent. Password authentication MUST remain in the foreground terminal without capturing passwords or weakening explicit action approvals. The TUI itself need not be a shell script; no source checkout or manual project build is required for a supported release.
- **FR-002**: Before installing, the manager MUST identify host support, existing components and ownership, missing prerequisites, required privileges, intended paths, and proposed changes. The first release MUST support x86-64 Linux hosts using the project's systemd/udev deployment baseline; other host architectures and unsupported environments MUST fail clearly before mutation. On supported hosts it MUST offer to install missing required tools after showing the proposed changes and obtaining explicit approval. Declined, failed, or unavailable prerequisite installation MUST block the dependent step with an actionable explanation, never bypass its checks. Inspection MUST not require blanket administrator privileges.
- **FR-003**: The inventory MUST distinguish installed manager/CLI/daemon versions and locations, running daemon version and service state, live firmware version, device identity and connection mode, configuration readiness, and release availability. Each unavailable or inferred fact MUST be labelled rather than substituted with an expected value.
- **FR-004**: Pool discovery MUST reconcile the complete authenticated device membership with host bindings, covering all 64 supported pools. Failed or unsupported discovery MUST NOT be interpreted as an empty device or authorize destructive cleanup.
- **FR-005**: Pool views MUST expose device/pool/incarnation identity, active and staged generations, certificate start and expiry periods, current absolute and generation-relative KES periods, remaining valid periods, publication/readiness state, context validity, and blocking reasons when available. Estimated time to expiry MUST identify its trusted inputs and be withheld when those inputs are unavailable or stale.
- **FR-006**: Monitoring MUST refresh while the TUI is open, show observation age and connection failures, support manual refresh and keyboard-only navigation, and convey status without color alone. Observation MUST NOT automatically install, repair, restart, enroll, delete, generate, export, or change configuration.
- **FR-007**: Installation and setup MUST cover the manager, agent daemon, operator CLI, host access/service configuration, firmware acquisition and attended first installation on a factory/BOOTSEL-only board, attended device commissioning, public device pinning, and transition to normal operation. First installation MUST use authenticated compatible firmware, explicit physical target selection and retained transfer evidence without requiring a nonexistent application identity, a source build, erasure, or OTP. Before commissioning, the sole commissioning daemon MUST observe the selected firmware and blank/uncommissioned application state; unknown or nonblank state blocks commissioning. Existing data MUST be preserved; rerunning setup MUST resume from observed state.
- **FR-008**: Setup MUST explain and validate required device identity, network context, host memory/security policy, and service-access inputs before declaring readiness. It MUST NOT silently change host-wide security policy or reset an unexpected device to satisfy preflight.
- **FR-009**: Operators MUST be able to discover releases, view installed/running/available versions, explicitly select releases and review the complete compatible change set before installation. `p2kesup upgrade` MUST infer the installed role and coordinate the full signed host and firmware tuple; `--version TAG` selects an exact release, `--bundle DIRECTORY` selects offline, and an already installed tuple is a no-op. Firmware actions remain attended; interruption MUST use forward-only `--resume ORIGINAL_PLAN_PATH`. Stable releases are the default; prereleases require explicit selection. No unattended version change is implied.
- **FR-010**: The documented bootstrap pipeline explicitly trusts its HTTPS-hosted initial launcher; this does not claim OpenPGP verification of that launcher. The installer and manager MUST establish downloaded payload authenticity from the pinned project authority before running project payload code or installing firmware, verify completeness/integrity and target compatibility, and reject invalid or unknown evidence. A downloaded verifier declaring itself trustworthy is insufficient. Signed authorization of an exact compatible candidate tuple MUST be distinct from final release qualification: candidates may be admitted only through explicit tag or local-bundle acceptance on reviewed disposable targets, with unchanged trust/state/hardware prerequisites and no claim of qualification. Default discovery MUST offer qualified stable releases only. Promotion MUST bind passing evidence to unchanged tested payload digests, not rebuild or alter code after acceptance.
  - The pinned OpenPGP authority MUST separately authorize distribution use of the existing secp256k1 key through a locally signed public statement. The firmware-only delegation remains unchanged and MUST NOT authorize host distributions by implication. CI MUST use the delegated key with distinct distribution/bootstrap signature contexts, never receive the personal PGP private key, and MUST NOT replace independently signed human qualification approval with its own release signature.
- **FR-011**: Upgrades and downgrades MUST be permitted only where the selected host tools, firmware, hardware, and current persistent-state interpretation are compatible. Unknown compatibility MUST block the change. Software downgrade MUST never mean KES-period rollback, restoration of an older journal/flash snapshot, or deletion of unsupported state.
- **FR-012**: Every maintenance operation MUST show its scope, target identities, version changes, affected pools, disruption, and recovery prerequisites before approval. It MUST preserve configuration, permissions, public identity/pin, journal, receipts, recipient policy, and device pool/generation state; legitimate forward lifecycle transitions remain allowed.
- **FR-013**: Firmware installation MUST use authenticated compatible content and an explicitly identified attended device. It MUST guide necessary physical bootloader actions, validate the actual destination, and preserve operational storage. Updates of an existing installation MUST verify reconnection, expected firmware, pinned identity, and retained public pool/generation bindings before declaring completion. First installation before any pin exists MUST instead meet FR-007's application-build and blank-admission checks; a missing pin on an existing installation MUST NOT authorize this path. Missing verification MUST produce an incomplete or uncertain result, not success.
- **FR-014**: Failed maintenance MUST retain the last confirmed step and public diagnostic evidence, report whether mutation is known or uncertain, and offer only compatible recovery actions. Recovery MUST NOT silently erase, recommission, re-pin, restore older KES state, or perform irreversible device locking.
- **FR-015**: The manager MUST remain usable for local status and diagnosis without release-network access. It MUST distinguish cached from fresh release information and support installing already obtained trusted compatible release bundles when verification dependencies are available.
- **FR-016**: The management surface MUST cover commissioning; pool enrollment, listing, detail inspection, and deletion; staged generation creation and discard; public verification-key and encrypted-artifact export; public certificate installation; public recipient installation/rotation; and original-operation reconciliation. It MUST also provide the separate backup-host recipient/restoration workflows and optional attended OTP provisioning specified below, preserving each action's existing validation, identity, confirmation, and record requirements.
- **FR-017**: Lifecycle workflows MUST preserve off-primary cold signing and backup-recipient private-key custody. Primary-host workflows may handle public inputs and encrypted backups, never request those private keys or persist plaintext operational KES state. Backup restoration MUST remain an explicit backup-host operation under the existing restricted-output policy.
- **FR-018**: Destructive or mutating operations MUST identify exact targets, revalidate current preconditions, require deliberate confirmation where destructive, retain durable receipts, and reconcile uncertain outcomes using the original operation identity. The TUI MUST retain existing socket-based authorization without inventing per-pool credentials or an additional administrator role.
- **FR-019**: Operators MUST be able to start, stop, restart, inspect diagnostics, and review/validate configuration changes for the agent service. Configuration validation failure MUST preserve the previous working configuration. Service uptime MUST NOT be represented as evidence of valid pool delivery or successful block production.
- **FR-020**: The manager MAY perform bounded read-only discovery of local systemd node units and referenced public node configuration, environment and genesis files for network selection and producer-unit suggestions. It MUST NOT execute node scripts, open a node socket, run Cardano CLI, check node integration, or otherwise install, configure, update or control nodes. Missing, invalid or conflicting inputs MUST block rather than fabricate defaults. The producer exception permits only installing the supplied drop-in, reloading systemd and explicitly approved producer restarts. Existing agent security protections remain enforced.
  - Reviewed configuration MUST import public genesis files under `/etc/pico2-kes-agent/genesis/<network>/` as root-owned mode 0644, rechecking source and destination digests and refusing to clobber different bytes.
  - **Set up my Pico 2**, **Add a pool**, and **Rotate KES key** MUST guide the corresponding jobs with existing mutation, admission and receipt safety. Add enrolls and binds before rotation; only a certain durable missing-recipient generation rejection permits selecting and setting a public recipient before a fresh generate. Uncertain outcomes MUST use original-operation reconciliation.
  - **FR-030 (wipe and recommission)**: An explicit attended **Wipe board and start over** MAY erase only an eligible OTP-unlocked commissioned board after reviewed target, complete inventory and safety evidence. It MUST stop services, archive host configuration and state including the journal under root-owned mode 0700 `/var/lib/p2kesup/archive/<operation-id>/`, verify erasure and blank state, and require separate commissioning. Recovery MUST be forward-only and MUST NOT retry an uncertain erase or automatically restore the archive. Wipe MUST NOT be offered as update or OTP recovery.
  - **FR-031 (local KES clock)**: Rotation MUST calculate the current absolute KES period locally from validated genesis timing and host UTC using daemon-equivalent arithmetic, not a node query or Cardano CLI. The operator remains responsible for correct time and network inputs.
  - Root and firmware handoffs MUST require attended default-no `[y/N]` approval, retaining plan digest binding and revalidation; no scripted confirmation or nonterminal mutation is allowed.
- **FR-021**: Uninstall MUST remove only explicitly selected manager-owned host components and preserve operator configuration, public journal, receipts, device identity, service account/group, and all device storage. Applied producer memory-hardening drop-ins MUST also be retained and listed, without restarting producers. It MUST list retained data and never imply secure erasure or revocation of already delivered keys.
- **FR-022**: Diagnostics, maintenance records, and on-screen status MUST exclude secret-bearing traffic, plaintext KES material, cold/private recipient keys, and passphrases. Public evidence MUST remain sufficient to identify failures and reconcile operations. Device application reports MUST NOT be labelled independent hardware attestation.
- **FR-023**: The manager MUST respect the daemon as the sole owner of the operational USB connection and preserve existing lifecycle safety checks. Attended firmware maintenance MUST coordinate daemon shutdown and subsequent validation rather than competing with the running service for the device.
- **FR-024**: Optional irreversible OTP provisioning MUST be a separate attended workflow before commissioning, with read-only preview, explicit exact-device confirmation for each applying stage, and the existing preparation, enablement, and locking order. It MUST verify supported hardware, blank/uncommissioned admission, authenticated bundle, bound tools, and required qualification evidence before writes. It MUST NOT erase a populated device to make it eligible, run implicitly, or become a firmware-update/recovery step.
- **FR-025**: Provisioning MUST preserve the existing physical-transition, direct operator-confirmation, readback, protected-record, and post-stage observation requirements. A foreground handoff from the TUI to the trusted provisioning tool is acceptable; scripted confirmation or loss of terminal interaction is not. Failed or uncertain stages MUST retain their original records and block automatic replay/advancement; only specifically admitted recovery checkpoints or read-only assessment may be offered. Completion MUST distinguish observed locking from unproven physical-security claims.
- **FR-026**: A separate backup-host workflow MUST support recipient creation and authenticated local restoration without a daemon or device. It MUST require independently trusted identity and matching artifact/public bindings, preserve the existing host-memory protections, and publish plaintext restored keys only to owner-restricted nonexisting destinations. Wrong credentials, invalid evidence, unsafe memory policy, or destination collisions MUST fail without key publication. Private material MUST NOT be accepted in the primary-host workflow.
- **FR-027**: Backup workflows MUST explain that restoration neither extends certificate validity nor revokes other copies, and that the operator remains responsible for producer fencing and any node use. They MUST NOT configure or inspect a node, import restored secrets into a device, or transfer private recipient material to the primary. Public recipient transfer and encrypted backup export MUST remain explicit operator actions.
- **FR-028**: The manager MUST offer installation of the existing [producer memory-hardening drop-in](../../deploy/cardano-node-memory-hardening.conf) at `/etc/systemd/system/<unit>.d/pico2-kes-memory.conf` for operator-specified local producer units, including custom names and concrete instances. Unit names MUST be validated before use as paths or command arguments. Installation MUST require administrative approval, reuse the same destination on repeat runs, and preserve unrelated files and services.
- **FR-029**: After installation, the manager MUST run `systemctl daemon-reload` and offer an explicitly approved restart of the selected running producers. If restart is deferred, it MUST explain that the policy applies on the next start/restart. It MUST report file-operation and command failures, without adding runtime-policy inspection, a dedicated verification state machine, or changes to existing agent preflight.

### Key Entities *(include if feature involves data)*

- **Managed installation**: Host support status, component ownership and locations, installed/running versions, configuration, service state, and access readiness.
- **Device observation**: Pinned and observed identity, connection mode, firmware version, supported capabilities, security-report limitations, observation time, and freshness.
- **Pool observation**: Device membership and host binding, pool/incarnation identity, active/staged generation identities, certificate periods, KES progress, readiness, and failure reasons.
- **Release**: Component, version, release classification, authentic origin, supported host/hardware, compatibility constraints, required artifacts, and verification result.
- **Maintenance operation**: Approved targets and changes, prerequisites, disruption, pre-change public observations, confirmed progress, post-change observations, and recovery disposition.
- **Lifecycle receipt**: Existing durable operation identity, target, expected revision, request identity, result or uncertainty, and reconciliation outcome; not a replacement mutation protocol.
- **Operator artifact**: Public identity/certificate/recipient records or encrypted backup outputs with their destinations and pool/generation bindings; never a primary-host plaintext KES backup.
- **Provisioning record**: Intended device, authenticated bundle/tool bindings, observed hardware/security state, completed stage, pending/uncertain action, and verification evidence; retained separately from ordinary pool-operation receipts.
- **Supplied pool inputs**: Operator-entered values or selected public files, their source, network and pool bindings, and validation results; never a substitute for authenticated device inventory.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Across clean, partial, healthy, mixed-version, disconnected, and permission-denied acceptance installations, 100% of known component/device states are reported correctly or explicitly unknown; none are falsely reported healthy, absent, or empty.
- **SC-002**: On a supported host with responsive local components, the initial local overview is available within 5 seconds and all 64 pools are inspectable within 10 seconds. A loss of access or connection is visibly reflected within 10 seconds; an unavailable release service does not prevent local navigation.
- **SC-003**: Before evaluation, fix a cohort of exactly five intended operators, each with prior Linux terminal/systemd and Cardano stake-pool operational experience. Exclude `p2kesup` implementers and anyone who has rehearsed the evaluated workflows. Record each participant's eligibility under a non-identifying label without recording private identities. At least four distinct cohort participants must each complete all three actions: installation/setup, identifying a pool's readiness and remaining KES validity, and a compatible version change. Participants may use only the manager and its linked instructions, without coaching, undocumented help, project source builds, or undocumented commands. Physical device actions and offline signing are permitted explicit steps. Supplementary runs do not change the fixed cohort or its results.
- **SC-004**: In every supported host/firmware upgrade and downgrade acceptance scenario, all retained configuration, public identities, pool/incarnation/generation bindings, and permissions match the expected post-maintenance state, allowing only independently accounted-for forward lifecycle transitions. Zero scenarios roll back KES state or erase operational storage.
- **SC-005**: All tampered/untrusted release, incompatible/unknown-compatibility, wrong-device, stale-target, and denied-permission acceptance scenarios are rejected without unintended persistent changes; each provides an actionable reason.
- **SC-006**: Every tested interrupted setup, host replacement, firmware transfer, or lifecycle mutation is shown as completed, failed, or explicitly uncertain according to observed evidence, with a safe next action and retained reconciliation information. Zero uncertain operations are automatically resubmitted under new identities.
- **SC-007**: Every lifecycle action listed in FR-016 is completable through the TUI or its explicit offline/physical handoff, with observable confirmation of the intended result and no unintended effects on other pools. Cancellation before applying a destructive action leaves state unchanged; cancellation between provisioning stages preserves completed stages and does not start the next.
- **SC-008**: All primary flows are completable with keyboard-only navigation and without color cues. Inspection, diagnostics, and uninstall acceptance runs expose no secret material; uninstall preserves every designated operator and device data item.
- **SC-009**: Every eligible provisioning acceptance run records the required evidence before advancing each stage. All wrong-device, nonblank, unsupported, evidence-mismatched, and uncertain-write cases block applying or advancement as appropriate; zero runs automatically replay OTP writes, erase state, or treat partial provisioning as completed.
- **SC-010**: A valid restoration succeeds on an isolated backup host with no daemon or device, while all wrong-recipient, tampered, identity-mismatched, unsafe-memory, and destination-collision cases publish no key. No primary-host workflow accepts private recipient material.
- **SC-011**: Installation, monitoring and lifecycle flows may read bounded local node unit/configuration and public genesis evidence but never initiate node connections or integration checks. Node service changes occur only through approved producer hardening. Missing or invalid inputs yield explicit errors.
- **SC-012**: Operators can install the supplied drop-in and reload service configuration through one guided action, with an optional approved restart and clear command outcomes. No dedicated multi-producer testing or runtime hardening verification is required.

## Assumptions

- Operators already have or can obtain authorized local host access and physical access for device maintenance. One session manages one local agent installation and its selected device; remote fleet orchestration, unattended remote flashing, cloud accounts, and distributed producer fencing are not inferred from this request. Running the interface in an operator-established remote terminal does not remove physical maintenance requirements.
- The first release supports x86-64 Linux hosts with the project's existing systemd/udev deployment model. Supported distributions must be explicitly published with qualified release artifacts; unsupported hosts are rejected rather than silently built from source. ARM64 and other host architectures, Windows, and macOS are outside this release's scope; this host restriction does not change the Pico2 firmware target.
- The user selected a shell bootstrap installer with a separately installed persistent TUI, full normal lifecycle plus optional attended OTP provisioning, and agent-only scope with one exception: installing the supplied producer memory-hardening drop-in and running the associated systemd commands. No new hardening policy or verification subsystem is required.
- Release publication must supply authentic component artifacts and explicit compatibility information for every supported installation path. Acceptance candidates carry signed compatibility authorization separately from their unqualified status; final release qualification requires passing evidence for the exact tested payloads. Existing firmware-release tooling is a starting point, not evidence that all manager/host distribution requirements already exist.
- Existing README procedures govern trusted release bootstrap, attended firmware updates, preservation of current device state, commissioning, host security, and key custody. The manager must make these procedures usable without weakening them. Compatibility-preserving downgrades are allowed; arbitrary state migrations are not silently added.
- Routine manager observations may be unavailable on older firmware. Such limitations must be visible; full release acceptance requires the advertised observations, including firmware version and complete pool inventory, on the supported combination.
- Expiry estimates depend on trustworthy validated network parameters, host time and agent period information. Bounded read-only local node configuration/genesis discovery is permitted; node connections, integration checks and general node management remain excluded. Installing the supplied producer drop-in, reloading systemd, and optionally restarting approved producers are the only node-management exception. Device pool inventory remains automatic.
- Normal KES evolution remains automatic under the agent's existing rules. The manager does not introduce a new scheduler, backup-readiness gate, certificate authority, or manual activation approval.
- Opening the TUI does not grant stronger authority than the current operator possesses. Privilege elevation is limited to reviewed host changes; normal monitoring does not require running the entire interface as root.
- Existing deployment and firmware procedures are described in [README.md](../../README.md); the governing safety, custody, device-ownership, and quality requirements are in the [constitution](../../.specify/memory/constitution.md). Planning must select and inspect applicable Software Observatory sensors before implementation, as required there. This specification is not hardware qualification or evidence of working implementation.
- Producer hardening relies on the existing [drop-in](../../deploy/cardano-node-memory-hardening.conf) and standard systemd behavior; it does not re-test systemd or redesign agent preflight. Existing normal-mode preflight still checks `cardano-node.service`; installing the drop-in for a custom unit does not change that existing deployment constraint. Host-wide swap, sleep, crash-dump, and snapshot policies remain separate obligations.
- OTP provisioning is optional, irreversible, and restricted to eligible blank devices. Deliberate erase-to-convert, arbitrary OTP repair, and automatic recovery from uncertain programming are not included. Existing explicitly admitted pre-OTP recovery and read-only assessment remain available with their original restrictions; physical qualification cannot be replaced by a successful TUI flow.
- Backup-host use is an explicit operator-selected deployment role, not remote orchestration or proof that the host was never used as a primary. The manager must refuse private-recipient workflows on a detected active primary and explain the custody requirement; operator declarations do not override contradictory local evidence.
