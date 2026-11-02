# Acceptance reconciliation — NOT COMPLETE / NOT QUALIFIED

57 of 70 tasks are marked complete in [tasks.md](../../../specs/002-manage-kes-agent/tasks.md). All requested implementation surfaces and documentation were delivered; 13 combined acceptance/qualification tasks remain unchecked. This is not a scope reduction, release approval or claim that all feature behavior passed. No promotion command was run.

## Evidence identity and authority

[source-identity.json](source-identity.json) records the exact final revision/dirty content and executable hashes. The binaries label themselves `development-unqualified`; there is no signed source-free candidate/payload tuple to promote. Raw model/native reports retain their own earlier source identities; their unchanged code-path scope is not silently relabelled as physical or final signed-candidate qualification. Documentation/task-marker changes do not turn development checks into release evidence.

Supported acceptance platforms are Debian 12 and Ubuntu 24.04 on x86-64/systemd/udev. This execution host is Ubuntu 26.04 and has an external inactive installation, active swap and an unqualified attached application-mode candidate. It was not adopted, erased, recommissioned, flashed or OTP-programmed. No live node connection, service mutation, producer restart or private backup workflow was performed.

## Functional requirements

Each row maps implementation scope to observed evidence and its remaining acceptance limit. None is presented as full release acceptance while the named scenario is incomplete.

| Requirement | Implemented scope | Evidence / remaining gate |
|---|---|---|
| FR-001 | Bootstrap/persistent manager and component packaging | Q2; signed source-free supported-host installation absent |
| FR-002 | Host/prerequisite/ownership review and finite privilege actions | Q1/Q2; unsupported external-host refusal exercised, qualified installation absent |
| FR-003 | Independent installed/running/device/connection/config/release observations | Q1/Q3; local unknown/external evidence exercised, managed matrix absent |
| FR-004 | Complete bounded membership/config/journal joins | Q3; protocol/model cases pass, physical 64-pool reading absent |
| FR-005 | Generation/certificate/context/period/remaining evidence | Q3; checked derivation tested, live supported full workload absent |
| FR-006 | Refresh, age/stale evidence, keyboard and no-color navigation | Q3/Q10; real terminal and isolated stale defect detection pass, packaged timing absent |
| FR-007 | Install/first firmware/restricted commission/pin/normal transition | Q2/Q4; authorities implemented, complete blank-target physical setup absent |
| FR-008 | Public input validation and unchanged host security prerequisites | Q2/Q9; invalid/FIFO refusal observed, qualified readiness absent |
| FR-009 | Qualified stable discovery and explicit compatible component review | Q5; trusted fixture/selection checks pass, genuine release transition absent |
| FR-010 | Independent signatures, exact tuple/payload validation and separate promotion | Q2/Q5; fixture checks pass, production-authority candidate and promotion evidence absent |
| FR-011 | State-compatible upgrade/downgrade without KES rollback | Q5/Q6; comparison checks pass, actual transitions absent |
| FR-012 | Exact maintenance review, checkpoints and retained forward state | Q5/Q6; model/record checks pass, installed/physical preservation absent |
| FR-013 | Attended firmware selection/transfer and daemon post-check | Q2/Q6; no physical transfer or reconnection accepted |
| FR-014 | Original maintenance recovery and explicit uncertainty | Q5/Q6/Q9; guarded source/fixtures, actual interruption matrix absent |
| FR-015 | Local/offline observation and authenticated cached bundle use | Q1/Q5; no-network development navigation exercised, signed offline install absent |
| FR-016 | Complete lifecycle, receipt, backup and optional OTP surfaces | Q4/Q7/Q8; all routes implemented, qualified positive workflows absent |
| FR-017 | Off-primary private custody and inherited secret terminal streams | Q4/Q8; role refusal/no-connect sentinel observed, isolated positive restore absent |
| FR-018 | Exact revalidation, durable original receipts and connected-peer authority | Q4; regression checks pass, live lost-response reconciliation absent |
| FR-019 | Service/configuration review and public diagnostics | Q9; actual refusal/FIFO/export checks, approved systemd/config apply absent |
| FR-020 | Agent-only scope plus narrowly approved producer exception | Q1–Q11; boundary review passed, end-to-end supported scenario matrix absent |
| FR-021 | Selected ownership-proven uninstall with retained records/state/drop-ins | Q9/Q11; source/fixture guards, actual selected/self removal absent |
| FR-022 | Field-selected bounded diagnostics and no private child capture | Q9/Q10; actual public export/no-clobber/terminal handoff, full private-flow acceptance absent |
| FR-023 | Sole daemon operational USB owner and attended shutdown/handoff | Q2/Q6/Q7; implemented coordination, physical ownership/readback absent |
| FR-024 | Optional qualified blank-target per-stage OTP admission | Q7; admission checks, no physical application |
| FR-025 | Owning provisioning tool records, direct prompts and no uncertain replay | Q7/Q10; record/terminal checks, attended physical stage outcomes absent |
| FR-026 | Isolated recipient creation/authenticated restricted restore | Q8; primary/swap refusal evidence, valid isolated restore absent |
| FR-027 | Explicit public transfer/custody/fencing guidance without node access | Q8; documented/reviewed, positive backup workflow blocked before forms |
| FR-028 | Exact supplied drop-in and concrete selected-unit validation | Q11; boundary tests and actual invalid-unit refusal, approved publication absent |
| FR-029 | Explicit reload/restart/defer and precise failures | Q11; original recovery guards, actual approved systemd outcomes absent |

## Success criteria

| Criterion | Required result | Current disposition |
|---|---|---|
| SC-001 | No falsely healthy/absent/empty state across complete installation matrix | Q1/Q3 partial; no supported multi-state acceptance matrix |
| SC-002 | 5-second overview, 10-second 64-pool/failure visibility | Performance blocked; no baseline/sensitivity or qualifying measured workload |
| SC-003 | At least four of five eligible operators complete all three actions | Q10 blocked; zero qualifying participants |
| SC-004 | All maintenance preserves expected forward-only state/permissions | Q5/Q6 blocked; actual upgrade/downgrade matrix absent |
| SC-005 | All unauthorized/tampered/incompatible/stale targets refused | Fixture and local refusals pass; complete signed/physical matrix absent |
| SC-006 | All interruptions retain truthful original reconciliation | Recovery tests pass; qualified setup/host/firmware interruption matrix absent |
| SC-007 | Every lifecycle path and cancellation completes correctly | Q4/Q7 blocked; implementation and selected regressions are not all-path acceptance |
| SC-008 | Keyboard/no-color completion and secret-free retained uninstall | Q9/Q10 partial; packaged all-flow and actual removal coverage absent |
| SC-009 | Every eligible OTP stage records evidence and rejects unsafe advancement | Q7 blocked; no qualified physical run |
| SC-010 | Valid isolated restore and all invalid cases publish no unintended key | Q8 blocked; active-swap failures and no isolated positive reading |
| SC-011 | Supplied inputs/agent observations only, approved producer exception | Boundary review and zero-connect backup sentinel pass; full flow coverage absent |
| SC-012 | Guided supplied drop-in/reload/optional restart with actual results | Q11 blocked; no approved selected-unit application |

## Quality sensors and inherited release qualification

| Gate | Observed evidence | Disposition |
|---|---|---|
| SO-002b behavioral checks | Final check/Clippy, 104 host-library cases, 74 explicitly filtered integration cases, 84 Python cases; exact complete workspace failed protected-memory cases | Blocked; see developer-checks |
| Behavioral defect calibration | Original pass → approved stale-to-fresh defect fails intended assertion → restored pass, exact source/binary hashes retained | Rust unit path passes; packaged Q3 and applicable Python-runner demonstration missing |
| SO-002c acceptance | Actual development UI/foreground/refusal/export smokes; Q1–Q11 reports explicitly scoped | Blocked; no signed packaged supported-host/physical/isolated/cohort completion |
| SO-006e workload | Existing 64-active/64-staged model and stalled/malformed-client isolation passed | Supporting model evidence only; real full-capacity device/TUI timing absent |
| Project performance gate | No approved comparable baseline or sensitivity experiment; no five-pair timing sample set | Not activated; no pass inferred |
| Deterministic transition/recovery faults | Existing 39 recovery tests and platform/explorer checks passed, including prepare/commit/clean and multi-pool faults | Development-model support, not physical power-loss proof |
| Identified Pico2 A2/fitted-storage host/device recovery | No complete candidate-applicable physical recovery smoke | Blocked |
| Native compatibility | Configured runner retained source-pin failure; isolated required-commit node build plus actual --version passed; its 13 protocol regressions passed | Scoped supplemental pass in native-check; no live block claim |
| Independent generation-time backup decoding | Native-feature-gated target ran zero tests; no current independent decoder report established | Blocked; not replaced by format/signature/unit checks |
| Firmware resource fit | Target check/release link/Clippy passed; section sizes retained | Link fit only, not runtime stack or hardware safety proof |
| Optional physical-cut/live-block campaigns | Not performed | Explicitly unverified; not confused with mandatory physical recovery |
| Manual privilege/custody review | Findings fixed; executable bounds/peer/recovery checks and terminal smokes | Completed review, not SAST or general security certification |

The approved Rust defect existed only in a disposable build copy, was restored with identical original source/test-binary hashes, and that copy was removed. No defective payload was installed or promoted. Performance calibration is a separate unsatisfied obligation. No mutable trust, memory, ownership, signature or qualification policy was weakened to obtain green output.

## Outstanding task prerequisites

| Task | Blocking prerequisite / actual limit |
|---|---|
| T019 | Full Q3 requires a supported packaged host and qualified disposable 64-active/64-staged physical workload; only development terminal/model evidence exists. |
| T023 | Source-free authenticated candidate acceptance on supported disposable hosts is unavailable; fixture signatures do not qualify a published candidate. |
| T030 | Q2 installation/first firmware/commissioning requires a signed candidate, supported disposable host and approved blank qualified physical target. |
| T039 | Q5/Q6 require authentic compatible release tuples and supported disposable host/qualified physical maintenance scenarios. |
| T046 | Q4 needs a managed qualified device and public pool/context inputs; current UI stops at missing authenticated CLI. No physical lifecycle mutation was authorized. |
| T052 | Views and diagnostic smoke are complete; Q9 approved service/configuration/removal and retention acceptance require a supported disposable managed installation. |
| T056 | Q7 applying requires a qualified sacrificial target with matching signed tool/image/evidence and attended irreversible-stage authorization. |
| T060 | Q8 needs an isolated memory-protected backup host and independent restore validation. Current host has primary evidence and active swap; no secret workflow was opened. |
| T063 | UI and policy workflow are implemented; Q11 needs an approved disposable concrete producer unit and supported managed host for actual file/reload/restart outcomes. |
| T067 | Full workspace run failed four backup_restore cases with MemoryProtection; protected prompt test also failed before input, recipient rotation was filtered. Swap remains active after two timed-out Polkit attempts. Rust known-defect calibration passed; packaged Q3 and applicable Python-runner calibration remain missing. |
| T068 | Signed source-free supported-platform, qualified physical/power-loss/full-capacity and independent backup-decoder readings are absent; comparable baseline/performance sensitivity is unapproved. Isolated pinned native build and model/protocol checks passed only their scoped gates. |
| T069 | Development PTY keyboard/NO_COLOR/resize/refusal/foreground smokes passed; full packaged flow coverage and the fixed five eligible uncoached participants are unavailable. |
| T070 | Acceptance matrix is recorded but upstream required checks/calibrations/qualification remain blocked. No metadata promotion or qualified-release claim is permitted. |

## Reports and continuation

- [Developer checks](developer-checks.md), [security review](security-review.md), [behavioral calibration](behavioral-calibration.md), [performance](performance.md), [native follow-through](native-check.md).
- [Q1](Q1.md), [Q2](Q2.md), [Q3](Q3.md), [Q4](Q4.md), [Q5](Q5.md), [Q6](Q6.md), [Q7](Q7.md), [Q8](Q8.md), [Q9](Q9.md), [Q10](Q10.md), [Q11](Q11.md).

Supply the production-authority-authenticated compatible candidate tuples, supported disposable hosts, isolated memory-protected backup host, qualified disposable/sacrificial hardware and required public fixtures. Establish the approved comparable baseline and applicable missing behavioral calibration; then execute the existing finite quality/quickstart procedures and fixed eligible cohort. Preserve failed evidence and original operation identities. Only after every required gate passes may the existing metadata-only promotion bind unchanged tested payloads and signatures. Current evidence does not authorize that step.
