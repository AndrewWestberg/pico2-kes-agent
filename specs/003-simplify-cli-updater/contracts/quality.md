# Quality Gate & Software Observatory Selection

**Feature**: `003-simplify-cli-updater` | **Constitution**: v3.0.0 (v4.0.0 upon CLI rename amendment)

## 1. Selected Software Observatory Sensors

Consulted live via Software Observatory MCP (`suggest_sensors`, `get_sensor` full entries, and `stack_coverage`) before implementation:

| Sensor ID | Title | Family | Executable Check | Pass Rule & Budget | Known Limitation |
| --- | --- | --- | --- | --- | --- |
| **SO-001** | Type Checker | Structural | `cargo check --locked --workspace --exclude pico2-kes-firmware`, `cargo clippy --locked --workspace --exclude pico2-kes-firmware --all-targets -- -D warnings`, firmware target `cargo check`/`clippy` | Zero errors, zero warnings; <5 min | Proves type/structural consistency only, not runtime logic. |
| **SO-002b** | Example-Based Tests | Behavioral | `cargo test --locked --workspace --exclude pico2-kes-firmware --features kes-core/qualification` | Zero failures, zero newly skipped tests; <15 min | Only tests author-chosen examples; misses untested branches. |
| **SO-002c** | Integration Tests | Behavioral | End-to-end tests in `tests/` exercising live `pico2-kes-agentd` + `p2kes` + `p2kesup` + `p2kes-flash` (mock/USB transport) + operator quickstart scenarios Q1–Q5 | All acceptance scenarios pass without retries/flakes; <15 min | Host-simulated USB does not prove real RP2350 silicon behavior. |
| **SO-005e** | Property-Based Testing | Adversarial | `proptest` suites covering journal compaction/replay equivalence, UF2/manifest parser rejection, and existing `kes-core`/`kes-protocol` properties | Zero falsifying counterexamples across default cases; <5 min | Only checks stated properties; cannot detect missing features. |
| **SO-006e** | Load Testing | Runtime | `cargo run --locked -p qualification -- load` + 64-pool status latency & idle-wakeup measurement (SC-005) | 64-pool workload passes; status <100 ms with 10k journal entries; idle wakeups <5/sec across 64 pools; <10 min | Synthetic load does not replace real hardware power-loss tests. |

### Supporting Hygiene Checks (Not Labeled as Additional Catalog Sensors)
- `cargo fmt --all --check`
- `cargo audit` and `cargo deny check` (dependency advisories & license policy)
- Line-count verification for SC-006 (host management/updater footprint reduced ≥85% vs. baseline 36,261 LOC `src/manager/`)

## 2. Coverage Gaps & Rationale (`stack_coverage` Output)

`stack_coverage` identified 6 uncovered families: `test-effectiveness` (mutation/coverage), `invariants`, `change`, `architecture`, `evolution`, `comprehension`.
- **`test-effectiveness` (SO-003 / SO-003c)**: Existing `kes-core`/`kes-protocol` mutation & coverage infrastructure remains available; no new mutation campaign is mandated for the simplified ~300-LOC `p2kesup` wrapper, where targeted negative tests (tampered signature, partial bundle, atomic swap failure) provide direct defect detection.
- **`invariants` / `change` / `architecture` / `evolution` / `comprehension`**: Addressed via explicit contract docs (`contracts/cli.md`, `contracts/updater-and-flash.md`), code review, and the Constitution Principle II hardware power-loss and OTP re-qualification gates below.

## 3. Mandatory Hardware Re-Qualification (Inherited + New `p2kes-flash`)

Per Constitution Principle II:
1. **Inherited Pico 2 A2 qualification**: Because `firmware/`, `crates/kes-core/`, and USB protocol v1 are unchanged, existing hardware power-loss and storage evidence remains applicable unless touched during implementation.
2. **New `p2kes-flash` hardware re-qualification (MANDATORY before production release)**: Because `p2kes-flash` replaces `tools/firmware.py` for operator runtime flashing, wiping, and OTP provisioning, real Pico 2 A2 hardware smoke runs MUST verify:
   - `p2kes-flash verify` and `p2kes-flash flash` (BOOTSEL UF2 install + firmware upgrade preserving commissioned state)
   - `p2kes-flash wipe` on a disposable unlocked board
   - `p2kes-flash otp --stage prepare|enable|lock` on a disposable board before declaring OTP provisioning qualified in production.

## 4. Project Performance Gate (SC-005)

Not an invented Software Observatory sensor—explicit project performance gate:
- **Status latency**: Measure `p2kes status --json` against a daemon with 64 pools and a journal seeded with 10 entries vs. 10,000 completed entries. Both medians MUST be `<100 ms` with no linear growth.
- **Idle wakeups**: Measure daemon thread wakeups over a 10-second idle window with 64 bound pool sockets and no active node connections (e.g., via `/proc/<pid>/task/*/sched` or `strace -c`). Must be `<5 wakeups/sec` (down from >1,000/sec).
