# Development checks — not release acceptance

Status: **BLOCKED** for T067. Current executables identify themselves as `development-unqualified`. No signed or qualified package is asserted. Exact final source, executable and lockfile digests are in [source-identity.json](source-identity.json). Commands ran from `/home/westbam/Development/pico2-kes-agent` unless stated otherwise.

## Environment

Ubuntu 26.04, x86-64, Linux 7.0.0-42-generic; this is not either supported acceptance image. Rust `1.99.1 (58cf8f9c3 2026-10-13)`, Cargo `1.99.1 (5f94df478 2026-08-27)`, Python 3.14.4, cargo-audit 0.22.1, cargo-deny 0.19.8. Rust/Cargo/audit/deny match the existing tool inventory. Swap remains active. Two earlier Polkit swapoff attempts timed out; no further authentication was attempted and no protection was bypassed.

## Executed commands

| Command | Observed result |
|---|---|
| `cargo fmt --all --check` | Pass after integration and the narrow-terminal footer correction |
| `cargo check --locked` | Pass on final source |
| `cargo clippy --locked --workspace --exclude pico2-kes-firmware --all-targets -- -D warnings` | Pass on final source |
| `cargo test --locked --workspace --exclude pico2-kes-firmware` | Failed in all four `backup_restore` cases with `MemoryProtection`; earlier core/protocol suites and 104 host-library tests passed. Cargo stopped before later integration targets. |
| `cargo audit` | Exit 0; three allowed unmaintained-package warnings, listed below |
| `cargo deny check` | Exit 0; advisories, bans, licenses and sources passed with existing duplicate/unmatched-license warnings |
| `python3 -I -m unittest discover -s tools/tests` | 84 tests passed; disposable test signing authorities, not production signatures |
| `cargo check --locked -p kes-core --no-default-features` | Pass |
| `cargo check --locked -p kes-protocol --no-default-features` | Pass |
| `cargo check --locked -p pico2-kes-firmware --target thumbv8m.main-none-eabihf` | Pass |
| `cargo build --locked --release -p pico2-kes-firmware --target thumbv8m.main-none-eabihf` | Pass; not flashed |
| `cargo clippy --locked -p pico2-kes-firmware --target thumbv8m.main-none-eabihf -- -D warnings` | Pass; upstream future-incompatibility notice for proc-macro-error2 2.0.1 remains |
| `cargo run --locked -p qualification -- load` | Pass for the existing host model/client-isolation scope; [raw report](../../f23486803f9d2c730a4c943d6c32cdead361bfe9-615982a894f261dd0055905c683597def2687cc72e35ba4f08ec60b51cce50b1/load/report.json) |
| `cargo run --locked -p qualification -- native-regression` | Failed configured node-source pin check; node-service protocol regressions passed. [Raw report](../../f23486803f9d2c730a4c943d6c32cdead361bfe9-bcc3fa4a4d1463368c41e596c3efe6f1c850359b5d86f87aa8c6bf748348b132/native/report.json); [isolated follow-through](native-check.md). |
| `cargo build --locked --bins` | Pass; actual development binaries exercised |
| `bash -n install.sh deploy/uninstall.sh` | Pass; all five embedded Python programs also parsed with Python AST |

The bootstrap's real bounded subprocess helper was exercised for normal output, exact output limit, overflow, deadlines including closed stdout, nonzero exit, discarded stderr, closed stdin and isolated environment. These are executable helper checks, not source-text assertions. The syntax-check harness initially omitted a here-document with trailing shell syntax and concatenated chunk boundaries; corrected extraction parsed all five programs without a source change.

### Additional integration execution

The first targeted host-security run passed 12 cases but failed `recipient_prompt_protects_process_before_accepting_passphrase` on this swap-active environment; it stopped before the other requested targets. The protected prompt was not reached. No memory policy was relaxed.

The following explicit filtered command completed:

```sh
cargo test --locked --test host_security --test service_lifecycle --test operator_cli --test management_recovery --test single_pool --test node_service -- --skip recipient_prompt_protects_process_before_accepting_passphrase --skip recipient_rotation_is_future_only_and_private_keys_stay_off_primary
```

| Suite | Passed | Filtered |
|---|---:|---:|
| host_security | 12 | 1 |
| management_recovery | 11 | 0 |
| node_service | 13 | 0 |
| operator_cli | 12 | 0 |
| service_lifecycle | 3 | 0 |
| single_pool | 23 | 1 |

This is 74 passing integration cases, not a passing complete suite. The four backup-restore cases and the two named protected-memory cases remain unverified for current-source acceptance. Historical US1 success with temporarily disabled swap is not substituted for them.

The workspace run also passed the existing 39 recovery cases, including prepare/commit/clean cuts, discard/reboot races, directory intent recovery, replenishment faults, and full-capacity pool isolation. Existing platform/explorer checks passed. The native-feature-gated crypto compatibility target executed zero tests in this command and supplies no independent-decoder reading.

### Warnings retained

- RUSTSEC-2026-0110: bare-metal 0.2.5 deprecated/unmaintained.
- RUSTSEC-2024-0436: paste 1.0.15 unmaintained.
- RUSTSEC-2026-0173: proc-macro-error2 2.0.1 unmaintained.
- cargo-deny reported duplicate getrandom, rand_core and syn versions and an unencountered Unicode-3.0 allowance. No new suppression was added.

## Resource fit

GNU `size` on the linked target ELF reported:

| Section category | Bytes |
|---|---:|
| text | 361624 |
| data | 0 |
| bss | 548 |

The linker configuration reserves 1 MiB for firmware flash and `0x82000` bytes of RAM, excluding the persistent-state partitions from firmware allocation. Successful linking and these section sizes do not prove stack/runtime headroom, device durability or physical qualification.

## Actual smoke, calibration and limits

[Q9](Q9.md) and [Q10](Q10.md) record actual public diagnostic, keyboard/NO_COLOR, refusal, cancellation and foreground-terminal checks. The daemon rejected a FIFO `--config` with `configuration I/O: public input must be a regular file`, exit 1, in 0.0022 seconds; the pre-fix command had blocked until its one-second smoke deadline. Nonterminal UI invocation returned 4; unprivileged lifecycle/backup helpers returned 3; unpaired expected-peer CLI flags returned 2.

[Behavioral calibration](behavioral-calibration.md) contains the isolated Rust known-defect detection. Packaged Q3 and applicable Python-runner calibration remain absent. [Performance](performance.md) is not activated. SO-002b is incomplete because the complete required suite/calibration does not pass; SO-002c remains blocked on end-to-end qualification; the load report is supporting SO-006e model evidence, not the required real TUI/device reading. No coverage percentage, new fuzz/mutation campaign or SAST reading is claimed.
