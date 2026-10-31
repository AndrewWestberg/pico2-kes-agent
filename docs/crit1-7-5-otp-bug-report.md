# RP2350 CRIT1 redundant-write false-success investigation

The investigation below is a historical record, not authorization for additional OTP writes. The later [rc.9 preservation-upgrade evidence](../evidence/2e22f818e15d1824f88c9eed365aaffc29dff803-2593f2817f21af96923ca5693f5f776a1bd1d93c63d9c8b50e25249f06cfb92b/hardware/preservation-upgrade.json) reports `critical=7` and `redundancy_ok=true` before and after the signed upgrade. That observation supersedes the board-disposition snapshot below; it does not resolve the ROM multi-row false-success mechanism or establish firmware readback/attestation.

## Historical handoff status (2026-10-30)

This is a maintainer/engineering bug report, not end-user documentation.

The affected board is explicitly authorized for destructive root-cause testing. It may be sacrificed. That authorization applies only to this board:

- Application serial / CHIPID: `00afd9003906a634`
- Silicon: RP2350 A2
- Intended profile: `rp2350-signed-msd-v1`
- Authorized boot-key SHA-256: `be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0`
- Bundle: `target/security-qualification/cb667487ff87c69cd0a9881e71e4c5696a8bdf2c`
- Bundle manifest SHA-256 recorded by provisioning: `6b95bfa8bbf9abe87cd2e42be3e73ce76cbc5734f689864c2901586eb39ffb2b`
- Provisioning record: `/var/lib/pico2-kes-provisioning/00afd9003906a634/otp-provisioning.json`
- Erase record: `/var/lib/pico2-kes-provisioning/00afd9003906a634/erase-state.json`

At the previous investigation's last observation, the board was in BOOTSEL and the daemon was stopped. That live PICOBOOT session was **already lost before the 2026-10-30 work began**: the first passive enumeration found the application (`1209:4b45`). No reset or OTP write was issued to establish this. The lock-stage flags have now been sampled. The old live-session instructions below describe the original opportunity, not the board's present state.

Destructive authorization is not authorization to run blind retries. Preserve the existing record and current state first, instrument every attempted write, and restrict tests to this serial. Do not attach or modify a backup board.

**Disposition at the end of this investigation:** the exact false-success pattern was reproduced through the stock ROM with no PICOBOOT/picotool in the write path. Stock-ROM **single-row** calls subsequently passed all 24 tested transitions. Host hardening and 39 permanent tests were implemented. The authenticated application was restored, the daemon was inactive, and the board remained sacrificial with its original CRIT1 mismatch—not qualified or repaired at that point. Upstream publication was explicitly declined in favor of a local draft.

### 2026-10-30 evidence preservation and revised experiment protocol

The operator stopped the daemon and ran a serial-specific preservation script. Original provisioning and erase records were copied into a separate root-only directory with contents, UID/GID, mode, atime and mtime preserved; source metadata was checked before and after reading with `O_NOATIME`. Ctime/inode necessarily differ for the copies. Neither original was changed. The protected incident directory is `/home/westbam/pico2-otp-incident-20261030-5awtsdcy`; its `preservation.json` records source/copy metadata and SHA-256:

| Record | SHA-256 |
|---|---|
| `otp-provisioning.json` | `d01a35538282ac8db824c04d64a4af0aa0ca8a18a6da5b7c0b693a180902f2d0` |
| `erase-state.json` | `c1dac9401bb78a11b7ec1f1467531a6a6ef46483bfbd045663662428bee047aa` |

A read-only application `Hello`/`SecurityStatus` probe revalidated serial `00afd9003906a634`. It reported A2, `critical=5`, `boot_flags0=0x2da180`, `boot_flags1=0xe01`, the authorized boot key, page-2/page-63 lock1 `0x15`, `debugen=0`, `debugen_lock=0x10f`, `redundancy_ok=false`, blank storage and profile `incomplete`. This API reports a redundancy verdict, not all eight raw copies; the preserved original record supplies the historical physical values. Do not relabel that historical snapshot as a fresh raw read.

Actual dynamic-loader probing found the same installed picotool SHA-256 as the incident, GNU build ID `a671ab82e6f89b410d3e27ef1dfebe9814183a76`, and loaded `/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0.5.0`, SHA-256 `e422dc361a501e8175a94e16228704de7ca6376037fc29a0e7272e8fe2c8edc1`, Debian package `libusb-1.0-0:amd64` version `2:1.0.29-2build1`. Full outputs, host/compiler metadata and pre-edit tool/report copies are retained privately. Source candidate is `cb667487ff87c69cd0a9881e71e4c5696a8bdf2c` plus the uncommitted hardening changes; no new qualification result is implied.

**Protocol, prepared before any new device mutation:**

1. Do not attempt to recover PICOBOOT by blind reset or run the unsigned preparation helper. Since the old session is gone, use only the retained authenticated flash/MSD path for a diagnostic, after preserving application evidence.
2. Build a lab-only Secure flash diagnostic, excluded from release artifacts and normal firmware. Hard-bind its CHIPID, A2 ROM, secure-boot state and authorized public key. Startup is read-only. Disable SDK USB auto-reset facilities. Never erase the application state region.
3. Permit only fixed commands: `SNAPSHOT`, `ROMTEST 00afd9003906a634`, and `SBPITEST 00afd9003906a634`. No row/value/address arguments or generic OTP programming interface. Capture the complete bounded CDC request/result transcript with timestamps and image/source/tool hashes.
4. Reserve only page-3 user rows `0x00c4..0x00cb` for the ROM batch test and `0x00d0..0x00d7` for the instrumented test. These have no named allocation in the pinned OTP schema and are not used by this firmware. Exclude all factory, boot-key, boot-policy and lock rows. Before consumption require exact identity/authority, both page-3 lock words and its volatile lock zero, and every selected row blank. Unexpected data means stop, not select another range automatically.
5. ROM test: one eight-row/32-byte raw call for each transition `0→1→5→7`; retain exact payload, API result, post-call SBPI status and immediate raw readback of every row. Stop on the first failure or mismatch, even with `BOOTROM_OK`. The ROM clears internal status, so a zero post-call status is **not** evidence that no `INSTR_MISS` occurred.
6. Direct test: the reviewed ROM-derived SBPI sequence on the other eight rows, recording every instruction/status in a bounded RAM trace. Treat `INSTR_MISS`, timeout or trace exhaustion as fail-stop; never continue programming or silently overwrite the trace. Restore the read configuration and verify each physical row before advancing. This added readback/reinitialization changes timing relative to the opaque batch, so a passing direct test cannot exonerate the batch implementation.
7. Execute each test at most once; nonblank admission prevents replay after reboot. No deliberate collision injection, CRIT1 repair, key/lock write, or supply disturbance is part of this matrix. Do not infer voltage stability from USB connectivity; no external voltage measurement has been made.
8. Preserve a failure before deciding another experiment. Board-count/identity changes, lost USB, unexpected locks/rows, short/error transport, API error, physical mismatch or any `INSTR_MISS` stop the run. Do not use a backup board.

PICOBOOT header/ACK/`GET_COMMAND_STATUS` capture cannot be obtained through a disabled PICOBOOT interface. The revised experiment records the signed diagnostic's actual API/CDC traffic instead; it must not be described as a captured replay of the original host command. The original incident's triggering mechanism remains unproven.

Host-only reproduction using the preserved old tool showed that `[7,5,5,5,5,5,5,5]` was appended as a successful observation and `pending` cleared. The hardened action rejected that same injected observation with exit class 6, durable `state: uncertain`, and no successful action/observation. This proves the host defect and its rejection path, not a silicon root cause.

### Hardware reproduction: stock ROM batch versus reinitialized single rows

The signed diagnostic booted through MSD with only USB mass-storage class `08` exposed by BOOTSEL; no PICOBOOT interface remained. Its fresh Secure raw snapshot confirmed the original CRIT1 `[7,5,5,5,5,5,5,5]` pattern, both reserved ranges blank and page-3 lock0/lock1/volatile lock zero. The first diagnostic UF2 SHA-256 is `8b67be170e63d4887bb06f52b70bc1dbc962fe4144581f78cb90381a2d0391ba`; source SHA-256 is `2c18103c2b5aa37437e0e04c3ee82881991c3a3a4f3977e3a3e64dd70ec352bc`. Its signature was independently verified against the existing authority. No private key was retained.

**The exact false-success pattern reproduced outside PICOBOOT/picotool.** `ROMTEST` called the stock Secure ROM `otp_access()` directly from the signed application:

| Transition on `0x00c4..0x00cb` | ROM result | Immediate physical readback | Post-call SBPI status |
|---|---|---|---|
| `0→1` | `0` | `[1,1,1,1,1,1,1,1]` | `0x00800001` |
| `1→5` | `0` | `[5,5,5,5,5,5,5,5]` | `0x00800001` |
| `5→7` | `0` | `[7,5,5,5,5,5,5,5]` | `0x00801001` |

The helper halted on that mismatch. The command/payload/readback transcript is `rom-test.txt`; structured results are `rom-result.json`. Logged start/end brackets include a pre-call USB stdio flush, so they are not isolated programming-time measurements. The final `FLAG` bit is observable but its meaning is not established here. Post-call status cannot reveal a MISS already cleared by ROM.

After preserving/reviewing this result, the same signed image was restarted through MSD for the separately admitted, still-blank range. `SBPITEST` performed full DAP/PMC preparation and cleanup for **each** physical row, read it back immediately, and emitted its trace before advancing. All 24 transitions (`0→1→5→7` on eight rows) passed. Every one of **1,796** traced SBPI instructions reported DONE; none reported MISS. Final independent raw readback showed eight `7` values at `0x00d0..0x00d7`, with CRIT1 and the failed range unchanged.

This isolates the reproduced failure to the on-device ROM/controller/programming path and demonstrates the per-row strategy on this board. It does **not** prove the unobserved original instruction-miss hypothesis, nor isolate reinitialization from the changed timing/read-data-latch handling of the diagnostic. The complete `sbpi-test.txt`, `sbpi-result.json` and `after-tests-snapshot.txt` are protected incident artifacts.

**Additional comparison protocol, reviewed before consumption:** a separately signed diagnostic adds only `BATCHTRACE 00afd9003906a634`, restricted to the still-unallocated page-3 rows `0x00e0..0x00e7`. The same identity/key/lock/blank admission and fail-stop rules apply. It mirrors one prepare/cleanup per eight-row batch, the ROM's USER-port pre-read between rows, uncleared `RDATA_VLD`, and undelayed busy polling, while retaining complete instruction status and rejecting MISS. Physical readback is deliberately after each batch—not after each row—to avoid changing the sequencing being compared. It uses a fixed 17,408-entry trace buffer; trace exhaustion is failure, never overwritten evidence. Existing ranges are not retried and no critical/key/lock rows are writable through this image.

The batch-comparison image (UF2 SHA-256 `97a3f62c18bb4a8b76440381844a01d4d8958bf3d51ad5acf9e0a5c07b84d91d`) stopped during its second row of the first transition: the helper's **1,024-poll bound** expired while PMC status bit 7 remained set. All **1,159** traced SBPI instructions reported DONE, none MISS; status read data progressed through `0xc0..0xc7`. The low-bit meaning is not documented by the examined public source—interpreting it as a retry counter is only a hypothesis. This is a bounded-helper timeout, not another demonstrated `BOOTROM_OK` false success.

After the complete trace was fsynced, the operator power-cycled to terminate any remaining programming activity. A new read-only snapshot showed `0x00e0..0x00e7 = [1,1,0,0,0,0,0,0]`; all earlier test ranges, CRIT1, boot flags and page-3 locks were unchanged. No retry or additional write was made to this range. Artifacts: `batch-trace.txt`, `batch-trace-result.json`, `batch-after-powercycle.txt`.

**Final workaround-confirmation protocol, reviewed before consumption:** add `ROMROWTEST 00afd9003906a634` on `0x00e8..0x00ef`, with the same blank/identity/key/lock admission. Use the *unmodified ROM API* with count one and a four-byte raw payload, followed immediately by same-row readback, for each `0→1→5→7` transition. Verify the entire group after each stage. This removes the custom SBPI wait/latch behavior from the workaround test; it is not a repair of CRIT1. Stop on the first API/readback/controller mismatch; no automatic replay or alternate-range selection. Afterwards retain the board sacrificial and restore the authenticated application, not production qualification.

`ROMROWTEST` completed successfully: all **24** stock-ROM calls returned zero, each immediate same-row readback matched, and all three independent group checks passed. The calls took **416–435 µs** (this test brackets the API call itself). The final fresh snapshot showed eight `7` values at `0x00e8..0x00ef`, with every earlier public row and page-3 lock unchanged. Post-call SBPI status was `0x00801001` for all these successful calls, so that value alone cannot identify a failed write.

The final diagnostic UF2 SHA-256 is `ca0a814ef7b2ac14ebf03fa14f126a87c7badd80ee07ae52dc8964b66dd499c3`; source SHA-256 is `29892161aa7b2430175a535bd6021d25230012a719815c4c3ed4a63f7bf2631e`. Artifacts: `rom-rows-test.txt`, `rom-rows-result.json`, `final-diagnostic-snapshot.txt`. This validates the one-row ROM-call strategy on the affected board; it is not a full production PICOBOOT qualification run.

### Restoration, verification and upstream disposition

The unchanged authenticated application UF2 (`1ec283ab1c53a72f46482733fc47a170d3c81145d01b3b3a33ed5b3d186909e8`) was restored through serial-checked MSD, confined to the firmware partition. No state erase or CRIT1 repair occurred. The real application then reported A2/ROM2, CRIT1 vote `5`, boot flags `0x2da180`/`0xe01`, authorized key, page-2/page-63 permissions `0x15`, debugen `0`, debugen_lock `0x10f`, `redundancy_ok: false`, `storage_blank_at_boot: true`, and `profile=incomplete`. `pico2-kes-agentd` is inactive. The application probe was temporary and removed after use.

All protected evidence lives under `/home/westbam/pico2-otp-incident-20261030-5awtsdcy` (owner-only), alongside hash-pinned, root-protected pre-test originals, separately signed diagnostic variants and `evidence-index.json`. The original production provisioning/erase records were not promoted or rewritten.

The implementation now binds executable/library/provisioner/trace identities, checkpoints bounded process diagnostics, compares physical postconditions before clearing pending, preserves uncertain actions without replay, and uses separately verified physical rows for CRIT1 and both boot-flag groups. Full-group and final-policy readbacks are independently recorded. Permission-helper preparation and signed-image installation/reinstallation also require their exact observed postconditions. Schema-1 records remain incident evidence; `reconcile-prepare` no longer clears uncertainty.

Verification includes the 39-test Python suite, applying-stage host smoke through prepare/enable/lock (47 verified actions, no pending state), real subprocess-group timeout/diagnostic retention and wrapped provenance smoke, diagnostic cross-builds, the live hardware matrix above, and restored-application observation. Host stage smoke uses fake board boundaries; no PICOBOOT packet capture is claimed.

**Upstream: not filed, by explicit operator choice.** The local draft is `/home/westbam/pico2-otp-incident-20261030-5awtsdcy/upstream-report.md`, with public evidence references and the unresolved vendor questions. There is no new Raspberry Pi issue URL. Picotool #330 remains a separate recovery hazard, not this incident's upstream disposition. No private keys or operational material were published.



## Executive conclusion

The host did not intentionally issue a one-row CRIT1 write. Picotool 2.3.1 constructed one raw eight-row PICOBOOT OTP write with a 32-byte payload containing eight copies of `0x00000007`. The command returned success, and a subsequent independent raw snapshot showed:

```text
CRIT1 rows 0x0040..0x0047 = [7, 5, 5, 5, 5, 5, 5, 5]
```

The failure is now **reproduced on-device**: a stock Secure ROM eight-row call returned `BOOTROM_OK` for `5→7`, while immediate readback of disposable user rows gave the same first-row-only result. No PICOBOOT OTP transfer or picotool setter participates in that call. Conversely, stock-ROM count-one calls with immediate readback passed all 24 transitions on a separate range. The practical fix is explicit single-row programming plus fail-closed physical verification, not trusting a successful command or a voted value.

The internal triggering mechanism remains unproven. The released A2 ROM's `INSTR_MISS | INSTR_DONE` completion predicate is a real source-backed hazard, but no MISS was observed in either instrumented comparison. Stock ROM clears that evidence internally, so those comparisons cannot prove what happened inside the failed opaque call. The separate ROM-like batch hit a helper-imposed busy-poll limit; it did not reproduce the original false-success result under an internal trace.

The ROM explicitly delegates physical verification to its caller. Our provisioner failed that contract by appending the mismatching observation as success and clearing `pending`; the hardened code now rejects it durably and stops. Controller sequencing, programming verification, read-data timing and local OTP power remain unresolved possibilities. Public source and available USB/kernel observations do not establish the electrical cause; vendor PMC/SBPI semantics or external measurements are still needed.

## Incident chronology

### Known-good starting state

Before lock-stage programming:

```text
CRIT1 rows 0x0040..0x0047 = [1, 1, 1, 1, 1, 1, 1, 1]
BOOT_FLAGS0 rows 0x0048..0x004a = [0, 0, 0]
BOOT_FLAGS1 rows 0x004b..0x004d = [0x0e01, 0x0e01, 0x0e01]
BOOTKEY0 = be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0
PAGE2_LOCK1 = 0x151515
PAGE63_LOCK1 = 0x151515
secure boot = enabled
```

The enable stage had already demonstrated:

- signed application startup;
- signed UF2 reinstall through MSD;
- matching application serial;
- blank commissioning state;
- secure boot enabled with the intended key;
- preparation record reconciled successfully.

### Lock-stage command sequence

`tools/firmware.py` ran one picotool process for each field:

1. Eight `BOOT_FLAGS0` named-field writes.
2. `CRIT1.DEBUG_DISABLE=1`.
3. `CRIT1.SECURE_DEBUG_DISABLE=1`.
4. Final raw redundant readback.

Every `BOOT_FLAGS0` group reached its intended three-copy value `0x2da180`.

After `DEBUG_DISABLE`, all eight CRIT1 rows changed as intended:

```text
[1, 1, 1, 1, 1, 1, 1, 1]
 ->
[5, 5, 5, 5, 5, 5, 5, 5]
```

After `SECURE_DEBUG_DISABLE`, only the first copy changed:

```text
[5, 5, 5, 5, 5, 5, 5, 5]
 ->
[7, 5, 5, 5, 5, 5, 5, 5]
```

The final guard rejected the stage:

```text
rejected: final public redundant readback mismatch
```

The record remained:

```json
{
  "completed_stage": "enable",
  "pending": null,
  "serial": "00afd9003906a634"
}
```

The final saved observation was `SECURE_DEBUG_DISABLE`, containing the mismatched raw rows. A later direct `Board.snapshot()` independently confirmed the same values.

### Why `pending` is null

`record_action()` performs this sequence:

1. persist `pending=label`;
2. invoke picotool;
3. take a public snapshot;
4. append the observation;
5. clear `pending` and persist the record.

The `SECURE_DEBUG_DISABLE` observation proves that picotool exited zero and the snapshot completed. The per-action helper did not validate that the physical row values matched the intended result. The later final guard found the mismatch.

## Exact host operation

The affected call was equivalent to:

```text
picotool otp set CRIT1.SECURE_DEBUG_DISABLE 1 \
  --bus <current-bus> --address <current-address>
```

For CRIT1, pinned picotool 2.3.1 resolves the metadata to:

```text
wRow             = 0x0040
wRowCount        = 8
bEcc             = 0
dTransferLength  = 32
payload           = 8 * little-endian uint32(0x00000007)
```

The setter:

1. reads raw row `0x0040`;
2. merges field mask `0x2` into the old value `0x5`;
3. obtains `0x7`;
4. repeats that value eight times because CRIT1 metadata specifies redundancy 8;
5. checks `payload_length == 4 * wRowCount`;
6. calls one synchronous `picoboot_otp_write`.

There is no normal direct-field path that reduces this command to one row. The immediately preceding `DEBUG_DISABLE` write used the same CRIT1 redundancy metadata and successfully updated all eight rows.

## Incident-time host provenance

The operator invoked the firmware tool with:

```bash
FIRMWARE_TOOL="$PWD/tools/firmware.py"
TOOL_BIN=/usr/local/bin
PATH="$TOOL_BIN:/usr/bin:/bin" /usr/bin/python3 -I "$FIRMWARE_TOOL" ...
```

The files were unchanged between their recorded timestamps and the approximately 21:00 lock attempt:

| Component | SHA-256 | Timestamp before incident |
|---|---|---|
| `tools/firmware.py` | `102118fc05b64dffb8a782a740169d403d75457ff8a4e960a20ae2cb51bbe6b7` | `2026-10-29 20:18:54 +0000` |
| `/usr/local/bin/picotool` | `ae14caf911c0e0b67dc04baefd1b681ceb216279c8d5662e516a6bd5b9d1c60c` | `2026-10-29 14:20:16 +0000` |
| `/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0` | `e422dc361a501e8175a94e16228704de7ca6376037fc29a0e7272e8fe2c8edc1` | package `2:1.0.29-2build1` |

The installed picotool reports:

```text
picotool v2.3.1 (Linux, GNU-15.2.0, Release)
```

The installed binary's relevant embedded CRIT1 metadata and normalized disassembly match the pinned 2.3.1 source. The separately built `/tmp/pico2-picotool/build/picotool` was linked against private libusb 1.0.30 but was not selected by the explicit PATH. Both report 2.3.1 because that version is compiled into their source; version text alone is not provenance.

The provisioning record stores only the version string, not executable and library hashes. The filesystem evidence is strong, but the record itself does not cryptographically bind the executable.

## Host USB/PICOBOOT path

The host sends:

1. one 32-byte PICOBOOT command header;
2. one 32-byte OTP data transfer;
3. waits for the opposite-direction success ACK.

The data transfer is one full-speed USB packet because the endpoint maximum packet size is 64 bytes.

The host rejects:

- a command-header short transfer;
- a nonzero data-transfer result;
- a successful data transfer reporting fewer than 32 bytes.

The Python wrapper rejects every nonzero picotool exit. Because `record_action()` appended the observation, this command returned zero.

The host does not query command status after a successful ACK. Its ACK path also fails to require that the received byte count is exactly one. Those are observability/robustness defects, but neither constructs a four-byte OTP payload.

The ROM validates:

```text
dTransferLength == wRowCount * (bEcc ? 2 : 4)
```

For this command, it accepts only 32 bytes. The USB stream helper receives the 32-byte packet, invokes the asynchronous OTP task with `data_length=32`, and derives eight raw rows. It does not normally schedule a four-byte row-0 task followed by seven later tasks.

A normal host-side four-byte truncation would produce a nonzero result and would not explain the saved successful observation.

## Released A2 ROM OTP path

The released A2 disassembly and public source show that `otp_access()`:

1. derives `num_rows = buf_len >> 2` for raw rows;
2. prepares the OTP programming interface once;
3. loops sequentially from the base row through every requested row;
4. checks permissions and prohibited 1-to-0 transitions per row;
5. invokes `s_varm_otp_program_blocking(row, full_value)`;
6. does not read back the programmed value;
7. returns `BOOTROM_OK` after the loop unless a software check failed.

The SDK contract says `BOOTROM_OK` means all rows were written successfully. The actual low-level implementation cannot guarantee that because it neither verifies each fuse result nor distinguishes the SBPI dropped-instruction status.

### SBPI false-completion mechanism

The A2 ROM implementation is:

```c
static void s_varm_otp_wait_sbpi_done(void) {
    uint32_t status_mask =
        OTP_SBPI_STATUS_INSTR_MISS_BITS |
        OTP_SBPI_STATUS_INSTR_DONE_BITS;
    while (!(otp_hw->sbpi_status & status_mask))
        ;
    otp_hw->sbpi_status = status_mask;
}
```

The RP2350 register contract defines:

- `INSTR_DONE`, bit 4: last instruction completed;
- `INSTR_MISS`, bit 8: last attempted instruction was dropped because the previous one had not finished;
- both bits are write-one-to-clear.

The ROM therefore converts a dropped low-level instruction into an apparent completion. A row program uses multiple SBPI instructions for row address, data, programming control, busy/status reads and STOP. If one later instruction is issued while a prior one is still active:

1. hardware drops it and sets `INSTR_MISS`;
2. the ROM wait wakes on `INSTR_MISS`;
3. the ROM clears the evidence and continues;
4. subsequent instructions may also be issued against stale address/data/controller state;
5. a cascade can leave later rows unchanged;
6. the outer row loop has no post-write verification and can still return success;
7. PICOBOOT emits its normal success ACK.

This is a source-backed false-success route, not an observed cause. The original and reproduced opaque ROM calls did not retain internal instruction status. Both later instrumented comparisons observed DONE without MISS, while changing timing/sequencing. Do not rank this hypothesis above other on-device programming failures on the strength of the source predicate alone.

The public current bootrom source still contains the same `INSTR_MISS | INSTR_DONE` predicate. No published fix or erratum specifically naming this behavior was found.

### Silent physical programming failure

`otp_access()` contains this explicit comment after each programming call:

```c
// note: we expect user to verify the data was written correctly
```

The programming function waits for controller busy completion but does not verify that the requested fuses changed. A charge-pump, OTP-array, sequencing or power-related failure could therefore return apparent success. The direct ROM reproduction proves physical mismatch despite success, but does not identify which internal failure produced it.

RP2350 A2 erratum E16 concerns corrupt OTP row reads when `USB_OTP_VDD` is disrupted. It does not document an eight-row programming truncation. The board was USB-powered only, and the kernel logged no USB/xHCI/over-current/voltage event around the incident. Neither fact excludes a local OTP-rail or internal-controller transient.

## Candidate ranking

| Candidate | Assessment | Evidence |
|---|---|---|
| On-device ROM/controller programming path returns success despite mismatch | Reproduced | Direct stock-ROM eight-row call produced `[7,5,5,5,5,5,5,5]`; count-one calls passed all 24 transitions |
| Host accepts an incorrect physical postcondition | Reproduced and fixed | Old action cleared pending; hardened action retains uncertainty and stops |
| ROM treats `INSTR_MISS` as successful completion | Source-backed hazard; trigger unproven | No MISS in either instrumented comparison; failed opaque ROM call clears internal evidence |
| Silent fuse/charge-pump/sequencing failure | Unresolved | No ROM post-program verification; instrumented batch exceeded its own busy-poll bound |
| Host generated a partial payload, wrong executable, or USB short transfer | Not necessary for reproduction | Exact pattern reproduced without any host OTP write transfer |
| First CRIT1 copy immediately disabled later writes | Not necessary for reproduction | Failure also occurs in ordinary user rows; original configuration is sampled on OTP reset |
| RP2350-E16 directly produced this pattern | Not established | Published erratum concerns read corruption, not a successful row-0-only write |
| Picotool issue #330 initiated the mismatch | Excluded | The issue begins with an already unequal redundant register |

## Picotool issue #330: recovery hazard, not initiating cause

Upstream issue <https://github.com/raspberrypi/picotool/issues/330> documents the exact existing state:

```text
RAW_VALUE=0x000007;0x000005;0x000005;0x000005;
          0x000005;0x000005;0x000005;0x000005
```

Picotool's named-field setter reads only the first physical copy when deciding which bits require programming. Once row `0x0040` is `7`, rerunning:

```text
picotool otp set CRIT1.SECURE_DEBUG_DISABLE 1
```

can decide that no write is required even though rows `0x0041..0x0047` remain `5`.

Do not use the named-field command to repair this board. Any eventual reconciliation must address explicit physical rows and verify each one, after the root-cause experiment is complete.

## Current board implications

The currently programmed raw values include:

```text
CRIT1 0x0040         = 0x000007
CRIT1 0x0041..0x0047 = 0x000005
BOOT_FLAGS0 copies   = 0x2da180
BOOT_FLAGS1 copies   = 0x000e01
BOOTKEY0             = authorized hash
PAGE2_LOCK1          = 0x151515
PAGE63_LOCK1         = 0x151515
```

`DEBUG_DISABLE` is present in all eight CRIT1 copies. The lock-stage BOOT flags have now been sampled. Observed effects are:

- hardware debug disabled;
- PICOBOOT disabled;
- signed USB MSD BOOTSEL retained;
- secure boot latched on; authenticated diagnostic/application images booted (unsigned-image rejection was not tested here).

The original live PICOBOOT session was already gone when this work began. Subsequent physical BOOTSEL enumeration exposed only mass storage. Do not mistake the historical PICOBOOT-dependent plan below for an available recovery path on the restored sacrificial board.

The board must not be used as successful qualification evidence unless the root cause is understood, the final physical policy is verified, and the complete required acceptance procedure is rerun. It may instead be permanently designated sacrificial.

## Original PICOBOOT-dependent test plan (historical)

The following was the pre-instrumentation plan. Its live-session prerequisite was unavailable; the reviewed signed-flash protocols and actual results above supersede it for this board. Retain the distinction between observing a mechanism and merely repairing the mismatch. No further destructive run is authorized by treating this historical matrix as an automatic retry loop.

### 1. Preserve the incident evidence before mutation

Before the first new device write:

1. Copy the owner-only provisioning record to a separate protected incident directory without modifying the original.
2. Record SHA-256, size, ownership, mode and timestamps for the original and copy.
3. Save the existing public snapshots and this report with the incident material.
4. Record hashes/build IDs for the exact firmware tool, picotool and dynamically loaded libusb.
5. Record the current host kernel, USB controller, picotool, compiler and libusb versions.
6. Start a timestamped operator transcript with shell tracing disabled around any secret-bearing operation.
7. Confirm exactly one attached RP2350 and revalidate CHIPID `00afd9003906a634` before every command.
8. Do not reset or power-cycle merely to confirm the last observation.

Do not store RANDID, private boot keys, decrypted signing keys, raw secret pages, or operational KES material in the incident bundle.

### 2. Capture the host transport on every destructive write

Prepare instrumentation before issuing another OTP command:

- Capture USB traffic with `usbmon`/Wireshark or an equivalent kernel trace.
- Patch or wrap picotool to preserve, for each command:
  - executable SHA-256 and GNU build ID;
  - loaded libusb path and SHA-256;
  - complete 32-byte PICOBOOT command header;
  - OTP payload bytes;
  - requested and reported transfer lengths;
  - libusb return codes;
  - ACK endpoint, return code and received length;
  - `GET_COMMAND_STATUS` response after success and failure;
  - selected bus/address and revalidated CHIPID.
- Preserve stdout and stderr even on success.
- Do not log private signing material or unrelated secret OTP contents.

The host trace should prove whether every test submits the intended row count and repeated payload. It cannot by itself expose an internal SBPI miss that the ROM has already cleared.

### 3. Select disposable OTP rows deliberately

Do not use CRIT1 for the first reproduction attempt; its remaining zero bits are security-significant and one-way.

Choose a blank, writable, noncritical user OTP range only after validating its schema, page locks and current raw values. Exclude:

- page 0 factory data and RANDID;
- page 1 critical/boot flags;
- page 2 boot-key hashes;
- page-lock words and pages 62/63;
- any row used by firmware, boot metadata, keys or recorded board identity.

Document the selected rows and why they are disposable. Because the board is sacrificial, consuming selected user OTP is acceptable, but an unreviewed arbitrary row is not.

### 4. Reproduce the redundant batch operation

On disposable raw rows, construct controlled experiments that mirror the incident:

1. Confirm all selected rows have the same initial value.
2. Submit one multi-row raw PICOBOOT write with the same row count and payload size as CRIT1: eight raw rows, 32 bytes, one new bit in each value.
3. Capture USB and picotool diagnostics.
4. Read every physical row back immediately.
5. Repeat on fresh disposable rows until the behavior is reproduced or the allocated test matrix is exhausted.
6. Vary one factor at a time:
   - installed picotool versus the separately built pinned binary;
   - system libusb 1.0.29 versus private libusb 1.0.30;
   - multi-row batch versus eight explicit one-row commands;
   - inter-command delay;
   - USB port/controller/cable, only after preserving the current-session opportunity;
   - host scheduling/load;
   - monitored supply conditions if measurement equipment is available.

A test is not successful merely because picotool exits zero. Record all physical rows after every write.

### 5. Instrument SBPI directly

A decisive test requires observing `INSTR_MISS` before it is cleared. The stock ROM API cannot provide that evidence.

Design a narrowly scoped diagnostic helper for this sacrificial board that:

- executes in an allowed Secure SRAM context in the current security state;
- is authenticated as required by the already-enabled boot authority;
- targets only the reviewed disposable OTP rows;
- implements or wraps the documented SBPI sequence;
- records the complete `SBPI_STATUS` value after every instruction;
- distinguishes `INSTR_MISS` from `INSTR_DONE`;
- aborts immediately on `INSTR_MISS`;
- performs per-row raw readback before advancing;
- emits a bounded public diagnostic report without exposing secret OTP data;
- has no generic production OTP programming interface;
- is never added to a release bundle or normal firmware.

Before running it, establish whether the current latched BOOT flags permit authenticated SRAM execution without a reset. Do not discover this by resetting the board. If the helper cannot run in the current session, preserve that result and move to host-observed destructive testing rather than weakening another board.

A useful second experiment deliberately attempts to provoke an SBPI miss on disposable rows, then checks whether the unmodified ROM-style wait would convert it into apparent completion and whether the resulting physical pattern matches the incident. Keep this isolated from CRIT1 and all boot-key/lock rows.

### 6. Investigate the silent-programming alternative

For every disposable-row test:

- read back the row immediately after the programming busy cycle;
- record whether SBPI reported DONE or MISS;
- record controller status and any available power-good/diagnostic state;
- monitor USB VBUS and, if safely accessible, the OTP-related supply behavior;
- avoid inferring stable voltage from the absence of kernel USB messages;
- compare first-row and later-row timing;
- determine whether failures correlate with repeated programming of the same bit position across adjacent rows.

A zero exit plus `INSTR_DONE` for every low-level instruction and failed physical readback would materially strengthen the charge-pump/fuse-programming hypothesis.

### 7. Decide separately whether to reconcile CRIT1

Do not mix root-cause reproduction with repair. After testing, make an explicit decision:

- **Leave sacrificial:** preserve the mismatched CRIT1 state as a physical reproducer and never use the board operationally.
- **Reconcile for further locked-device tests:** program rows `0x0041..0x0047` explicitly and individually, with transport capture and immediate raw readback after each irreversible write.

If reconciliation is selected, never invoke the named-field setter because issue #330 reads only row 0. Stop after the first unexpected result. A successful reconciliation does not retroactively qualify the original lock operation or erase the bug.

## Hardening checklist and disposition

The repository hardening below is implemented and verified as described above. The original PICOBOOT capture requirement was unavailable on this device and was replaced by the reviewed signed-flash experiment; no wire capture is claimed. Upstream publication was explicitly changed to a local draft. These distinctions remain part of qualification evidence.

### Preserve board and incident records

1. Preserve the board and record unchanged until instrumentation and the destructive test protocol are ready.
2. After destructive testing begins, retain immutable pre-test copies and append new evidence rather than rewriting the original record.
3. Bind every evidence item to serial `00afd9003906a634`, candidate commit, tool hashes and timestamps.

### File an upstream Raspberry Pi report

Report the incident to Raspberry Pi with:

- A2 stepping and serial;
- exact before/after CRIT1 raw values;
- successful picotool exit and successful post-command snapshot;
- `/usr/local/bin/picotool` SHA-256 and build ID;
- libusb version and hash;
- exact command header/payload if reproduced under capture;
- the A2 released disassembly and public-source `INSTR_MISS | INSTR_DONE` logic;
- the complete public provisioning record or a minimally redacted copy;
- the fact that no reset occurred between the successful command and failing readback;
- the board's USB-only power condition and absence of relevant kernel log entries;
- a direct question: can `s_varm_otp_wait_sbpi_done()` convert `INSTR_MISS` into `BOOTROM_OK`, and can that cause later rows in one `otp_access()` call to remain unchanged?

Do not claim the ROM mechanism is proven. Ask Raspberry Pi to confirm intended SBPI semantics, any unpublished erratum, and whether A3/A4 silicon or ROM behavior differs.

### Reproduce on sacrificial hardware with complete instrumentation

The minimum reproduction evidence is:

- `usbmon` capture;
- picotool log of command header, all 32 payload bytes, transfer counts, ACK and command status;
- executable and libusb hashes;
- raw before/after rows;
- retained stdout/stderr;
- custom-helper `INSTR_MISS` versus `INSTR_DONE` observations if feasible;
- power/timing observations where available.

The current board is authorized for this role. Do not move to a backup board merely because the current board is inconvenient.

### Harden `tools/firmware.py` and the provisioning record

Implement all of the following before provisioning another production board:

1. Record picotool SHA-256, GNU build ID, canonical executable path and full version output.
2. Record the dynamically loaded libusb canonical path, package version and SHA-256.
3. Preserve bounded stdout/stderr for each irreversible subprocess, including successful commands.
4. Record the exact intended OTP operation in public form: register/row, physical copy count, raw expected values and expected postcondition.
5. Validate each `record_action()` observation against that action's expected physical result before clearing `pending`.
6. On mismatch, retain a distinct uncertain/potentially-applied state; do not append a successful action or continue to later writes.
7. Never identify a tool solely by `picotool version`.
8. Add an optional operator-selected transport trace hook suitable for qualification without making packet capture a production dependency.

### Replace batch redundant-field programming

For critical redundant fields and boot flags:

1. Compute the intended raw physical values from the reviewed policy.
2. Program one physical row per command rather than relying on one multi-row named-field write.
3. Read that same physical row back immediately.
4. Stop before the next physical row if the result is not exact.
5. After all copies, read the complete redundant group independently and validate every copy plus the voted value.
6. Preserve the command/payload/result for every copy in the owner-only public record.
7. Never use the named-field setter to reconcile an already unequal redundant group.
8. Keep preview output in named policy terms while making the applying path's physical-row operations explicit and auditable.

This does not make OTP programming transactional. It bounds a failure to one physical copy and detects it before consuming additional rows.

### Add permanent behavior tests

Add tests that prove:

- an action observation that differs from its expected physical postcondition leaves the record uncertain and stops the stage;
- tool identity includes hashes/build ID and rejects a changed executable despite identical `version` output;
- bounded stdout/stderr are retained for success and failure;
- redundant groups are programmed as explicit physical copies with readback after each copy;
- a simulated row-0-only success is rejected immediately;
- an already unequal group is never passed to the named-field setter;
- resume cannot replay a partially observed critical-field write;
- final stage completion requires every physical copy, not only a voted value;
- diagnostics do not contain private key material, RANDID or secret OTP pages.

Use fake process/board adapters for permanent tests. Hardware reproduction remains qualification evidence, not a nondeterministic unit test.

### Update maintainer procedures and qualification criteria

Update maintainer documentation to require:

- exact tool and library hashes before attended provisioning;
- immutable incident records after any uncertain OTP operation;
- no reset/retry until the uncertain state is diagnosed;
- explicit physical-row readback evidence for every redundant security field;
- upstream incident reference and disposition;
- a failed lock-stage attempt never being promoted to qualification by later repair alone.

The end-user README must not receive maintainer incident internals or signing-key upload procedures.

## Safe stopping points

Stop and preserve evidence if any of these occur:

- board identity changes or more than one RP2350 is attached;
- the current PICOBOOT session disappears before instrumentation is ready;
- a selected disposable row is not blank or has unexpected locks;
- command header/payload differs from the test plan;
- libusb reports a short/error transfer;
- picotool returns zero but any physical row differs;
- `INSTR_MISS` is observed;
- custom-helper code would require weakening another device or publishing a generic OTP programmer;
- the provisioning record or its protected copy changes unexpectedly.

A stop is a useful experimental result. Do not turn it into a retry without reviewing the captured state.

## Primary evidence and references

Repository evidence:

- `tools/firmware.py::run`
- `tools/firmware.py::Board.command`
- `tools/firmware.py::Board.snapshot`
- `tools/firmware.py::record_action`
- lock-stage loops and final guard near `tools/firmware.py` lines 1090–1103 at incident time
- `/var/lib/pico2-kes-provisioning/00afd9003906a634/otp-provisioning.json`

Upstream references:

- RP2350 A2 boot ROM source at commit `fd6104450fa8f55c11c0c9b54dbc69a27537130f`:
  <https://github.com/raspberrypi/pico-bootrom-rp2350/blob/fd6104450fa8f55c11c0c9b54dbc69a27537130f/src/main/arm/varm_otp.c>
- RP2350 A2 released disassembly:
  <https://github.com/raspberrypi/pico-bootrom-rp2350/releases/download/A2/arm-bootrom.dis>
- RP2350 datasheet, PICOBOOT OTP commands, OTP SBPI status and A2 errata:
  <https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf>
- Pinned picotool 2.3.1 source commit `2041936441b48a3cc53ae3da9e805229fe8f4e18`:
  <https://github.com/raspberrypi/picotool/tree/2041936441b48a3cc53ae3da9e805229fe8f4e18>
- Picotool redundant-row issue #330:
  <https://github.com/raspberrypi/picotool/issues/330>
- Pico SDK `otp_access()` contract:
  <https://github.com/raspberrypi/pico-sdk/blob/2.3.1/src/rp2_common/pico_bootrom/include/pico/bootrom.h>

## Original handoff acceptance

This historical checklist required a reviewable protocol and instrumentation before device mutation. The initial passive observation established that its live-PICOBOOT prerequisite was already unavailable; the signed-flash protocols above were reviewed before consuming their fixed ranges. The checklist asked for:

- how the current live PICOBOOT session is preserved;
- which reviewed disposable rows will be consumed;
- how command/payload/ACK/status and raw readback are captured;
- whether and how direct SBPI status can be observed;
- the exact stop conditions;
- which repository hardening changes are implemented before another production provisioning attempt.

Only after that protocol is reviewable should destructive device commands begin. The board may be lost; the evidence must not be.
