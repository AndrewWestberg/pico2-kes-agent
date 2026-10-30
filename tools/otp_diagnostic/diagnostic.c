/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 * Copyright (c) 2026 pico2-kes-agent contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Lab-only, board-specific destructive experiment. The SBPI constants and
 * configuration tables follow pico-bootrom-rp2350 fd6104450fa8f55c11c0c9b54dbc69a27537130f,
 * src/main/arm/varm_otp.c and src/main/native/bootrom_otp.h. Direct SBPI tests
 * record each instruction's terminal status and reject MISS; stock-ROM calls
 * expose only post-call status. Page 3 is user OTP; only four fixed eight-row
 * ranges are consumable, each admitted only while blank.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "pico/bootrom.h"
#include "hardware/regs/otp.h"
#include "hardware/regs/otp_data.h"
#include "hardware/structs/otp.h"
#include "hardware/address_mapped.h"
#include "hardware/regs/addressmap.h"

#define ROM_FIRST 0xc4u
#define SBPI_FIRST 0xd0u
#define BATCH_FIRST 0xe0u
#define ROM_ROWS_FIRST 0xe8u
#define ROWS 8u
#define STATUS_MASK (OTP_SBPI_STATUS_INSTR_DONE_BITS | OTP_SBPI_STATUS_INSTR_MISS_BITS)
#define TRACE_MAX 17408u
#define POLL_MAX 4096u
#define BUSY_MAX 1024u
#define DAP 0x02u
#define PMC 0x3au

static const uint8_t expected_key[32] = {
    0xbe,0x36,0x4e,0x66,0x0f,0x6e,0x72,0x36,0xcc,0x14,0xd3,0xe7,0x4b,0x33,0x66,0x03,
    0x11,0x60,0x8f,0xa7,0x8f,0x38,0xcd,0x6c,0xc5,0xc4,0xf0,0x31,0xc9,0x10,0xb8,0xa0
};
#ifndef PICO2_OTP_CRIT1_REPAIR
/* RQ0..RQ11, CQ0..CQ1; exact ROM raw-program and read tables. */
static const uint8_t dap_read[14] = {1,0x6e,9,4,0,0,0x1f,1,8,0,0,0,0,0};
static const uint8_t dap_prog[14] = {1,0x48,0x29,4,0,0,0x1f,1,8,0,1,0,0,0};
static const uint8_t pmc_prog[14] = {1,0x48,0x13,0xdb,0x8f,0x47,0x81,0x4b,0x12,0x0e,0x5d,2,0x0a,0};

typedef struct { uint32_t us, what, value, polls; } trace_entry;
static trace_entry trace[TRACE_MAX];
static unsigned trace_count;
static bool terminal;
static const char *failure;
static bool rom_read_latch;

static void record(uint32_t what, uint32_t value) {
    if (trace_count < TRACE_MAX)
        trace[trace_count++] = (trace_entry){time_us_32(), what, value, 0};
}
static void emit_trace(uint32_t row, uint32_t value) {
    printf("SBPI row=%04" PRIx32 " target=%08" PRIx32 " result=%s entries=%u\n",
           row, value, failure ? failure : "verified", trace_count);
    for (unsigned i = 0; i < trace_count; ++i)
        printf("trace %u us=%" PRIu32 " what=%08" PRIx32 " value=%08" PRIx32 " polls=%" PRIu32 "\n",
               i, trace[i].us, trace[i].what, trace[i].value, trace[i].polls);
}
#endif
static bool raw(uint32_t row, uint32_t *value) {
    otp_cmd_t cmd = {.flags = row};
    return rom_func_otp_access((uint8_t *)value, 4, cmd) == BOOTROM_OK;
}
static bool identity(bool announce) {
    uint32_t info[4] = {0};
    int n = rom_get_sys_info(info, 4, SYS_INFO_CHIP_INFO);
    uint8_t version = rp2350_rom_version();
    uint32_t critical = otp_hw->critical;
    bool ok = n == 4 && info[0] == SYS_INFO_CHIP_INFO && info[2] == 0x3906a634u &&
              info[3] == 0x00afd900u && version == 2 &&
              (critical & OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS);
    uint32_t key[8] = {0}; /* ROM requires a word-aligned output buffer. */
    otp_cmd_t cmd = {.flags = 0x80u | OTP_CMD_ECC_BITS};
    int rc = rom_func_otp_access((uint8_t *)key, sizeof key, cmd);
    bool key_ok = rc == BOOTROM_OK && memcmp(key, expected_key, sizeof key) == 0;
    ok = ok && key_ok;
    if (announce) {
        printf("identity result=%d words=%d flags=%08" PRIx32 " package=%08" PRIx32 " chip=%08" PRIx32 "%08" PRIx32 " rom=%u critical=%08" PRIx32 " key_match=%u",
               ok, n, info[0], info[1], info[3], info[2], version, critical, key_ok);
#ifdef PICO2_OTP_CRIT1_REPAIR
        printf(" key=");
        for (unsigned i = 0; i < sizeof key; ++i) printf("%02x", ((uint8_t *)key)[i]);
#endif
        puts("");
    }
    return ok;
}
#ifndef PICO2_OTP_CRIT1_REPAIR
static bool locks(bool announce) {
    uint32_t l0 = 0, l1 = 0;
    bool ok = raw(OTP_DATA_PAGE3_LOCK0_ROW, &l0) && raw(OTP_DATA_PAGE3_LOCK1_ROW, &l1);
    uint32_t sw = otp_hw->sw_lock[3];
    if (announce) printf("page3 lock0=%08" PRIx32 " lock1=%08" PRIx32 " sw=%08" PRIx32 " reads_ok=%u\n", l0, l1, sw, ok);
    return ok && !l0 && !l1 && !sw;
}
static bool rows(uint32_t first, uint32_t expected, bool announce) {
    bool ok = true;
    for (unsigned i = 0; i < ROWS; ++i) {
        uint32_t value = 0;
        bool read_ok = raw(first + i, &value);
        if (announce) printf("row=%04" PRIx32 " raw=%08" PRIx32 " read_ok=%u\n", first+i, value, read_ok);
        if (!read_ok || value != expected) ok = false;
    }
    return ok;
}
static bool preflight(uint32_t first) {
    bool id = identity(true), lock_ok = locks(true);
    bool blank = rows(first, 0, true);
    uint32_t status = otp_hw->sbpi_status, usr = otp_hw->usr;
    printf("preflight status=%08" PRIx32 " usr=%08" PRIx32 " dbg=%08" PRIx32 "\n", status, usr, otp_hw->dbg);
    return id && lock_ok && blank && !(status & STATUS_MASK) && usr == OTP_USR_DCTRL_BITS;
}
static void snapshot(void) {
    identity(true);
    for (uint32_t row = 0x40; row < 0x4e; ++row) {
        uint32_t v = 0; bool ok = raw(row, &v);
        printf("row=%04" PRIx32 " raw=%08" PRIx32 " read_ok=%u\n", row, v, ok);
    }
    locks(true);
    (void)rows(ROM_FIRST, 0, true);
    (void)rows(SBPI_FIRST, 0, true);
    (void)rows(BATCH_FIRST, 0, true);
    (void)rows(ROM_ROWS_FIRST, 0, true);
    printf("controller status=%08" PRIx32 " usr=%08" PRIx32 " dbg=%08" PRIx32 "\n",
           otp_hw->sbpi_status, otp_hw->usr, otp_hw->dbg);
}
static void rom_test(void) {
    if (!preflight(ROM_FIRST)) { puts("ABORT preflight"); terminal = true; return; }
    puts("ROM status is post-call only: stock ROM can clear MISS before returning.");
    const uint32_t values[] = {1, 5, 7};
    for (unsigned stage = 0; stage < 3; ++stage) {
        uint32_t payload[ROWS];
        for (unsigned i = 0; i < ROWS; ++i) payload[i] = values[stage];
        printf("ROM row=00c4 count=8 payload=");
        for (unsigned i = 0; i < sizeof payload; ++i) printf("%02x", ((uint8_t *)payload)[i]);
        printf(" start_us=%" PRIu32 "\n", time_us_32());
        stdio_flush();
        if (!stdio_usb_connected()) { puts("ABORT disconnected"); terminal = true; return; }
        otp_cmd_t cmd = {.flags = ROM_FIRST | OTP_CMD_WRITE_BITS};
        int rc = rom_func_otp_access((uint8_t *)payload, sizeof payload, cmd);
        uint32_t end = time_us_32(), status = otp_hw->sbpi_status;
        printf("ROM end_us=%" PRIu32 " rc=%d status=%08" PRIx32 "\n", end, rc, status);
        bool matched = rows(ROM_FIRST, values[stage], true);
        bool good_locks = locks(true), good_id = identity(true);
        if (rc != BOOTROM_OK || (status & STATUS_MASK) || !matched || !good_locks || !good_id) {
            puts("ABORT ROM"); terminal = true; return;
        }
    }
    puts("ROM complete");
}
static void rom_rows_test(void) {
    if (!preflight(ROM_ROWS_FIRST)) { puts("ABORT preflight"); terminal = true; return; }
    const uint32_t values[] = {1, 5, 7};
    for (unsigned stage = 0; stage < 3; ++stage) {
        for (unsigned i = 0; i < ROWS; ++i) {
            uint32_t row = ROM_ROWS_FIRST + i, payload = values[stage], observed = 0;
            printf("ROMROW row=%04" PRIx32 " count=1 payload=", row);
            for (unsigned b = 0; b < sizeof payload; ++b) printf("%02x", ((uint8_t *)&payload)[b]);
            puts("");
            stdio_flush();
            if (!stdio_usb_connected()) { puts("ABORT disconnected"); terminal = true; return; }
            otp_cmd_t cmd = {.flags = row | OTP_CMD_WRITE_BITS};
            uint32_t start = time_us_32();
            int rc = rom_func_otp_access((uint8_t *)&payload, sizeof payload, cmd);
            uint32_t elapsed = time_us_32() - start, status = otp_hw->sbpi_status;
            bool read_ok = raw(row, &observed);
            printf("ROMROW row=%04" PRIx32 " rc=%d elapsed_us=%" PRIu32
                   " status=%08" PRIx32 " raw=%08" PRIx32 " read_ok=%u\n",
                   row, rc, elapsed, status, observed, read_ok);
            if (rc != BOOTROM_OK || (status & STATUS_MASK) || !read_ok ||
                observed != values[stage] || !locks(false) || !identity(false)) {
                puts("ABORT ROMROW"); terminal = true; return;
            }
        }
        if (!rows(ROM_ROWS_FIRST, values[stage], true)) {
            puts("ABORT ROMROW group"); terminal = true; return;
        }
    }
    puts("ROMROW complete");
}

/* A sticky MISS is checked on EVERY poll, before DONE. Retain the complete
 * terminal status, poll count and timestamp for every dispatched instruction.
 * Buffers are emitted between verified rows, never while a pulse is active. */
static bool instruction(uint32_t instr, uint8_t *result) {
    if (trace_count + 3 > TRACE_MAX) { failure = "trace_capacity"; return false; }
    uint32_t prior = otp_hw->sbpi_status;
    if (prior & STATUS_MASK) { record(0x80000001u, prior); failure = "pre_instruction_status"; return false; }
    /* RDATA_VLD is W1C and the stock ROM leaves it set after reads.
     * Clear only this stale read latch before a new read, never DONE/MISS. */
    if (result && !rom_read_latch) otp_hw->sbpi_status = OTP_SBPI_STATUS_RDATA_VLD_BITS;
    otp_hw->sbpi_instr = instr;
    uint32_t s = 0;
    unsigned polls;
    for (polls = 1; polls <= POLL_MAX; ++polls) {
        s = otp_hw->sbpi_status;
        if (s & STATUS_MASK) break;
    }
    record(instr, s);
    trace[trace_count - 1].polls = polls <= POLL_MAX ? polls : POLL_MAX;
    if (s & OTP_SBPI_STATUS_INSTR_MISS_BITS) { failure = "MISS"; return false; }
    if (!(s & OTP_SBPI_STATUS_INSTR_DONE_BITS)) { failure = "instruction_timeout"; return false; }
    if (result) {
        if (!(s & OTP_SBPI_STATUS_RDATA_VLD_BITS)) { failure = "missing_read_data"; return false; }
        *result = (uint8_t)otp_hw->sbpi_rdata[0];
        record(0x80000002u, *result);
    }
    otp_hw->sbpi_status = OTP_SBPI_STATUS_INSTR_DONE_BITS |
        (result && !rom_read_latch ? OTP_SBPI_STATUS_RDATA_VLD_BITS : 0);
    return true;
}
static bool wr(uint8_t target, uint8_t addr, uint8_t data) {
    uint32_t ins = OTP_SBPI_INSTR_EXEC_BITS | OTP_SBPI_INSTR_IS_WR_BITS | OTP_SBPI_INSTR_HAS_PAYLOAD_BITS |
        ((uint32_t)target << OTP_SBPI_INSTR_TARGET_LSB) | ((uint32_t)(0xc0u | addr) << OTP_SBPI_INSTR_CMD_LSB) | data;
    return instruction(ins, NULL);
}
static bool command(uint8_t cmd) {
    return instruction(OTP_SBPI_INSTR_EXEC_BITS | OTP_SBPI_INSTR_IS_WR_BITS |
        (PMC << OTP_SBPI_INSTR_TARGET_LSB) | ((uint32_t)cmd << OTP_SBPI_INSTR_CMD_LSB), NULL);
}
static bool pmc_status(uint8_t *value) {
    return instruction(OTP_SBPI_INSTR_EXEC_BITS | OTP_SBPI_INSTR_HAS_PAYLOAD_BITS |
        (PMC << OTP_SBPI_INSTR_TARGET_LSB) | (0xbfu << OTP_SBPI_INSTR_CMD_LSB), value);
}
static bool configure(uint8_t target, const uint8_t table[14]) {
    for (unsigned i = 0; i < 14; ++i) if (!wr(target, 0x30u+i, table[i])) return false;
    return true;
}
static bool prepare(void) {
    record(0x80000003u, otp_hw->usr);
    otp_hw->usr = 0;
    return configure(DAP, dap_prog) && configure(PMC, pmc_prog) && wr(PMC, 0x3f, 0x0a);
}
static bool restore(void) {
    if (!configure(DAP, dap_read)) return false;
    otp_hw->usr = OTP_USR_DCTRL_BITS;
    record(0x80000004u, otp_hw->usr);
    return true;
}
static bool program_row(uint32_t row, uint32_t value) {
    record(0x80000005u, (row << 16) | value);
    if (!wr(DAP, 0x3c, row) || !wr(DAP, 0x3d, row >> 8) ||
        !wr(DAP, 0, value) || !wr(DAP, 1, value >> 8) || !wr(DAP, 0x20, value >> 16) || !command(1)) return false;
    bool ready = false;
    for (unsigned i = 0; i < BUSY_MAX; ++i) {
        uint8_t s;
        if (!pmc_status(&s)) return false;
        if (!(s & 0x80)) { ready = true; break; }
        if (!rom_read_latch) busy_wait_us_32(10);
    }
    if (!ready) { failure = "pmc_busy_timeout"; return false; }
    return command(2);
}
static void sbpi_test(void) {
    if (!preflight(SBPI_FIRST)) { puts("ABORT preflight"); terminal = true; return; }
    failure = NULL;
    const uint32_t values[] = {1, 5, 7};
    for (unsigned stage = 0; stage < 3 && !failure; ++stage) {
        for (unsigned i = 0; i < ROWS && !failure; ++i) {
            trace_count = 0;
            record(0x80000007u, otp_hw->sbpi_status);
            record(0x80000008u, otp_hw->dbg);
            uint32_t row = SBPI_FIRST + i, v = 0;
            if (prepare() && program_row(row, values[stage]) && restore()) {
                bool read_ok = raw(row, &v);
                record(0x80000006u | (row << 8), v);
                if (!read_ok || v != values[stage]) failure = "row_readback";
                if (!failure && (!locks(false) || !identity(false) ||
                    (otp_hw->sbpi_status & STATUS_MASK))) failure = "post_row_preflight";
            }
            emit_trace(row, values[stage]);
            if (!stdio_usb_connected()) failure = "diagnostic_disconnected";
        }
    }
    if (failure) terminal = true;
    printf("SBPI result=%s\n", failure ? failure : "complete");
}
/* Deliberately mirror ROM batch sequencing on a separate disposable range:
 * one prepare/cleanup, USER-port pre-read between rows, no per-row reprepare,
 * no explicit RDATA_VLD clearing and no extra PMC polling delay. Full physical
 * verification follows each bounded batch; this is NOT the production path. */
static void batch_trace(void) {
    if (!preflight(BATCH_FIRST)) { puts("ABORT preflight"); terminal = true; return; }
    failure = NULL;
    rom_read_latch = true;
    const uint32_t values[] = {1, 5, 7};
    for (unsigned stage = 0; stage < 3 && !failure; ++stage) {
        trace_count = 0;
        record(0x80000007u, otp_hw->sbpi_status);
        record(0x80000008u, otp_hw->dbg);
        if (prepare()) {
            for (unsigned i = 0; i < ROWS && !failure; ++i) {
                uint32_t row = BATCH_FIRST + i;
                hw_xor_bits(&otp_hw->usr, OTP_USR_DCTRL_BITS);
                uint32_t before = *(volatile uint32_t *)(OTP_DATA_RAW_BASE + 4 * row);
                hw_xor_bits(&otp_hw->usr, OTP_USR_DCTRL_BITS);
                record(0x80000009u | (row << 8), before);
                if (before != (stage ? values[stage - 1] : 0)) {
                    failure = "batch_pre_read"; break;
                }
                if (!program_row(row, values[stage])) break;
            }
            if (!failure && restore()) {
                if (!rows(BATCH_FIRST, values[stage], true)) failure = "batch_readback";
                if (!failure && (!locks(false) || !identity(false))) failure = "batch_identity_locks";
            }
        }
        emit_trace(BATCH_FIRST, values[stage]);
        if (!stdio_usb_connected()) failure = "diagnostic_disconnected";
    }
    rom_read_latch = false;
    if (failure) terminal = true;
    printf("BATCHTRACE result=%s\n", failure ? failure : "complete");
}
int main(void) {
    stdio_init_all();
    while (!stdio_usb_connected()) sleep_ms(20);
    puts("OTP lab diagnostic: SNAPSHOT | ROMTEST/SBPITEST/BATCHTRACE/ROMROWTEST 00afd9003906a634");
    char line[64]; unsigned n = 0; bool overflow = false;
    for (;;) {
        int c = getchar_timeout_us(100000);
        if (c == PICO_ERROR_TIMEOUT) continue;
        if (c == '\r') continue;
        if (c != '\n') { if (n + 1 < sizeof line) line[n++] = (char)c; else overflow = true; continue; }
        line[n] = 0;
        if (terminal) puts("HALTED: no further commands");
        else if (!overflow && !strcmp(line, "SNAPSHOT")) snapshot();
        else if (!overflow && !strcmp(line, "ROMTEST 00afd9003906a634")) rom_test();
        else if (!overflow && !strcmp(line, "SBPITEST 00afd9003906a634")) sbpi_test();
        else if (!overflow && !strcmp(line, "BATCHTRACE 00afd9003906a634")) batch_trace();
        else if (!overflow && !strcmp(line, "ROMROWTEST 00afd9003906a634")) rom_rows_test();
        else puts("UNKNOWN command");
        n = 0; overflow = false;
    }
}
#else
#include "repair_sequence.h"

#define REPAIR_STATUS_MASK (OTP_SBPI_STATUS_INSTR_DONE_BITS | OTP_SBPI_STATUS_INSTR_MISS_BITS)
#define SERIAL "00afd9003906a634"
static struct repair_sequence sequence = { IDLE, 1 };
static uint32_t admitted_lock1, admitted_sw1;

static bool read_row(uint32_t row, uint32_t *value, bool announce) {
    *value = 0;
    bool ok = raw(row, value);
    if (announce) printf("row=%04" PRIx32 " raw=%08" PRIx32 " read_ok=%u\n", row, *value, ok);
    return ok;
}

static bool page(unsigned p, uint32_t *l0, uint32_t *l1, bool announce) {
    bool a = raw(0xf80u + p * 2u, l0);
    bool b = raw(0xf81u + p * 2u, l1);
    if (announce) printf("page%u lock0=%08" PRIx32 " lock1=%08" PRIx32 " sw=%08" PRIx32 " reads_ok=%u\n",
                         p, *l0, *l1, otp_hw->sw_lock[p], a && b);
    return a && b;
}

static void snapshot(void) {
    puts("CRIT1_REPAIR protocol=1");
    identity(true);
    uint32_t v;
    for (uint32_t row = 0x40; row <= 0x4d; ++row) read_row(row, &v, true);
    const unsigned pages[] = {1, 2, 3, 63};
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t l0 = 0, l1 = 0;
        page(pages[i], &l0, &l1, true);
    }
    for (uint32_t row = 0xc4; row <= 0xcb; ++row) read_row(row, &v, true);
    for (uint32_t row = 0xd0; row <= 0xd7; ++row) read_row(row, &v, true);
    for (uint32_t row = 0xe0; row <= 0xef; ++row) read_row(row, &v, true);
    uint32_t dbg = otp_hw->dbg;
    printf("controller status=%08" PRIx32 " usr=%08" PRIx32 " dbg=%08" PRIx32
           " debugen=%08" PRIx32 " debugen_lock=%08" PRIx32 " rma=%u\n",
           otp_hw->sbpi_status, otp_hw->usr, dbg, otp_hw->debugen, otp_hw->debugen_lock,
           !!(dbg & OTP_DBG_CUSTOMER_RMA_FLAG_BITS));
    puts("SNAPSHOT_END");
}

/* Verify the immutable public policy separately from write permissions, so
 * already-complete devices never need to have Secure write access. */
static bool policy(void) {
    if (!identity(false) || (otp_hw->critical != 5 && otp_hw->critical != 7) ||
        (otp_hw->dbg & OTP_DBG_CUSTOMER_RMA_FLAG_BITS) ||
        (otp_hw->debugen & 0x10fu) || (otp_hw->debugen_lock & 0x10fu) != 0x10fu)
        return false;
    for (uint32_t row = 0x48; row <= 0x4d; ++row) {
        uint32_t v;
        if (!read_row(row, &v, false) || v != (row <= 0x4a ? 0x2da180u : 0xe01u)) return false;
    }
    uint32_t l0 = 0, l1 = 0;
    if (!page(2, &l0, &l1, false) || l0 != 0 || l1 != 0x151515u) return false;
    if (!page(63, &l0, &l1, false) || l0 != 0 || l1 != 0x151515u) return false;
    return true;
}

static bool permissions(void) {
    uint32_t l0 = 0, l1 = 0, sw = otp_hw->sw_lock[1];
    if (!page(1, &l0, &l1, false) || l0 != 0 || (l1 & 0xff000000u)) return false;
    uint32_t b = l1 & 0xffu;
    if (l1 != (b | b << 8 | b << 16) || (b & 0xc3u) ||
        ((b >> 2) & 3u) == 2 || ((b >> 4) & 3u) == 2) return false;
    return !(sw & ~0x0fu) && !(sw & 3u) && ((sw >> 2) & 3u) != 2;
}

static bool controller(void) {
    return otp_hw->usr == OTP_USR_DCTRL_BITS && !(otp_hw->sbpi_status & REPAIR_STATUS_MASK);
}

/* completed is the number of newly programmed rows following row 0x40. */
static bool group(unsigned completed) {
    for (unsigned i = 0; i < 8; ++i) {
        uint32_t v;
        if (!read_row(0x40u + i, &v, false) || v != (i <= completed ? 7u : 5u)) return false;
    }
    return true;
}

static void arm(void) {
    if (sequence.phase != IDLE) { repair_abort(&sequence); puts("ABORT reason=sequence"); return; }
    if (!policy()) { repair_abort(&sequence); puts("ABORT reason=admission"); return; }
    if (group(7)) { repair_abort(&sequence); puts("ALREADY_COMPLETE"); return; }
    if (otp_hw->critical != 5 || !group(0) || !permissions() || !controller()) {
        repair_abort(&sequence); puts("ABORT reason=admission"); return;
    }
    uint32_t lock0 = 0;
    if (!page(1, &lock0, &admitted_lock1, false) || lock0 != 0) {
        repair_abort(&sequence); puts("ABORT reason=admission"); return;
    }
    admitted_sw1 = otp_hw->sw_lock[1];
    if (!repair_arm(&sequence)) { puts("ABORT reason=sequence"); return; }
    puts("READY step=1 next=0041");
}

static bool permissions_unchanged(void) {
    uint32_t l0 = 0, l1 = 0;
    return permissions() && page(1, &l0, &l1, false) && l0 == 0 &&
           l1 == admitted_lock1 && otp_hw->sw_lock[1] == admitted_sw1;
}

static void next(unsigned step) {
    if (!repair_claim(&sequence, (uint8_t)step)) { puts("ABORT reason=sequence"); return; }
    if (otp_hw->critical != 5 || !policy() || !permissions_unchanged() || !group(step - 1) || !controller()) {
        repair_abort(&sequence); puts("ABORT reason=preflight"); return;
    }
    uint32_t row = 0x40u + step, payload = 7, observed = 0;
    printf("INTENT step=%u row=%04" PRIx32 " count=1 payload=00000007\n", step, row);
    stdio_flush();
    if (!stdio_usb_connected()) { repair_abort(&sequence); puts("ABORT reason=disconnected"); return; }
    otp_cmd_t cmd = {.flags = row | OTP_CMD_WRITE_BITS};
    uint32_t start = time_us_32();
    int rc = rom_func_otp_access((uint8_t *)&payload, 4, cmd);
    uint32_t elapsed = time_us_32() - start, status = otp_hw->sbpi_status;
    bool read_ok = read_row(row, &observed, false);
    printf("RESULT step=%u row=%04" PRIx32 " rc=%d status=%08" PRIx32
           " raw=%08" PRIx32 " read_ok=%u elapsed_us=%" PRIu32 "\n",
           step, row, rc, status, observed, read_ok, elapsed);
    bool verified = rc == BOOTROM_OK && !(status & REPAIR_STATUS_MASK) && read_ok &&
                    observed == 7 && policy() && permissions_unchanged() && group(step) && controller();
    if (!repair_finish(&sequence, verified)) { puts("ABORT reason=verification"); return; }
    if (sequence.phase == COMPLETE) puts("COMPLETE");
}

int main(void) {
    otp_hw->debugen = otp_hw->debugen & ~0x10fu;
    otp_hw->debugen_lock = 0x10fu;
    if ((otp_hw->debugen & 0x10fu) || (otp_hw->debugen_lock & 0x10fu) != 0x10fu)
        for (;;) tight_loop_contents();
    stdio_init_all();
    while (!stdio_usb_connected()) sleep_ms(20);
    puts("CRIT1_REPAIR protocol=1");
    char line[64]; unsigned n = 0; bool overflow = false;
    for (;;) {
        int c = getchar_timeout_us(100000);
        if (c == PICO_ERROR_TIMEOUT) {
            if (sequence.phase == ARMED && !stdio_usb_connected()) repair_abort(&sequence);
            continue;
        }
        if (c != '\n') {
            if (c < 0x20 || c > 0x7e) { overflow = true; repair_abort(&sequence); }
            else if (n + 1 < sizeof line) line[n++] = (char)c;
            else { overflow = true; repair_abort(&sequence); }
            continue;
        }
        line[n] = 0;
        if (!overflow && !strcmp(line, "SNAPSHOT")) snapshot();
        else if (!overflow && !strcmp(line, "CRIT1REPAIR " SERIAL)) arm();
        else if (!overflow && !strncmp(line, "NEXT " SERIAL " ", sizeof("NEXT " SERIAL " ") - 1) &&
                 strlen(line) == sizeof("NEXT " SERIAL " ") && line[sizeof("NEXT " SERIAL " ") - 1] >= '1' &&
                 line[sizeof("NEXT " SERIAL " ") - 1] <= '7')
            next((unsigned)(line[sizeof("NEXT " SERIAL " ") - 1] - '0'));
        else { repair_abort(&sequence); puts("ABORT reason=command"); }
        n = 0; overflow = false;
    }
}
#endif
