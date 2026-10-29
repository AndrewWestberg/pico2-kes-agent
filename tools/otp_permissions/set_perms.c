/**
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 * Copyright (c) 2026 pico2-kes-agent contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Adapted from picotool 2.3.1 xip_ram_perms. This preparation-only
 * executable has no generic OTP programming interface. The host must
 * authenticate the original ELF, bind the two public CHIPID words, and
 * independently read back both complete lock rows after execution.
 */
#include <stdbool.h>
#include <stdint.h>

#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include "pico/binary_info.h"
#include "hardware/regs/otp.h"
#include "hardware/regs/otp_data.h"
#include "hardware/structs/otp.h"

static bool read_raw(uint32_t row, uint32_t *value) {
    otp_cmd_t cmd = { .flags = row & OTP_CMD_ROW_BITS };
    return rom_func_otp_access((uint8_t *)value, sizeof(*value), cmd) == BOOTROM_OK;
}

static bool write_raw(uint32_t row, uint32_t value) {
    otp_cmd_t cmd = { .flags = (row & OTP_CMD_ROW_BITS) | OTP_CMD_WRITE_BITS };
    return rom_func_otp_access((uint8_t *)&value, sizeof(value), cmd) == BOOTROM_OK;
}

static bool read_lock(uint32_t row, uint8_t *value) {
    uint32_t raw;
    if (!read_raw(row, &raw) || (raw & 0xff000000u)) return false;
    uint8_t a = (uint8_t)raw;
    if (a != (uint8_t)(raw >> 8) || a != (uint8_t)(raw >> 16)) return false;
    *value = a;
    return true;
}

static uint32_t copies(uint8_t value) {
    return (uint32_t)value * 0x010101u;
}

/* No access keys, no reserved bits or lock encodings. Secure access must
 * remain read/write until the final write to that page's lock row. */
static bool check_page(uint32_t lock0, unsigned page, uint8_t *lock1) {
    uint8_t keys;
    if (!read_lock(lock0, &keys) || keys != 0 || !read_lock(lock0 + 1, lock1)) return false;
    if ((*lock1 & 0xc0u) || (*lock1 & 3u) != 0) return false;
    if (((*lock1 >> 2) & 3u) == 2 || ((*lock1 >> 4) & 3u) == 2) return false;
    /* A volatile Secure lock can be stricter than the fuse state. */
    if ((otp_hw->sw_lock[page] & 3u) != 0) return false;
    return true;
}

static bool lock_page(uint32_t lock1_row, uint8_t old) {
    uint8_t intermediate = old | 0x14u; /* NS and bootloader read-only */
    uint8_t observed;
    if (intermediate != old) {
        if (!write_raw(lock1_row, copies(intermediate)) ||
            !read_lock(lock1_row, &observed) || observed != intermediate) return false;
    }
    uint8_t final = intermediate | 1u; /* Secure read-only, strictly last */
    return write_raw(lock1_row, copies(final)) &&
           read_lock(lock1_row, &observed) && observed == final;
}

static void fail_stop(void) {
    /* No success indication or reboot on failure, including partial writes. */
    for (;;) tight_loop_contents();
}

int main(void) {
    bi_decl(bi_program_feature_group(0x1111, 0x2222, "otp_target"));
    bi_decl(bi_ptr_int32(0x1111, 0x2222, expected_chipid_low, -1));
    bi_decl(bi_ptr_int32(0x1111, 0x2222, expected_chipid_high, -1));

    uint32_t info[4];
    if (rom_get_sys_info(info, 4, SYS_INFO_CHIP_INFO) != 4 ||
        info[0] != SYS_INFO_CHIP_INFO ||
        ((uint32_t)expected_chipid_low == UINT32_MAX &&
         (uint32_t)expected_chipid_high == UINT32_MAX) ||
        info[2] != (uint32_t)expected_chipid_low ||
        info[3] != (uint32_t)expected_chipid_high) fail_stop();

    if (otp_hw->critical & OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS) fail_stop();
    /* Reject even a partial secure-boot fuse, not just the voted value. */
    for (uint32_t row = OTP_DATA_CRIT1_ROW; row <= OTP_DATA_CRIT1_R7_ROW; ++row) {
        uint32_t raw;
        if (!read_raw(row, &raw) || (raw & OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS)) fail_stop();
    }
    uint8_t page2, page63, page62;
    /* Page 2's lock rows themselves reside in page 62; verify that the
     * containing page is writable too. No page-62 values are programmed. */
    if (!check_page(OTP_DATA_PAGE62_LOCK0_ROW, 62, &page62) ||
        !check_page(OTP_DATA_PAGE2_LOCK0_ROW, 2, &page2) ||
        !check_page(OTP_DATA_PAGE63_LOCK0_ROW, 63, &page63)) fail_stop();
    if (!lock_page(OTP_DATA_PAGE2_LOCK1_ROW, page2) ||
        !lock_page(OTP_DATA_PAGE63_LOCK1_ROW, page63)) fail_stop();
    reset_usb_boot(0, 0);
    fail_stop();
}
