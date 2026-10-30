/* Copyright (c) 2026 pico2-kes-agent contributors. */
/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef PICO2_REPAIR_SEQUENCE_H
#define PICO2_REPAIR_SEQUENCE_H
#include <stdbool.h>
#include <stdint.h>

enum repair_phase { IDLE, ARMED, PENDING, HALTED, COMPLETE };
struct repair_sequence { enum repair_phase phase; uint8_t next_step; };

static inline void repair_abort(struct repair_sequence *s) { s->phase = HALTED; }
static inline bool repair_arm(struct repair_sequence *s) {
    if (s->phase != IDLE || s->next_step != 1) { repair_abort(s); return false; }
    s->phase = ARMED;
    return true;
}
static inline bool repair_claim(struct repair_sequence *s, uint8_t expected_step) {
    if (s->phase != ARMED || expected_step != s->next_step || expected_step < 1 || expected_step > 7) {
        repair_abort(s); return false;
    }
    s->phase = PENDING;
    return true;
}
static inline bool repair_finish(struct repair_sequence *s, bool verified) {
    if (s->phase != PENDING || !verified) { repair_abort(s); return false; }
    if (s->next_step == 7) s->phase = COMPLETE;
    else { ++s->next_step; s->phase = ARMED; }
    return true;
}
#endif
