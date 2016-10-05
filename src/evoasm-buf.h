/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "evoasm-error.h"
#include "evoasm-log.h"

typedef enum {
  EVOASM_BUF_TYPE_MMAP,
  EVOASM_BUF_TYPE_MALLOC,
  EVOASM_BUF_TYPE_NONE
} evoasm_buf_type_t;

typedef struct {
    size_t  capa;
    size_t  pos;
    evoasm_buf_type_t type : 2;
    uint8_t *data;
} evoasm_buf_t;

typedef struct evoasm_buf_ref {
  size_t *pos;
  uint8_t *data;
} evoasm_buf_ref_t;

evoasm_success_t
evoasm_buf_init(evoasm_buf_t *buf, evoasm_buf_type_t buf_type, size_t size);

evoasm_success_t
evoasm_buf_destroy(evoasm_buf_t *buf);

void
evoasm_buf_reset(evoasm_buf_t *buf);

size_t
evoasm_buf_append(evoasm_buf_t * restrict dst, evoasm_buf_t * restrict src);

evoasm_success_t
evoasm_buf_protect(evoasm_buf_t *buf, int mode);

intptr_t
evoasm_buf_exec(evoasm_buf_t *buf);

void
evoasm_buf_log(evoasm_buf_t *buf, evoasm_log_level_t log_level);

evoasm_success_t
evoasm_buf_clone(evoasm_buf_t * restrict buf, evoasm_buf_t * restrict cloned_buf);


static inline void
evoasm_buf_ref_write8(evoasm_buf_ref_t *buf_ref, int64_t datum) {
  size_t pos = *buf_ref->pos;
  size_t new_pos = pos + 1;
  *((uint8_t *)(buf_ref->data + pos)) = (uint8_t) datum;
  *buf_ref->pos = new_pos;
}

static inline void
evoasm_buf_ref_write16(evoasm_buf_ref_t *buf_ref, int64_t datum) {
  size_t pos = *buf_ref->pos;
  size_t new_pos = pos + 2;
  *((int16_t *)(buf_ref->data + pos)) = (int16_t) datum;
  *buf_ref->pos = new_pos;
}

static inline void
evoasm_buf_ref_write32(evoasm_buf_ref_t *buf_ref, int64_t datum) {
  size_t pos = *buf_ref->pos;
  size_t new_pos = pos + 4;
  *((int32_t *)(buf_ref->data + pos)) = (int32_t) datum;
  *buf_ref->pos = new_pos;
}

static inline void
evoasm_buf_ref_write64(evoasm_buf_ref_t *buf_ref, int64_t datum) {
  size_t pos = *buf_ref->pos;
  size_t new_pos = pos + 8;
  *((int64_t *)(buf_ref->data + pos)) = (int64_t) datum;
  *buf_ref->pos = new_pos;
}
