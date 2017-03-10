/*
 * Copyright (C) 2016 Julian Aron Prenner <jap@polyadic.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "evoasm-error.h"
#include "evoasm-log.h"
#include "evoasm-alloc.h"
#include "evoasm.h"

typedef enum {
  EVOASM_BUF_TYPE_MMAP,
  EVOASM_BUF_TYPE_MALLOC,
  EVOASM_BUF_TYPE_NONE
} evoasm_buf_type_t;

typedef enum {
  EVOASM_BUF_ERROR_CODE_NO_SPACE
} evoasm_buf_error_code_t;

typedef struct {
    size_t  capa;
    size_t  pos;
    unsigned type : 2;
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
evoasm_buf_protect(evoasm_buf_t *buf, evoasm_mprot_mode_t mode);

intptr_t
evoasm_buf_exec(evoasm_buf_t *buf);

void
evoasm_buf_log(evoasm_buf_t *buf, evoasm_log_level_t log_level);

evoasm_success_t
evoasm_buf_clone(evoasm_buf_t * restrict buf, evoasm_buf_t * restrict cloned_buf);

void
evoasm_buf_to_buf_ref(evoasm_buf_t *buf, evoasm_buf_ref_t *buf_ref);

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

static inline uint8_t *
evoasm_buf_get_pos_addr_(evoasm_buf_t *buf) {
  return buf->data + buf->pos;
}

static inline void
evoasm_buf_set_pos_(evoasm_buf_t *buf, size_t pos) {
  buf->pos = pos;
}

static inline size_t
evoasm_buf_get_pos_(evoasm_buf_t *buf) {
  return buf->pos;
}
