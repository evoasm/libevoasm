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

#include <string.h>

#include "evoasm-buf.h"
#include "evoasm-alloc.h"
#include "evoasm-util.h"
#include "evoasm-signal.h"
#include "evoasm.h"

EVOASM_DEF_LOG_TAG("buf")

static evoasm_success_t
evoasm_buf_init_mmap(evoasm_buf_t *buf, size_t size) {
  uint8_t *mem;

  //size = EVOASM_ALIGN_UP(size, evoasm_get_page_size());
  mem = evoasm_mmap(size, NULL);

  if(mem) {
    buf->capa = size;
    buf->data = mem;
    buf->pos = 0;
    return true;
  } else {
    return false;
  }
}

static evoasm_success_t
evoasm_buf_init_malloc(evoasm_buf_t *buf, size_t size) {
  uint8_t *mem;

  mem = malloc(size);

  if(mem) {
    buf->capa = size;
    buf->data = mem;
    buf->pos = 0;
    return true;
  } else {
    return false;
  }
}

evoasm_success_t
evoasm_buf_init(evoasm_buf_t *buf, evoasm_buf_type_t buf_type, size_t size) {
  buf->type = buf_type;
  switch(buf_type) {
    case EVOASM_BUF_TYPE_MMAP:
      return evoasm_buf_init_mmap(buf, size);
    case EVOASM_BUF_TYPE_MALLOC:
      return evoasm_buf_init_malloc(buf, size);
    default:
      evoasm_assert_not_reached();
  }
}

static evoasm_success_t
evoasm_buf_destroy_mmap(evoasm_buf_t *buf) {
  if(buf->data != NULL) {
    return evoasm_munmap(buf->data, buf->capa);
  }
  return true;
}

static evoasm_success_t
evoasm_buf_destroy_malloc(evoasm_buf_t *buf) {
  evoasm_free(buf->data);
  return true;
}

evoasm_success_t
evoasm_buf_destroy(evoasm_buf_t *buf) {
  switch(buf->type) {
    case EVOASM_BUF_TYPE_MMAP:
      return evoasm_buf_destroy_mmap(buf);
    case EVOASM_BUF_TYPE_MALLOC:
      return evoasm_buf_destroy_malloc(buf);
    default:
      evoasm_assert_not_reached();
  }
}

void
evoasm_buf_reset(evoasm_buf_t *buf) {
  memset(buf->data, 0, buf->pos);
  buf->pos = 0;
}

evoasm_success_t
evoasm_buf_protect(evoasm_buf_t *buf, evoasm_mprot_mode_t mode) {
  return evoasm_mprot(buf->data, buf->capa, mode);
}

intptr_t
evoasm_buf_exec(evoasm_buf_t *buf) {
  intptr_t (*func)(void);
  intptr_t result = 0;
  *(void **) (&func) = buf->data;
  result = func();
  return result;
}

evoasm_success_t
evoasm_buf_safe_exec(evoasm_buf_t *buf, uint64_t exception_mask, intptr_t *retval) {
  bool success;

  evoasm_signal_set_exception_mask(exception_mask);

  if(EVOASM_SIGNAL_TRY()) {
    *retval = evoasm_buf_exec(buf);
    success = true;
  } else {
    *retval = evoasm_signal_get_last_exception();
    success = false;
  }

  evoasm_signal_clear_exception_mask();

  return success;
}

void
evoasm_buf_log(evoasm_buf_t *buf, evoasm_log_level_t log_level) {
  if(_evoasm_min_log_level > log_level) return;

  evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Buffer: capa: %zu, pos: %zu, addr: %p\n",
             buf->capa, buf->pos, (void *) buf->data);
  for(size_t i = 0; i < buf->pos; i++) {
    if(i > 0) evoasm_log(log_level, EVOASM_LOG_TAG, "   ");
    evoasm_log(log_level, EVOASM_LOG_TAG, " %02X ", buf->data[i]);
  }
  evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
}

void
evoasm_buf_to_buf_ref(evoasm_buf_t *buf, evoasm_buf_ref_t *buf_ref) {
  buf_ref->data = buf->data;
  buf_ref->pos = &buf->pos;
}

size_t
evoasm_buf_write(evoasm_buf_t *buf, uint8_t *data, size_t len) {
  size_t free = buf->capa - buf->pos;
  if(len > free) {
    evoasm_error(EVOASM_ERROR_TYPE_BUF, EVOASM_BUF_ERROR_CODE_NO_SPACE,
                 "buffer does not fit (need %zu bytes but only %zu free)", len, free);
    return len - free;
  }
  memcpy(buf->data + buf->pos, data, len);
  buf->pos += len;
  return 0;
}

size_t
evoasm_buf_append(evoasm_buf_t *restrict dst, evoasm_buf_t *restrict src) {
  return evoasm_buf_write(dst, src->data, src->pos);
}

evoasm_success_t
evoasm_buf_clone(evoasm_buf_t *restrict buf, evoasm_buf_t *restrict cloned_buf) {
  if(!evoasm_buf_init(cloned_buf, (evoasm_buf_type_t) buf->type, buf->capa)) {
    return false;
  }
  return evoasm_buf_append(cloned_buf, buf) == 0;
}

uint8_t *
evoasm_buf_data(evoasm_buf_t *buf) {
  return buf->data;
}


EVOASM_DEF_ALLOC_FREE_FUNCS(buf_ref)

EVOASM_DEF_ALLOC_FREE_FUNCS(buf)

EVOASM_DEF_GETTER(buf, capa, size_t)
EVOASM_DEF_GETTER(buf, pos, size_t)
EVOASM_DEF_GETTER(buf, type, evoasm_buf_type_t)
EVOASM_DEF_GETTER(buf, data, const uint8_t *)

void
evoasm_buf_ref_init(evoasm_buf_ref_t *buf_ref, uint8_t *data, size_t *pos) {
  buf_ref->data = data;
  buf_ref->pos = pos;
}

