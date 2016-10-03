/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include <string.h>

#include "evoasm-buf.h"
#include "evoasm-alloc.h"
#include "evoasm-util.h"

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
  }
  else {
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
  }
  else {
    return false;
  }
}

evoasm_success_t
evoasm_buf_init(evoasm_buf_t *buf, evoasm_buf_type_t buf_type, size_t size)
{
  buf->type = buf_type;
  switch(buf_type) {
    case EVOASM_BUF_TYPE_MMAP: return evoasm_buf_init_mmap(buf, size);
    case EVOASM_BUF_TYPE_MALLOC: return evoasm_buf_init_malloc(buf, size);
    default: evoasm_assert_not_reached();
  }
}

static evoasm_success_t
evoasm_buf_destroy_mmap(evoasm_buf_t *buf) {
  if(buf->data != NULL) {
    return evoasm_munmap(buf->data, buf->capa);
  }
}

static evoasm_success_t
evoasm_buf_destroy_malloc(evoasm_buf_t *buf) {
  evoasm_free(buf->data);
  return true;
}

evoasm_success_t
evoasm_buf_destroy(evoasm_buf_t *buf)
{
  switch(buf->type) {
    case EVOASM_BUF_TYPE_MMAP: return evoasm_buf_destroy_mmap(buf);
    case EVOASM_BUF_TYPE_MALLOC: return evoasm_buf_destroy_malloc(buf);
    default: evoasm_assert_not_reached();
  }
}

void
evoasm_buf_reset(evoasm_buf_t *buf) {
  memset(buf->data, 0, buf->pos);
  buf->pos = 0;
}

evoasm_success_t
evoasm_buf_protect(evoasm_buf_t *buf, int mode) {
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

void
evoasm_buf_log(evoasm_buf_t *buf, evoasm_log_level_t log_level) {
  unsigned i;

  if(_evoasm_min_log_level > log_level) return;

  evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Buffer: capa: %zu, pos: %zu, addr: %p\n",
             buf->capa, buf->pos, (void *) buf->data);
  for(i = 0; i < buf->pos; i++)
  {
    if (i > 0) evoasm_log(log_level, EVOASM_LOG_TAG, "   ");
    evoasm_log(log_level, EVOASM_LOG_TAG, " %02X ", buf->data[i]);
  }
  evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
}

size_t
evoasm_buf_append(evoasm_buf_t * restrict dst, evoasm_buf_t * restrict src) {
  size_t free = dst->capa - dst->pos;
  if(src->pos > free) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
      NULL, "buffer does not fit (need %zu bytes but only %zu free)", src->pos, free);
    return src->pos - (dst->capa - dst->pos);
  }
  memcpy(dst->data + dst->pos, src->data, src->pos);
  dst->pos += src->pos;
  return 0;
}

evoasm_success_t
evoasm_buf_clone(evoasm_buf_t * restrict buf, evoasm_buf_t * restrict cloned_buf) {
  if(!evoasm_buf_init(cloned_buf, buf->type, buf->capa)) {
    return false;
  }
  return evoasm_buf_append(cloned_buf, buf) == 0;
}

uint8_t *
evoasm_buf_data(evoasm_buf_t *buf) {
  return buf->data;
}


_EVOASM_DEF_ALLOC_FREE_FUNCS(buf_ref)

void
evoasm_buf_ref_init(evoasm_buf_ref_t *buf_ref, uint8_t *data, size_t *pos) {
  buf_ref->data = data;
  buf_ref->pos = pos;
}

