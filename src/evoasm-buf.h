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
  EVOASM_N_BUF_TYPES
} evoasm_buf_type_t;

typedef struct {
    size_t  capa;
    size_t  pos;
    evoasm_buf_type_t type : 2;
    uint8_t *data;
} evoasm_buf_t;

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
evoasm_buf_log(evoasm_buf_t *buf, evoasm_log_level log_level);

evoasm_success_t
evoasm_buf_clone(evoasm_buf_t * restrict buf, evoasm_buf_t * restrict cloned_buf);

