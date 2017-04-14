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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

#include "evoasm-util.h"
#include "evoasm-log.h"

#define EVOASM_ERROR_MAX_FILENAME_LEN 128
#define EVOASM_ERROR_MAX_MSG_LEN 128

#define EVOASM_ERROR_HEADER \
  uint16_t type; \
  uint16_t code; \
  uint32_t line; \
  char filename[EVOASM_ERROR_MAX_FILENAME_LEN]; \
  char msg[EVOASM_ERROR_MAX_MSG_LEN];

typedef enum {
  EVOASM_ERROR_CODE_NONE
} evoasm_error_code_t;

typedef enum {
  EVOASM_ERROR_TYPE_BUF,
  EVOASM_ERROR_TYPE_ALLOC,
  EVOASM_ERROR_TYPE_ARCH,
  EVOASM_ERROR_TYPE_KERNEL,
  EVOASM_ERROR_TYPE_POP_PARAMS,
  EVOASM_ERROR_TYPE_POP,
  EVOASM_ERROR_TYPE_NONE,
} evoasm_error_type_t;

typedef struct {
  uint8_t data[64];
} evoasm_error_data_t;

typedef struct {
  EVOASM_ERROR_HEADER
  evoasm_error_data_t data;
} evoasm_error_t;


void
evoasm_error_setv(evoasm_error_t *error, unsigned error_type, unsigned error_code,
                 void *error_data, const char *file,
                 unsigned line, const char *format, va_list args);

void
evoasm_error_set(evoasm_error_t *error, unsigned error_type, unsigned error_code,
                void *error_data, const char *file,
                unsigned line, const char *format, ...) evoasm_printf(7, 8);


evoasm_error_t *
evoasm_get_last_error();

void
evoasm_set_last_error(evoasm_error_t *error);

extern _Thread_local evoasm_error_t evoasm_last_error;

#define EVOASM_TRY(label, func, ...) \
  do { if(!func(__VA_ARGS__)) {goto label;} } while(0)


#define EVOASM_TRY_WARN(func, ...) \
  do { \
    if(!func(__VA_ARGS__)) { \
      evoasm_log(EVOASM_LOG_LEVEL_WARN, EVOASM_LOG_TAG, #func "failed"); \
    } \
  } while(0)

#define evoasm_success_t evoasm_check_return bool

#define evoasm_error(type, code, ...) evoasm_error2(type, code, NULL, __VA_ARGS__)

#define evoasm_error2(type, code, data, ...) \
  evoasm_error_set(&evoasm_last_error, (type), (code), (data),\
                   __FILE__, __LINE__, __VA_ARGS__)

#define evoasm_assert_not_reached() \
  do { \
    evoasm_log(EVOASM_LOG_LEVEL_FATAL, "error", "%s:%d should not be reached", __FILE__, __LINE__); \
    abort(); \
  } while(0)

