/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
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

#define EVOASM_ERROR_MAX_FILENAME_LEN 128
#define EVOASM_ERROR_MAX_MSG_LEN 128

#define EVOASM_ERROR_HEADER \
  uint16_t type; \
  uint16_t code; \
  uint32_t line; \
  char filename[EVOASM_ERROR_MAX_FILENAME_LEN]; \
  char msg[EVOASM_ERROR_MAX_MSG_LEN];

typedef enum {
  EVOASM_ERROR_CODE_MISSING_PARAM,
  EVOASM_ERROR_CODE_NOT_ENCODABLE,
  EVOASM_ERROR_CODE_NONE
} evoasm_error_code_t;

typedef enum {
  EVOASM_ERROR_TYPE_ARG,
  EVOASM_ERROR_TYPE_MEMORY,
  EVOASM_ERROR_TYPE_ENC,
  EVOASM_ERROR_TYPE_RUNTIME,
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
                unsigned line, const char *format, ...);


evoasm_error_t *
evoasm_get_last_error();

void
evoasm_set_last_error(evoasm_error_t *error);

extern _Thread_local evoasm_error_t _evoasm_last_error;

#define EVOASM_TRY(label, func, ...) \
  do { if(!func(__VA_ARGS__)) {goto label;} } while(0)

#define evoasm_success_t evoasm_check_return bool

#define evoasm_error(type, code, data, ...) \
  evoasm_error_set(&_evoasm_last_error, (type), (code), (data),\
                   __FILE__, __LINE__, __VA_ARGS__)

#define evoasm_assert_not_reached() \
  evoasm_assert_not_reached_full(__FILE__, __LINE__)

static inline _Noreturn void evoasm_assert_not_reached_full(const char *file, unsigned line) {
  fprintf(stderr, "FATAL: %s:%d should not be reached\n", file, line);
  abort();
}
