/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdint.h>

#define EVOASM_PROGRAM_IO_MAX_ARITY 8

typedef enum {
  EVOASM_PROGRAM_IO_VAL_TYPE_I64,
  EVOASM_PROGRAM_IO_VAL_TYPE_U64,
  EVOASM_PROGRAM_IO_VAL_TYPE_F64,
} evoasm_program_io_val_type_t;

typedef union {
  double f64;
  int64_t i64;
  uint64_t u64;
} evoasm_program_io_val_t;

typedef struct {
  uint8_t arity;
  uint16_t len;
  evoasm_program_io_val_type_t types[EVOASM_PROGRAM_IO_MAX_ARITY];
  evoasm_program_io_val_t vals[1];
} evoasm_program_io_t;

#define EVOASM_PROGRAM_OUTPUT_MAX_ARITY EVOASM_PROGRAM_IO_MAX_ARITY
#define EVOASM_PROGRAM_INPUT_MAX_ARITY EVOASM_PROGRAM_IO_MAX_ARITY

typedef evoasm_program_io_t evoasm_program_output_t;
typedef evoasm_program_io_t evoasm_program_input_t;

#define EVOASM_PROGRAM_IO_N_EXAMPLES(program_io) ((size_t)((program_io)->len / (program_io)->arity))
#define EVOASM_PROGRAM_INPUT_N_EXAMPLES(program_input) EVOASM_PROGRAM_IO_N_EXAMPLES((evoasm_program_io_t *)program_input)
#define EVOASM_PROGRAM_OUTPUT_N_EXAMPLES(program_output) EVOASM_PROGRAM_IO_N_EXAMPLES((evoasm_program_io_t *)program_output)

evoasm_program_io_t *
evoasm_program_io_alloc(size_t len);

void
evoasm_program_io_destroy(evoasm_program_io_t *program_io);

#define evoasm_program_output_destroy(program_output) \
  evoasm_program_io_destroy((evoasm_program_io *)program_output)
