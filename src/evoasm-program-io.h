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
