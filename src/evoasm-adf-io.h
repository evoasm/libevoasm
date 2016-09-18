/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdint.h>

#define EVOASM_ADF_IO_MAX_ARITY 8

typedef enum {
  EVOASM_ADF_IO_VAL_TYPE_I64,
  EVOASM_ADF_IO_VAL_TYPE_U64,
  EVOASM_ADF_IO_VAL_TYPE_F64,
} evoasm_adf_io_val_type_t;

typedef union {
  double f64;
  int64_t i64;
  uint64_t u64;
} evoasm_adf_io_val_t;

typedef struct {
  uint8_t arity;
  uint16_t len;
  evoasm_adf_io_val_type_t types[EVOASM_ADF_IO_MAX_ARITY];
  evoasm_adf_io_val_t vals[1];
} evoasm_adf_io_t;

#define EVOASM_ADF_OUTPUT_MAX_ARITY EVOASM_ADF_IO_MAX_ARITY
#define EVOASM_ADF_INPUT_MAX_ARITY EVOASM_ADF_IO_MAX_ARITY
typedef evoasm_adf_io_t evoasm_adf_output_t;
typedef evoasm_adf_io_t evoasm_adf_input_t;

#define EVOASM_ADF_IO_N_EXAMPLES(adf_io) ((uint16_t)((adf_io)->len / (adf_io)->arity))
#define EVOASM_ADF_INPUT_N_EXAMPLES(adf_input) EVOASM_ADF_IO_N_EXAMPLES((evoasm_adf_io_t *)adf_input)
#define EVOASM_ADF_OUTPUT_N_EXAMPLES(adf_output) EVOASM_ADF_IO_N_EXAMPLES((evoasm_adf_io_t *)adf_output)

evoasm_adf_io_t *
evoasm_adf_io_alloc(uint16_t len);

void
evoasm_adf_io_destroy(evoasm_adf_io_t *adf_io);

#define evoasm_adf_output_destroy(adf_output) \
  evoasm_adf_io_destroy((evoasm_adf_io *)adf_output)
