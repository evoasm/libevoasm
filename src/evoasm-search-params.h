/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-domain.h"
#include "evoasm-param.h"
#include "evoasm.h"

typedef uint8_t evoasm_adf_size_t;
typedef double evoasm_loss_t;

#define EVOASM_KERNEL_SIZE_MAX UINT8_MAX
typedef uint8_t evoasm_kernel_size_t;
#define EVOASM_KERNEL_MAX_SIZE (EVOASM_KERNEL_SIZE_MAX - 1)

#define EVOASM_ADF_MAX_SIZE 64

typedef enum {
  EVOASM_EXAMPLE_TYPE_I64,
  EVOASM_EXAMPLE_TYPE_U64,
  EVOASM_EXAMPLE_TYPE_F64,
} evoasm_example_type_t;

typedef union {
  double f64;
  int64_t i64;
  uint64_t u64;
} evoasm_example_val_t;

#define EVOASM_ADF_IO_MAX_ARITY 8

typedef struct {
  uint8_t arity;
  uint16_t len;
  evoasm_example_type_t types[EVOASM_ADF_IO_MAX_ARITY];
  evoasm_example_val_t vals[1];
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

#define EVOASM_SEARCH_PARAMS_MAX_PARAMS 32

typedef struct {
  evoasm_param_id_t param_ids[EVOASM_SEARCH_PARAMS_MAX_PARAMS];
  evoasm_domain_t *domains[EVOASM_SEARCH_PARAMS_MAX_PARAMS];
  evoasm_adf_size_t min_adf_size;
  evoasm_adf_size_t max_adf_size;
  evoasm_kernel_size_t min_kernel_size;
  evoasm_kernel_size_t max_kernel_size;
  uint32_t recur_limit;
  uint8_t n_params;
  uint32_t pop_size;
  uint32_t mut_rate;
  evoasm_adf_input_t *adf_input;
  evoasm_adf_output_t *adf_output;
  evoasm_prng_seed_t seed;
  evoasm_loss_t max_loss;
  /* no other architecture should have more instruction
   * that that */
  uint16_t n_insts;
  evoasm_inst_id_t inst_ids[EVOASM_X64_N_INSTS];
} evoasm_search_params_t;

bool
evoasm_search_params_valid(evoasm_search_params_t *search_params);
