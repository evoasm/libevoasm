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
#include "evoasm-program.h"

typedef float evoasm_loss_t;

#define EVOASM_POP_PARAMS_MAX_PARAMS 32
#define EVOASM_POP_PARAMS_MAX_DEPTH 32
#define EVOASM_POP_PARAMS_KERNELS_DEPTH(params) ((params)->depth - 1)
#define EVOASM_POP_PARAMS_KERNEL_DEME_COUNT(params) ((params)->deme_counts[EVOASM_POP_PARAMS_KERNELS_DEPTH(params)])
#define EVOASM_POP_PARAMS_KERNEL_DEME_SIZE(params) ((params)->deme_sizes[EVOASM_POP_PARAMS_KERNELS_DEPTH(params)])
#define EVOASM_POP_PARAMS_MAX_KERNEL_SIZE(params) ((params)->max_indiv_sizes[EVOASM_POP_PARAMS_KERNELS_DEPTH(params)])

typedef struct evoasm_pop_params_s {
  evoasm_param_id_t param_ids[EVOASM_POP_PARAMS_MAX_PARAMS];
  evoasm_domain_t *domains[EVOASM_POP_PARAMS_MAX_PARAMS];
  uint8_t n_params;

  uint16_t n_kernel_demes;
  uint16_t kernel_deme_size;
  uint16_t n_program_demes;
  uint16_t program_deme_size;
  uint16_t library_size;

  uint16_t min_kernel_size;
  uint16_t max_kernel_size;
  uint16_t min_program_size;
  uint16_t max_program_size;
  uint16_t min_module_size;
  uint16_t max_module_size;
  float mut_rate;
  float evap_rate;

  uint8_t depth;
  evoasm_prng_state_t seed;
  uint32_t recur_limit;
  uint16_t n_insts;
  evoasm_program_input_t *program_input;
  evoasm_program_output_t *program_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_INST_NONE];
} evoasm_pop_params_t;

bool
evoasm_pop_params_valid(evoasm_pop_params_t *pop_params);
