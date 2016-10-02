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

typedef double evoasm_loss_t;
typedef uint16_t evoasm_team_size_t;
typedef uint16_t evoasm_deme_size_t;

#define EVOASM_POP_PARAMS_MAX_PARAMS 32
#define EVOASM_POP_MAX_DEPTH 128

typedef struct evoasm_pop_params_s {
  evoasm_param_id_t param_ids[EVOASM_POP_PARAMS_MAX_PARAMS];
  evoasm_domain_t *domains[EVOASM_POP_PARAMS_MAX_PARAMS];
  uint8_t n_params;
  evoasm_deme_size_t deme_sizes[EVOASM_POP_MAX_DEPTH + 1];
  evoasm_team_size_t max_team_sizes[EVOASM_POP_MAX_DEPTH];
  evoasm_team_size_t min_team_sizes[EVOASM_POP_MAX_DEPTH];
  uint8_t depth;
  uint32_t mut_rate;
  evoasm_prng_state_t seed;
  evoasm_kernel_size_t min_kernel_size;
  evoasm_kernel_size_t max_kernel_size;
  uint32_t recur_limit;
  uint16_t n_insts;
  evoasm_program_input_t *program_input;
  evoasm_program_output_t *program_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_N_INSTS];
} evoasm_pop_params_t;

bool
evoasm_pop_params_valid(evoasm_pop_params_t *pop_params);
