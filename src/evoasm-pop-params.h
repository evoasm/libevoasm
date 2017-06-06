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

#include "evoasm-domain.h"
#include "evoasm-param.h"
#include "evoasm.h"

typedef float evoasm_loss_t;

#include "evoasm-kernel.h"
#include "evoasm-kernel-io.h"

#define EVOASM_POP_PARAMS_MAX_PARAMS 32

typedef enum {
  EVOASM_POP_PARAMS_ERROR_CODE_INVALID
} evoasm_pop_params_error_code_t;

typedef struct evoasm_pop_params_s {
  uint8_t n_params;
  uint8_t dist_metric;
  uint8_t tourn_size;
  uint16_t n_demes;
  uint16_t deme_size;
  uint16_t min_kernel_size;
  uint16_t max_kernel_size;
  uint16_t example_win_size;
  uint16_t n_local_search_iters;
  uint16_t n_minor_gens;
  uint16_t migr_freq;
  evoasm_prng_state_t seed;
  uint16_t n_insts;
  evoasm_kernel_io_t *kernel_input;
  evoasm_kernel_io_t *kernel_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_INST_NONE];
  evoasm_param_id_t param_ids[EVOASM_POP_PARAMS_MAX_PARAMS];
  evoasm_domain_t *domains[EVOASM_POP_PARAMS_MAX_PARAMS];
} evoasm_pop_params_t;

bool
evoasm_pop_params_validate(evoasm_pop_params_t *pop_params);
