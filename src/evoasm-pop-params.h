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

#include "evoasm-program.h"
#include "evoasm-program-io.h"

#define EVOASM_POP_PARAMS_MAX_PARAMS 32

typedef enum {
  EVOASM_POP_PARAMS_ERROR_CODE_INVALID
} evoasm_pop_params_error_code_t;

typedef struct evoasm_pop_params_s {
  evoasm_param_id_t param_ids[EVOASM_POP_PARAMS_MAX_PARAMS];
  evoasm_domain_t *domains[EVOASM_POP_PARAMS_MAX_PARAMS];
  uint8_t n_params;

  uint16_t n_demes;
  uint16_t library_size;
  uint16_t deme_size;
  uint16_t kernel_size;
  uint16_t program_size;
  uint16_t min_module_size;
  uint16_t max_module_size;
  float evap_rate;

  uint8_t depth;
  evoasm_prng_state_t seed;
  uint32_t recur_limit;
  uint16_t n_insts;
  evoasm_program_io_t *program_input;
  evoasm_program_io_t *program_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_INST_NONE];
} evoasm_pop_params_t;

bool
evoasm_pop_params_validate(evoasm_pop_params_t *pop_params);
