/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-pop-params.h"
#include "evoasm-program-io.h"
#include "evoasm-domain.h"
#include "evoasm-param.h"
#include "evoasm-program.h"

typedef struct {
  evoasm_pop_params_t pop_params;
  uint16_t min_kernel_count;
  uint16_t max_kernel_count;
  uint16_t min_kernel_size;
  uint16_t max_kernel_size;
  uint32_t recur_limit;
  uint16_t inst_count;
  evoasm_program_input_t *program_input;
  evoasm_program_output_t *program_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_N_INSTS];
} evoasm_program_pop_params_t;

bool
evoasm_program_pop_params_valid(evoasm_program_pop_params_t *program_pop_params);