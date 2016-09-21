/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-deme-params.h"
#include "evoasm-program-io.h"
#include "evoasm-domain.h"
#include "evoasm-param.h"
#include "evoasm-program.h"

typedef struct {
  evoasm_deme_params_t deme_params;
  evoasm_kernel_count_t min_kernel_count;
  evoasm_kernel_count_t max_kernel_count;
  evoasm_kernel_size_t min_kernel_size;
  evoasm_kernel_size_t max_kernel_size;
  uint32_t recur_limit;
  uint16_t n_insts;
  evoasm_program_input_t *program_input;
  evoasm_program_output_t *program_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_N_INSTS];
} evoasm_program_deme_params_t;

