/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-deme-params.h"
#include "evoasm-adf-io.h"
#include "evoasm-domain.h"
#include "evoasm-param.h"
#include "evoasm-adf.h"

typedef struct {
  evoasm_deme_params_t deme_params;
  evoasm_adf_size_t min_adf_size;
  evoasm_adf_size_t max_adf_size;
  evoasm_kernel_size_t min_kernel_size;
  evoasm_kernel_size_t max_kernel_size;
  uint32_t recur_limit;
  uint16_t n_insts;
  evoasm_adf_input_t *adf_input;
  evoasm_adf_output_t *adf_output;
  evoasm_inst_id_t inst_ids[EVOASM_X64_N_INSTS];
} evoasm_adf_deme_params_t;

bool
evoasm_adf_deme_params_valid(evoasm_adf_deme_params_t *adf_deme_params);
