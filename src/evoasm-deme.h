/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-deme-params.h"
#include "evoasm-adf.h"

typedef struct {
  evoasm_loss_t best_loss;
  evoasm_buf_t buf;
  evoasm_buf_t body_buf;
  evoasm_prng_t prng;

  uint_fast8_t *matching;
  evoasm_example_val_t *output_vals;
  evoasm_loss_t *losses;
  unsigned char *adfs;
  unsigned char *main_adfs;
  unsigned char *swap_adfs;
  uint64_t *error_counters;
  uint64_t error_counter;
  evoasm_deme_params_t *params;

  evoasm_domain_t *domains;
  evoasm_arch_info_t *arch_info;
} evoasm_deme_t;

evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme,
                 evoasm_adf_t *found_adf,
                 evoasm_loss_t *found_loss);
void
evoasm_deme_new_gen(evoasm_deme_t *deme);

void
evoasm_deme_seed(evoasm_deme_t *deme);
