/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "tinycthread.h"
#include "evoasm-deme.h"

typedef struct {

} evoasm_search_params_t;

typedef struct {
  evoasm_arch_id_t arch_id;
  evoasm_deme_t **demes;
  mtx_t *mtxs;
  thrd_t *thrds;
  unsigned char **migration_adfs;

  uint16_t n_demes;
  evoasm_search_params_t *params;

} evoasm_search_t;

evoasm_success_t
evoasm_search_init(evoasm_search_t *search,
                   evoasm_search_params_t *params,
                   uint16_t n_demes,
                   ...);

void
evoasm_search_destroy(evoasm_search_t *search);

typedef bool (*evoasm_search_goal_func_t)(evoasm_adf_t *adf,
                                          evoasm_loss_t loss, void *user_data);

typedef bool (*evoasm_search_progress_func_t)(unsigned deme_idx,
                                              unsigned cycle, unsigned gen,
                                              evoasm_loss_t deme_loss,
                                              unsigned n_inf, void *user_data);

evoasm_success_t
evoasm_search_start(evoasm_search_t *search,
                    evoasm_search_progress_func_t progress_func,
                    evoasm_search_goal_func_t result_func,
                    void *user_data);

