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
#include <stdatomic.h>

#include "evoasm-threads.h"
#include "evoasm-island.h"


typedef struct {
  void *dummy;
} evoasm_island_model_params_t;

struct evoasm_island_model_s;

typedef bool (*evoasm_island_model_result_cb_t)(struct evoasm_island_model_s *island_model,
                                                const evoasm_indiv_t *indiv,
                                                evoasm_loss_t loss, void *user_data);

typedef bool (*evoasm_island_model_progress_cb_t)(struct evoasm_island_model_s *island_model,
                                                  evoasm_island_t *island,
                                                  unsigned cycle,
                                                  unsigned gen,
                                                  evoasm_loss_t pop_loss,
                                                  unsigned inf_count,
                                                  void *user_data);

typedef struct evoasm_island_model_s {
  evoasm_arch_id_t arch_id;
  uint16_t n_islands;
  evoasm_island_t *first_island;
  evoasm_island_model_params_t *params;
  evoasm_mutex_t result_mutex;
  evoasm_mutex_t progress_mutex;
  evoasm_mutex_t error_mutex;
  evoasm_island_model_result_cb_t result_cb;
  evoasm_island_model_progress_cb_t progress_cb;
  void *result_user_data;
  void *progress_user_data;
  bool errored;
  evoasm_error_t error;
} evoasm_island_model_t;


evoasm_success_t
evoasm_island_model_destroy(evoasm_island_model_t *island_model);

evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                         evoasm_island_model_params_t *params);

void
evoasm_island_model_set_progress_cb(evoasm_island_model_t *island_model,
                                    evoasm_island_model_progress_cb_t progress_cb,
                                    void *user_data);

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model,
                          evoasm_island_model_result_cb_t result_cb,
                          void *user_data);

