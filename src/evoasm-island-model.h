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

#define EVOASM_ISLAND_MAX_IMMIGR_ISLANDS 8

typedef enum {
  EVOASM_ISLAND_TOPOLOGY_RING,
  EVOASM_N_ISLAND_TOPOLOGIES
} evoasm_island_topology_t;

typedef struct {
} evoasm_island_model_params_t;

typedef struct {
  float emigr_rate;
  uint16_t emigr_freq;
  evoasm_loss_t max_loss;
} evoasm_island_params_t;

struct evoasm_island_model_s;

typedef struct evoasm_island_s {
  mtx_t mtx;
  thrd_t thrd;
  evoasm_deme_t *deme;
  struct evoasm_island_model_s *model;
  struct evoasm_island_s *immigr_islands[EVOASM_ISLAND_MAX_IMMIGR_ISLANDS];
  evoasm_island_params_t *params;
  uint8_t n_immigr_islands;
  atomic_bool cancel;
  evoasm_error_t error;
} evoasm_island_t;

typedef struct evoasm_island_model_s {
  evoasm_arch_id_t arch_id;
  uint16_t n_islands;
  evoasm_island_t *islands;
  evoasm_island_model_params_t *params;

} evoasm_island_model_t;

evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                   evoasm_island_model_params_t *params,
                   uint16_t n_demes,
                   ...);

void
evoasm_island_model_destroy(evoasm_island_model_t *island_model);

typedef bool (*evoasm_island_model_goal_func_t)(evoasm_adf_t *adf,
                                          evoasm_loss_t loss, void *user_data);

typedef bool (*evoasm_island_progress_func_t)(unsigned deme_idx,
                                              unsigned cycle, unsigned gen,
                                              evoasm_loss_t deme_loss,
                                              unsigned n_inf, void *user_data);

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model,
                    evoasm_island_progress_func_t progress_func,
                    evoasm_island_model_goal_func_t result_func,
                    void *user_data);

