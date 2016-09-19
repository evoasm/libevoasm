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
#include "evoasm-deme.h"

#define EVOASM_ISLAND_MAX_IMMIGR_ISLANDS 8

typedef enum {
  EVOASM_ISLAND_TOPOLOGY_RING,
  EVOASM_N_ISLAND_TOPOLOGIES
} evoasm_island_topology_t;

typedef struct {
  void *dummy;
} evoasm_island_model_params_t;

typedef struct {
  float emigr_rate;
  uint16_t emigr_freq;
  evoasm_loss_t max_loss;
} evoasm_island_params_t;

struct evoasm_island_model_s;

typedef struct evoasm_island_s {
  evoasm_rwlock_t rwlock;
  evoasm_thread_t thread;
  evoasm_deme_t *deme;
  struct evoasm_island_model_s *model;
  struct evoasm_island_s *immigr_islands[EVOASM_ISLAND_MAX_IMMIGR_ISLANDS];
  evoasm_island_params_t *params;
  uint8_t n_immigr_islands;
  atomic_bool cancel;
  evoasm_error_t error;
  bool errored;
} evoasm_island_t;

typedef enum {
  EVOASM_ISLAND_MODEL_RESULT_FUNC_RETVAL_CONTINUE,
  EVOASM_ISLAND_MODEL_RESULT_FUNC_RETVAL_STOP
} evoasm_island_model_result_func_retval_t;


typedef evoasm_island_model_result_func_retval_t (*evoasm_island_model_result_func_t)(struct evoasm_island_model_s *island_model,
                                                  const evoasm_indiv_t *indiv,
                                                  evoasm_loss_t loss, void *user_data);

typedef bool (*evoasm_island_model_progress_func_t)(struct evoasm_island_model_s *island_model,
                                                    evoasm_island_t *island,
                                                    unsigned cycle,
                                                    unsigned gen,
                                                    evoasm_loss_t deme_loss,
                                                    unsigned n_inf,
                                                    void *user_data);

typedef struct evoasm_island_model_s {
  evoasm_arch_id_t arch_id;
  uint16_t n_islands;
  evoasm_island_t *islands;
  evoasm_island_model_params_t *params;
  evoasm_mutex_t result_mutex;
  evoasm_mutex_t progress_mutex;
  evoasm_island_model_result_func_t result_func;
  evoasm_island_model_progress_func_t progress_func;
  void *user_data;
} evoasm_island_model_t;


evoasm_success_t
evoasm_island_model_destroy(evoasm_island_model_t *island_model);


evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                         evoasm_island_model_params_t *params,
                         evoasm_island_model_result_func_t result_func,
                         evoasm_island_model_progress_func_t progress_func,
                         void *user_data,
                         uint16_t n_demes,
                         ...);

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model,
                          evoasm_island_model_progress_func_t progress_func,
                          evoasm_island_model_result_func_t result_func,
                          void *user_data);

