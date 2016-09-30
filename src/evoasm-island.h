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
#include "evoasm-pop.h"

#define EVOASM_ISLAND_MAX_IMMIGR_ISLANDS 8

typedef struct {
  double emigr_rate;
  uint16_t emigr_freq;
  evoasm_loss_t max_loss;
} evoasm_island_params_t;

struct evoasm_island_model_s;

typedef struct evoasm_island_s {
  evoasm_rwlock_t rwlock;
  evoasm_thread_t thread;
  evoasm_pop_t *pop;
  struct evoasm_island_s *immigr_islands[EVOASM_ISLAND_MAX_IMMIGR_ISLANDS];
  evoasm_island_params_t *params;
  uint8_t n_immigr_islands;
  atomic_bool cancelled;
  struct evoasm_island_model_s *model;
  struct evoasm_island_s *next;
} evoasm_island_t;


evoasm_success_t
evoasm_island_run(evoasm_island_t *island);

_EVOASM_DECL_ALLOC_FREE_FUNCS(island)
