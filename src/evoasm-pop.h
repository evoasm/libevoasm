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

#include <stdalign.h>
#include "evoasm-error.h"
#include "evoasm-pop-params.h"

typedef struct {
  evoasm_loss_t *samples;
  evoasm_bitmap_t *timed_out;
} evoasm_pop_losses_t;

typedef struct {
  uint8_t *edges;
  uint8_t *default_succs;
} evoasm_pop_topologies_t;

typedef struct {
  float *pheromones;
  uint16_t *sizes;
  evoasm_pop_topologies_t topologies;
} evoasm_pop_modules_t;

typedef struct  {
  evoasm_inst_id_t *insts;
  union {
    evoasm_x64_basic_params_t *x64;
    void *data;
  } params;
} evoasm_pop_kernels_t;

struct evoasm_pop_s;

struct evoasm_deme_s {

  bool best_timed_out;
  uint16_t example_win_off;
  uint16_t stagn_counter;
  uint16_t idx;
  float mut_rate;
  evoasm_arch_id_t arch_id;
  uint64_t error_counter;
  evoasm_loss_t top_loss;
  evoasm_loss_t best_loss;
  evoasm_prng_t prng;
  evoasm_program_t program;
  evoasm_pop_losses_t losses;
  evoasm_pop_topologies_t topologies;
  evoasm_pop_kernels_t kernels;
  evoasm_pop_topologies_t best_topologies;
  evoasm_pop_kernels_t best_kernels;

  uint16_t *immig_idxs;
  uint8_t *won_tourns_counters;
  uint64_t *error_counters;
  struct evoasm_pop_s *pop;
  evoasm_domain_t *domains;
  const evoasm_pop_params_t *params;
} evoasm_aligned(EVOASM_CACHE_LINE_SIZE) ;

typedef struct evoasm_deme_s evoasm_deme_t;

typedef struct evoasm_pop_s {
  const evoasm_pop_params_t *params;
  evoasm_domain_t *domains;
  evoasm_deme_t *demes;
  evoasm_pop_modules_t modules;
  evoasm_loss_t *summary_losses;
  bool seeded : 1;
  uint16_t gen_counter;
  uint16_t n_demes;
} evoasm_pop_t;

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                const evoasm_pop_params_t *params);


evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop, size_t n_minor_gens);

void
evoasm_pop_next_gen(evoasm_pop_t *pop);

evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop, evoasm_pop_topologies_t *topologies, size_t n_topologies, evoasm_pop_kernels_t *kernels, size_t n_kernels);

void
evoasm_pop_destroy(evoasm_pop_t *pop);

//void
//evoasm_pop_inject(evoasm_pop_t *pop, evoasm_indiv_t *indiv, size_t indiv_size, evoasm_loss_t loss);

