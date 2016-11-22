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
  uint8_t *counters;
} evoasm_pop_loss_data_t;

typedef struct {
  int16_t *jmp_offs;
  uint8_t *jmp_cond;
} evoasm_pop_program_data_t;

typedef struct {
  float *pheromones;
  uint16_t *sizes;
  evoasm_pop_program_data_t program_data;
} evoasm_pop_module_data_t;

typedef struct  {
  evoasm_inst_id_t *insts;
  union {
    evoasm_x64_basic_params_t *x64;
    void *data;
  } params;
} evoasm_pop_kernel_data_t;

struct evoasm_deme_s {
  evoasm_prng_t prng;
  uint16_t *selected_parent_idxs;
  evoasm_pop_program_data_t parent_program_data;
  evoasm_pop_kernel_data_t parent_kernel_data;
  evoasm_program_t program;
  uint64_t *error_counters;
  uint64_t error_counter;
  evoasm_pop_loss_data_t loss_data;
  evoasm_pop_program_data_t program_data;
  evoasm_pop_kernel_data_t kernel_data;
  evoasm_loss_t *top_losses;

  evoasm_loss_t best_loss;
  evoasm_pop_program_data_t best_program_data;
  evoasm_pop_kernel_data_t best_kernel_data;

  uint16_t n_examples;
  evoasm_arch_id_t arch_id;
  evoasm_pop_params_t *params;
  evoasm_domain_t *domains;
} evoasm_aligned(EVOASM_CACHE_LINE_SIZE) ;

typedef struct evoasm_deme_s evoasm_deme_t;

typedef struct evoasm_pop_s {
  evoasm_pop_params_t *params;
  evoasm_domain_t *domains;
  evoasm_deme_t *demes;
  int max_threads;
  evoasm_pop_module_data_t module_data;
  bool seeded : 1;
  evoasm_loss_t *summary_losses;

} evoasm_pop_t;

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                evoasm_pop_params_t *params);


evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop);

void
evoasm_pop_next_gen(evoasm_pop_t *pop);


evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop);

void
evoasm_pop_destroy(evoasm_pop_t *pop);

//void
//evoasm_pop_inject(evoasm_pop_t *pop, evoasm_indiv_t *indiv, size_t indiv_size, evoasm_loss_t loss);

