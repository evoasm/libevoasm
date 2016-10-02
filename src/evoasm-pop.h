/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdalign.h>
#include "evoasm-error.h"
#include "evoasm-pop-params.h"

typedef struct {
  void *dummy;
} evoasm_indiv_t;

struct evoasm_pop_s;

typedef evoasm_success_t (*evoasm_pop_seed_indiv_func_t)(struct evoasm_pop_s *pop, evoasm_indiv_t *indiv);

typedef evoasm_success_t (*evoasm_pop_eval_prepare_func_t)(struct evoasm_pop_s *pop);

typedef evoasm_success_t (*evoasm_pop_eval_cleanup_func_t)(struct evoasm_pop_s *pop);

typedef evoasm_success_t (*evoasm_pop_eval_indiv_func_t)(struct evoasm_pop_s *pop, evoasm_indiv_t *indiv,
                                                          evoasm_loss_t *loss);

typedef evoasm_success_t (*evoasm_pop_crossover_func_t)(struct evoasm_pop_s *pop,
                                                         evoasm_indiv_t *parent_a,
                                                         evoasm_indiv_t *parent_b,
                                                         evoasm_indiv_t *child_a,
                                                         evoasm_indiv_t *child_b);


typedef enum {
  EVOASM_POP_TYPE_BASE,
  EVOASM_POP_TYPE_PROGRAM
} evoasm_pop_type_t;

typedef struct {
  evoasm_pop_seed_indiv_func_t seed_indiv_func;
  evoasm_pop_eval_prepare_func_t eval_prepare_func;
  evoasm_pop_eval_cleanup_func_t eval_cleanup_func;
  evoasm_pop_eval_indiv_func_t eval_indiv_func;
  evoasm_pop_crossover_func_t crossover_func;
  evoasm_pop_type_t type;
} evoasm_pop_impl_t;

typedef struct alignas(128) {
  evoasm_prng_t prng;
  evoasm_program_io_val_t *output_vals;
  evoasm_program_t program;
} evoasm_pop_thread_data_t;


typedef struct {
  evoasm_deme_size_t *member_idxs;
  evoasm_team_size_t *alt_succ_idxs;
  uint8_t *jmp_selectors;
  evoasm_loss_t *losses;
  evoasm_team_size_t *sizes;
  unsigned len;
  unsigned kernels_per_member;
} evoasm_pop_team_layer_t;

typedef struct {
  evoasm_inst_id_t *insts;
  union {
    evoasm_x64_basic_params_t *x64;
  } params;
  evoasm_kernel_size_t *sizes;
  evoasm_loss_t *losses;
  unsigned len;
} evoasm_pop_kernel_layer_t;

typedef struct evoasm_pop_s {
  evoasm_pop_params_t *params;
  evoasm_loss_t best_loss;
  uint32_t best_indiv_idx;
  uint32_t n_examples;
  bool seeded : 1;
  evoasm_loss_t *losses;
  uint64_t *error_counters;
  uint64_t error_counter;
  unsigned char *indivs;
  unsigned char *data;
  evoasm_pop_team_layer_t team_layers[EVOASM_POP_MAX_DEPTH];
  evoasm_pop_kernel_layer_t kernel_layer;
  unsigned char *main_indivs;
  evoasm_domain_t *domains;
  evoasm_loss_t max_loss;
  const evoasm_pop_impl_t *impl;
  evoasm_pop_thread_data_t *thread_data;
  evoasm_arch_info_t *arch_info;
  int max_threads;
} evoasm_pop_t;


typedef bool (*evoasm_pop_result_cb_t)(evoasm_pop_t *pop,
                                        const evoasm_indiv_t *indiv,
                                        evoasm_loss_t loss,
                                        void *user_data);

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                evoasm_pop_params_t *params);


evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop, evoasm_loss_t max_loss, evoasm_pop_result_cb_t result_cb,
                 void *user_data);

evoasm_success_t
evoasm_pop_next_gen(evoasm_pop_t *pop);

evoasm_indiv_t *
evoasm_pop_get_indiv(evoasm_pop_t *pop, uint32_t idx);

evoasm_loss_t
evoasm_pop_get_indiv_loss(evoasm_pop_t *pop, uint32_t idx);

size_t
evoasm_pop_get_indiv_size(evoasm_pop_t *pop);

evoasm_loss_t
evoasm_pop_get_loss(evoasm_pop_t *pop, unsigned *n_inf, bool per_example);

evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop);

void
evoasm_pop_select(evoasm_pop_t *pop, uint32_t *idxs, unsigned n_idxs);

bool
evoasm_pop_destroy(evoasm_pop_t *pop);

void
evoasm_pop_inject(evoasm_pop_t *pop, evoasm_indiv_t *indiv, size_t indiv_size, evoasm_loss_t loss);

