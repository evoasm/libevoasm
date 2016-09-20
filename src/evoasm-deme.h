/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-deme-params.h"

typedef struct {
  void *dummy;
} evoasm_indiv_t;

struct evoasm_deme_s;

typedef evoasm_success_t (*evoasm_deme_seed_indiv_func_t)(struct evoasm_deme_s *deme, evoasm_indiv_t *indiv);

typedef evoasm_success_t (*evoasm_deme_eval_setup_func_t)(struct evoasm_deme_s *deme);

typedef evoasm_success_t (*evoasm_deme_eval_teardown_func_t)(struct evoasm_deme_s *deme);

typedef evoasm_success_t (*evoasm_deme_eval_indiv_func_t)(struct evoasm_deme_s *deme, evoasm_indiv_t *indiv,
                                                        evoasm_loss_t *loss);

typedef evoasm_success_t (*evoasm_deme_extract_indiv_func_t)(struct evoasm_deme_s *deme, evoasm_indiv_t *indiv,
                                                           evoasm_indiv_t *dst_indiv);

typedef evoasm_success_t (*evoasm_deme_crossover_func_t)(struct evoasm_deme_s *deme,
                                                       evoasm_indiv_t *parent_a,
                                                       evoasm_indiv_t *parent_b,
                                                       evoasm_indiv_t *child_a,
                                                       evoasm_indiv_t *child_b);


typedef enum {
  EVOASM_DEME_TYPE_BASE,
  EVOASM_DEME_TYPE_ADF
} evoasm_deme_type_t;

typedef struct {
  evoasm_deme_seed_indiv_func_t seed_indiv_func;
  evoasm_deme_eval_setup_func_t eval_setup_func;
  evoasm_deme_eval_teardown_func_t eval_teardown_func;
  evoasm_deme_eval_indiv_func_t eval_indiv_func;
  evoasm_deme_extract_indiv_func_t extract_indiv_func;
  evoasm_deme_crossover_func_t crossover_func;
  evoasm_deme_type_t type;
} evoasm_deme_cls_t;

typedef struct evoasm_deme_s {
  evoasm_deme_params_t *params;
  evoasm_prng_t prng;
  evoasm_loss_t best_loss;
  uint32_t best_indiv_idx;
  evoasm_loss_t *losses;
  uint64_t *error_counters;
  uint64_t error_counter;
  size_t indiv_size;
  uint32_t n_examples;
  unsigned char *indivs;
  unsigned char *main_indivs;
  unsigned char *swap_indivs;
  evoasm_domain_t *domains;

  const evoasm_deme_cls_t *cls;
} evoasm_deme_t;

typedef enum {
  EVOASM_DEME_RESULT_FUNC_RETVAL_CONTINUE,
  EVOASM_DEME_RESULT_FUNC_RETVAL_STOP
} evoasm_deme_result_func_retval_t;

typedef evoasm_deme_result_func_retval_t (*evoasm_deme_result_func)(evoasm_deme_t *deme,
                                        const evoasm_indiv_t *indiv,
                                        evoasm_loss_t loss,
                                        void *user_data);

evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme,
                 evoasm_deme_params_t *params,
                 const evoasm_deme_cls_t *cls,
                 size_t indiv_size,
                 uint32_t n_examples);

evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme, evoasm_deme_result_func result_func,
                 evoasm_loss_t max_loss, void *user_data);

evoasm_success_t
evoasm_deme_new_gen(evoasm_deme_t *deme);

evoasm_indiv_t *
evoasm_deme_indiv(evoasm_deme_t *deme, uint32_t idx);

size_t
evoasm_deme_indiv_size(evoasm_deme_t *deme);

evoasm_loss_t
evoasm_deme_loss(evoasm_deme_t *deme, unsigned *n_inf, bool normed);

evoasm_success_t
evoasm_deme_seed(evoasm_deme_t *deme);

void
evoasm_deme_select(evoasm_deme_t *deme, uint32_t *idxs, unsigned n_idxs);

void
evoasm_deme_destroy(evoasm_deme_t *deme);

void
evoasm_deme_inject(evoasm_deme_t *deme, evoasm_indiv_t *indiv, size_t indiv_size, evoasm_loss_t loss);

evoasm_loss_t
evoasm_deme_indiv_loss(evoasm_deme_t *deme, uint32_t idx);
