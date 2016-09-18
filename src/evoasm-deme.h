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

} evoasm_indiv_t;

struct evoasm_deme_s;

typedef evoasm_success_t (*evoasm_deme_seed_indiv_func)(struct evoasm_deme_s *deme, evoasm_indiv_t *indiv);
typedef evoasm_success_t (*evoasm_deme_eval_setup_func)(struct evoasm_deme_s *deme);
typedef evoasm_success_t (*evoasm_deme_eval_teardown_func)(struct evoasm_deme_s *deme);
typedef evoasm_success_t (*evoasm_deme_eval_indiv_func)(struct evoasm_deme_s *deme, evoasm_indiv_t *indiv, evoasm_loss_t *loss);
typedef evoasm_success_t (*evoasm_deme_extract_indiv_func)(struct evoasm_deme_s *deme, evoasm_indiv_t *indiv, evoasm_indiv_t *dst_indiv);
typedef evoasm_success_t (*evoasm_deme_crossover_func)(struct evoasm_deme_s *deme,
                                                       evoasm_indiv_t *parent_a,
                                                       evoasm_indiv_t *parent_b,
                                                       evoasm_indiv_t *child_a,
                                                       evoasm_indiv_t *child_b);

typedef struct {
  evoasm_deme_seed_indiv_func seed_indiv_func;
  evoasm_deme_eval_setup_func eval_setup_func;
  evoasm_deme_eval_teardown_func eval_teardown_func;
  evoasm_deme_eval_indiv_func eval_indiv_func;
  evoasm_deme_extract_indiv_func extract_indiv_func;
  evoasm_deme_crossover_func crossover_func;
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
  uint32_t  n_examples;
  unsigned char *indivs;
  unsigned char *main_indivs;
  unsigned char *swap_indivs;
  evoasm_domain_t *domains;

  evoasm_deme_cls_t *cls;
} evoasm_deme_t;


evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme,
                 evoasm_deme_params_t *params,
                 const evoasm_deme_cls_t *cls,
                 size_t indiv_size,
                 uint32_t n_examples);

evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme);

void
evoasm_deme_new_gen(evoasm_deme_t *deme);


evoasm_loss_t
evoasm_deme_loss(evoasm_deme_t *deme, unsigned *n_inf, bool normed);

void
evoasm_deme_seed(evoasm_deme_t *deme);

void
evoasm_deme_select(evoasm_deme_t *deme, uint32_t *idxs, unsigned n_idxs);

void
evoasm_deme_destroy(evoasm_deme_t *deme);

evoasm_indiv_t *
evoasm_deme_best_indiv(evoasm_deme_t *deme, evoasm_loss_t max_loss);
