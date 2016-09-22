/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-island.h"

EVOASM_DEF_LOG_TAG("island")

static evoasm_success_t
evoasm_island_emigrate(evoasm_island_t *island) {

  unsigned i;
  for(i = 0; i < island->n_immigr_islands; i++) {
    evoasm_island_t *immigr_island = island->immigr_islands[i];
    unsigned emigr_size = (unsigned) island->params->emigr_rate * island->deme->params->size;
    uint32_t *emigr_selection = evoasm_alloca(sizeof(uint32_t) * emigr_size);

    EVOASM_TRY(error, evoasm_rwlock_rdlock, &island->rwlock);
    evoasm_deme_select(island->deme, emigr_selection, emigr_size);

    unsigned j;

    EVOASM_TRY(error, evoasm_rwlock_wrlock, &immigr_island->rwlock);
    for(j = 0; j < emigr_size; j++) {
      evoasm_indiv_t *emigr_indiv = evoasm_deme_indiv(island->deme, emigr_selection[j]);
      evoasm_loss_t emigr_loss = evoasm_deme_indiv_loss(island->deme, emigr_selection[i]);
      evoasm_deme_inject(island->deme, emigr_indiv, emigr_size, emigr_loss);
    }
    EVOASM_TRY(error, evoasm_rwlock_unlock, &immigr_island->rwlock);
    EVOASM_TRY(error, evoasm_rwlock_unlock, &island->rwlock);
  }

  return true;

error:
  return false;
}


bool
evoasm_island_model_call_progress_cb(struct evoasm_island_model_s *island_model, evoasm_island_t *island,
                                     unsigned cycle, unsigned gen, evoasm_loss_t loss, unsigned n_inf);


bool
evoasm_island_model_call_result_cb(struct evoasm_island_model_s *island_model, const evoasm_indiv_t *indiv,
                                   evoasm_loss_t loss);

static bool
island_result_func(evoasm_deme_t *deme, const evoasm_indiv_t *indiv, evoasm_loss_t loss, void *user_data) {
  evoasm_island_t *island = (evoasm_island_t *) user_data;
  return evoasm_island_model_call_result_cb(island->model, indiv, loss);
}

static evoasm_success_t
evoasm_island_cycle(evoasm_island_t *island,
                    unsigned cycle) {
  unsigned gen;
  unsigned regress = 0;
  bool retval = true;
  bool unlock_at_exit = false;

  struct evoasm_island_model_s *island_model = island->model;
  evoasm_loss_t last_deme_loss = 0.0;

  for(gen = 0;; gen++) {

    EVOASM_TRY(error, evoasm_rwlock_rdlock, &island->rwlock);
    EVOASM_TRY(error_unlock, evoasm_deme_eval, island->deme, island->params->max_loss, island_result_func, island);

    if(gen % 256 == 0) {
      unsigned n_inf;
      evoasm_loss_t deme_loss = evoasm_deme_loss(island->deme, &n_inf, true);
      evoasm_log_info("norm. deme loss: %g/%u\n\n", deme_loss, n_inf);

      EVOASM_TRY(error_unlock, evoasm_island_model_call_progress_cb,
                 island_model, island, cycle, gen, deme_loss, n_inf);

      if(gen > 0) {
        if(last_deme_loss <= deme_loss) {
          regress++;
        }
      }

      last_deme_loss = deme_loss;

      if(regress >= 3) {
        evoasm_log_info("reached convergence\n");
        goto exit_unlock;
      }
    }
    EVOASM_TRY(error, evoasm_rwlock_unlock, &island->rwlock);

    if(gen % island->params->emigr_freq == 0) {
      EVOASM_TRY(error, evoasm_island_emigrate, island);
    }

    EVOASM_TRY(error, evoasm_rwlock_wrlock, &island->rwlock);
    EVOASM_TRY(error_unlock, evoasm_deme_new_gen, island->deme);
    EVOASM_TRY(error, evoasm_rwlock_unlock, &island->rwlock);
  }

exit:
  if(unlock_at_exit) {
    bool v = evoasm_rwlock_unlock(&island->rwlock);
    (void) v;
  }
  return retval;

exit_unlock:
  retval = true;
  unlock_at_exit = true;
  goto exit;

error_unlock:
  unlock_at_exit = true;
error:
  retval = false;
  goto exit;
}

#if 0
static void
evoasm_island_model_merge(evoasm_island_model_t *model) {
  unsigned i;

  evoasm_log_info("merging\n");

  for(i = 0; i < model->params->kernel_count; i++) {
    evoasm_program_params_t *parent_a = _EVOASM_SEARCH_PROGRAM_PARAMS(model, model->deme.programs_main, i);
    evoasm_program_params_t *parent_b = _EVOASM_SEARCH_PROGRAM_PARAMS(model, model->deme.programs_aux, i);

    evoasm_program_params_t *child = _EVOASM_SEARCH_PROGRAM_PARAMS(model, model->deme.programs_swap, i);
    evoasm_island_model_crossover(model, parent_a, parent_b, child, NULL);
  }
  evoasm_deme_swap(&model->deme, &model->deme.programs_main);
}
#endif


evoasm_success_t
evoasm_island_run(evoasm_island_t *island) {
  unsigned cycle;
  island->cancelled = false;

  for(cycle = 0;; cycle++) {
    if(island->cancelled) break;

    EVOASM_TRY(error, evoasm_rwlock_wrlock, &island->rwlock);
    EVOASM_TRY(error, evoasm_deme_seed, island->deme);
    EVOASM_TRY(error, evoasm_rwlock_unlock, &island->rwlock);
    EVOASM_TRY(error, evoasm_island_cycle, island, cycle);
  }

  return true;

error:
  return false;
}

void
evoasm_island_model_add_island(struct evoasm_island_model_s *island_model,
                               evoasm_island_t *island);

evoasm_success_t
evoasm_island_init(evoasm_island_t *island, struct evoasm_island_model_s *island_model,
                   evoasm_deme_t *deme, evoasm_island_params_t *params) {
  EVOASM_TRY(error, evoasm_rwlock_init, &island->rwlock);

  island->model = island_model;
  island->params = params;
  island->deme = deme;
  island->next = NULL;

  evoasm_island_model_add_island(island_model, island);

  return true;

error:
  return false;
}

evoasm_success_t
evoasm_island_destroy(evoasm_island_t *island) {
  bool retval = true;

  if(!evoasm_rwlock_destroy(&island->rwlock)) retval = false;

  return retval;
}

evoasm_success_t
evoasm_island_connect_to(evoasm_island_t *island, evoasm_island_t *immigr_island) {
  if(island->model != immigr_island->model) {
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                     "islands belong to different models");
    return false;
  }

  if(island->n_immigr_islands == EVOASM_ISLAND_MAX_IMMIGR_ISLANDS) {
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                     "maximum number of immigration islands exceeded");
    return false;
  }

  if(immigr_island->deme->cls->type != island->deme->cls->type ||
     evoasm_deme_indiv_size(immigr_island->deme) < evoasm_deme_indiv_size(island->deme)) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                     "island demes incompatible");
    return false;
  }

  island->immigr_islands[island->n_immigr_islands++] = immigr_island;

  return true;
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(island_params)
_EVOASM_DEF_ZERO_INIT_FUNC(island_params)

_EVOASM_DEF_FIELD_ACCESSOR(island_params, emigr_rate, double)
_EVOASM_DEF_FIELD_ACCESSOR(island_params, emigr_freq, uint16_t)
_EVOASM_DEF_FIELD_ACCESSOR(island_params, max_loss, evoasm_loss_t)

_EVOASM_DEF_ALLOC_FREE_FUNCS(island)
