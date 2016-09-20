/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include <stdatomic.h>
#include "evoasm-island-model.h"

#define EVOASM_SEARCH_CONVERGENCE_THRESHOLD 0.03

EVOASM_DEF_LOG_TAG("model")

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

static void
evoasm_island_model_stop(struct evoasm_island_model_s *island_model) {
  unsigned i;
  for(i = 0; i < island_model->n_islands; i++) {
    island_model->islands[i].cancel = true;
  }
}

static evoasm_deme_result_func_retval_t
island_result_func(evoasm_deme_t *deme, const evoasm_indiv_t *indiv, evoasm_loss_t loss, void *user_data) {
  evoasm_island_t *island = (evoasm_island_t *) user_data;
  evoasm_deme_result_func_retval_t retval;

  EVOASM_TRY(error, evoasm_mutex_lock, &island->model->result_mutex);
  evoasm_island_model_result_func_retval_t island_model_retval =
      island->model->result_func(island->model, indiv, loss, island->model->user_data);

  switch(island_model_retval) {
    case EVOASM_ISLAND_MODEL_RESULT_FUNC_RETVAL_CONTINUE:
      retval = EVOASM_DEME_RESULT_FUNC_RETVAL_CONTINUE;
      break;
    case EVOASM_ISLAND_MODEL_RESULT_FUNC_RETVAL_STOP:
      retval = EVOASM_DEME_RESULT_FUNC_RETVAL_STOP;
      break;
    default:
      evoasm_assert_not_reached();
  }
  EVOASM_TRY(error, evoasm_mutex_unlock, &island->model->result_mutex);

  return retval;

error:
  return EVOASM_ISLAND_MODEL_RESULT_FUNC_RETVAL_STOP;
}

static evoasm_success_t
evoasm_island_start_(evoasm_island_t *island,
                     unsigned cycle) {
  unsigned gen;
  unsigned regress = 0;
  bool retval = true;
  bool unlock_at_exit = false;

  evoasm_island_model_t *island_model = island->model;
  evoasm_loss_t last_deme_loss = 0.0;

  for(gen = 0;; gen++) {

    EVOASM_TRY(error, evoasm_rwlock_rdlock, &island->rwlock);
    EVOASM_TRY(error_unlock, evoasm_deme_eval, island->deme, island_result_func, island->params->max_loss, island);

    if(gen % 256 == 0) {
      unsigned n_inf;
      evoasm_loss_t deme_loss = evoasm_deme_loss(island->deme, &n_inf, true);
      evoasm_info("norm. deme loss: %g/%u\n\n", deme_loss, n_inf);

      if(island_model->progress_func != NULL) {
        EVOASM_TRY(error_unlock, evoasm_mutex_lock, &island_model->progress_mutex);
        evoasm_island_model_progress_func_retval_t progress_func_retval =
            island_model->progress_func(island_model, island, cycle, gen,
                                        deme_loss, n_inf,
                                        island_model->user_data);
        switch(progress_func_retval) {
          case EVOASM_ISLAND_MODEL_PROGRESS_FUNC_RETVAL_CONTINUE:
            break;
          case EVOASM_ISLAND_MODEL_PROGRESS_FUNC_RETVAL_STOP:
            goto exit_unlock;
          default:
            evoasm_assert_not_reached();
        }
        EVOASM_TRY(error_unlock, evoasm_mutex_unlock, &island_model->progress_mutex);
      }

      if(gen > 0) {
        if(last_deme_loss <= deme_loss) {
          regress++;
        }
      }

      last_deme_loss = deme_loss;

      if(regress >= 3) {
        evoasm_info("reached convergence\n");
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

  evoasm_info("merging\n");

  for(i = 0; i < model->params->size; i++) {
    evoasm_adf_params_t *parent_a = _EVOASM_SEARCH_ADF_PARAMS(model, model->deme.adfs_main, i);
    evoasm_adf_params_t *parent_b = _EVOASM_SEARCH_ADF_PARAMS(model, model->deme.adfs_aux, i);

    evoasm_adf_params_t *child = _EVOASM_SEARCH_ADF_PARAMS(model, model->deme.adfs_swap, i);
    evoasm_island_model_crossover(model, parent_a, parent_b, child, NULL);
  }
  evoasm_deme_swap(&model->deme, &model->deme.adfs_main);
}
#endif

void *
island_thread_func(void *arg) {
  unsigned cycle;
  evoasm_island_t *island = arg;

  for(cycle = 0;; cycle++) {
    EVOASM_TRY(error, evoasm_rwlock_wrlock, &island->rwlock);
    EVOASM_TRY(error, evoasm_deme_seed, island->deme);
    EVOASM_TRY(error, evoasm_rwlock_unlock, &island->rwlock);
    EVOASM_TRY(error, evoasm_island_start_, island, cycle);
  }

error:
  island->error = *evoasm_last_error();
  island->errored = true;
done:
  return NULL;
}

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model,
                          evoasm_island_model_progress_func_t progress_func,
                          evoasm_island_model_result_func_t goal_func,
                          void *user_data) {

  unsigned i;

  for(i = 0; i < island_model->n_islands; i++) {
    EVOASM_TRY(thread_create_failed, evoasm_thread_create,
               &island_model->islands[i].thread,
               island_thread_func, &island_model->islands[i]);
  }

  return true;

thread_create_failed:;
  evoasm_island_model_stop(island_model);
  return false;
}

static evoasm_success_t
evoasm_island_init(evoasm_island_t *island, evoasm_deme_t *deme, evoasm_island_model_t *island_model) {
  EVOASM_TRY(rwlock_init_failed, evoasm_rwlock_init, &island->rwlock);

  island->deme = deme;
  island->model = island_model;
  return true;

rwlock_init_failed:
  return false;
}

static evoasm_success_t
evoasm_island_destroy(evoasm_island_t *deme_ctx) {
  bool retval = true;

  if(!evoasm_rwlock_destroy(&deme_ctx->rwlock)) retval = false;

  return retval;
}

static evoasm_success_t
evoasm_island_model_destroy_(evoasm_island_model_t *island_model, bool destroy_result_mutex,
                             bool destroy_progress_mutex, bool free_islands, unsigned destroy_n_islands) {
  unsigned i;
  bool retval = true;

  if(!evoasm_mutex_destroy(&island_model->result_mutex)) retval = false;
  if(!evoasm_mutex_destroy(&island_model->progress_mutex)) retval = false;

  if(free_islands) {
    for(i = 0; i < destroy_n_islands; i++) {
      if(!evoasm_island_destroy(&island_model->islands[i])) retval = false;
    }
    evoasm_free(island_model->islands);
  }

  return retval;
}

evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                         evoasm_island_model_params_t *params,
                         evoasm_island_model_result_func_t result_func,
                         evoasm_island_model_progress_func_t progress_func,
                         void *user_data,
                         uint16_t n_demes,
                         ...) {
  va_list args;
  unsigned i;
  bool retval = true;

  bool destroy_result_mutex = false;
  bool destroy_progress_mutex = false;
  bool free_islands = false;
  unsigned destroy_n_islands = 0;

  va_start(args, n_demes);

  if(!evoasm_mutex_init(&island_model->result_mutex)) goto error;
  destroy_result_mutex = true;

  if(!evoasm_mutex_init(&island_model->progress_mutex)) goto error;
  destroy_progress_mutex = true;

  island_model->n_islands = n_demes;
  island_model->progress_func = progress_func;
  island_model->result_func = result_func;
  island_model->user_data = user_data;

  island_model->islands = evoasm_calloc(n_demes, sizeof(evoasm_island_t *));
  if(!island_model->islands) goto error;
  free_islands = true;

  for(i = 0; i < n_demes; i++) {
    evoasm_deme_t *deme = va_arg(args, evoasm_deme_t *);
    if(!evoasm_island_init(&island_model->islands[i], deme, island_model)) goto error;
    destroy_n_islands = i;
  }

  goto done;

error:
  retval = false;
  bool r = evoasm_island_model_destroy_(island_model, destroy_result_mutex, destroy_progress_mutex, free_islands,
                                        destroy_n_islands);
  (void) r;
done:
  va_end(args);
  return retval;
}

evoasm_success_t
evoasm_island_connect_to(evoasm_island_t *island, evoasm_island_t *immigr_island) {
  if(island->n_immigr_islands == EVOASM_ISLAND_MAX_IMMIGR_ISLANDS) {
    evoasm_set_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                     "maximum number of immigration islands exceeded");
    return false;
  }

  if(evoasm_deme_indiv_size(immigr_island->deme) < evoasm_deme_indiv_size(island->deme)) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                     "island demes incompatible");
    return false;
  }

  island->immigr_islands[island->n_immigr_islands++] = immigr_island;

  return true;
}

evoasm_success_t
evoasm_island_model_destroy(evoasm_island_model_t *island_model) {
  return evoasm_island_model_destroy_(island_model, island_model->n_islands, false, NULL, 0);
}


_EVOASM_DEF_ALLOC_FREE_FUNCS(island_model)
