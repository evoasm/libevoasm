/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include <stdatomic.h>
#include "evoasm-island-model.h"
#include "evoasm-adf-deme.h"
#include "evoasm-deme-params.h"

#define EVOASM_SEARCH_CONVERGENCE_THRESHOLD 0.03

EVOASM_DEF_LOG_TAG("model")

static void
evoasm_island_emigrate(evoasm_island_t *island) {

  unsigned i;
  for(i = 0; i < island->n_immigr_islands; i++) {
    evoasm_island_t *immigr_island = island->immigr_islands[i];

    unsigned selection_size =  island->params->emigr_rate * island->deme->params->size;
    uint32_t *selection = evoasm_alloca(sizeof(uint32_t) * selection_size);

    evoasm_deme_select(island->deme, selection, selection_size);


    mtx_lock(&immigr_island->mtx);

    mtx_unlock(&immigr_island->mtx);
  }

}

static void
evoasm_island_model_stop(struct evoasm_island_model_s *island_model) {
  unsigned i;
  for(i = 0; i < island_model->n_islands; i++) {
    island_model->islands[i].cancel = true;
  }
}

static evoasm_success_t
evoasm_island_start_(evoasm_island_t *island,
                     unsigned cycle,
                     evoasm_island_progress_func_t progress_func,
                     void *user_data) {
  unsigned gen;
  unsigned ups = 0;

  evoasm_adf_t *adf = evoasm_adf_alloc();
  evoasm_loss_t adf_loss = NAN;
  evoasm_loss_t last_deme_loss = 0.0;

  for(gen = 0;; gen++) {
    if(!evoasm_deme_eval(island->deme)) {
      return false;
    }

    evoasm_indiv_t *best_indiv = evoasm_deme_best_indiv(island->deme, island->params->max_loss);
    if(best_indiv) {
      evoasm_island_model_stop(island->model);
    }

    if(gen % 256 == 0) {
      unsigned n_inf;
      evoasm_loss_t deme_loss = evoasm_deme_loss(island->deme, &n_inf, true);
      evoasm_info("norm. deme loss: %g/%u\n\n", deme_loss, n_inf);

      if(progress_func != NULL) {
        progress_func(deme_idx, cycle, gen, deme_loss, n_inf, user_data);
      }

      if(gen > 0) {
        if(last_deme_loss <= deme_loss) {
          ups++;
        }
      }

      last_deme_loss = deme_loss;

      if(ups >= 3) {
        evoasm_info("reached convergence\n");
        *converged = true;
        return true;
      }
    }

    if(gen % 16 == 0) {
      evoasm_island_model_migrate(island->model, island);
    }

    mtx_lock(&island->mtx);
    evoasm_deme_new_gen(island->deme);
    mtx_unlock(&island->mtx);
  }
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

int
deme_thrd_func(void *arg) {
  unsigned cycle;
  evoasm_island_t *island = arg;

  for(cycle = 0;; cycle++) {
    evoasm_deme_seed(island->deme);
    if(!evoasm_island_start_(island, 0, cycle, data->progress_func, data->goal_func, data->user_data)) {
      island->error = *evoasm_last_error();
      return false;
    }
  }

  return true;
}

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model,
                    evoasm_island_progress_func_t progress_func,
                    evoasm_island_model_goal_func_t goal_func,
                    void *user_data) {

  unsigned i;
  bool retval = true;

  _evoasm_island_thrd_data_t *data = evoasm_alloca(island_model->n_islands * sizeof(_evoasm_island_thrd_data_t));

  for(i = 0; i < island_model->n_islands; i++) {
    if(thrd_create(&island_model->islands[i].thrd, deme_thrd_func, &island_model->islands[i]) != thrd_success) {
      evoasm_set_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                       "thread creation failed");
      goto thrd_create_failed;
    }
  }

thrd_create_failed:;
  return retval;
}

static evoasm_success_t
evoasm_island_init(evoasm_island_t *island, evoasm_adf_deme_t *deme, evoasm_island_model_t *island_model) {
  if(mtx_init(&island->mtx, mtx_plain) != thrd_success) {
    evoasm_set_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                     "mutex initialization failed");
    goto mtx_init_failed;
  }

  island->deme = deme;
  island->model = island_model;

  return true;

mtx_init_failed:
  return false;
}

static void
evoasm_island_ctx_destroy(evoasm_island_t *deme_ctx) {
  mtx_destroy(&deme_ctx->mtx);
}

evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                   evoasm_island_model_params_t *params,
                   uint16_t n_demes,
                   ...) {
  va_list args;
  unsigned i;
  bool retval = true;

  va_start(args, n_demes);

  island_model->n_islands = n_demes;

  island_model->islands = evoasm_calloc(n_demes, sizeof(evoasm_island_t *));
  if(!island_model->islands) {
    goto alloc_failed;
  }

  for(i = 0; i < n_demes; i++) {
    evoasm_adf_deme_t *deme = va_arg(args, evoasm_adf_deme_t *);
    if(!evoasm_island_init(&island_model->islands[i], deme, island_model)) {
      goto island_init_failed;
    }
  }

  goto done;

island_init_failed:
  evoasm_island_model_destroy_(island_model, i);
alloc_failed:
  retval = false;
done:
  va_end(args);
  return retval;
}

evoasm_success_t
evoasm_island_connect_to(evoasm_island_t *island, evoasm_island_t *immigr_island) {
  if(island->n_immigr_islands == EVOASM_ISLAND_MAX_IMMIGR_ISLANDS) {
    evoasm_set_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                     "maximum number of neighbors exceeded");
    return false;
  }

  if(evoasm_deme_adf_params_size(immigr_island) < evoasm_deme_adf_params_size(island->deme)) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                     "island demes incompatible");
    return false;
  }

  island->immigr_islands[island->n_immigr_islands++] = immigr_island;

  return true;
}


static void
evoasm_island_model_destroy_(evoasm_island_model_t *island_model, unsigned n_demes) {
  unsigned i;

  for(i = 0; i < n_demes; i++) {
    evoasm_island_ctx_destroy(&island_model->islands[i]);
  }
  evoasm_free(island_model->islands);
}

void
evoasm_island_model_destroy(evoasm_island_model_t *island_model) {
  evoasm_island_model_destroy_(island_model, island_model->n_islands);
}


_EVOASM_DEF_ALLOC_FREE_FUNCS(island_model)
