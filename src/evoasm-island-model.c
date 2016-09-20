/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-island-model.h"

EVOASM_DEF_LOG_TAG("island-model")

static void
evoasm_island_model_stop(struct evoasm_island_model_s *island_model) {
  evoasm_island_t *island;

  for(island = island_model->first_island; island != NULL; island = island->next) {
    island->cancelled = true;
  }
}

static evoasm_success_t
evoasm_island_model_wait(evoasm_island_model_t *island_model) {
  evoasm_island_t *island;
  bool retval = true;
  for(island = island_model->first_island; island != NULL; island = island->next) {
    if(!evoasm_thread_join(&island->thread, NULL)) {
      retval = false;
    }
  }

  return retval;
}

void *
island_thread_func(void *arg) {
  evoasm_island_t *island = arg;

  if(!evoasm_island_run(island)) {
    return NULL;
  }
  return NULL;
}

static void
evoasm_island_model_error(evoasm_island_model_t *island_model) {
  island_model->errored = true;
  island_model->error = *evoasm_last_error();

  evoasm_island_model_stop(island_model);
}

evoasm_deme_result_func_retval_t
evoasm_island_model_progress(struct evoasm_island_model_s *island_model, evoasm_island_t *island,
                             unsigned cycle, unsigned gen, evoasm_loss_t loss, unsigned n_inf) {

  evoasm_deme_result_func_retval_t retval;

  if(island_model->progress_func != NULL) {
    EVOASM_TRY(error, evoasm_mutex_lock, &island_model->progress_mutex);
    evoasm_island_model_progress_func_retval_t progress_func_retval =
        island_model->progress_func(island_model, island, cycle, gen,
                                    loss, n_inf,
                                    island_model->user_data);
    switch(progress_func_retval) {
      case EVOASM_ISLAND_MODEL_PROGRESS_FUNC_RETVAL_CONTINUE:
        retval = EVOASM_DEME_RESULT_FUNC_RETVAL_CONTINUE;
        break;
      case EVOASM_ISLAND_MODEL_PROGRESS_FUNC_RETVAL_STOP:
        retval = EVOASM_DEME_RESULT_FUNC_RETVAL_STOP;
      default:
        evoasm_assert_not_reached();
    }
    EVOASM_TRY(error, evoasm_mutex_unlock, &island_model->progress_mutex);
  }

  return retval;

error:
  evoasm_island_model_error(island_model);
  return EVOASM_DEME_RESULT_FUNC_RETVAL_STOP;
}

evoasm_deme_result_func_retval_t
evoasm_island_model_result(evoasm_island_model_t *island_model, const evoasm_indiv_t *indiv, evoasm_loss_t loss) {
  evoasm_deme_result_func_retval_t retval;

  EVOASM_TRY(error, evoasm_mutex_lock, &island_model->result_mutex);
  evoasm_island_model_result_func_retval_t island_model_retval =
      island_model->result_func(island_model, indiv, loss, island_model->user_data);

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
  EVOASM_TRY(error, evoasm_mutex_unlock, &island_model->result_mutex);

  return retval;

error:
  evoasm_island_model_error(island_model);
  return EVOASM_DEME_RESULT_FUNC_RETVAL_STOP;
}

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model) {

  evoasm_island_t *island;

  for(island = island_model->first_island; island != NULL; island = island->next) {
    EVOASM_TRY(thread_create_failed, evoasm_thread_create,
               &island->thread,
               island_thread_func, island);
  }

  bool r = evoasm_island_model_wait(island_model);
  (void) r;
  return true;

thread_create_failed:;
  evoasm_island_model_stop(island_model);
  return false;
}

static evoasm_success_t
evoasm_island_model_destroy_(evoasm_island_model_t *island_model, bool destroy_result_mutex,
                             bool destroy_progress_mutex) {
  bool retval = true;

  if(destroy_result_mutex) {
    if(!evoasm_mutex_destroy(&island_model->result_mutex)) retval = false;
  }

  if(destroy_progress_mutex) {
    if(!evoasm_mutex_destroy(&island_model->progress_mutex)) retval = false;
  }

  return retval;
}

void
evoasm_island_model_add_island(evoasm_island_model_t *island_model,
                               evoasm_island_t *island) {

  island->next = island_model->first_island;
  island_model->first_island = island;
  island_model->n_islands++;
}

evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                         evoasm_island_model_params_t *params,
                         evoasm_island_model_result_func_t result_func,
                         evoasm_island_model_progress_func_t progress_func,
                         void *user_data) {
  bool retval = true;

  bool destroy_result_mutex = false;
  bool destroy_progress_mutex = false;

  if(!evoasm_mutex_init(&island_model->result_mutex)) goto error;
  destroy_result_mutex = true;

  if(!evoasm_mutex_init(&island_model->progress_mutex)) goto error;
  destroy_progress_mutex = true;

  island_model->n_islands = 0;
  island_model->progress_func = progress_func;
  island_model->result_func = result_func;
  island_model->user_data = user_data;
  island_model->first_island = NULL;
  island_model->errored = false;

  goto done;

error:
  retval = false;
  bool r = evoasm_island_model_destroy_(island_model, destroy_result_mutex, destroy_progress_mutex);
  (void) r;
done:
  return retval;
}

evoasm_success_t
evoasm_island_model_destroy(evoasm_island_model_t *island_model) {
  return evoasm_island_model_destroy_(island_model, true, true);
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(island_model)
