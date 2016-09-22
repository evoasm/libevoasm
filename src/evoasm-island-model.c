/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include <error.h>
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

static void
evoasm_island_model_error(evoasm_island_model_t *island_model) {
  evoasm_error_t error = *evoasm_last_error();
  if(!evoasm_mutex_lock(island_model->error_mutex)) {}
  if(island_model->errored) return;
  island_model->errored = true;
  island_model->error = error;
  evoasm_island_model_stop(island_model);
  if(!evoasm_mutex_unlock(island_model->error_mutex)) {}
}

static void *
island_thread_func(void *arg) {
  evoasm_island_t *island = arg;

  if(!evoasm_island_run(island)) {
    evoasm_island_model_error(island->model);
    return NULL;
  }
  return NULL;
}

bool
evoasm_island_model_call_progress_cb(struct evoasm_island_model_s *island_model, evoasm_island_t *island,
                                     unsigned cycle, unsigned gen, evoasm_loss_t loss, unsigned n_inf) {

  bool retval;

  if(island_model->progress_cb != NULL) {
    EVOASM_TRY(error, evoasm_mutex_lock, island_model->progress_mutex);
    retval = island_model->progress_cb(island_model, island, cycle, gen,
                                       loss, n_inf,
                                       island_model->result_user_data);
    EVOASM_TRY(error, evoasm_mutex_unlock, island_model->progress_mutex);
  }

  return retval;

error:
  evoasm_island_model_error(island_model);
  return EVOASM_CB_STOP;
}

bool
evoasm_island_model_call_result_cb(evoasm_island_model_t *island_model, const evoasm_indiv_t *indiv,
                                   evoasm_loss_t loss) {
  bool retval;

  EVOASM_TRY(error, evoasm_mutex_lock, island_model->result_mutex);
  retval = island_model->result_cb(island_model, indiv, loss, island_model->result_user_data);
  EVOASM_TRY(error, evoasm_mutex_unlock, island_model->result_mutex);

  return retval;

error:
  evoasm_island_model_error(island_model);
  return EVOASM_CB_STOP;
}

evoasm_success_t
evoasm_island_model_start(evoasm_island_model_t *island_model,
                          evoasm_island_model_result_cb_t result_cb,
                          void *user_data) {

  evoasm_island_t *island;

  island_model->result_cb = result_cb;
  island_model->result_user_data = user_data;

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

void
evoasm_island_model_add_island(evoasm_island_model_t *island_model,
                               evoasm_island_t *island) {

  island->next = island_model->first_island;
  island_model->first_island = island;
  island_model->n_islands++;
}

evoasm_success_t
evoasm_island_model_init(evoasm_island_model_t *island_model,
                         evoasm_island_model_params_t *params) {
  bool retval = true;

  static evoasm_island_model_t zero_island_model = {0};
  *island_model = zero_island_model;

  if(!evoasm_mutex_init(&island_model->result_mutex_)) goto error;
  island_model->result_mutex = &island_model->result_mutex_;

  if(!evoasm_mutex_init(&island_model->progress_mutex_)) goto error;
  island_model->progress_mutex = &island_model->progress_mutex_;

  if(!evoasm_mutex_init(&island_model->error_mutex_)) goto error;
  island_model->error_mutex = &island_model->error_mutex_;

  goto done;

error:
  retval = false;
  bool r = evoasm_island_model_destroy(island_model);
  (void) r;
done:
  return retval;
}

evoasm_success_t
evoasm_island_model_destroy(evoasm_island_model_t *island_model) {
  bool retval = true;

  if(!evoasm_mutex_destroy(island_model->error_mutex)) retval = false;
  if(!evoasm_mutex_destroy(island_model->progress_mutex)) retval = false;
  if(!evoasm_mutex_destroy(island_model->result_mutex)) retval = false;

  return retval;
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(island_model)
_EVOASM_DEF_ZERO_INIT_FUNC(island_model_params)
_EVOASM_DEF_ALLOC_FREE_FUNCS(island_model_params)
