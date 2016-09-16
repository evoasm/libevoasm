/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */


#include "evoasm-search.h"
#include "evoasm-deme.h"
#include "evoasm-deme-params.h"

#define EVOASM_SEARCH_CONVERGENCE_THRESHOLD 0.03

static evoasm_success_t
evoasm_search_start_(evoasm_search_t *search,
                     unsigned deme_idx,
                     unsigned cycle,
                     evoasm_search_progress_func_t progress_func,
                     evoasm_search_goal_func_t goal_func,
                     void *user_data) {
  unsigned gen;
  unsigned ups = 0;

  evoasm_adf_t *adf = evoasm_adf_alloc();
  evoasm_loss_t last_deme_loss = 0.0;

  for(gen = 0;; gen++) {
    if(!evoasm_deme_eval(search->demes[0], adf, user_data)) {
      return false;
    }

    if(gen % 256 == 0) {
      unsigned n_inf;
      evoasm_loss_t deme_loss = evoasm_deme_loss(search, &n_inf);
      evoasm_info("norm. deme deme_loss: %g/%u\n\n", deme_loss / search->params->pop_size, n_inf);

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
        return false;
      }
    }

    evoasm_deme_new_generation(search, adfs);
  }
}

#if 0
static void
evoasm_search_merge(evoasm_search_t *search) {
  unsigned i;

  evoasm_info("merging\n");

  for(i = 0; i < search->params->size; i++) {
    evoasm_adf_params_t *parent_a = _EVOASM_SEARCH_ADF_PARAMS(search, search->deme.adfs_main, i);
    evoasm_adf_params_t *parent_b = _EVOASM_SEARCH_ADF_PARAMS(search, search->deme.adfs_aux, i);

    evoasm_adf_params_t *child = _EVOASM_SEARCH_ADF_PARAMS(search, search->deme.adfs_swap, i);
    evoasm_search_crossover(search, parent_a, parent_b, child, NULL);
  }
  evoasm_deme_swap(&search->deme, &search->deme.adfs_main);
}
#endif

int
deme_thrd_func(void *arg) {

  return 0;
}

evoasm_success_t
evoasm_search_start(evoasm_search_t *search,
                    evoasm_search_progress_func_t progress_func,
                    evoasm_search_goal_func_t goal_func,
                    void *user_data) {

  unsigned cycle;
  unsigned i;
  bool retval = true;

  for(i = 0; i < search->n_demes; i++) {
    if(thrd_create(&search->thrds[i], deme_thrd_func, NULL) != thrd_success) {
      evoasm_set_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES, NULL,
                       "failed to create thread");
      retval = false;
      goto done;
    }
    evoasm_deme_seed(search->demes[i]);
  }

  for(cycle = 0;; cycle++) {
    if(!evoasm_search_start_(search, 0, cycle, progress_func, goal_func, user_data)) {
      retval = false;
      goto done;
    } else {

    }
#if 0
      evoasm_search_seed(search, search->deme.adfs_aux);
      evoasm_info("starting aux search");
      if(!evoasm_search_start_(search, 1, cycle, &search->deme.adfs_aux, progress_func, goal_func, user_data)) {
        evoasm_search_merge(search);
      } else {
        goto done;
      }
    } else {
      goto done;
    }
#endif
  }

done:;
  return retval;
}

evoasm_success_t
evoasm_search_init(evoasm_search_t *search,
                   evoasm_search_params_t *params,
                   uint16_t n_demes,
                   ...) {
  va_list args;
  unsigned i;

  va_start(args, n_demes);

  search->n_demes = n_demes;

  search->demes = evoasm_calloc(n_demes, sizeof(evoasm_deme_t *));
  if(!search->demes) goto alloc_failed;

  search->mtxs = evoasm_calloc(n_demes, sizeof(mtx_t));
  if(!search->mtxs) goto alloc_failed;

  search->thrds = evoasm_calloc(n_demes, sizeof(thrd_t));
  if(!search->thrds) goto alloc_failed;

  for(i = 0; i < n_demes; i++) {
    mtx_init(&search->mtxs[i], mtx_plain);
  }

  search->migration_adfs = evoasm_calloc(n_demes, sizeof(unsigned char *));
  if(!search->migration_adfs) goto alloc_failed;

  for(i = 0; i < n_demes; i++) {
    evoasm_deme_t *deme = va_arg(args, evoasm_deme_t *);
    search->demes[i] = deme;

    search->migration_adfs[i] = evoasm_calloc(0.1 * deme->params->size,
                                              EVOASM_ADF_SIZE(deme->params->max_adf_size, deme->params->max_kernel_size));
    if(!search->migration_adfs[i]) goto alloc_failed;
  }


  va_end(args);
  return true;

alloc_failed:
  va_end(args);
  evoasm_search_destroy(search);
  return false;
}

void
evoasm_search_destroy(evoasm_search_t *search) {
  unsigned i;

  evoasm_free(search->demes);
  evoasm_free(search->mtxs);
  evoasm_free(search->thrds);

  for(i = 0; i < search->n_demes; i++) {
    evoasm_free(search->migration_adfs[i]);
  }
  evoasm_free(search->migration_adfs);
}



_EVOASM_DEF_ALLOC_FREE_FUNCS(search)
