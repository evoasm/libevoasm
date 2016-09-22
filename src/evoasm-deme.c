//
// Created by jap on 9/16/16.
//


#include "evoasm-deme.h"
#include "evoasm-deme-params.h"

EVOASM_DEF_LOG_TAG("deme")

void
evoasm_deme_destroy(evoasm_deme_t *deme) {
  evoasm_free(deme->indivs);
  evoasm_free(deme->losses);
  evoasm_free(deme->error_counters);
  evoasm_free(deme->domains);
}

evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme,
                 evoasm_deme_params_t *params,
                 const evoasm_deme_cls_t *cls,
                 size_t indiv_size,
                 uint32_t n_examples) {

  uint32_t deme_len = params->size;

  static evoasm_deme_t zero_deme = {0};
  *deme = zero_deme;

  deme->params = params;
  deme->indiv_size = indiv_size;
  deme->n_examples = n_examples;
  deme->cls = cls;

  evoasm_prng_init(&deme->prng, &params->seed);

  size_t swap_len = 2;

  deme->indivs = evoasm_calloc(deme_len + swap_len, indiv_size);
  if(!deme->indivs) goto alloc_failed;

  deme->main_indivs = deme->indivs;
  deme->swap_indivs = deme->indivs + (params->size * indiv_size);

  deme->losses = (evoasm_loss_t *) evoasm_calloc(deme_len, sizeof(evoasm_loss_t));
  if(!deme->losses) goto alloc_failed;

  deme->best_loss = INFINITY;
  deme->best_indiv_idx = UINT32_MAX;

  deme->error_counters = evoasm_calloc(n_examples, sizeof(uint64_t));
  if(!deme->error_counters) goto alloc_failed;
  deme->error_counter = 0;

  return true;

alloc_failed:
  evoasm_deme_destroy(deme);
  return false;
}

static evoasm_indiv_t *
evoasm_deme_indiv_(evoasm_deme_t *deme, uint32_t idx, unsigned char *ptr) {
  return (evoasm_indiv_t *) (ptr + idx * deme->indiv_size);
}

evoasm_indiv_t *
evoasm_deme_indiv(evoasm_deme_t *deme, uint32_t idx) {
  return evoasm_deme_indiv_(deme, idx, deme->main_indivs);
}

evoasm_loss_t
evoasm_deme_indiv_loss(evoasm_deme_t *deme, uint32_t idx) {
  return deme->losses[idx];
}

size_t
evoasm_deme_indiv_size(evoasm_deme_t *deme) {
  return deme->indiv_size;
}

void
evoasm_deme_inject(evoasm_deme_t *deme, evoasm_indiv_t *indiv, size_t indiv_size, evoasm_loss_t loss) {
  unsigned i;

  while(true) {
    for(i = 0; i < deme->params->size; i++) {
      uint32_t r = _evoasm_prng_rand32(&deme->prng);
      if(r > UINT32_MAX * ((deme->best_loss + 1.0) / (deme->losses[i] + 1.0))) {
        goto done;
      }
    }
  }
done:;
  assert(indiv_size <= deme->indiv_size);
  memcpy(evoasm_deme_indiv(deme, i), indiv, indiv_size);
  deme->losses[i] = loss;
}

evoasm_success_t
evoasm_deme_seed(evoasm_deme_t *deme) {
  unsigned i;

  for(i = 0; i < deme->params->size; i++) {
    if(!deme->cls->seed_indiv_func(deme, evoasm_deme_indiv(deme, i))) {
      return false;
    }
  }

  deme->seeded = true;
  return true;
}


evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme, evoasm_loss_t max_loss, evoasm_deme_result_cb_t result_cb,
                 void *user_data) {
  unsigned i;
  bool retval;
  uint32_t n_examples = deme->n_examples;

  if(!deme->seeded) {
    retval = false;
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES,
                 NULL, "not seeded");
    goto done;
  }

  if(!deme->cls->eval_setup_func(deme)) {
    retval = false;
    goto done;
  }

  for(i = 0; i < deme->params->size; i++) {
    evoasm_loss_t loss;

    evoasm_indiv_t *indiv = evoasm_deme_indiv(deme, i);

    if(!deme->cls->eval_indiv_func(deme, indiv, &loss)) {
      retval = false;
      goto done;
    }

    deme->losses[i] = loss;

    evoasm_log_debug("individual %d has loss %lf", i, loss);

    if(loss <= deme->best_loss) {
      deme->best_loss = loss;
      deme->best_indiv_idx = i;
      evoasm_log_debug("program %d has best loss %lf", i, loss);
    }

    if(EVOASM_UNLIKELY(loss / n_examples <= max_loss)) {
      evoasm_log_info("individual %d has best norm. loss %lf", i, loss);

      if(result_cb(deme, indiv, loss, user_data) == EVOASM_CB_STOP) {
        retval = true;
        goto done;
      }

      /*
      deme->extract_indiv_func(indiv, best_indiv)
      evoasm_program_clone(&program, found_program);
      found_program->_output = *deme->params->program_output;
      found_program->_input = *deme->params->program_input;
      *best_loss = loss;
       */

      retval = true;
      goto done;
    }
  }

  retval = true;
done:
  if(!deme->cls->eval_teardown_func(deme)) {
    retval = false;
  }
  return retval;
}

void evoasm_deme_immigrate(evoasm_deme_t *deme, evoasm_indiv_t *indiv) {
}

void
evoasm_deme_emigrate(evoasm_deme_t *deme, evoasm_deme_t *dest_deme) {

}

void
evoasm_deme_select(evoasm_deme_t *deme, uint32_t *idxs, unsigned n_idxs) {
  uint32_t n = 0;
  unsigned i;

  while(true) {
    for(i = 0; i < deme->params->size; i++) {
      uint32_t r = _evoasm_prng_rand32(&deme->prng);
      if(n >= n_idxs) goto done;
      if(r < UINT32_MAX * ((deme->best_loss + 1.0) / (deme->losses[i] + 1.0))) {
        idxs[n++] = i;
      }
    }
  }
done:;
}

static evoasm_success_t
evoasm_deme_combine_parents(evoasm_deme_t *deme, uint32_t *parents) {
  unsigned i;

  for(i = 0; i < deme->params->size; i += 2) {
    evoasm_indiv_t *parent_a_ = evoasm_deme_indiv(deme, parents[i]);
    evoasm_indiv_t *parent_a =  evoasm_deme_indiv_(deme, 0, deme->swap_indivs);
    evoasm_indiv_t *parent_b_ = evoasm_deme_indiv(deme, parents[i + 1]);
    evoasm_indiv_t *parent_b = evoasm_deme_indiv_(deme, 1, deme->swap_indivs);

    // save parents into swap space
    memcpy(parent_a, parent_a_, deme->indiv_size);
    memcpy(parent_b, parent_b_, deme->indiv_size);

    evoasm_indiv_t *child_a = parent_a_;
    evoasm_indiv_t *child_b = parent_b_;

    if(!deme->cls->crossover_func(deme, parent_a, parent_b, child_a, child_b)) {
      return false;
    }
  }

  return true;
}

evoasm_loss_t
evoasm_deme_loss(evoasm_deme_t *deme, unsigned *n_inf, bool normed) {
  unsigned i;
  double scale = 1.0 / deme->params->size;
  double deme_loss = 0.0;
  *n_inf = 0;
  for(i = 0; i < deme->params->size; i++) {
    double loss = deme->losses[i];
    if(loss != INFINITY) {
      deme_loss += scale * loss;
    } else {
      (*n_inf)++;
    }
  }

  if(normed) deme_loss /= deme->params->size;

  return deme_loss;
}

evoasm_success_t
evoasm_deme_new_gen(evoasm_deme_t *deme) {
  uint32_t *parents = alloca(deme->params->size * sizeof(uint32_t));
  evoasm_deme_select(deme, parents, deme->params->size);

#if 0
  {
    double scale = 1.0 / deme->params->kernel_count;
    double deme_loss = 0.0;
    unsigned n_inf = 0;
    for(i = 0; i < deme->params->kernel_count; i++) {
      double loss = deme->deme.losses[parents[i]];
      if(loss != INFINITY) {
        deme_loss += scale * loss;
      }
      else {
        n_inf++;
      }
    }

    evoasm_log_info("deme selected loss: %g/%u", deme_loss, n_inf);
  }

  unsigned i;
  for(i = 0; i < deme->params->kernel_count; i++) {
    evoasm_program_params_t *program_params = _EVOASM_SEARCH_PROGRAM_PARAMS(deme, deme->deme.indivs, parents[i]);
    assert(program_params->kernel_count > 0);
  }
#endif

  return evoasm_deme_combine_parents(deme, parents);
}

