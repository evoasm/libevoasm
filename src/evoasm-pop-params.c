//
// Created by jap on 9/9/16.
//

#include "evoasm-pop-params.h"
#include "evoasm-util.h"

_EVOASM_DEF_ALLOC_FREE_FUNCS(pop_params)

#define _EVOASM_POP_PARAMS_DEF_GETTER_SETTER(field, type) _EVOASM_DEF_GETTER_SETTER(pop_params, field, type)

_EVOASM_POP_PARAMS_DEF_GETTER_SETTER(size, uint32_t)
_EVOASM_POP_PARAMS_DEF_GETTER_SETTER(n_params, uint8_t)

double
evoasm_pop_params_get_mut_rate(evoasm_pop_params_t *pop_params) {
  return EVOASM_CLAMP(pop_params->mut_rate / (double) UINT32_MAX, 0.0, 1.0);
}

void
evoasm_pop_params_set_mut_rate(evoasm_pop_params_t *pop_params, double mut_rate) {
  pop_params->mut_rate = (uint32_t)(EVOASM_CLAMP(mut_rate, 0.0, 1.0) * UINT32_MAX);
}

static evoasm_domain_t **
evoasm_pop_params_find_domain(evoasm_pop_params_t *pop_params, evoasm_param_id_t param_id) {
  unsigned i;
  for(i = 0; i < pop_params->n_params; i++) {
    if(pop_params->param_ids[i] == param_id) {
      return &pop_params->domains[i];
    }
  }
  return NULL;
}

bool
evoasm_pop_params_set_domain(evoasm_pop_params_t *pop_params, evoasm_param_id_t param_id, evoasm_domain_t *domain) {
  evoasm_domain_t **domain_ptr = evoasm_pop_params_find_domain(pop_params, param_id);
  if(domain_ptr) {
    *domain_ptr = domain;
    return true;
  }
  else {
    return false;
  }
}

evoasm_domain_t *
evoasm_pop_params_get_domain(evoasm_pop_params_t *pop_params, evoasm_param_id_t param_id) {
  evoasm_domain_t **domain_ptr = evoasm_pop_params_find_domain(pop_params, param_id);
  if(domain_ptr) {
    return *domain_ptr;
  } else {
    return NULL;
  }
}

evoasm_param_id_t
evoasm_pop_params_get_param(evoasm_pop_params_t *pop_params, unsigned index) {
  return pop_params->param_ids[index];
}

void
evoasm_pop_params_set_param(evoasm_pop_params_t *pop_params, unsigned index, evoasm_param_id_t param) {
  pop_params->param_ids[index] = param;
}

uint8_t
evoasm_search_get_n_params(evoasm_pop_params_t *pop_params) {
  return pop_params->n_params;
}

uint64_t
evoasm_pop_params_get_seed(evoasm_pop_params_t *pop_params, unsigned index) {
  return pop_params->seed.data[index];
}

void
evoasm_pop_params_set_seed(evoasm_pop_params_t *pop_params, unsigned index, uint64_t seed) {
  pop_params->seed.data[index] = seed;
}

void
evoasm_pop_params_destroy(evoasm_pop_params_t *pop_params) {
}


bool
evoasm_pop_params_valid(evoasm_pop_params_t *pop_params) {
  if(pop_params->n_params == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "No parameters given");
    goto fail;
  }

  if(pop_params->size == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "Population size cannot be zero");
    goto fail;
  }

  return true;

fail:
  return false;
}
