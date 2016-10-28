//
// Created by jap on 9/9/16.
//

#include "evoasm-pop-params.h"
#include "evoasm-util.h"

EVOASM_DEF_ALLOC_FREE_FUNCS(pop_params)

#define EVOASM_POP_PARAMS_DEF_GETTER_SETTER(field, value_type, field_type) \
  EVOASM_DEF_GETTER(pop_params, field, value_type) \
  EVOASM_DEF_SETTER(pop_params, field, value_type, field_type)

EVOASM_POP_PARAMS_DEF_GETTER_SETTER(n_programs_per_deme, size_t, uint16_t)
EVOASM_POP_PARAMS_DEF_GETTER_SETTER(n_kernels_per_deme, size_t, uint16_t)
EVOASM_POP_PARAMS_DEF_GETTER_SETTER(n_params, size_t, uint8_t)
EVOASM_POP_PARAMS_DEF_GETTER_SETTER(n_demes, size_t, uint16_t)

static evoasm_domain_t **
evoasm_pop_params_find_domain(evoasm_pop_params_t *pop_params, evoasm_param_id_t param_id) {
  for(size_t i = 0; i < pop_params->n_params; i++) {
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
  } else {
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
evoasm_pop_params_get_param(evoasm_pop_params_t *pop_params, size_t idx) {
  return pop_params->param_ids[idx];
}

void
evoasm_pop_params_set_param(evoasm_pop_params_t *pop_params, size_t idx, evoasm_param_id_t param) {
  pop_params->param_ids[idx] = param;
}

uint8_t
evoasm_search_get_n_params(evoasm_pop_params_t *pop_params) {
  return pop_params->n_params;
}

uint64_t
evoasm_pop_params_get_seed(evoasm_pop_params_t *pop_params, size_t idx) {
  return pop_params->seed.data[idx];
}

void
evoasm_pop_params_set_seed(evoasm_pop_params_t *pop_params, size_t idx, uint64_t seed) {
  pop_params->seed.data[idx] = seed;
}

void
evoasm_pop_params_destroy(evoasm_pop_params_t *pop_params) {
}


bool
evoasm_pop_params_validate(evoasm_pop_params_t *pop_params) {
  if(pop_params->n_params == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "No parameters given");
    goto fail;
  }

  if(pop_params->n_kernels_per_deme == 0 || pop_params->n_programs_per_deme) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "Deme size cannot be zero");
    goto fail;
  }

  if(pop_params->max_kernel_size > EVOASM_KERNEL_MAX_SIZE) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "Program size cannot exceed %d", EVOASM_PROGRAM_MAX_SIZE);
    goto fail;
  }

  if(pop_params->max_program_size > EVOASM_PROGRAM_MAX_SIZE) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "Program size cannot exceed %d", EVOASM_PROGRAM_MAX_SIZE);
    goto fail;
  }

  if(pop_params->n_insts == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "No instructions given");
    goto fail;
  }

  if(pop_params->program_input == NULL || pop_params->program_input->len == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "No input values given");
    goto fail;
  }

  if(pop_params->program_output == NULL || pop_params->program_output->len == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "No output values given");
    goto fail;
  }

  if(pop_params->min_kernel_size == 0 || pop_params->min_kernel_size > pop_params->max_kernel_size) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "Invalid kernel size");
    goto fail;
  }

  if(pop_params->min_program_size == 0 || pop_params->min_program_size > pop_params->max_program_size) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "Invalid program size");
    goto fail;
  }

  if(pop_params->n_demes == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                 NULL, "Invalid number of demes");
    goto fail;
  }

  return true;

fail:
  return false;
}
