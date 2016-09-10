//
// Created by jap on 9/9/16.
//

#include "evoasm-search-params.h"
#include "evoasm-alloc.h"

static const char * const _evoasm_example_type_names[] = {
 "i64",
 "u64",
 "f64"
};

evoasm_adf_io_t *
evoasm_adf_io_alloc(uint16_t len) {
  evoasm_adf_io_t *adf_io = evoasm_malloc(sizeof(evoasm_adf_io_t) + len * sizeof(evoasm_example_val_t));
  adf_io->len = len;

  return adf_io;
}

evoasm_success_t
evoasm_adf_io_init(evoasm_adf_io_t *adf_io, uint8_t arity, ...) {
  va_list args;
  unsigned i;
  adf_io->arity = arity;

  va_start(args, arity);
  for(i = 0; i < adf_io->len; i++) {
    unsigned type_idx = i % arity;
    evoasm_example_type_t type = va_arg(args, evoasm_example_type_t);
    evoasm_example_val_t val;
    switch(type) {
      case EVOASM_EXAMPLE_TYPE_F64:
        val.f64 = va_arg(args, double);
        break;
      case EVOASM_EXAMPLE_TYPE_I64:
        val.i64 = va_arg(args, int64_t);
        break;
      case EVOASM_EXAMPLE_TYPE_U64:
        val.u64 = va_arg(args, uint64_t);
        break;
      default:
        evoasm_assert_not_reached();
    }

    adf_io->vals[i] = val;

    if(i >= arity) {
      evoasm_example_type_t prev_type = adf_io->types[type_idx];

      if(prev_type != type) {
        evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                         NULL, "Example value type mismatch (previously %s, now %s)",
                         _evoasm_example_type_names[prev_type], _evoasm_example_type_names[type]);
        evoasm_free(adf_io);
        return false;
      }
    }
    adf_io->types[type_idx] = type;
  }

  return true;
}

double
evoasm_adf_io_value_f64(evoasm_adf_io_t *adf_io, unsigned idx) {
  return adf_io->vals[idx].f64;
}

int64_t
evoasm_adf_io_value_i64(evoasm_adf_io_t *adf_io, unsigned idx) {
  return adf_io->vals[idx].i64;
}

void
evoasm_adf_io_destroy(evoasm_adf_io_t *adf_io) {

}

evoasm_example_type_t
evoasm_adf_io_type(evoasm_adf_io_t *adf_io, unsigned idx) {
  return adf_io->types[idx % adf_io->arity];
}

_EVOASM_DEF_FREE_FUNC(adf_io)

_EVOASM_DEF_FIELD_READER(adf_io, arity, uint8_t)
_EVOASM_DEF_FIELD_READER(adf_io, len, uint16_t)

_EVOASM_DEF_ALLOC_FREE_FUNCS(search_params)
_EVOASM_DEF_ZERO_INIT_FUNC(search_params)

#define _EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(field, type) _EVOASM_DEF_FIELD_ACCESSOR(search_params, field, type)

_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(min_adf_size, evoasm_adf_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(max_adf_size, evoasm_adf_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(min_kernel_size, evoasm_kernel_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(max_kernel_size, evoasm_kernel_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(recur_limit, uint32_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(pop_size, uint32_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(mut_rate, uint32_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(max_loss, evoasm_loss_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(n_insts, uint16_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(n_params, uint8_t)

evoasm_prng_seed_t *
evoasm_search_params_seed(evoasm_search_params_t *search_params) {
  return &search_params->seed;
}


evoasm_param_id_t
evoasm_search_params_param(evoasm_search_params_t *search_params, unsigned index) {
  return search_params->param_ids[index];
}

static evoasm_domain_t **
evoasm_search_params_find_domain(evoasm_search_params_t *search_params, evoasm_param_id_t param_id) {
  unsigned i;
  for(i = 0; i < search_params->n_params; i++) {
    if(search_params->param_ids[i] == param_id) {
      return &search_params->domains[i];
    }
  }
  return NULL;
}

bool
evoasm_search_params_set_domain(evoasm_search_params_t *search_params, evoasm_param_id_t param_id, evoasm_domain_t *domain) {
  evoasm_domain_t **domain_ptr = evoasm_search_params_find_domain(search_params, param_id);
  if(domain_ptr) {
    *domain_ptr = domain;
    return true;
  }
  else {
    return false;
  }
}

evoasm_domain_t *
evoasm_search_params_domain(evoasm_search_params_t *search_params, evoasm_param_id_t param_id) {
  evoasm_domain_t **domain_ptr = evoasm_search_params_find_domain(search_params, param_id);
  if(domain_ptr) {
    return *domain_ptr;
  } else {
    return NULL;
  }
}



void
evoasm_search_params_set_param(evoasm_search_params_t *search_params, unsigned index, evoasm_param_id_t param) {
  search_params->param_ids[index] = param;
}

uint8_t
evoasm_search_n_params(evoasm_search_params_t *search_params) {
  return search_params->n_params;
}

void
evoasm_search_params_set_inst(evoasm_search_params_t *search_params, unsigned index, evoasm_inst_id_t inst_id) {
  search_params->inst_ids[index] = inst_id;
}

evoasm_inst_id_t
evoasm_search_params_inst(evoasm_search_params_t *search_params, unsigned index) {
  return search_params->inst_ids[index];
}

void
evoasm_search_params_destroy(evoasm_search_params_t *search_params) {
}

void
evoasm_search_params_set_adf_input(evoasm_search_params_t *search_params, evoasm_adf_io_t *adf_io) {
  search_params->adf_input = adf_io;
}

void
evoasm_search_params_set_adf_output(evoasm_search_params_t *search_params, evoasm_adf_io_t *adf_io) {
  search_params->adf_output = adf_io;
}

_EVOASM_DEF_FIELD_READER(search_params, adf_input, evoasm_adf_io_t *)
_EVOASM_DEF_FIELD_READER(search_params, adf_output, evoasm_adf_io_t *)

bool
evoasm_search_params_valid(evoasm_search_params_t *search_params) {

  if(search_params->max_adf_size > EVOASM_ADF_MAX_SIZE) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "Program size cannot exceed %d", EVOASM_ADF_MAX_SIZE);
    goto fail;
  }

  if(search_params->n_params == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "No parameters given");
    goto fail;
  }

  if(search_params->n_insts == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "No instructions given");
    goto fail;
  }

  if(search_params->adf_input->len == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "No _input values given");
    goto fail;
  }

  if(search_params->adf_output->len == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "No output values given");
    goto fail;
  }

  if(search_params->pop_size == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "Population size cannot be zero");
    goto fail;
  }

  if(search_params->min_adf_size == 0 || search_params->min_adf_size > search_params->max_adf_size) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "Invalid ADF size");
    goto fail;
  }

  if(search_params->min_kernel_size == 0 || search_params->min_kernel_size > search_params->max_kernel_size) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                     NULL, "Invalid kernel size");
    goto fail;
  }

  return true;

fail:
  return false;
}
