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
evoam_adf_io_alloc(uint16_t len, uint8_t arity, ...) {
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

_EVOASM_DEF_FREE_FUNC(adf_io)
_EVOASM_DEF_UNREF_REF_FUNCS(adf_io)

_EVOASM_DEF_FIELD_READER(adf_io, arity, uint8_t)
_EVOASM_DEF_FIELD_READER(adf_io, len, uint16_t)


evoasm_search_insts_t *
evoam_search_insts_alloc(uint16_t len) {
  evoasm_search_insts_t *search_insts = evoasm_malloc(sizeof(evoasm_search_insts_t) + len * sizeof(uint16_t));
  search_insts->len = len;

  return search_insts;
}

static void
evoasm_search_insts_destroy() {
}

_EVOASM_DEF_ZERO_INIT_FUNC(search_insts)
_EVOASM_DEF_FREE_FUNC(search_insts)
_EVOASM_DEF_UNREF_REF_FUNCS(search_insts)

void
evoasm_search_insts_set(evoasm_search_insts_t *search_insts, unsigned index, evoasm_param_id_t param_id) {
  search_insts->ids[index] = param_id;
}

unsigned
evoasm_search_insts_get(evoasm_search_insts_t *search_insts, unsigned index) {
  return search_insts->ids[index];
}


#define _EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(field, type) _EVOASM_DEF_FIELD_ACCESSOR(search_params, field, type)

_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(min_adf_size, evoasm_adf_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(max_adf_size, evoasm_adf_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(min_kernel_size, evoasm_kernel_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(max_kernel_size, evoasm_kernel_size_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(recur_limit, uint32_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(pop_size, uint32_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(mut_rate, uint32_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(adf_input, evoasm_adf_io_t *)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(adf_output, evoasm_adf_io_t *)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(max_loss, evoasm_loss_t)
_EVOASM_SEARCH_PARAMS_DEF_FIELD_ACCESSOR(insts, evoasm_search_insts_t *)

evoasm_prng_seed_t *
evoasm_search_params_seed(evoasm_search_params_t *search_params) {
  return &search_params->seed;
}

evoasm_domain_t *
evoasm_search_params_domain(evoasm_search_params_t *search_params, unsigned index) {
  return search_params->domains[index];
}

void
evoasm_search_params_set_domain(evoasm_search_params_t *search_params, unsigned index, evoasm_domain_t *domain) {
  search_params->domains[index] = domain;
}

evoasm_param_id_t
evoasm_search_params_param(evoasm_search_params_t *search_params, unsigned index) {
  return search_params->param_ids[index];
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
evoasm_search_set_n_params(evoasm_search_params_t *search_params, uint8_t n_params) {
  search_params->n_params = n_params;
}

void
evoasm_search_params_destroy(evoasm_search_params_t *search_params) {
  evoasm_search_insts_unref(search_params->insts);
  evoasm_adf_io_unref(search_params->adf_input);
  evoasm_adf_io_unref(search_params->adf_output);
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(search_params)
_EVOASM_DEF_UNREF_REF_FUNCS(search_params)

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

  if(search_params->insts->len == 0) {
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
