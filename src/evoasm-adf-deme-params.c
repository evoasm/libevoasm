//
// Created by jap on 9/9/16.
//

#include "evoasm-adf-deme-params.h"
#include "evoasm-alloc.h"

_EVOASM_DEF_ALLOC_FREE_FUNCS(adf_deme_params)
_EVOASM_DEF_ZERO_INIT_FUNC(adf_deme_params)

#define _EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(field, type) _EVOASM_DEF_FIELD_ACCESSOR(adf_deme_params, field, type)

_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(min_adf_size, evoasm_adf_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(max_adf_size, evoasm_adf_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(min_kernel_size, evoasm_kernel_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(max_kernel_size, evoasm_kernel_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(recur_limit, uint32_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(n_insts, uint16_t)

void
evoasm_adf_deme_params_set_inst(evoasm_adf_deme_params_t *adf_deme_params, unsigned index, evoasm_inst_id_t inst_id) {
  adf_deme_params->inst_ids[index] = inst_id;
}

evoasm_inst_id_t
evoasm_adf_deme_params_inst(evoasm_adf_deme_params_t *adf_deme_params, unsigned index) {
  return adf_deme_params->inst_ids[index];
}

void
evoasm_adf_deme_params_destroy(evoasm_adf_deme_params_t *adf_deme_params) {
}

void
evoasm_adf_deme_params_set_adf_input(evoasm_adf_deme_params_t *adf_deme_params, evoasm_adf_io_t *adf_io) {
  adf_deme_params->adf_input = adf_io;
}

void
evoasm_adf_deme_params_set_adf_output(evoasm_adf_deme_params_t *adf_deme_params, evoasm_adf_io_t *adf_io) {
  adf_deme_params->adf_output = adf_io;
}

_EVOASM_DEF_FIELD_READER(adf_deme_params, adf_input, evoasm_adf_io_t *)
_EVOASM_DEF_FIELD_READER(adf_deme_params, adf_output, evoasm_adf_io_t *)

bool
evoasm_adf_deme_params_valid(evoasm_adf_deme_params_t *adf_deme_params) {

  if(!evoasm_deme_params_valid(&adf_deme_params->deme_params)) {
    goto fail;
  }

  if(adf_deme_params->max_adf_size > EVOASM_ADF_MAX_SIZE) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "Program size cannot exceed %d", EVOASM_ADF_MAX_SIZE);
    goto fail;
  }

  if(adf_deme_params->n_insts == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "No instructions given");
    goto fail;
  }

  if(adf_deme_params->adf_input == NULL || adf_deme_params->adf_input->len == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "No input values given");
    goto fail;
  }

  if(adf_deme_params->adf_output == NULL || adf_deme_params->adf_output->len == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "No output values given");
    goto fail;
  }

  if(adf_deme_params->min_adf_size == 0 || adf_deme_params->min_adf_size > adf_deme_params->max_adf_size) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "Invalid ADF size");
    goto fail;
  }

  if(adf_deme_params->min_kernel_size == 0 || adf_deme_params->min_kernel_size > adf_deme_params->max_kernel_size) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "Invalid kernel size");
    goto fail;
  }

  return true;

fail:
  return false;
}
