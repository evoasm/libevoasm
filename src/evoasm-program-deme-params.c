//
// Created by jap on 9/9/16.
//

#include "evoasm-program-deme-params.h"
#include "evoasm-alloc.h"

_EVOASM_DEF_ALLOC_FREE_FUNCS(program_deme_params)
_EVOASM_DEF_ZERO_INIT_FUNC(program_deme_params)

#define _EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(field, type) _EVOASM_DEF_FIELD_ACCESSOR(program_deme_params, field, type)

_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(min_program_size, evoasm_program_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(max_program_size, evoasm_program_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(min_kernel_size, evoasm_kernel_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(max_kernel_size, evoasm_kernel_size_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(recur_limit, uint32_t)
_EVOASM_DEME_PARAMS_DEF_FIELD_ACCESSOR(n_insts, uint16_t)

void
evoasm_program_deme_params_set_inst(evoasm_program_deme_params_t *program_deme_params, unsigned index, evoasm_inst_id_t inst_id) {
  program_deme_params->inst_ids[index] = inst_id;
}

evoasm_inst_id_t
evoasm_program_deme_params_inst(evoasm_program_deme_params_t *program_deme_params, unsigned index) {
  return program_deme_params->inst_ids[index];
}

void
evoasm_program_deme_params_destroy(evoasm_program_deme_params_t *program_deme_params) {
}

void
evoasm_program_deme_params_set_program_input(evoasm_program_deme_params_t *program_deme_params, evoasm_program_io_t *program_io) {
  program_deme_params->program_input = program_io;
}

void
evoasm_program_deme_params_set_program_output(evoasm_program_deme_params_t *program_deme_params, evoasm_program_io_t *program_io) {
  program_deme_params->program_output = program_io;
}

_EVOASM_DEF_FIELD_READER(program_deme_params, program_input, evoasm_program_io_t *)
_EVOASM_DEF_FIELD_READER(program_deme_params, program_output, evoasm_program_io_t *)

bool
evoasm_program_deme_params_valid(evoasm_program_deme_params_t *program_deme_params) {

  if(!evoasm_deme_params_valid(&program_deme_params->deme_params)) {
    goto fail;
  }

  if(program_deme_params->max_program_size > EVOASM_PROGRAM_MAX_SIZE) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "Program size cannot exceed %d", EVOASM_PROGRAM_MAX_SIZE);
    goto fail;
  }

  if(program_deme_params->n_insts == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "No instructions given");
    goto fail;
  }

  if(program_deme_params->program_input == NULL || program_deme_params->program_input->len == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "No input values given");
    goto fail;
  }

  if(program_deme_params->program_output == NULL || program_deme_params->program_output->len == 0) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "No output values given");
    goto fail;
  }

  if(program_deme_params->min_program_size == 0 || program_deme_params->min_program_size > program_deme_params->max_program_size) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "Invalid PROGRAM size");
    goto fail;
  }

  if(program_deme_params->min_kernel_size == 0 || program_deme_params->min_kernel_size > program_deme_params->max_kernel_size) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                     NULL, "Invalid kernel size");
    goto fail;
  }

  return true;

fail:
  return false;
}
