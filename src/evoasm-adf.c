/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-adf.h"

static bool
evoasm_adf_destroy_(evoasm_adf_t *adf, bool free_buf, bool free_body_buf,
                    bool free_params, unsigned free_n_kernels) {

  unsigned i;
  bool retval = true;

  for(i = 0; i < adf->params->size; i++) {
    if(i < free_n_kernels) {
      evoasm_free(adf->kernels[i].params);
    }
  }

  if(free_params) {
    evoasm_free(adf->params);
  }

  if(free_buf) {
    if(!evoasm_buf_destroy(adf->buf)) {
      retval = false;
    }
  }

  if(free_body_buf) {
    if(!evoasm_buf_destroy(adf->body_buf)) {
      retval = false;
    }
  }
  return retval;
}

evoasm_success_t
evoasm_adf_clone(evoasm_adf_t *adf, evoasm_adf_t *cloned_adf) {
  unsigned i = 0;
  bool free_buf = false, free_body_buf = false, free_params = false;

  *cloned_adf = *adf;
  cloned_adf->index = 0;
  cloned_adf->_signal_ctx = NULL;
  cloned_adf->reset_rflags = false;
  cloned_adf->_input.len = 0;
  cloned_adf->_output.len = 0;
  cloned_adf->output_vals = NULL;

  /* memory addresses in original buffer point to memory in original adf,
   * we need to reemit assembly, this is done in a lazy fashion */
  cloned_adf->need_emit = true;

  EVOASM_TRY(error, evoasm_buf_clone, adf->buf, &cloned_adf->_buf);
  EVOASM_TRY(error_free_buf, evoasm_buf_clone, adf->body_buf, &cloned_adf->_body_buf);

  cloned_adf->buf = &cloned_adf->_buf;
  cloned_adf->body_buf = &cloned_adf->_body_buf;

  size_t adf_params_size = sizeof(evoasm_adf_params_t);
  cloned_adf->params = evoasm_malloc(adf_params_size);

  if(!cloned_adf->params) {
    goto error_free_body_buf;
  }

  memcpy(cloned_adf->params, adf->params, adf_params_size);

  for(; i < adf->params->size; i++) {
    evoasm_kernel_t *orig_kernel = &adf->kernels[i];
    evoasm_kernel_t *cloned_kernel = &cloned_adf->kernels[i];
    *cloned_kernel = *orig_kernel;

    size_t params_size = sizeof(evoasm_kernel_params_t) + orig_kernel->params->size * sizeof(evoasm_kernel_param_t);
    cloned_kernel->params = evoasm_malloc(params_size);
    if(!cloned_kernel->params) {
      goto error_free_params;
    }
    memcpy(cloned_kernel->params, orig_kernel->params, params_size);
  }

  return true;

error_free_params:
  free_params = true;
error_free_body_buf:
  free_body_buf = true;
error_free_buf:
  free_buf = true;
error:
  (void) evoasm_adf_destroy_(cloned_adf, free_buf, free_body_buf, free_params, i);
  return false;
}

evoasm_success_t
evoasm_adf_destroy(evoasm_adf_t *adf) {
  return evoasm_adf_destroy_(adf, true, true, true, UINT_MAX);
}

evoasm_buf_t *
evoasm_adf_buf(evoasm_adf_t *adf, bool body) {
  if(body) {
    return adf->body_buf;
  } else {
    return adf->buf;
  }
}

evoasm_adf_size_t
evoasm_adf_size(evoasm_adf_t *adf) {
  return adf->params->size;
}

size_t
evoasm_adf_kernel_code(evoasm_adf_t *adf, unsigned kernel_idx, const uint8_t **code) {
  evoasm_kernel_t *kernel = &adf->kernels[kernel_idx];
  size_t len = (size_t) kernel->buf_end - kernel->buf_start;
  *code = adf->body_buf->data + kernel->buf_start;
  return len;
}

size_t
evoasm_adf_code(evoasm_adf_t *adf, bool frame, const uint8_t **code) {
  evoasm_buf_t *buf;
  if(frame) {
    buf = adf->buf;
  } else {
    buf = adf->body_buf;
  }
  *code = buf->data;
  return buf->pos;
}


unsigned
evoasm_adf_kernel_alt_succ(evoasm_adf_t *adf, unsigned kernel_idx) {
  evoasm_kernel_t *kernel = &adf->kernels[kernel_idx];
  return kernel->params->alt_succ_idx;
}


bool
evoasm_adf_is_input_reg(evoasm_adf_t *adf, unsigned kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &adf->kernels[kernel_idx];
  switch(adf->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->reg_info.x64[reg_id].input;
    default:
      evoasm_assert_not_reached();
  }
}

bool
evoasm_adf_is_output_reg(evoasm_adf_t *adf, unsigned kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &adf->kernels[kernel_idx];
  switch(adf->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->reg_info.x64[reg_id].output;
    default:
      evoasm_assert_not_reached();
  }
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(adf)
