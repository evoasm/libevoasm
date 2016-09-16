/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-deme-params.h"
#include "evoasm-x64.h"

typedef struct {
  unsigned inst : EVOASM_X64_INST_BITSIZE;
  evoasm_x64_basic_params_t params;
} evoasm_x64_kernel_param_t;

typedef union {
  evoasm_x64_kernel_param_t x64;
} evoasm_kernel_param_t;

typedef struct {
  evoasm_kernel_size_t size;
  /* kernel executed next (jumped to)
   * Kernel terminates if EVOASM_KERNEL_SIZE_MAX
   */
  evoasm_kernel_size_t alt_succ_idx;
  uint8_t jmp_selector;
  evoasm_kernel_param_t params[];
} evoasm_kernel_params_t;

typedef struct {
  evoasm_adf_size_t size;
} evoasm_adf_params_t;

#define EVOASM_KERNEL_MAX_OUTPUT_REGS 254
#define EVOASM_KERNEL_MAX_INPUT_REGS 254

#define EVOASM_KERNEL_REG_INFO_N_TRANS_REGS 2

typedef struct {
  bool input : 1;
  bool written : 1;
  bool output : 1;
  evoasm_x64_reg_id_t trans_regs[EVOASM_KERNEL_REG_INFO_N_TRANS_REGS];
} evoasm_kernel_x64_reg_info_t;

typedef union {
  evoasm_kernel_x64_reg_info_t x64[EVOASM_X64_N_REGS];
} evoasm_kernel_reg_info_t;


typedef struct {
  evoasm_kernel_params_t *params;
  evoasm_kernel_reg_info_t reg_info;

  union {
    evoasm_x64_reg_id_t x64[EVOASM_KERNEL_MAX_OUTPUT_REGS];
  } output_regs;

  uint_fast8_t n_input_regs;
  uint_fast8_t n_output_regs;
  uint8_t idx;
  uint16_t buf_start;
  uint16_t buf_end;
} evoasm_kernel_t;


#define EVOASM_KERNEL_SIZE(max_kernel_size) \
   (sizeof(evoasm_kernel_params_t) + \
    (max_kernel_size) * sizeof(evoasm_kernel_param_t))

#define EVOASM_ADF_SIZE(max_adf_size, max_kernel_size) \
  (sizeof(evoasm_adf_params_t) + \
   (max_adf_size) * EVOASM_KERNEL_SIZE(max_kernel_size))

typedef struct {
  evoasm_arch_info_t *arch_info;
  evoasm_buf_t *buf;
  evoasm_buf_t *body_buf;
  uint32_t index;
  uint8_t in_arity;
  uint8_t out_arity;
  bool reset_rflags : 1;
  bool need_emit    : 1;
  void *_signal_ctx;
  uint32_t exception_mask;
  evoasm_example_type_t types[EVOASM_ADF_OUTPUT_MAX_ARITY];
  evoasm_example_val_t *output_vals;
  evoasm_kernel_t kernels[EVOASM_ADF_MAX_SIZE];
  uint32_t recur_counters[EVOASM_ADF_MAX_SIZE];
  evoasm_adf_params_t *params;

  /* these two are incomplete (values missig)
   * We only need arity and types */
  evoasm_adf_input_t _input;
  evoasm_adf_output_t _output;

  evoasm_deme_params_t *deme_params;
  evoasm_reg_id_t output_regs[EVOASM_ADF_IO_MAX_ARITY];
  evoasm_buf_t _buf;
  evoasm_buf_t _body_buf;

  union {
    /* register at index i has _input i % input_arity */
    uint8_t x64[EVOASM_X64_N_REGS];
  } reg_inputs;

} evoasm_adf_t;

evoasm_success_t
evoasm_adf_clone(evoasm_adf_t *adf, evoasm_adf_t *cloned_adf);


evoasm_adf_output_t *
evoasm_adf_run(evoasm_adf_t *adf,
               evoasm_adf_input_t *input);


evoasm_success_t
evoasm_adf_destroy(evoasm_adf_t *adf);

evoasm_success_t
evoasm_adf_eliminate_introns(evoasm_adf_t *adf);


_EVOASM_DECL_ALLOC_FREE_FUNCS(adf)
