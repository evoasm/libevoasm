/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-pop-params.h"
#include "evoasm-x64.h"
#include "evoasm-program-io.h"

typedef struct {
  unsigned inst : EVOASM_X64_INST_BITSIZE;
  evoasm_x64_basic_params_t params;
} evoasm_kernel_param_x64_t;

typedef union {
  evoasm_kernel_param_x64_t x64;
} evoasm_kernel_param_t;

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
  evoasm_kernel_x64_reg_info_t x64[EVOASM_X64_REG_NONE];
} evoasm_kernel_reg_info_t;


typedef struct {
  uint16_t kernel_size;
  evoasm_inst_id_t *insts;
  union {
    evoasm_x64_basic_params_t *x64;
  } params;
  evoasm_kernel_reg_info_t reg_info;

  union {
    evoasm_x64_reg_id_t x64[EVOASM_KERNEL_MAX_OUTPUT_REGS];
  } output_regs;

  uint_fast8_t n_input_regs;
  uint_fast8_t n_output_regs;
  uint16_t idx;
  uint16_t buf_start;
  uint16_t buf_end;
} evoasm_kernel_t;

typedef enum {
  EVOASM_PROGRAM_EMIT_FLAG_PREPARE = (1 << 0),
  EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS = (1 << 1),
  EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE = (1 << 2),
  EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING = (1 << 3)
} evoasm_program_emit_flags_t;


#define EVOASM_PROGRAM_OUTPUT_VALS_LEN(io) \
  ((size_t)EVOASM_PROGRAM_IO_N_EXAMPLES(io) * (size_t)EVOASM_KERNEL_MAX_OUTPUT_REGS)

#define EVOASM_PROGRAM_OUTPUT_VALS_SIZE(io) \
  (EVOASM_PROGRAM_OUTPUT_VALS_LEN(io) * sizeof(evoasm_program_io_val_t))

#define EVOASM_KERNEL_PARAMS_SIZE(max_kernel_size) \
   (sizeof(evoasm_kernel_params_t) + \
    (max_kernel_size) * sizeof(evoasm_kernel_param_t))

#define EVOASM_PROGRAM_PARAMS_SIZE(max_program_size, max_kernel_size) \
  (sizeof(evoasm_program_params_t) + \
   (max_program_size) * EVOASM_KERNEL_PARAMS_SIZE(max_kernel_size))

#define EVOASM_PROGRAM_MAX_SIZE 64

typedef struct {
  evoasm_arch_info_t *arch_info;
  evoasm_buf_t *buf;
  evoasm_buf_t *body_buf;
  uint8_t in_arity;
  uint8_t out_arity;
  bool reset_rflags : 1;
  bool need_emit    : 1;
  bool shallow : 1;

  uint32_t exception_mask;
  evoasm_program_io_val_type_t types[EVOASM_PROGRAM_OUTPUT_MAX_ARITY];
  evoasm_program_io_val_t *output_vals;
  evoasm_kernel_t *kernels;
  uint16_t *jmp_offs;
  uint8_t *jmp_selectors;
  uint32_t *recur_counters;
  uint16_t program_size;

  /* these two are incomplete (values missig)
   * We only need arity and types */
  evoasm_program_input_t _input;
  evoasm_program_output_t _output;

  uint32_t recur_limit;
  evoasm_reg_id_t output_regs[EVOASM_PROGRAM_IO_MAX_ARITY];
  evoasm_buf_t _buf;
  evoasm_buf_t _body_buf;

  union {
    /* register at index i has _input i % input_arity */
    uint8_t x64[EVOASM_X64_REG_NONE];
  } reg_inputs;
} evoasm_program_t;

evoasm_success_t
evoasm_program_clone(evoasm_program_t *program, evoasm_program_t *cloned_program);

evoasm_success_t
evoasm_program_init(evoasm_program_t *program,
                    evoasm_arch_id_t arch_id,
                    evoasm_program_io_t *program_input,
                    uint16_t n_kernels,
                    uint16_t kernel_size,
                    uint32_t recur_limit);


evoasm_program_output_t *
evoasm_program_run(evoasm_program_t *program,
               evoasm_program_input_t *input);


evoasm_success_t
evoasm_program_destroy(evoasm_program_t *program);

evoasm_success_t
evoasm_program_eliminate_introns(evoasm_program_t *program);

evoasm_success_t
evoasm_program_emit(evoasm_program_t *program,
                evoasm_program_input_t *input,
                bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping);

evoasm_loss_t
evoasm_program_assess(evoasm_program_t *program,
                  evoasm_program_output_t *output);

_EVOASM_DECL_ALLOC_FREE_FUNCS(program)
