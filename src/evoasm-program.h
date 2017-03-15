/*
 * Copyright (C) 2016 Julian Aron Prenner <jap@polyadic.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "evoasm-pop-params.h"
#include "evoasm-x64.h"
#include "evoasm-program-io.h"

#define EVOASM_KERNEL_MAX_OUTPUT_REGS 254
#define EVOASM_KERNEL_MAX_INPUT_REGS 254

typedef struct {
  bool input : 1;
  bool written : 1;
  /*registers in following kernels whose input is this register */
} evoasm_kernel_x64_reg_info_reg_t;

typedef struct {
  evoasm_kernel_x64_reg_info_reg_t reg_info[EVOASM_X64_REG_NONE];
} evoasm_kernel_reg_info_x64_t;

typedef struct {
  /* transn_regs[trans_idx][reg_id] stores the register in this kernel that is used
   * to initialize reg_id in the trans_idx'th transition kernel.
   * Right now, trans_idx=0 is the next kernel in line,
   * while trans_idx=1 is the kernel jumped to using the programs jmp_offs table.
   */
  evoasm_x64_reg_id_t transn_regs[EVOASM_X64_JMP_COND_NONE + 1][EVOASM_X64_REG_NONE];
} evoasm_kernel_trans_regs_x64_t;

typedef struct {
  evoasm_x64_basic_params_t *params;
  evoasm_kernel_reg_info_x64_t reg_info;
  evoasm_kernel_trans_regs_x64_t transn_regs;
  unsigned maybe_written_flags : EVOASM_X64_RFLAGS_FLAGS_BITSIZE;
  evoasm_x64_reg_id_t output_regs[EVOASM_KERNEL_MAX_OUTPUT_REGS];
} evoasm_kernel_x64_t;

typedef struct {
  evoasm_inst_id_t *insts;

  union {
    evoasm_kernel_x64_t x64;
  };

  uint_fast8_t n_input_regs;
  uint_fast8_t n_output_regs;
  uint16_t size;
  uint16_t idx;
  uint32_t active_succs[EVOASM_X64_JMP_COND_NONE + 2];

#ifdef EVOASM_ENABLE_PARANOID_MODE
  evoasm_program_io_val_t rand_vals[EVOASM_X64_REG_NONE];
#endif

} evoasm_kernel_t;


typedef enum {
  EVOASM_PROGRAM_ERROR_CODE_NO_OUTPUT
} evoasm_program_error_code_t;

typedef enum {
  EVOASM_PROGRAM_EMIT_FLAG_NO_RUNS = (1 << 0),
  EVOASM_PROGRAM_EMIT_FLAG_ONLY_RUNS = (1 << 1),
  EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING = (1 << 2),
  EVOASM_PROGRAM_EMIT_FLAG_PRESERVE_OUTPUT_REGS = (1 << 3)
} evoasm_program_emit_flags_t;

#define EVOASM_PROGRAM_TOPOLOGY_MAX_SIZE 24
#define EVOASM_KERNEL_MAX_SIZE 1024

static_assert(EVOASM_PROGRAM_TOPOLOGY_MAX_SIZE % 8 == 0, "max topology size must be multiple of 8");

typedef evoasm_bitmap64_t evoasm_bitmap_max_program_size_t;
typedef evoasm_bitmap1024_t evoasm_bitmap_max_kernel_size_t;
typedef evoasm_bitmap256_t evoasm_bitmap_max_output_regs_t;

#define EVOASM_PROGRAM_TOPOLOGY_MIN_BACKBONE_LEN 2
#define EVOASM_PROGRAM_TOPOLOGY_MAX_CONDS (EVOASM_X64_JMP_COND_NONE + 1)

typedef struct {
  uint16_t size;
  uint32_t cycle_bitmap;
  uint32_t used_bitmap;
  uint8_t succs[EVOASM_PROGRAM_TOPOLOGY_MAX_SIZE][EVOASM_PROGRAM_TOPOLOGY_MAX_CONDS];
} evoasm_program_topology_t;

typedef struct {
  bool dummy;
} evoasm_program_x64_t;

typedef struct {
  bool reset_rflags : 1;
  bool shallow : 1;
  uint16_t max_tuples;
  uint16_t max_kernel_size;
  uint32_t recur_limit;
  uint32_t exception_mask;
  uint16_t buf_pos_kernels_start;
  uint16_t buf_pos_kernels_end;
  uint16_t buf_pos_epilog_start;
  uint16_t buf_pos_epilog_end;
  uint16_t buf_pos_kernel_start[EVOASM_PROGRAM_TOPOLOGY_MAX_SIZE];
  uint16_t buf_pos_kernel_end[EVOASM_PROGRAM_TOPOLOGY_MAX_SIZE];

  evoasm_arch_info_t *arch_info;
  evoasm_buf_t *buf;
  evoasm_program_io_val_type_t types[EVOASM_PROGRAM_OUTPUT_MAX_ARITY];
  evoasm_program_io_val_t *output_vals;
  evoasm_kernel_t *kernels;
  uint32_t recur_counter;

  /* these two are incomplete (values missing)
   * We only need arity and types */
  evoasm_program_input_t _input;
  evoasm_program_output_t _output;

  evoasm_program_topology_t topology;
  evoasm_reg_id_t output_regs_mapping[EVOASM_PROGRAM_IO_MAX_ARITY];
  evoasm_buf_t _buf;

  union {
    evoasm_program_x64_t x64;
  };

  union {
    /* register at index i has _input i % input_arity */
    uint8_t x64[EVOASM_X64_REG_NONE];
  } reg_input_mapping;

} evoasm_program_t;


evoasm_success_t
evoasm_program_clone(evoasm_program_t *program, evoasm_program_t *cloned_program);

evoasm_success_t
evoasm_program_init(evoasm_program_t *program,
                    evoasm_arch_info_t *arch_info,
                    size_t program_size,
                    size_t max_kernel_size,
                    size_t max_tuples,
                    size_t recur_limit,
                    bool shallow);


evoasm_program_output_t *
evoasm_program_run(evoasm_program_t *program,
               evoasm_program_input_t *input);


void
evoasm_program_update_topology(evoasm_program_t *program,
                               uint8_t *edges, size_t n_edges,
                               uint8_t *default_succs);

evoasm_success_t
evoasm_program_destroy(evoasm_program_t *program);

evoasm_success_t
evoasm_program_elim_introns(evoasm_program_t *program, evoasm_program_t *dest_program);

evoasm_success_t
evoasm_program_emit(evoasm_program_t *program,
                evoasm_program_input_t *input,
                size_t win_off,
                size_t win_size,
                evoasm_program_emit_flags_t emit_flags);

evoasm_loss_t
evoasm_program_eval(evoasm_program_t *program,
                    evoasm_program_output_t *output,
                    size_t win_off,
                    size_t win_len);

evoasm_success_t
evoasm_program_detach(evoasm_program_t *program,
                      evoasm_program_io_t *input,
                      evoasm_program_io_t *output);


void
evoasm_program_log(evoasm_program_t *program, evoasm_log_level_t log_level);

EVOASM_DECL_ALLOC_FREE_FUNCS(program)
