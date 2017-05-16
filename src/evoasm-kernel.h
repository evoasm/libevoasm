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
#include "evoasm-kernel-io.h"
#include "gen/evoasm-enums.h"

#define EVOASM_KERNEL_MAX_OUTPUT_REGS 254
#define EVOASM_KERNEL_MAX_INPUT_REGS 254

typedef struct {
  bool input : 1;
  bool written : 1;
} evoasm_kernel_x64_reg_info_reg_t;

typedef struct {
  evoasm_kernel_x64_reg_info_reg_t reg_info[EVOASM_X64_REG_NONE];
} evoasm_kernel_reg_info_x64_t;

typedef struct {
  evoasm_x64_basic_params_t *params;
  evoasm_kernel_reg_info_x64_t reg_info;
  unsigned maybe_written_flags : EVOASM_X64_RFLAGS_FLAGS_BITSIZE;
  evoasm_x64_reg_id_t output_regs[EVOASM_KERNEL_MAX_OUTPUT_REGS];

  /* register at index i has _input i % input_arity */
  uint8_t reg_input_mapping[EVOASM_X64_REG_NONE];
} evoasm_kernel_x64_t;

typedef struct {

  bool reset_rflags : 1;
  bool shallow : 1;
  uint_fast8_t n_input_regs;
  uint_fast8_t n_output_regs;
  uint16_t size;
  uint16_t max_tuples;
  uint16_t max_kernel_size;
  uint32_t exception_mask;
  uint16_t buf_pos_body_start;
  uint16_t buf_pos_body_end;
  uint16_t buf_pos_epilog_start;
  uint16_t buf_pos_epilog_end;
  evoasm_arch_info_t *arch_info;
  evoasm_arch_id_t arch_id;
  evoasm_buf_t *buf;
  evoasm_kernel_io_val_type_t types[EVOASM_KERNEL_OUTPUT_MAX_ARITY];
  evoasm_kernel_io_val_t *output_vals;
  evoasm_inst_id_t *insts;

  union {
    evoasm_kernel_x64_t x64;
  };

  /* these two are incomplete (values missing)
   * We only need arity and types */
  evoasm_kernel_input_t _input;
  evoasm_kernel_output_t _output;

  evoasm_reg_id_t output_reg_mapping[EVOASM_PROGRAM_IO_MAX_ARITY];
  evoasm_buf_t _buf;

#ifdef EVOASM_ENABLE_PARANOID_MODE
  evoasm_kernel_io_val_t rand_vals[EVOASM_X64_REG_NONE];
#endif

} evoasm_kernel_t;


typedef enum {
  EVOASM_KERNEL_ERROR_CODE_NO_OUTPUT
} evoasm_kernel_error_code_t;

typedef enum {
  EVOASM_PROGRAM_EMIT_FLAG_NO_RUNS = (1 << 0),
  EVOASM_PROGRAM_EMIT_FLAG_ONLY_RUNS = (1 << 1),
  EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING = (1 << 2),
  EVOASM_PROGRAM_EMIT_FLAG_PRESERVE_OUTPUT_REGS = (1 << 3)
} evoasm_kernel_emit_flags_t;

#define EVOASM_KERNEL_MAX_SIZE 1024

typedef evoasm_bitmap1024_t evoasm_bitmap_max_kernel_size_t;
typedef evoasm_bitmap256_t evoasm_bitmap_max_output_regs_t;

evoasm_success_t
evoasm_kernel_clone(evoasm_kernel_t *program, evoasm_kernel_t *cloned_program);

evoasm_success_t
evoasm_kernel_init(evoasm_kernel_t *kernel,
                    evoasm_arch_info_t *arch_info,
                    size_t max_kernel_size,
                    size_t max_tuples,
                    bool shallow);


evoasm_success_t
evoasm_kernel_run(evoasm_kernel_t *kernel,
                  evoasm_kernel_input_t *input,
                  evoasm_kernel_output_t *output);

void
evoasm_kernel_update_topo(evoasm_kernel_t *program,
                               uint8_t *edges, size_t n_edges,
                               uint8_t *default_succs);

evoasm_success_t
evoasm_kernel_destroy(evoasm_kernel_t *program);

evoasm_success_t
evoasm_kernel_elim_introns(evoasm_kernel_t *kernel, evoasm_kernel_t *dst_kernel);

evoasm_success_t
evoasm_kernel_emit(evoasm_kernel_t *kernel,
                    evoasm_kernel_input_t *input,
                    size_t win_off,
                    size_t win_size,
                    evoasm_kernel_emit_flags_t emit_flags);

evoasm_loss_t
evoasm_kernel_eval(evoasm_kernel_t *program,
                    evoasm_kernel_output_t *output,
                    evoasm_metric_t,
                    size_t win_off,
                    size_t win_len);

evoasm_success_t
evoasm_kernel_detach(evoasm_kernel_t *program,
                      evoasm_kernel_io_t *input,
                      evoasm_kernel_io_t *output);


void
evoasm_kernel_log(evoasm_kernel_t *program, evoasm_log_level_t log_level);

EVOASM_DECL_ALLOC_FREE_FUNCS(kernel)
