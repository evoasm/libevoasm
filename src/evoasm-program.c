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

#include "evoasm-signal.h"
#include "evoasm-program.h"
#include "evoasm-arch.h"
#include "evoasm.h"
#include "evoasm-x64.h"
#include "evoasm-param.h"
#include "evoasm-program-io.h"


EVOASM_DEF_LOG_TAG("program")

static inline double
evoasm_program_io_val_to_dbl(evoasm_program_io_val_t io_val, evoasm_program_io_val_type_t io_val_type) {
  switch(io_val_type) {
    case EVOASM_PROGRAM_IO_VAL_TYPE_F64:
      return io_val.f64;
    case EVOASM_PROGRAM_IO_VAL_TYPE_I64:
      return (double) io_val.i64;
    default:
      evoasm_log_fatal("unsupported input/output value type %d", io_val_type);
      evoasm_assert_not_reached();
  }
}

//#define EVOASM_PROGRAM_TOPOLOGY_ELEM_OFF(program_topology, kernel_idx, cond) ((kernel_idx) * ((program_topology)->n_conds) + (cond))

void
evoasm_program_topology_destroy(evoasm_program_topology_t *program_topology) {
}

bool
evoasm_program_destroy(evoasm_program_t *program) {

  bool retval = true;

  if(!program->shallow) {
    for(size_t i = 0; i < program->size; i++) {
      evoasm_kernel_t *kernel = &program->kernels[i];
      evoasm_free(kernel->insts);
      switch(program->arch_info->id) {
        case EVOASM_ARCH_X64:
          evoasm_free(kernel->x64.params);
          break;
        default:
          evoasm_assert_not_reached();
      }
    }
  }

  evoasm_program_topology_destroy(&program->topology);

  evoasm_free(program->kernels);
  evoasm_free(program->recur_counters);
  evoasm_free(program->output_vals);

  if(program->buf) {
    if(!evoasm_buf_destroy(program->buf)) {
      retval = false;
    }
  }

  if(program->body_buf) {
    if(!evoasm_buf_destroy(program->body_buf)) {
      retval = false;
    }
  }

  return retval;
}

#if 0
evoasm_success_t
evoasm_program_clone(evoasm_program_t *program, evoasm_program_t *cloned_program) {
  size_t i = 0;

  *cloned_program = *program;
  cloned_program->reset_rflags = false;
  cloned_program->_input.len = 0;
  cloned_program->_output.len = 0;
  cloned_program->output_vals = NULL;
  cloned_program->buf = NULL;
  cloned_program->body_buf = NULL;

  /* memory addresses in original buffer point to memory in original program,
   * we need to reemit assembly, this is done in a lazy fashion */
  cloned_program->need_emit = true;

  EVOASM_TRY(error, evoasm_buf_clone, program->buf, &cloned_program->_buf);
  cloned_program->buf = &cloned_program->_buf;
  EVOASM_TRY(error, evoasm_buf_clone, program->body_buf, &cloned_program->_body_buf);
  cloned_program->body_buf = &cloned_program->_body_buf;

  size_t program_params_size = sizeof(evoasm_program_params_t);
  cloned_program->params = evoasm_malloc(program_params_size);

  if(!cloned_program->params) {
    goto error;
  }

  memcpy(cloned_program->params, program->params, program_params_size);

  for(; i < program->size; i++) {
    evoasm_kernel_t *orig_kernel = &program->kernels[i];
    evoasm_kernel_t *cloned_kernel = &cloned_program->kernels[i];
    *cloned_kernel = *orig_kernel;

    size_t params_size =
        sizeof(evoasm_kernel_params_t) + orig_kernel->size * sizeof(evoasm_kernel_param_t);
    cloned_kernel->params = evoasm_malloc(params_size);
    if(!cloned_kernel->params) {
      goto error;
    }
    memcpy(cloned_kernel->params, orig_kernel->params, params_size);
  }

  return true;

error:
  (void) evoasm_program_destroy_(cloned_program, i);
  return false;
}
#endif

evoasm_buf_t *
evoasm_program_get_buf(evoasm_program_t *program, bool body) {
  if(body) {
    return program->body_buf;
  } else {
    return program->buf;
  }
}

size_t
evoasm_program_get_size(evoasm_program_t *program) {
  return program->size;
}

size_t
evoasm_program_get_kernel_code(evoasm_program_t *program, size_t kernel_idx, const uint8_t **code) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  size_t len = (size_t) kernel->buf_end - kernel->buf_start;
  *code = program->body_buf->data + kernel->buf_start;
  return len;
}

size_t
evoasm_program_get_code(evoasm_program_t *program, bool frame, const uint8_t **code) {
  evoasm_buf_t *buf;
  if(frame) {
    buf = program->buf;
  } else {
    buf = program->body_buf;
  }
  *code = buf->data;
  return buf->pos;
}

bool
evoasm_program_is_kernel_input_reg(evoasm_program_t *program, size_t kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->x64.reg_info.reg_info[reg_id].input;
    default:
      evoasm_assert_not_reached();
  }
}

bool
evoasm_program_is_kernel_output_reg(evoasm_program_t *program, size_t kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64:
      for(size_t i = 0; i < kernel->n_output_regs; i++) {
        if(kernel->x64.output_regs[i] == reg_id) return true;
      }
      return false;
    default:
      evoasm_assert_not_reached();
  }
}

evoasm_reg_id_t
evoasm_program_get_output_reg(evoasm_program_t *program, size_t idx) {
  if(idx >= EVOASM_PROGRAM_OUTPUT_MAX_ARITY) return EVOASM_X64_REG_NONE;
  return program->output_regs[idx];
}

size_t
evoasm_program_get_arity(evoasm_program_t *program) {
  return program->_output.arity;
}

#define EVOASM_PROGRAM_TMP_REG_X64 EVOASM_X64_REG_14

static evoasm_success_t
evoasm_program_x64_emit_rflags_reset(evoasm_program_t *program) {
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = program->buf;

  evoasm_log_debug("emitting RFLAGS reset");
  EVOASM_X64_ENC(pushfq);
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_REG_SP);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, 0);
  EVOASM_X64_ENC(mov_rm64_imm32);
  EVOASM_X64_ENC(popfq);

  return true;
enc_failed:
  return false;
}

static evoasm_used evoasm_success_t
evoasm_program_x64_emit_mxcsr_reset(evoasm_program_t *program) {
  static uint32_t default_mxcsr_val = 0x1f80;
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = program->buf;

  evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) &default_mxcsr_val;
  evoasm_x64_reg_id_t reg_tmp0 = EVOASM_PROGRAM_TMP_REG_X64;

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg_tmp0);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
  EVOASM_X64_ENC(mov_r32_imm32);

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, reg_tmp0);
  EVOASM_X64_ENC(ldmxcsr_m32);

  return true;
enc_failed:
  return false;
}

static evoasm_kernel_t *
evoasm_program_get_start_kernel(evoasm_program_t *program) {
  return &program->kernels[0];
}

static evoasm_kernel_t *
evoasm_program_get_terminal_kernel(evoasm_program_t *program) {
  return &program->kernels[program->topology.backbone_len - 1];
}

static evoasm_success_t
evoasm_program_x64_emit_output_store(evoasm_program_t *program,
                                     size_t tuple_idx) {

  evoasm_x64_params_t params = {0};
  evoasm_kernel_t *terminal_kernel = evoasm_program_get_terminal_kernel(program);
  evoasm_buf_t *buf = program->buf;

  for(size_t i = 0; i < terminal_kernel->n_output_regs; i++) {
    evoasm_x64_reg_id_t reg_id = terminal_kernel->x64.output_regs[i];
    evoasm_program_io_val_t *val_addr = &program->output_vals[(tuple_idx * terminal_kernel->n_output_regs) + i];
    evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(reg_id);

    evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) val_addr;

    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_PROGRAM_TMP_REG_X64);
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
    EVOASM_X64_ENC(mov_r64_imm64);

    switch(reg_type) {
      case EVOASM_X64_REG_TYPE_GP: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_PROGRAM_TMP_REG_X64);
        EVOASM_X64_ENC(mov_rm64_r64);
        break;
      }
      case EVOASM_X64_REG_TYPE_XMM: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_PROGRAM_TMP_REG_X64);
        EVOASM_X64_ENC(movsd_xmmm64_xmm);
        break;
      }
      case EVOASM_X64_REG_TYPE_RFLAGS: {
        /*FIXME: should we store RFLAGS ? */
        break;
      }
      default: {
        evoasm_assert_not_reached();
      }
    }
  }

  return true;

enc_failed:
  return false;
}

static evoasm_x64_reg_id_t
evoasm_kernel_get_operand_reg_id_x64(evoasm_kernel_t *kernel, evoasm_x64_operand_t *op, size_t inst_idx) {
  if(op->implicit) {
    if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
      return EVOASM_X64_REG_RFLAGS;
    } else if(op->reg_id < EVOASM_X64_REG_NONE) {
      return (evoasm_x64_reg_id_t) op->reg_id;
    } else {
      evoasm_assert_not_reached();
      return EVOASM_X64_REG_NONE;
    }
  } else {
    evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[inst_idx]);
    if(op->param_idx < inst->n_params) {
      return (evoasm_x64_reg_id_t) evoasm_x64_basic_params_get_(&kernel->x64.params[inst_idx],
                                                                (evoasm_x64_basic_param_id_t) inst->params[op->param_idx].id);
    } else {
      evoasm_assert_not_reached();
      return EVOASM_X64_REG_NONE;
    }
  }
}

typedef struct {
  evoasm_bitmap512_t mask;
} evoasm_x64_reg_cover_t;

static void
evoasm_x64_reg_cover_or_mask(evoasm_x64_inst_t *inst, evoasm_x64_operand_t *op, evoasm_x64_basic_params_t *params,
                             evoasm_bitmap512_t *mask512, bool read) {
  evoasm_bitmap_t *mask = (evoasm_bitmap_t *) mask512;

  if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
    unsigned flags;
    if(read) {
      flags = op->read_flags;
    } else {
      flags = op->written_flags;
    }

    for(evoasm_x64_rflags_flag_t flag = (evoasm_x64_rflags_flag_t) 0; flag < EVOASM_X64_RFLAGS_FLAG_NONE; flag++) {
      if(EVOASM_X64_RFLAGS_FLAGS_GET(flags, flag)) {
        evoasm_bitmap_or64(mask, 0, evoasm_x64_get_rflags_flag_mask_(flag));
      }
    }
    return;
  } else {
    if(!read && op->maybe_written) {
      return;
    }
  }

  switch(op->word) {
    case EVOASM_X64_OPERAND_WORD_LB:
      if(!op->implicit && op->param_idx < inst->n_params &&
         (
             (inst->params[op->param_idx].id == EVOASM_X64_BASIC_PARAM_REG0 && params->reg0_high_byte)
             ||
             (inst->params[op->param_idx].id == EVOASM_X64_BASIC_PARAM_REG1 && params->reg1_high_byte)
         )) {
        goto hb;
      }
      evoasm_bitmap_or64(mask, 0, 0x00ffu);
      break;
    case EVOASM_X64_OPERAND_WORD_HB: {
hb:
      evoasm_bitmap_or64(mask, 0, 0xff00u);
      break;
    }
    case EVOASM_X64_OPERAND_WORD_W:
      evoasm_bitmap_or64(mask, 0, 0xffffu);
      break;
    case EVOASM_X64_OPERAND_WORD_DW:
      /* 32bit writes clear the whole register */
      if(op->reg_type == EVOASM_X64_REG_TYPE_GP) {
        evoasm_bitmap_or64(mask, 0, 0xffffffffffffffffull);
      } else {
        /* xmm[0..31] does this for example */
        evoasm_bitmap_or64(mask, 0, 0xffffffffu);
      }
      break;
    case EVOASM_X64_OPERAND_WORD_LQW:
      evoasm_bitmap_or64(mask, 0, 0xffffffffffffffffull);
      break;
    case EVOASM_X64_OPERAND_WORD_HQW:
      evoasm_bitmap_or64(mask, 1, 0xffffffffffffffffull);
      break;
    case EVOASM_X64_OPERAND_WORD_DQW:
      evoasm_bitmap_or64(mask, 0, 0xffffffffffffffffull);
      evoasm_bitmap_or64(mask, 1, 0xffffffffffffffffull);
      break;
    case EVOASM_X64_OPERAND_WORD_VW:
      evoasm_bitmap_or64(mask, 0, 0xffffffffffffffffull);
      evoasm_bitmap_or64(mask, 1, 0xffffffffffffffffull);
      evoasm_bitmap_or64(mask, 2, 0xffffffffffffffffull);
      evoasm_bitmap_or64(mask, 3, 0xffffffffffffffffull);
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_x64_reg_cover_update(evoasm_x64_reg_cover_t *reg_cover, evoasm_x64_inst_t *inst,
                            evoasm_x64_operand_t *op, evoasm_x64_basic_params_t *params) {
  evoasm_x64_reg_cover_or_mask(inst, op, params, &reg_cover->mask, false);
}


static bool
evoasm_x64_reg_cover_is_covered_(evoasm_x64_reg_cover_t *reg_cover,
                                 evoasm_bitmap512_t *mask) {

  evoasm_bitmap512_andn(mask, &reg_cover->mask, mask);
  return evoasm_bitmap512_is_zero(mask);
}

static bool
evoasm_x64_reg_cover_is_covered(evoasm_x64_reg_cover_t *reg_cover, evoasm_x64_inst_t *inst,
                                evoasm_x64_operand_t *op,
                                evoasm_x64_basic_params_t *params) {

  evoasm_bitmap512_t mask = {0};
  evoasm_x64_reg_cover_or_mask(inst, op, params, &mask, true);

  return evoasm_x64_reg_cover_is_covered_(reg_cover, &mask);
}

static void
evoasm_x64_reg_cover_init(evoasm_x64_reg_cover_t *reg_cover) {
  static evoasm_x64_reg_cover_t zero_reg_cover = {0};
  *reg_cover = zero_reg_cover;
}

static evoasm_success_t
evoasm_program_x64_prepare_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel, bool preserve_output_regs) {
  /* NOTE: output register are register that are written to
   *       _input registers are register that are read from without
   *       a previous write
   */
  evoasm_x64_reg_cover_t reg_coveres[EVOASM_X64_REG_NONE];
  for(int i = 0; i < EVOASM_X64_REG_NONE; i++) {
    evoasm_x64_reg_cover_init(&reg_coveres[i]);
  }

  kernel->n_input_regs = 0;

  if(!preserve_output_regs) {
    kernel->n_output_regs = 0;
  }
  kernel->x64.maybe_written_flags = 0;

  static evoasm_kernel_reg_info_x64_t zero_reg_info = {0};
  kernel->x64.reg_info = zero_reg_info;

  /* First, handle read ops, so that writing ops do not disturb us */
  for(size_t i = 0; i < kernel->size; i++) {
    evoasm_x64_inst_t *x64_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
    evoasm_x64_basic_params_t *x64_basic_params = &kernel->x64.params[i];

    for(size_t j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if((op->read || op->maybe_written) &&
         (op->type == EVOASM_X64_OPERAND_TYPE_REG || op->type == EVOASM_X64_OPERAND_TYPE_RM)) {

        /*if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
          program->reset_rflags = true;
        }  else*/ {
          evoasm_x64_reg_id_t reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, (uint16_t) i);
          evoasm_kernel_x64_reg_info_reg_t *reg_info = &kernel->x64.reg_info.reg_info[reg_id];
          evoasm_x64_reg_cover_t *reg_cover = &reg_coveres[reg_id];

          if(!reg_info->input) {
            // has not been written before, might contain garbage
            bool dirty_read;

            /* the writer rank check is needed for the following case
             * inst regX (operand1, written), regX (operand2, read)
             *
             * The first operand marks regX as written. The read in the second
             * operand, however, is dirty, since the write has not yet occurred at this point.
             */

            if(reg_info->written) {
              dirty_read = !evoasm_x64_reg_cover_is_covered(reg_cover, x64_inst, op, x64_basic_params);
            } else {
              dirty_read = true;
            }

            if(dirty_read) {
              reg_info->input = true;
              kernel->n_input_regs++;
            }
          }
        }
      }
    }

    for(size_t j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if(op->written && (op->type == EVOASM_X64_OPERAND_TYPE_REG || op->type == EVOASM_X64_OPERAND_TYPE_RM)) {

        if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
          kernel->x64.maybe_written_flags = op->maybe_written_flags & EVOASM_X64_RFLAGS_FLAGS_BITSIZE;
          //kernel->x64.reg_info.reg_info[EVOASM_X64_REG_RFLAGS].written = true;
        }

        {
          evoasm_x64_reg_id_t reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, (uint16_t) i);
          evoasm_kernel_x64_reg_info_reg_t *reg_info = &kernel->x64.reg_info.reg_info[reg_id];
          evoasm_x64_reg_cover_t *reg_cover = &reg_coveres[reg_id];

          if(!reg_info->written) {
            reg_info->written = true;
            if(!preserve_output_regs) {
              kernel->x64.output_regs[kernel->n_output_regs] = reg_id;
              kernel->n_output_regs++;
            }
          }
          evoasm_x64_reg_cover_update(reg_cover, x64_inst, op, x64_basic_params);
        }
      }
    }
  }

  for(size_t i = 0; i < kernel->n_output_regs; i++) {
    evoasm_x64_reg_id_t reg_id = kernel->x64.output_regs[i];
    evoasm_kernel_x64_reg_info_reg_t *reg_info = &kernel->x64.reg_info.reg_info[reg_id];
    if(!reg_info->input) {
      evoasm_x64_reg_cover_t *reg_cover = &reg_coveres[reg_id];

      evoasm_bitmap512_t mask = {0};

      switch(evoasm_x64_get_reg_type(reg_id)) {
        case EVOASM_X64_REG_TYPE_RFLAGS:
        case EVOASM_X64_REG_TYPE_GP:
          evoasm_bitmap_set64((evoasm_bitmap_t *) &mask, 0, 0xffffffffffffffffull);
          break;
        case EVOASM_X64_REG_TYPE_XMM:
        case EVOASM_X64_REG_TYPE_ZMM:
          evoasm_bitmap_set64((evoasm_bitmap_t *) &mask, 0, 0xffffffffffffffffull);
          evoasm_bitmap_set64((evoasm_bitmap_t *) &mask, 1, 0xffffffffffffffffull);
          evoasm_bitmap_set64((evoasm_bitmap_t *) &mask, 2, 0xffffffffffffffffull);
          evoasm_bitmap_set64((evoasm_bitmap_t *) &mask, 3, 0xffffffffffffffffull);
          break;
        default:
          evoasm_log_fatal("invalid register %s", evoasm_x64_get_reg_name(reg_id));
          evoasm_assert_not_reached();
      }

      bool dirty_read = !evoasm_x64_reg_cover_is_covered_(reg_cover, &mask);
      if(dirty_read) {
        reg_info->input = true;
        kernel->n_input_regs++;
      }
    }
  }

#ifdef EVOASM_ENABLE_PARANOID_MODE
  {
    size_t n_input_regs = 0;
    for(evoasm_x64_reg_id_t i = (evoasm_x64_reg_id_t) 0; i < EVOASM_X64_REG_NONE; i++) {
      if(kernel->x64.reg_info.regs[i].input) n_input_regs++;
    }
    assert(n_input_regs == kernel->n_input_regs);
  }
#endif

  assert(kernel->n_output_regs <= EVOASM_KERNEL_MAX_OUTPUT_REGS);
  assert(kernel->n_input_regs <= EVOASM_KERNEL_MAX_INPUT_REGS);

  if(kernel->n_output_regs == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_PROGRAM, EVOASM_PROGRAM_ERROR_CODE_NO_OUTPUT, "no output registers in kernel %d",
                 kernel->idx);
    return false;
  }

  return true;
}

static evoasm_success_t
evoasm_program_x64_prepare(evoasm_program_t *program, bool preserve_output_regs) {
  for(size_t i = 0; i < program->size; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    EVOASM_TRY(error, evoasm_program_x64_prepare_kernel, program, kernel, preserve_output_regs);
  }

  return true;

error:
  return false;

}


static evoasm_success_t
evoasm_program_x64_emit_input_reg_load(evoasm_program_t *program,
                                       evoasm_x64_reg_id_t input_reg_id,
                                       evoasm_buf_t *buf,
                                       evoasm_program_io_val_t *tuple,
                                       evoasm_program_io_val_t *loaded_tuple,
                                       bool force_load) {

  evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(input_reg_id);
  evoasm_x64_params_t params = {0};

  evoasm_log_debug("emitting _input register initialization of register %d to value %"
                       PRId64, input_reg_id, tuple->i64);

  switch(reg_type) {
    case EVOASM_X64_REG_TYPE_GP: {
      if(force_load) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_PROGRAM_TMP_REG_X64);
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) &tuple->i64);
        EVOASM_X64_ENC(mov_r64_imm64);

        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_PROGRAM_TMP_REG_X64);
        EVOASM_X64_ENC(mov_r64_rm64);
      } else {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        /*FIXME: hard-coded tuple type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) tuple->i64);
        EVOASM_X64_ENC(mov_r64_imm64);
      }
      break;
    }
    case EVOASM_X64_REG_TYPE_XMM: {
      /* load address of tuple into tmp_reg */
      if(loaded_tuple != tuple) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_PROGRAM_TMP_REG_X64);
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) &tuple->f64);
        EVOASM_X64_ENC(mov_r64_imm64);
        loaded_tuple = tuple;
      }

      /* load into xmm via address in tmp_reg */
      /*FIXME: hard-coded tuple type */
      EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
      EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_PROGRAM_TMP_REG_X64);
      EVOASM_X64_ENC(movsd_xmm_xmmm64);
      break;
    }
    case EVOASM_X64_REG_TYPE_RFLAGS:
      program->reset_rflags = true;
      break;
    default:
      evoasm_log_fatal("non-gpr register type (%d) (unimplemented)", reg_type);
      evoasm_assert_not_reached();
  }

  return true;

enc_failed:
  return false;
}


static evoasm_success_t
evoasm_program_x64_emit_input_load(evoasm_program_t *program,
                                   evoasm_program_io_val_t *input_vals,
                                   evoasm_program_io_val_type_t *types,
                                   size_t in_arity,
                                   bool set_io_mapping) {


  evoasm_program_io_val_t *loaded_tuple = NULL;
  evoasm_buf_t *buf = program->buf;
  evoasm_kernel_t *kernel = evoasm_program_get_start_kernel(program);

  evoasm_log_debug("n _input regs %d", kernel->n_input_regs);
#if 0
  for(input_reg_id = (evoasm_x64_reg_id_t) 13; input_reg_id < 19; input_reg_id++) {
    if(input_reg_id == EVOASM_X64_REG_SP) continue;
    evoasm_x64_params_t params = {0};
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
    /*FIXME: hard-coded tuple type */
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, 0);
    EVOASM_X64_ENC(mov_r64_imm64);
  }
#endif

  {
    size_t input_reg_idx = 0;
    for(evoasm_x64_reg_id_t input_reg = (evoasm_x64_reg_id_t) 0; input_reg < EVOASM_X64_REG_NONE; input_reg++) {
      if(!kernel->x64.reg_info.reg_info[input_reg].input) continue;

      size_t tuple_idx;

      if(set_io_mapping) {
        tuple_idx = input_reg_idx++ % in_arity;
        program->reg_inputs.x64[input_reg] = (uint8_t) tuple_idx;
      } else {
        tuple_idx = program->reg_inputs.x64[input_reg];
      }

      evoasm_program_io_val_t *tuple = &input_vals[tuple_idx];
      EVOASM_TRY(error, evoasm_program_x64_emit_input_reg_load, program, input_reg, buf, tuple, loaded_tuple, false);
    }
  }

#ifdef EVOASM_ENABLE_PARANOID_MODE
  EVOASM_TRY(error, evoasm_x64_emit_push, EVOASM_PROGRAM_TMP_REG_X64, buf);
  for(evoasm_x64_reg_id_t non_input_reg = (evoasm_x64_reg_id_t) EVOASM_X64_REG_A;
      non_input_reg < EVOASM_X64_REG_15; non_input_reg++) {
    if(kernel->x64.reg_info.regs[non_input_reg].input) continue;
    if(non_input_reg == EVOASM_X64_REG_SP) continue;

    evoasm_program_io_val_t *tuple = &kernel->rand_vals[non_input_reg];
    EVOASM_TRY(error, evoasm_program_x64_emit_input_reg_load, non_input_reg, buf, tuple, NULL, true);
  }
  EVOASM_TRY(error, evoasm_x64_emit_pop, EVOASM_PROGRAM_TMP_REG_X64, buf);
#endif

  if(program->reset_rflags) {
    EVOASM_TRY(error, evoasm_program_x64_emit_rflags_reset, program);
  }
  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit_kernel_transition_loads(evoasm_program_t *program,
                                                evoasm_kernel_t *from_kernel,
                                                evoasm_kernel_t *to_kernel,
                                                evoasm_buf_t *buf,
                                                evoasm_x64_jmp_cond_t cond,
                                                bool set_io_mapping) {
  assert(from_kernel->n_output_regs > 0);

  {
    evoasm_bitmap64_t output_regs_bitmap = {0};
    size_t input_reg_idx = 0;

    for(size_t i = 0; i < from_kernel->n_output_regs; i++) {
      evoasm_x64_reg_id_t output_reg_id = from_kernel->x64.output_regs[i];
      if(output_reg_id == EVOASM_X64_REG_RFLAGS) continue;
      evoasm_bitmap_set((evoasm_bitmap_t *) &output_regs_bitmap, output_reg_id);
    }

    for(evoasm_x64_reg_id_t input_reg_id = (evoasm_x64_reg_id_t) 0;
        input_reg_id < EVOASM_X64_REG_NONE; input_reg_id++) {
      if(!to_kernel->x64.reg_info.reg_info[input_reg_id].input) continue;
      if(input_reg_id == EVOASM_X64_REG_RFLAGS) continue;

      evoasm_x64_reg_id_t output_reg_id;

      if(set_io_mapping) {
        if(evoasm_bitmap_get((evoasm_bitmap_t *) &output_regs_bitmap, input_reg_id)) {
          output_reg_id = input_reg_id;
        } else {
          do {
            size_t output_reg_idx = input_reg_idx++ % from_kernel->n_output_regs;
            output_reg_id = from_kernel->x64.output_regs[output_reg_idx];
          } while(output_reg_id == EVOASM_X64_REG_RFLAGS);
        }
        from_kernel->x64.trans_regs.trans_regs[cond][input_reg_id] = output_reg_id;
      } else {
        output_reg_id = from_kernel->x64.trans_regs.trans_regs[cond][input_reg_id];
      }

      evoasm_x64_reg_type_t output_reg_type = evoasm_x64_get_reg_type(output_reg_id);
      evoasm_x64_reg_type_t input_reg_type = evoasm_x64_get_reg_type(input_reg_id);
      evoasm_x64_params_t params = {0};

      if(input_reg_id != output_reg_id) {
        if(output_reg_type == EVOASM_X64_REG_TYPE_GP &&
           input_reg_type == EVOASM_X64_REG_TYPE_GP) {
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
          EVOASM_X64_ENC(mov_r64_rm64);
        } else if(output_reg_type == EVOASM_X64_REG_TYPE_XMM &&
                  input_reg_type == EVOASM_X64_REG_TYPE_XMM) {
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
          if(program->arch_info->features & EVOASM_X64_FEATURE_AVX) {
            EVOASM_X64_ENC(vmovdqa_ymm_ymmm256);
          } else {
            EVOASM_X64_ENC(movdqa_xmm_xmmm128);
          }
        } else if(output_reg_type == EVOASM_X64_REG_TYPE_GP &&
                  input_reg_type == EVOASM_X64_REG_TYPE_XMM) {
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
          if(program->arch_info->features & EVOASM_X64_FEATURE_AVX) {
            EVOASM_X64_ENC(vmovq_xmm_rm64);
          } else {
            EVOASM_X64_ENC(movq_xmm_rm64);
          }
        } else if(output_reg_type == EVOASM_X64_REG_TYPE_XMM &&
                  input_reg_type == EVOASM_X64_REG_TYPE_GP) {
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
          if(program->arch_info->features & EVOASM_X64_FEATURE_AVX) {
            EVOASM_X64_ENC(vmovq_rm64_xmm);
          } else {
            EVOASM_X64_ENC(movq_rm64_xmm);
          }
        } else {
          evoasm_assert_not_reached();
        }
      }
    }
  }

  return true;

enc_failed:
  return false;
}

#define EVOASM_BUF_GET_RELOC_ADDR32(buf) ((uint32_t *)((buf)->data + (buf)->pos - 4))
#define EVOASM_BUF_SET_RELOC_ADDR32(label, val) \
do { (*(label) = (uint32_t)((uint8_t *)(val) - ((uint8_t *)(label) + 4)));} while(0);
#define EVOASM_BUF_GET_POS_ADDR(buf) (buf->data + buf->pos)

#define EVOASM_PROGRAM_X64_N_JMP_INSTS 16


static evoasm_success_t
evoasm_program_x64_emit_cond_transition(evoasm_program_t *program, evoasm_kernel_t *kernel, evoasm_buf_t *buf,
                                        uint32_t *jmp_reloc_addrs[], evoasm_x64_jmp_cond_t jmp_cond,
                                        bool set_io_mapping) {

  static const evoasm_x64_inst_id_t jmp_insts[] = {
      EVOASM_X64_INST_JA_REL32,  //  0
      EVOASM_X64_INST_JAE_REL32, //  1
      EVOASM_X64_INST_JB_REL32,  //  2
      EVOASM_X64_INST_JBE_REL32, //  3
      EVOASM_X64_INST_JE_REL32,  //  4
      EVOASM_X64_INST_JG_REL32,  //  5
      EVOASM_X64_INST_JGE_REL32, //  6
      EVOASM_X64_INST_JL_REL32,  //  7
      EVOASM_X64_INST_JLE_REL32, //  8
      EVOASM_X64_INST_JNE_REL32, //  9
      EVOASM_X64_INST_JNO_REL32, // 10
      EVOASM_X64_INST_JNP_REL32, // 11
      EVOASM_X64_INST_JNS_REL32, // 12
      EVOASM_X64_INST_JO_REL32,  // 13
      EVOASM_X64_INST_JP_REL32,  // 14
      EVOASM_X64_INST_JS_REL32,  // 15
  };
  evoasm_x64_params_t params = {0};


  if(jmp_cond < EVOASM_X64_JMP_COND_NONE) {
    evoasm_x64_inst_id_t jmp_inst_id = jmp_insts[jmp_cond];
    uint32_t *counter_reloc_addr = NULL;
    uint32_t *jmp_reloc_addr = NULL;

    evoasm_buf_ref_t buf_ref = {
        .data = buf->data,
        .pos = &buf->pos
    };

    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_TRY(error, evoasm_x64_enc_, (evoasm_x64_inst_id_t) jmp_inst_id, &params, &buf_ref);
    jmp_reloc_addr = EVOASM_BUF_GET_RELOC_ADDR32(buf);
    assert(*jmp_reloc_addr == 0xdeadbeef);

    if(program->topology.cycle_bitmap & (1u << kernel->idx)) {
      /* cyclic, guard with counter */

      uint32_t *counter = &program->recur_counters[kernel->idx];
      uintptr_t addr_imm = (uintptr_t) counter;

      EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_PROGRAM_TMP_REG_X64);
      EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) addr_imm);
      EVOASM_X64_ENC(mov_r64_imm64);

      EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_PROGRAM_TMP_REG_X64);
      EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, program->recur_limit);
      EVOASM_X64_ENC(cmp_rm32_imm32);

      EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
      EVOASM_X64_ENC(jge_rel32);

      counter_reloc_addr = EVOASM_BUF_GET_RELOC_ADDR32(buf);
      assert(*counter_reloc_addr == 0xdeadbeef);

      EVOASM_X64_ENC(inc_rm32);
    }

    evoasm_kernel_t *succ_kernel = &program->kernels[program->topology.mat[kernel->idx][jmp_cond]];

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transition_loads, program,
               kernel, succ_kernel, buf, jmp_cond, set_io_mapping);

    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_X64_ENC(jmp_rel32);

    jmp_reloc_addrs[jmp_cond] = EVOASM_BUF_GET_RELOC_ADDR32(buf);
    assert(*jmp_reloc_addrs[jmp_cond] == 0xdeadbeef);

    if(jmp_reloc_addr != NULL) {
      EVOASM_BUF_SET_RELOC_ADDR32(jmp_reloc_addr, EVOASM_BUF_GET_POS_ADDR(buf))
    }

    if(counter_reloc_addr != NULL) {
      EVOASM_BUF_SET_RELOC_ADDR32(counter_reloc_addr, EVOASM_BUF_GET_POS_ADDR(buf));
    }
  }

  return true;

error:
enc_failed:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit_default_transition(evoasm_program_t *program, evoasm_kernel_t *kernel, evoasm_buf_t *buf,
                                           uint32_t *jmp_reloc_addrs, bool set_io_mapping) {

  if(kernel != evoasm_program_get_terminal_kernel(program)) {
    evoasm_kernel_t *next_kernel = &program->kernels[program->topology.mat[kernel->idx][EVOASM_X64_JMP_COND_NONE]];

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transition_loads, program,
               kernel, next_kernel, buf, EVOASM_X64_JMP_COND_NONE, set_io_mapping);

    evoasm_buf_log(buf, EVOASM_LOG_LEVEL_DEBUG);
  }

  return true;

error:
  return false;


}

static evoasm_success_t
evoasm_program_x64_emit_cond_transitions(evoasm_program_t *program,
                                         evoasm_kernel_t *kernel,
                                         evoasm_buf_t *buf,
                                         uint32_t **jmp_reloc_addrs,
                                         bool set_io_mapping) {


  bool jbe = false;
  bool jle = false;

  if(kernel->x64.reg_info.reg_info[EVOASM_X64_REG_RFLAGS].written) {
    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_OF)) {
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JO,
                                              set_io_mapping);
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JNO,
                                              set_io_mapping);
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_SF)) {
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JS,
                                              set_io_mapping);
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JNS,
                                              set_io_mapping);

    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_ZF)) {

      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JE,
                                              set_io_mapping);
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JNE,
                                              set_io_mapping);
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JBE,
                                              set_io_mapping);
      jbe = true;
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JLE,
                                              set_io_mapping);
      jle = true;
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_CF)) {


      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JB,
                                              set_io_mapping);
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JAE,
                                              set_io_mapping);

      if(!jbe) {
        EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JBE,
                                                set_io_mapping);
      }
    }

    if((EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_ZF)) &&
       (EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_CF))) {

      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JA,
                                              set_io_mapping);
    }

    if((EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_SF)) &&
       (EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_OF))) {


      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JL,
                                              set_io_mapping);

      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JGE,
                                              set_io_mapping);

      if(!jle) {
        EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JLE,
                                                set_io_mapping);
      }

      if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_ZF)) {
        EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JG,
                                                set_io_mapping);
      }
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->x64.maybe_written_flags, EVOASM_X64_RFLAGS_FLAG_PF)) {

      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JP,
                                              set_io_mapping);
      EVOASM_TRY(error, evoasm_program_x64_emit_cond_transition, program, kernel, buf, jmp_reloc_addrs, EVOASM_X64_JMP_COND_JNP,
                                              set_io_mapping);
    }
  }

  return true;


error:
enc_failed:
  return false;
}


static evoasm_success_t
evoasm_program_x64_emit_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel, evoasm_buf_t *buf) {
  evoasm_buf_ref_t buf_ref = {
      .data = buf->data,
      .pos = &buf->pos
  };

  assert(kernel->size > 0);
  for(size_t i = 0; i < kernel->size; i++) {
    evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
    program->exception_mask = program->exception_mask | inst->exceptions;
    EVOASM_TRY(error, evoasm_x64_inst_enc_basic_, inst, &kernel->x64.params[i], &buf_ref);
  }
  return true;
error:
  return false;
}

static void
evoasm_program_topology_dfs(evoasm_program_topology_t *program_topology, size_t kernel_idx, size_t depth,
                            uint32_t *gray_depths) {
  size_t depth_bit = 1u << depth;

  gray_depths[kernel_idx] |= (uint32_t) depth_bit;
  program_topology->depth_bitmaps[kernel_idx] |= (uint32_t) depth_bit;

  for(size_t i = 0; i < EVOASM_X64_JMP_COND_NONE + 1; i++) {
    size_t succ_kernel_idx = program_topology->mat[kernel_idx][i];

    if(gray_depths[succ_kernel_idx] != 0) {
      program_topology->cycle_bitmap &= (1u << kernel_idx);
    }

    if(!(program_topology->depth_bitmaps[kernel_idx] & (1u << (depth + 1u)))) {
      evoasm_program_topology_dfs(program_topology, succ_kernel_idx, depth + 1, gray_depths);
    }
  }

  gray_depths[kernel_idx] &= ~(uint32_t)depth_bit;
}

void
evoasm_program_update_topology(evoasm_program_t *program, uint8_t *edges, size_t n_edges) {
  evoasm_program_topology_t *program_topology = &program->topology;

  memset(program_topology->mat, 0, sizeof(program_topology->mat));
  uint8_t n_conds = program->arch_info->n_conds;

  for(size_t i = 0; i < 3u * n_edges; i += 3) {
    uint8_t kernel_idx = edges[i];
    uint8_t succ_kernel_idx = edges[i + 1];
    uint8_t cond = edges[i + 2];
    uint8_t arch_cond;

    if(cond == UINT8_MAX) {
      arch_cond = n_conds;
    } else {
      arch_cond = cond % n_conds;
    }

    program_topology->mat[kernel_idx][arch_cond] = succ_kernel_idx;
  }

  uint32_t *gray_depths = evoasm_alloca(sizeof(uint32_t));
  evoasm_program_topology_dfs(program_topology, 0, 0, gray_depths);

  uint32_t depth_bitmap = 0;
  for(size_t i = 0; i < program->size; i++) {
    depth_bitmap |= program_topology->depth_bitmaps[i];
  }
  program_topology->depth_bitmap = depth_bitmap;
}

static evoasm_success_t
evoasm_program_x64_emit_program_kernels(evoasm_program_t *program, bool set_io_mapping) {
  evoasm_buf_t *buf = program->body_buf;
  evoasm_kernel_t *kernel;
  size_t program_size = program->size;
  uint32_t *jmp_reloc_addrs[EVOASM_PROGRAM_MAX_SIZE][EVOASM_X64_JMP_COND_NONE + 1] = {0};
  uint8_t *kernel_addrs[EVOASM_PROGRAM_MAX_SIZE];

  evoasm_buf_reset(buf);

  assert(program_size > 0);

  /* emit */
  for(size_t i = 0; i < program_size; i++) {
    /* no depth bit set means unreachable */
    if(!program->topology.depth_bitmaps[i]) continue;

    kernel = &program->kernels[i];

    kernel_addrs[i] = buf->data + buf->pos;
    kernel->buf_start = (uint16_t) buf->pos;

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel, program, kernel, buf);
    EVOASM_TRY(error, evoasm_program_x64_emit_cond_transitions, program, kernel, buf, jmp_reloc_addrs[i],
               set_io_mapping);
    EVOASM_TRY(error, evoasm_program_x64_emit_default_transition, program, kernel, buf,
               jmp_reloc_addrs[i][EVOASM_X64_JMP_COND_NONE], set_io_mapping);

    kernel->buf_end = (uint16_t) buf->pos;
  }

  /* link relocations */
  for(size_t i = 0; i < program_size; i++) {
    for(size_t j = 0; j < EVOASM_X64_JMP_COND_NONE + 1; j++) {
      size_t succ_kernel_idx = program->topology.mat[i][j];
      if(succ_kernel_idx < program->size) {
        uint32_t *jmp_reloc_addr = jmp_reloc_addrs[i][j];
        uint8_t *succ_kernel_addr = kernel_addrs[succ_kernel_idx];
        assert(*jmp_reloc_addr == 0xdeadbeef);
        EVOASM_BUF_SET_RELOC_ADDR32(jmp_reloc_addr, succ_kernel_addr);
      }
    }
  }

  return true;
error:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit_io_load_store(evoasm_program_t *program,
                                      evoasm_program_input_t *input,
                                      size_t input_win_off,
                                      size_t input_win_size,
                                      bool io_mapping) {

  size_t n_tuples = EVOASM_PROGRAM_INPUT_N_TUPLES(input);
  input_win_size = EVOASM_MIN(n_tuples, input_win_size);

  evoasm_buf_reset(program->buf);
  EVOASM_TRY(error, evoasm_x64_emit_func_prolog, EVOASM_X64_ABI_SYSV, program->buf);

  for(size_t i = 0; i < input_win_size; i++) {
    size_t tuple_idx = (input_win_off + i) % n_tuples;
    evoasm_program_io_val_t *input_vals = input->vals + tuple_idx * input->arity;
    EVOASM_TRY(error, evoasm_program_x64_emit_input_load, program, input_vals, input->types, input->arity,
               io_mapping);
    size_t r = evoasm_buf_append(program->buf, program->body_buf);
    (void) r;
    assert(r == 0);
    EVOASM_TRY(error, evoasm_program_x64_emit_output_store, program, tuple_idx);
  }

  EVOASM_TRY(error, evoasm_x64_emit_func_epilog, EVOASM_X64_ABI_SYSV, program->buf);
  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit(evoasm_program_t *program,
                        evoasm_program_input_t *input,
                        size_t input_win_off,
                        size_t input_win_size,
                        evoasm_program_emit_flags_t emit_flags) {

  bool set_io_mapping = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;

  if(emit_flags & EVOASM_PROGRAM_EMIT_FLAG_PREPARE) {
    bool preserve_output_regs = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_PRESERVE_OUTPUT_REGS;
    EVOASM_TRY(error, evoasm_program_x64_prepare, program, preserve_output_regs);
  }

  if(emit_flags & EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS) {
    EVOASM_TRY(error, evoasm_program_x64_emit_program_kernels, program, set_io_mapping);
  }

  if(emit_flags & EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE) {
    EVOASM_TRY(error, evoasm_program_x64_emit_io_load_store, program, input, input_win_off, input_win_size,
               set_io_mapping);
  }

  evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_DEBUG);

  return true;

error:
  return false;
}


typedef enum {
  EVOASM_METRIC_ABSDIFF,
  EVOASM_METRIC_NONE
} evoasm_metric;

static inline void
evoasm_program_update_dist_mat(evoasm_program_t *program,
                               evoasm_kernel_t *kernel,
                               evoasm_program_output_t *output,
                               size_t height,
                               size_t tuple_idx,
                               double *dist_mat,
                               evoasm_metric metric) {
  size_t width = kernel->n_output_regs;
  evoasm_program_io_val_t *io_vals = output->vals + tuple_idx * output->arity;

  for(size_t i = 0; i < height; i++) {
    evoasm_program_io_val_t io_val = io_vals[i];
    evoasm_program_io_val_type_t tuple_type = output->types[i];
    double io_val_dbl = evoasm_program_io_val_to_dbl(io_val, tuple_type);

    for(size_t j = 0; j < width; j++) {
      evoasm_program_io_val_t output_val = program->output_vals[tuple_idx * width + j];
      //uint8_t output_size = program->output_sizes[j];
      //switch(output_size) {
      //
      //}
      // FIXME: output is essentially just a bitstring and could be anything
      // an integer (both, signed or unsigned) a float or double.
      // Moreover, a portion of the output value could
      // hold the correct answer (e.g. lower 8 or 16 bits etc.).
      // For now we use the tuple output type and assume signedness.
      // This needs to be fixed.
      double output_val_dbl = evoasm_program_io_val_to_dbl(output_val, tuple_type);

      switch(metric) {
        default:
        case EVOASM_METRIC_ABSDIFF: {
          double dist = fabs(output_val_dbl - io_val_dbl);
          dist_mat[i * width + j] += dist;
          break;
        }
      }
    }
  }
}

static void
evoasm_program_log_program_output(evoasm_program_t *program,
                                  evoasm_kernel_t *kernel,
                                  evoasm_program_output_t *output,
                                  uint_fast8_t *const matching,
                                  evoasm_log_level_t log_level) {

  size_t n_tuples = EVOASM_PROGRAM_OUTPUT_N_TUPLES(output);
  size_t height = output->arity;
  size_t width = kernel->n_output_regs;

  evoasm_log(log_level, EVOASM_LOG_TAG, "OUTPUT MATRICES:\n");

  for(size_t i = 0; i < width; i++) {
    evoasm_log(log_level, EVOASM_LOG_TAG, " %d  ", kernel->x64.output_regs[i]);
  }

  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");

  for(size_t i = 0; i < n_tuples; i++) {
    for(size_t j = 0; j < height; j++) {
      for(size_t k = 0; k < width; k++) {
        bool matched = matching[j] == k;
        evoasm_program_io_val_t val = program->output_vals[i * width + k];

        if(matched) {
          evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[1m ");
        }
        evoasm_log(log_level, EVOASM_LOG_TAG, " %ld (%f)\t ", val.i64, val.f64);
        if(matched) {
          evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[0m ");
        }
      }
      evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
    }
    evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");
  }
}

static void
evoasm_program_log_dist_dist_mat(evoasm_program_t *program,
                                 evoasm_kernel_t *kernel,
                                 size_t height,
                                 double *dist_mat,
                                 uint_fast8_t *matching,
                                 evoasm_log_level_t log_level) {

  size_t width = kernel->n_output_regs;

  evoasm_log(log_level, EVOASM_LOG_TAG, "DIST MATRIX: (%zu, %zu)\n", height, width);
  for(size_t i = 0; i < height; i++) {
    for(size_t j = 0; j < width; j++) {
      if(matching[i] == j) {
        evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[1m ");
      }
      evoasm_log(log_level, EVOASM_LOG_TAG, " %.2g\t ", dist_mat[i * width + j]);
      if(matching[i] == j) {
        evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[0m ");
      }
    }
    evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
  }
  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");
}


static inline bool
evoasm_program_match(evoasm_program_t *program,
                     size_t width,
                     double *dist_mat,
                     uint_fast8_t *matching) {

  uint_fast8_t best_index = UINT_FAST8_MAX;
  double best_dist = INFINITY;
  uint_fast8_t i;

  for(i = 0; i < width; i++) {
    double v = dist_mat[i];
    if(v < best_dist) {
      best_dist = v;
      best_index = i;
    }
  }

  if(evoasm_likely(best_index != UINT_FAST8_MAX)) {
    *matching = best_index;
    return true;
  } else {
    /*evoasm_program_log_dist_dist_mat(program,
                                  1,
                                  dist_mat,
                                  matching,
                                  EVOASM_LOG_LEVEL_WARN);
    evoasm_assert_not_reached();*/
    /*
     * Might happen if all elements are inf or nan
     */
    return false;
  }
}

static inline void
evoasm_program_calc_stable_matching(evoasm_program_t *program,
                                    evoasm_kernel_t *kernel,
                                    size_t height,
                                    double *dist_mat,
                                    uint_fast8_t *matching) {

  uint_fast8_t width = (uint_fast8_t) kernel->n_output_regs;
  uint_fast8_t *inv_matching = evoasm_alloca(width * sizeof(uint_fast8_t));
  uint_fast8_t i;

  // calculates a stable matching
  for(i = 0; i < height; i++) {
    matching[i] = UINT_FAST8_MAX;
  }

  for(i = 0; i < width; i++) {
    inv_matching[i] = UINT_FAST8_MAX;
  }

  while(true) {
    uint_fast8_t unmatched_index = UINT_FAST8_MAX;
    uint_fast8_t best_index = UINT_FAST8_MAX;
    double best_dist = INFINITY;

    for(i = 0; i < height; i++) {
      if(matching[i] == UINT_FAST8_MAX) {
        unmatched_index = i;
        break;
      }
    }

    if(unmatched_index == UINT_FAST8_MAX) {
      break;
    }

    for(i = 0; i < width; i++) {
      double v = dist_mat[unmatched_index * width + i];
      if(v < best_dist) {
        best_dist = v;
        best_index = i;
      }
    }

    if(evoasm_likely(best_index != UINT_FAST8_MAX)) {
      if(inv_matching[best_index] == UINT_FAST8_MAX) {
        inv_matching[best_index] = unmatched_index;
        matching[unmatched_index] = best_index;
      } else {
        if(dist_mat[inv_matching[best_index] * width + best_index] > best_dist) {
          matching[inv_matching[best_index]] = UINT_FAST8_MAX;
          inv_matching[best_index] = unmatched_index;
          matching[unmatched_index] = best_index;
        } else {
          //dist_mat[unmatched_index * width + i] = copysign(best_dist, -1.0);
          dist_mat[unmatched_index * width + i] = INFINITY;
        }
      }
    } else {
      evoasm_program_log_dist_dist_mat(program,
                                       kernel,
                                       height,
                                       dist_mat,
                                       matching,
                                       EVOASM_LOG_LEVEL_DEBUG);
      evoasm_assert_not_reached();
    }
  }
}


static inline evoasm_loss_t
evoasm_program_calc_loss(evoasm_program_t *program,
                         evoasm_kernel_t *kernel,
                         size_t height,
                         size_t n_tuples,
                         double *dist_mat,
                         uint_fast8_t *matching) {
  size_t width = kernel->n_output_regs;
  double scale = 1.0 / (double) (width * n_tuples);
  double loss = 0.0;

  for(size_t i = 0; i < height; i++) {
    loss += (scale * dist_mat[i * width + matching[i]]);
  }

  return (evoasm_loss_t) loss;
}


static evoasm_loss_t
evoasm_program_assess(evoasm_program_t *program,
                      evoasm_program_output_t *output) {

  size_t n_tuples = EVOASM_PROGRAM_OUTPUT_N_TUPLES(output);
  size_t height = output->arity;
  evoasm_kernel_t *terminal_kernel = evoasm_program_get_terminal_kernel(program);
  size_t width = terminal_kernel->n_output_regs;
  size_t dist_mat_len = (size_t) (width * height);
  double *dist_mat = evoasm_alloca(dist_mat_len * sizeof(double));
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));
  evoasm_loss_t loss;

  for(size_t i = 0; i < dist_mat_len; i++) {
    dist_mat[i] = 0.0;
  }

  if(height == 1) {
    /* COMMON FAST-PATH */
    for(size_t i = 0; i < n_tuples; i++) {
      evoasm_program_update_dist_mat(program, terminal_kernel, output, 1, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    if(evoasm_program_match(program, width, dist_mat, matching)) {
      loss = evoasm_program_calc_loss(program, terminal_kernel, 1, n_tuples, dist_mat, matching);
    } else {
      loss = INFINITY;
    }
  } else {
    for(size_t i = 0; i < n_tuples; i++) {
      evoasm_program_update_dist_mat(program, terminal_kernel, output, height, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    evoasm_program_calc_stable_matching(program, terminal_kernel, height, dist_mat, matching);
    loss = evoasm_program_calc_loss(program, terminal_kernel, height, n_tuples, dist_mat, matching);
  }


  for(size_t i = 0; i < height; i++) {
    switch(program->arch_info->id) {
      case EVOASM_ARCH_X64: {
        program->output_regs[i] = terminal_kernel->x64.output_regs[matching[i]];
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }

#if EVOASM_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
  if(loss == 0.0) {
    evoasm_program_log_program_output(program,
                                      terminal_kernel,
                                      output,
                                      matching,
                                      EVOASM_LOG_LEVEL_DEBUG);
  }
#endif

  return loss;
}

static void
evoasm_program_reset_recur_counters(evoasm_program_t *program) {
  memset(program->recur_counters, 0, sizeof(program->recur_counters[0]) * program->size);
}

static inline evoasm_loss_t
evoasm_program_eval_(evoasm_program_t *program,
                     evoasm_program_output_t *output) {

  evoasm_kernel_t *terminal_kernel = evoasm_program_get_terminal_kernel(program);
  evoasm_loss_t loss;

  if(evoasm_unlikely(terminal_kernel->n_output_regs == 0)) {
    evoasm_log_info("program %p has no output", (void *) program);
    return INFINITY;
  }

  evoasm_program_reset_recur_counters(program);

  evoasm_signal_set_exception_mask(program->exception_mask);

#ifdef EVOASM_ENABLE_PARANOID_MODE
  for(size_t i = 0; i < program->size; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    for(size_t j = 0; j < EVOASM_X64_REG_NONE; j++) {
      kernel->rand_vals[j].i64 = rand() | (rand() << (rand() % 24));
    }
  }
#endif

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(program->buf);
    loss = evoasm_program_assess(program, output);
  } else {
    evoasm_log_debug("program %p signaled", (void *) program);
    loss = INFINITY;
  }

  evoasm_signal_clear_exception_mask();

  return loss;
}

evoasm_loss_t
evoasm_program_eval(evoasm_program_t *program,
                    evoasm_program_output_t *output) {

  evoasm_loss_t loss = evoasm_program_eval_(program, output);

#ifdef EVOASM_ENABLE_PARANOID_MODE
  for(size_t i = 0; i < 10; i++) {
    evoasm_loss_t loss_ = evoasm_program_eval_(program, output);

    if(loss_ != loss) {
      evoasm_program_log(program, EVOASM_LOG_LEVEL_WARN);
      evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_WARN);
    }
    assert(loss_ == loss);
  }
#endif

  return loss;
}

static evoasm_program_output_t *
evoasm_program_load_output(evoasm_program_t *program,
                           evoasm_kernel_t *kernel,
                           evoasm_program_input_t *input) {

  size_t width = kernel->n_output_regs;
  evoasm_program_output_t *output = &program->_output;
  size_t height = output->arity;
  size_t n_tuples = EVOASM_PROGRAM_INPUT_N_TUPLES(input);
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));

  evoasm_program_output_t *load_output = evoasm_program_io_alloc(
      (uint16_t) (EVOASM_PROGRAM_INPUT_N_TUPLES(input) * height));

  for(size_t i = 0; i < height; i++) {
    for(size_t j = 0; j < kernel->n_output_regs; j++) {
      if(program->output_regs[i] == kernel->x64.output_regs[j]) {
        matching[i] = (uint_fast8_t) j;
        goto next;
      }
    }
    evoasm_log_fatal("program output reg %d not found in kernel output regs", program->output_regs[i]);
    evoasm_assert_not_reached();
next:;
  }

  for(size_t i = 0; i < n_tuples; i++) {
    for(size_t j = 0; j < height; j++) {
      load_output->vals[i * height + j] = program->output_vals[i * width + matching[j]];
    }
  }

  load_output->arity = output->arity;
  memcpy(load_output->types, output->types, EVOASM_ARY_LEN(output->types));

#if EVOASM_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
  evoasm_program_log_program_output(program,
                                    kernel,
                                    load_output,
                                    matching,
                                    EVOASM_LOG_LEVEL_DEBUG);
#endif
  return load_output;
}

evoasm_program_output_t *
evoasm_program_run(evoasm_program_t *program,
                   evoasm_program_input_t *input) {
  evoasm_kernel_t *terminal_kernel = evoasm_program_get_terminal_kernel(program);
  evoasm_program_output_t *output;

  if(input->arity != program->_input.arity) {
    evoasm_error(EVOASM_ERROR_TYPE_PROGRAM, EVOASM_ERROR_CODE_NONE,
                 "arity mismatch (%d for %d)", input->arity, program->_input.arity);
    return NULL;
  }

  size_t n_tuples = EVOASM_PROGRAM_INPUT_N_TUPLES(input);
  if(n_tuples > program->max_tuples) {
    evoasm_error(EVOASM_ERROR_TYPE_PROGRAM, EVOASM_ERROR_CODE_NONE,
                 "Maximum number of input/output tuples exceeded (%zu > %d)", n_tuples, program->max_tuples);
    return NULL;
  }

  for(size_t i = 0; i < input->arity; i++) {
    if(input->types[i] != program->_input.types[i]) {
      evoasm_error(EVOASM_ERROR_TYPE_PROGRAM, EVOASM_ERROR_CODE_NONE,
                   "type mismatch (%d != %d)", input->types[i], program->_input.types[i]);
      return NULL;
    }
  }

  evoasm_program_emit_flags_t emit_flags = EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE;
  if(!evoasm_program_emit(program, input, 0, SIZE_MAX, emit_flags)) {
    return NULL;
  }

  evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_DEBUG);
  evoasm_signal_set_exception_mask(program->exception_mask);

  if(!evoasm_buf_protect(program->buf, EVOASM_MPROT_MODE_RX)) {
    evoasm_assert_not_reached();
  }

  evoasm_program_reset_recur_counters(program);

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(program->buf);
    output = evoasm_program_load_output(program,
                                        terminal_kernel,
                                        input);
  } else {
    evoasm_log_debug("signaled\n");
    output = NULL;
  }

  if(!evoasm_buf_protect(program->buf, EVOASM_MPROT_MODE_RW)) {
    evoasm_assert_not_reached();
  }

  evoasm_signal_clear_exception_mask();

  return output;
}

evoasm_success_t
evoasm_program_emit(evoasm_program_t *program,
                    evoasm_program_input_t *input,
                    size_t input_win_off,
                    size_t input_win_size,
                    evoasm_program_emit_flags_t emit_flags) {
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64: {
      return evoasm_program_x64_emit(program, input, input_win_off, input_win_size, emit_flags);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static size_t
evoasm_program_x64_find_writers(evoasm_program_t *program, evoasm_kernel_t *kernel,
                                size_t reader_inst_idx, evoasm_x64_reg_id_t reg_id,
                                evoasm_x64_operand_t *op, size_t *writers, bool *check_preds) {

  if(reader_inst_idx == 0) {
    *check_preds = true;
    return 0;
  }

  size_t len = 0;
  evoasm_x64_reg_cover_t reg_cover;
  evoasm_x64_reg_cover_init(&reg_cover);

  evoasm_x64_basic_params_t *params;
  evoasm_x64_inst_t *inst;

  if(reader_inst_idx < kernel->size) {
    params = &kernel->x64.params[reader_inst_idx];
    inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[reader_inst_idx]);
  } else {
    params = NULL;
    inst = NULL;
  }

  for(int i = (int) reader_inst_idx - 1; i >= 0; i--) {
    evoasm_x64_inst_t *writer_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);

    for(size_t j = 0; j < writer_inst->n_operands; j++) {
      evoasm_x64_operand_t *writer_op = &writer_inst->operands[j];
      evoasm_x64_reg_id_t writer_reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, writer_op, (size_t) i);

      if(writer_op->written && writer_reg_id == reg_id) {
        evoasm_x64_basic_params_t *writer_params = &kernel->x64.params[i];

        writers[len++] = (size_t) i;

        evoasm_x64_reg_cover_update(&reg_cover, writer_inst, writer_op, writer_params);

        /* if covered, any upstream writes have no direct effect on reg_id, so stop */
        if(evoasm_x64_reg_cover_is_covered(&reg_cover, inst, op, params)) {
          *check_preds = false;
          goto done;
        }
      }
    }
  }


done:
  return len;
}


typedef struct {
  bool change;
  evoasm_bitmap_max_kernel_size_t inst_bitmaps[EVOASM_PROGRAM_MAX_SIZE];
  evoasm_bitmap_max_output_regs_t output_regs_bitmaps[EVOASM_PROGRAM_MAX_SIZE];
  struct {
    evoasm_x64_operand_t x64[EVOASM_X64_REG_NONE];
  } output_reg_operands[EVOASM_PROGRAM_MAX_SIZE];
} evoasm_program_intron_elim_ctx_t;


#define EVOASM_LOG_INTRON_ELIM(...) evoasm_log(EVOASM_LOG_LEVEL_DEBUG, "program:intron_elim", __VA_ARGS__)

static void
evoasm_program_x64_mark_writers(evoasm_program_t *program, evoasm_kernel_t *kernel, size_t inst_idx,
                                evoasm_x64_operand_t *op, evoasm_program_intron_elim_ctx_t *ctx) {
  size_t writer_inst_idxs[EVOASM_KERNEL_MAX_SIZE];

  bool check_preds = true;

  EVOASM_LOG_INTRON_ELIM("Marking writers %d[%zu]\n", kernel->idx, inst_idx);

  evoasm_x64_reg_id_t reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, inst_idx);
  assert(reg_id != EVOASM_X64_REG_IP);

  size_t writers_len = evoasm_program_x64_find_writers(program, kernel, inst_idx, reg_id, op, writer_inst_idxs,
                                                       &check_preds);

  EVOASM_LOG_INTRON_ELIM("%d: Marking %zu writers to %s (check preds: %d) ---------------------\n",
                         kernel->idx, writers_len, evoasm_x64_get_reg_name(reg_id), check_preds);

  if(reg_id == EVOASM_X64_REG_RFLAGS) {
    for(size_t l = 0; l < EVOASM_X64_RFLAGS_FLAG_NONE; l++) {
      if(EVOASM_X64_RFLAGS_FLAGS_GET(op->read_flags, l)) {
        EVOASM_LOG_INTRON_ELIM("\tRFLAG: %s\n", evoasm_x64_get_rflags_flag_name(l));
      }
    }
  }

  for(size_t i = 0; i < writers_len; i++) {

    size_t writer_inst_idx = writer_inst_idxs[i];
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx->inst_bitmaps[kernel->idx];
    if(evoasm_bitmap_get(inst_bitmap, writer_inst_idx)) continue;

    evoasm_x64_inst_t *x64_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[writer_inst_idx]);
    evoasm_bitmap_set(inst_bitmap, writer_inst_idx);
    EVOASM_LOG_INTRON_ELIM("\tMarking %zuth writer to %s: %s (%zu)\n", i, evoasm_x64_get_reg_name(reg_id),
                           x64_inst->mnem, writer_inst_idx);
    ctx->change = true;

    for(size_t j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if(op->read && (op->type == EVOASM_X64_OPERAND_TYPE_REG || op->type == EVOASM_X64_OPERAND_TYPE_RM)) {
        evoasm_x64_reg_id_t op_reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, (uint16_t) writer_inst_idx);
        EVOASM_LOG_INTRON_ELIM("\t%s (%zu) reads %s\n", x64_inst->mnem, writer_inst_idx,
                               evoasm_x64_get_reg_name(op_reg_id));

        evoasm_program_x64_mark_writers(program, kernel, writer_inst_idx, op, ctx);
      }
    }
  }

  if(check_preds) {
    /* need to continue mark on predecessor kernels,
     * since loops are possible we use a fixpoint approach
     * and just set the output register operand on the predecessor kernel */

    for(size_t k = 0; k < program->size; k++) {
      if(k == kernel->idx) continue;

      for(size_t cond = 0; cond < EVOASM_X64_JMP_COND_NONE + 1; cond++) {
        if(program->topology.mat[k][cond] == kernel->idx) {
          evoasm_kernel_t *pred_kernel = &program->kernels[k];
          evoasm_x64_reg_id_t trans_reg_id;

          if(reg_id == EVOASM_X64_REG_RFLAGS) {
            trans_reg_id = EVOASM_X64_REG_RFLAGS;
          } else {
            trans_reg_id = pred_kernel->x64.trans_regs.trans_regs[cond][reg_id];
          }

          EVOASM_LOG_INTRON_ELIM("\t\tMarking %zu.%s (trans %zu)\n", k, evoasm_x64_get_reg_name(trans_reg_id),
                                 cond);

          if(reg_id == EVOASM_X64_REG_RFLAGS) {
            for(size_t l = 0; l < EVOASM_X64_RFLAGS_FLAG_NONE; l++) {
              if(EVOASM_X64_RFLAGS_FLAGS_GET(op->read_flags, l)) {
                EVOASM_LOG_INTRON_ELIM("\t\t\tRFLAG: %s\n", evoasm_x64_get_rflags_flag_name(l));
              }
            }
          }

          assert(trans_reg_id != EVOASM_X64_REG_IP);

          evoasm_x64_operand_t *trans_op = &ctx->output_reg_operands[k].x64[trans_reg_id];

          if(!evoasm_bitmap_get((evoasm_bitmap_t *) &ctx->output_regs_bitmaps[k], trans_reg_id)) {
            *trans_op = *op;
            trans_op->implicit = true;

            if(reg_id != EVOASM_X64_REG_RFLAGS) {
              trans_op->reg_id = trans_reg_id;
            }
            evoasm_bitmap_set((evoasm_bitmap_t *) &ctx->output_regs_bitmaps[k], trans_reg_id);
          } else {
            if(reg_id != EVOASM_X64_REG_RFLAGS) {
              trans_op->word = EVOASM_MAX(trans_op->word, op->word) & EVOASM_X64_OPERAND_WORD_BITSIZE_OPT;
            } else {
              trans_op->written_flags |= op->written_flags;
              trans_op->read_flags |= op->read_flags;
            }
          }
        }
      }
    }
  }

  EVOASM_LOG_INTRON_ELIM("---------------------------------\n");
}

static evoasm_success_t
evoasm_program_mark_kernel(evoasm_program_t *program, evoasm_program_t *dst_program, size_t kernel_idx,
                           evoasm_program_intron_elim_ctx_t *ctx) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  evoasm_kernel_t *dst_kernel = &dst_program->kernels[kernel_idx];
  EVOASM_LOG_INTRON_ELIM("Marking kernel %zu\n", kernel_idx);
  for(evoasm_x64_reg_id_t reg_id = (evoasm_x64_reg_id_t) 0; reg_id < EVOASM_X64_REG_NONE; reg_id++) {
    evoasm_x64_operand_t *output_reg_operand = &ctx->output_reg_operands[kernel_idx].x64[reg_id];
    if(evoasm_bitmap_get((evoasm_bitmap_t *) &ctx->output_regs_bitmaps[kernel_idx], reg_id)) {
      EVOASM_LOG_INTRON_ELIM("Marking kernel %d, output reg %s\n", kernel->idx, evoasm_x64_get_reg_name(reg_id));
      assert(output_reg_operand->implicit);
      evoasm_program_x64_mark_writers(program, kernel, kernel->size, output_reg_operand, ctx);

      dst_kernel->x64.output_regs[dst_kernel->n_output_regs++] = reg_id;

      evoasm_bitmap_unset((evoasm_bitmap_t *) &ctx->output_regs_bitmaps[kernel_idx], reg_id);
    }
  }

  return true;
}

evoasm_success_t
evoasm_program_elim_introns(evoasm_program_t *program, evoasm_program_t *dst_program) {
  size_t term_kernel_idx = (size_t) program->topology.backbone_len;
  evoasm_program_intron_elim_ctx_t ctx = {0};


  EVOASM_TRY(error, evoasm_program_init,
             dst_program,
             program->arch_info,
             program->size,
             program->kernels[0].size,
             program->max_tuples,
             program->recur_limit,
             false);

  for(size_t i = 0; i < program->_output.arity; i++) {
    evoasm_x64_reg_id_t output_reg = (evoasm_x64_reg_id_t) program->output_regs[i];
    evoasm_x64_reg_type_t output_reg_type = evoasm_x64_get_reg_type(output_reg);
    evoasm_x64_operand_t *output_reg_operand = &ctx.output_reg_operands[term_kernel_idx].x64[output_reg];

    evoasm_bitmap_set((evoasm_bitmap_t *) &ctx.output_regs_bitmaps[term_kernel_idx], output_reg);

    output_reg_operand->type = EVOASM_X64_OPERAND_TYPE_REG;
    output_reg_operand->reg_type = output_reg_type;
    output_reg_operand->implicit = true;
    output_reg_operand->read = true;
    output_reg_operand->reg_id = output_reg;

    switch(output_reg_type) {
      case EVOASM_X64_REG_TYPE_GP:
        output_reg_operand->word = EVOASM_X64_OPERAND_WORD_LQW;
        break;
      case EVOASM_X64_REG_TYPE_XMM:
      case EVOASM_X64_REG_TYPE_ZMM: {
        size_t reg_size = evoasm_x64_get_reg_type_bytesize(output_reg_type);
        if(reg_size == 16) {
          output_reg_operand->word = EVOASM_X64_OPERAND_WORD_DQW;
        } else {
          assert(reg_size == 32 || reg_size == 64);
          output_reg_operand->word = EVOASM_X64_OPERAND_WORD_VW;
        }
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
    EVOASM_LOG_INTRON_ELIM("Marking %s as output\n", evoasm_x64_get_reg_name(output_reg));

  }

  do {
    ctx.change = false;
    for(int i = (int) term_kernel_idx; i >= 0; i--) {
      EVOASM_TRY(error, evoasm_program_mark_kernel, program, dst_program, (size_t) i, &ctx);
    }
  } while(ctx.change);

  /* sweep */
  for(size_t i = 0; i <= term_kernel_idx; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    evoasm_kernel_t *dst_kernel = &dst_program->kernels[i];
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx.inst_bitmaps[i];

    size_t k = 0;
    for(size_t j = 0; j < kernel->size; j++) {
      if(evoasm_bitmap_get(inst_bitmap, j)) {
        dst_kernel->insts[k] = kernel->insts[j];
        dst_kernel->x64.params[k] = kernel->x64.params[j];
        k++;
      }
    }

    if(dst_kernel != kernel) {
      dst_kernel->size = (uint16_t) k;
      dst_kernel->x64.reg_info = kernel->x64.reg_info;
      dst_kernel->x64.trans_regs = kernel->x64.trans_regs;
      dst_kernel->n_input_regs = kernel->n_input_regs;
    }

    assert(dst_kernel->n_output_regs > 0);
  }

  if(dst_program != program) {
    dst_program->_input = program->_input;
    dst_program->_output = program->_output;
    dst_program->reg_inputs = program->reg_inputs;
    memcpy(dst_program->output_regs, program->output_regs, sizeof(program->output_regs));
    dst_program->topology = program->topology;
  }

  evoasm_program_emit_flags_t emit_flags =
      EVOASM_PROGRAM_EMIT_FLAG_PREPARE |
      EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS |
      EVOASM_PROGRAM_EMIT_FLAG_PRESERVE_OUTPUT_REGS;

  EVOASM_TRY(error, evoasm_program_emit, dst_program, NULL, 0, SIZE_MAX, emit_flags);

  return true;
error:
  return false;
}

#undef EVOASM_LOG_INTRON_ELIM


#define EVOASM_PROGRAM_PROLOG_EPILOG_SIZE UINT32_C(1024)
#define EVOASM_PROGRAM_TRANSITION_SIZE UINT32_C(512)


evoasm_success_t
evoasm_program_init(evoasm_program_t *program,
                    evoasm_arch_info_t *arch_info,
                    size_t program_size,
                    size_t kernel_size,
                    size_t max_tuples,
                    size_t recur_limit,
                    bool shallow) {

  static evoasm_program_t zero_program = {0};
  size_t n_transitions = program_size - 1u;

  *program = zero_program;
  program->arch_info = arch_info;
  program->recur_limit = (uint32_t) recur_limit;
  program->shallow = shallow;
  program->size = (uint16_t) program_size;
  program->max_tuples = (uint16_t) max_tuples;

  size_t body_buf_size =
      (size_t) (n_transitions * EVOASM_PROGRAM_TRANSITION_SIZE
                + program_size * kernel_size * program->arch_info->max_inst_len);

  size_t buf_size = max_tuples * (body_buf_size + EVOASM_PROGRAM_PROLOG_EPILOG_SIZE);

  EVOASM_TRY(error, evoasm_buf_init, &program->_buf, EVOASM_BUF_TYPE_MMAP, buf_size);
  program->buf = &program->_buf;

  EVOASM_TRY(error, evoasm_buf_init, &program->_body_buf, EVOASM_BUF_TYPE_MALLOC, body_buf_size);
  program->body_buf = &program->_body_buf;

  EVOASM_TRY(error, evoasm_buf_protect, &program->_buf,
             EVOASM_MPROT_MODE_RWX);

  size_t output_vals_len = max_tuples * EVOASM_KERNEL_MAX_OUTPUT_REGS;

  EVOASM_TRY_ALLOC(error, calloc, program->output_vals, output_vals_len, sizeof(evoasm_program_io_val_t));
  EVOASM_TRY_ALLOC(error, calloc, program->kernels, program_size, sizeof(evoasm_kernel_t));
  EVOASM_TRY_ALLOC(error, calloc, program->recur_counters, program_size, sizeof(uint32_t));

  for(uint16_t i = 0; i < program_size; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];

    kernel->idx = i;
    kernel->size = (uint16_t) kernel_size;

    if(!shallow) {
      EVOASM_TRY_ALLOC(error, calloc, kernel->insts, kernel_size, sizeof(kernel->insts[0]));
      switch(program->arch_info->id) {
        case EVOASM_ARCH_X64: {
          EVOASM_TRY_ALLOC(error, calloc, kernel->x64.params, kernel_size, sizeof(kernel->x64.params[0]));
          break;
        }
        default:
          evoasm_assert_not_reached();
      }
    }
  }


  return true;

error:
  EVOASM_TRY_WARN(evoasm_program_destroy, program);
  return false;
}

void
evoasm_kernel_log(evoasm_kernel_t *kernel, evoasm_arch_id_t arch_id, evoasm_log_level_t log_level) {
  if(_evoasm_log_level > log_level) return;

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      for(size_t i = 0; i < kernel->size; i++) {
        evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
        const char *mnem = evoasm_x64_inst_get_mnem(inst);
        evoasm_log(log_level, EVOASM_LOG_TAG, "%s", mnem);
      }
      break;
    default:
      evoasm_assert_not_reached();
  }
}

void
evoasm_program_log(evoasm_program_t *program, evoasm_log_level_t log_level) {
  if(_evoasm_log_level > log_level) return;

  evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Program: size: %d", program->size);

  for(size_t i = 0; i < program->size; i++) {
    evoasm_kernel_log(&program->kernels[i], (evoasm_arch_id_t) program->arch_info->id, log_level);
  }
  evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
}

EVOASM_DEF_ALLOC_FREE_FUNCS(program)
