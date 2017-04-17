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
#include "evoasm-kernel.h"
#include "evoasm-arch.h"
#include "evoasm.h"
#include "evoasm-x64.h"
#include "evoasm-param.h"
#include "evoasm-kernel-io.h"
#include "evoasm-buf.h"


EVOASM_DEF_LOG_TAG("kernel")

bool
evoasm_kernel_destroy(evoasm_kernel_t *kernel) {

  bool retval = true;

  if(!kernel->shallow) {
    evoasm_free(kernel->insts);
    switch(kernel->arch_info->id) {
      case EVOASM_ARCH_X64:
        evoasm_free(kernel->x64.params);
        break;
      default:
        evoasm_assert_not_reached();
    }
  }

  evoasm_free(kernel->output_vals);

  if(kernel->buf) {
    if(!evoasm_buf_destroy(kernel->buf)) {
      retval = false;
    }
  }

  return retval;
}

#if 0
evoasm_success_t
evoasm_kernel_clone(evoasm_kernel_t *kernel, evoasm_kernel_t *cloned_program) {
  size_t i = 0;

  *cloned_program = *kernel;
  cloned_program->reset_rflags = false;
  cloned_program->_input.len = 0;
  cloned_program->_output.len = 0;
  cloned_program->output_vals = NULL;
  cloned_program->buf = NULL;
  cloned_program->body_buf = NULL;

  /* memory addresses in original buffer point to memory in original kernel,
   * we need to reemit assembly, this is done in a lazy fashion */
  cloned_program->need_emit = true;

  EVOASM_TRY(error, evoasm_buf_clone, kernel->buf, &cloned_program->_buf);
  cloned_program->buf = &cloned_program->_buf;
  EVOASM_TRY(error, evoasm_buf_clone, kernel->body_buf, &cloned_program->_body_buf);
  cloned_program->body_buf = &cloned_program->_body_buf;

  size_t program_params_size = sizeof(evoasm_kernel_params_t);
  cloned_program->params = evoasm_malloc(program_params_size);

  if(!cloned_program->params) {
    goto error;
  }

  memcpy(cloned_program->params, kernel->params, program_params_size);

  for(; i < kernel->size; i++) {
    evoasm_kernel_t *orig_kernel = &kernel->kernels[i];
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
  (void) evoasm_kernel_destroy_(cloned_program, i);
  return false;
}
#endif

evoasm_buf_t *
evoasm_kernel_get_buf(evoasm_kernel_t *kernel) {
  return kernel->buf;
}

size_t
evoasm_kernel_get_size(evoasm_kernel_t *kernel) {
  return kernel->size;
}

size_t
evoasm_kernel_get_code(evoasm_kernel_t *kernel, bool frame, const uint8_t **code) {
  size_t len;

  if(frame) {
    *code = kernel->buf->data;
    len = kernel->buf->pos;
  } else {
    *code = kernel->buf->data + kernel->buf_pos_body_start;
    len = (size_t) (kernel->buf_pos_body_end - kernel->buf_pos_body_start);
  }
  return len;
}

bool
evoasm_kernel_is_input_reg(evoasm_kernel_t *kernel, evoasm_reg_id_t reg_id) {
  switch(kernel->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->x64.reg_info.reg_info[reg_id].input;
    default:
      evoasm_assert_not_reached();
  }
}

bool
evoasm_kernel_is_output_reg(evoasm_kernel_t *kernel, evoasm_reg_id_t reg_id) {
  switch(kernel->arch_info->id) {
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
evoasm_kernel_get_output_reg(evoasm_kernel_t *kernel, size_t idx) {
  if(idx >= EVOASM_KERNEL_OUTPUT_MAX_ARITY) return EVOASM_X64_REG_NONE;
  return kernel->output_reg_mapping[idx];
}

size_t
evoasm_kernel_get_arity(evoasm_kernel_t *kernel) {
  return kernel->_output.arity;
}

static evoasm_success_t
evoasm_kernel_x64_emit_rflags_reset(evoasm_kernel_t *kernel) {
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = kernel->buf;

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
evoasm_kernel_x64_emit_mxcsr_reset(evoasm_kernel_t *kernel) {
  static uint32_t default_mxcsr_val = 0x1f80;
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = kernel->buf;

  evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) &default_mxcsr_val;
  evoasm_x64_reg_id_t reg_tmp0 = EVOASM_X64_SCRATCH_REG1;

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg_tmp0);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
  EVOASM_X64_ENC(mov_r32_imm32);

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, reg_tmp0);
  EVOASM_X64_ENC(ldmxcsr_m32);

  return true;
enc_failed:
  return false;
}

static evoasm_success_t
evoasm_kernel_x64_emit_output_store(evoasm_kernel_t *kernel,
                                    size_t tuple_idx) {

  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = kernel->buf;
  bool have_avx = evoasm_x64_have_avx();

  for(size_t i = 0; i < kernel->n_output_regs; i++) {
    evoasm_x64_reg_id_t reg_id = kernel->x64.output_regs[i];
    evoasm_kernel_io_val_t *val_addr =
        &kernel->output_vals[(tuple_idx * kernel->n_output_regs) + i];

    evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(reg_id);

    evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) val_addr;

    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_X64_SCRATCH_REG1);
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
    EVOASM_X64_ENC(mov_r64_imm64);

    switch(reg_type) {
      case EVOASM_X64_REG_TYPE_GP: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_SCRATCH_REG1);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_ENC(mov_rm64_r64);
        break;
      }
      case EVOASM_X64_REG_TYPE_XMM: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_SCRATCH_REG1);

        if(have_avx) {
          EVOASM_X64_ENC(movdqa_xmmm128_xmm);
        } else {
          EVOASM_X64_ENC(vmovdqa_ymmm256_ymm);
        }
        break;
      }
      case EVOASM_X64_REG_TYPE_RFLAGS: {
        EVOASM_X64_ENC(pushfq);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_X64_SCRATCH_REG2);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_REG_SP);
        EVOASM_X64_ENC(mov_r64_rm64);

        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_SCRATCH_REG1);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, EVOASM_X64_SCRATCH_REG2);
        EVOASM_X64_ENC(mov_rm64_r64);
        EVOASM_X64_ENC(popfq);
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
        evoasm_bitmap_or64(mask, 0, evoasm_x64_rflags_flag_get_mask_(flag));
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
evoasm_kernel_x64_prepare(evoasm_kernel_t *kernel, bool preserve_output_regs) {
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

  /* FIXME: this could in theory happen after intron elimination
   * in which case the elimination process should remove the whole kernel */
  assert(kernel->size > 0);

  /* First, handle read ops, so that writing ops do not disturb us */
  for(size_t i = 0; i < kernel->size; i++) {
    evoasm_x64_inst_t *x64_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
    evoasm_x64_basic_params_t *x64_basic_params = &kernel->x64.params[i];

    for(size_t j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if((op->read || op->maybe_written) &&
         (op->type == EVOASM_X64_OPERAND_TYPE_REG || op->type == EVOASM_X64_OPERAND_TYPE_RM)) {

        /*if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
          kernel->reset_rflags = true;
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
          kernel->x64.maybe_written_flags =
              (kernel->x64.maybe_written_flags | op->maybe_written_flags) & EVOASM_X64_RFLAGS_FLAGS_BITSIZE;
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
      if(kernel->x64.reg_info.reg_info[i].input) n_input_regs++;
    }
    assert(n_input_regs == kernel->n_input_regs);
  }
#endif

  assert(kernel->n_output_regs <= EVOASM_KERNEL_MAX_OUTPUT_REGS);
  assert(kernel->n_input_regs <= EVOASM_KERNEL_MAX_INPUT_REGS);

  if(kernel->n_output_regs == 0) {
    evoasm_error(EVOASM_ERROR_TYPE_KERNEL, EVOASM_PROGRAM_ERROR_CODE_NO_OUTPUT, "no output registers in kernel");
    return false;
  }

  return true;
}

static const evoasm_x64_inst_enc_func_t xmm_load_funcs[2][EVOASM_KERNEL_IO_VAL_TYPE_NONE] = {
    [false] = {
      [EVOASM_KERNEL_IO_VAL_TYPE_I64X1] = evoasm_x64_movq_xmm_rm64,
      [EVOASM_KERNEL_IO_VAL_TYPE_U64X1] = evoasm_x64_movq_xmm_rm64,
      [EVOASM_KERNEL_IO_VAL_TYPE_F32X1] = evoasm_x64_movss_xmm_xmmm32,
      [EVOASM_KERNEL_IO_VAL_TYPE_F64X1] = evoasm_x64_movsd_xmm_xmmm64,
      [EVOASM_KERNEL_IO_VAL_TYPE_I64X2] = evoasm_x64_movdqa_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_U64X2] = evoasm_x64_movdqa_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_F64X2] = evoasm_x64_movapd_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_I32X4] = evoasm_x64_movaps_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_U32X4] = evoasm_x64_movaps_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_F32X4] = evoasm_x64_movaps_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_I16X8] = evoasm_x64_movdqa_xmm_xmmm128,
      [EVOASM_KERNEL_IO_VAL_TYPE_U16X8] = evoasm_x64_movdqa_xmm_xmmm128,
    },
    [true] = {
        [EVOASM_KERNEL_IO_VAL_TYPE_I64X1] = evoasm_x64_vmovq_xmm_rm64,
        [EVOASM_KERNEL_IO_VAL_TYPE_U64X1] = evoasm_x64_vmovq_xmm_rm64,
        [EVOASM_KERNEL_IO_VAL_TYPE_F32X1] = evoasm_x64_vmovss_xmm_m32,
        [EVOASM_KERNEL_IO_VAL_TYPE_F64X1] = evoasm_x64_vmovsd_xmm_m64,
        [EVOASM_KERNEL_IO_VAL_TYPE_I64X2] = evoasm_x64_vmovdqa_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_U64X2] = evoasm_x64_vmovdqa_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_F64X2] = evoasm_x64_vmovapd_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_I32X4] = evoasm_x64_vmovaps_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_U32X4] = evoasm_x64_vmovaps_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_F32X4] = evoasm_x64_vmovaps_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_F64x4] = evoasm_x64_vmovapd_ymm_ymmm256,
        [EVOASM_KERNEL_IO_VAL_TYPE_I16X8] = evoasm_x64_movdqa_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_U16X8] = evoasm_x64_movdqa_xmm_xmmm128,
        [EVOASM_KERNEL_IO_VAL_TYPE_F32X8] = evoasm_x64_vmovaps_ymm_ymmm256,
        [EVOASM_KERNEL_IO_VAL_TYPE_I8X16] = evoasm_x64_vmovdqa_ymm_ymmm256,
        [EVOASM_KERNEL_IO_VAL_TYPE_U8X16] = evoasm_x64_vmovdqa_ymm_ymmm256
    }
};

static const evoasm_used evoasm_x64_inst_enc_func_t xmm_store_funcs[2][EVOASM_KERNEL_IO_VAL_TYPE_NONE] = {
    [false] = {
      [EVOASM_KERNEL_IO_VAL_TYPE_I64X1] = evoasm_x64_movq_rm64_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_U64X1] = evoasm_x64_movq_rm64_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_F32X1] = evoasm_x64_movss_xmmm32_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_F64X1] = evoasm_x64_movsd_xmmm64_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_I64X2] = evoasm_x64_movdqa_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_U64X2] = evoasm_x64_movdqa_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_F64X2] = evoasm_x64_movapd_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_I32X4] = evoasm_x64_movaps_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_U32X4] = evoasm_x64_movaps_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_F32X4] = evoasm_x64_movaps_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_F64x4] = NULL,
      [EVOASM_KERNEL_IO_VAL_TYPE_I16X8] = evoasm_x64_movdqa_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_U16X8] = evoasm_x64_movdqa_xmmm128_xmm,
      [EVOASM_KERNEL_IO_VAL_TYPE_F32X8] = NULL,
      [EVOASM_KERNEL_IO_VAL_TYPE_I8X16] = NULL,
      [EVOASM_KERNEL_IO_VAL_TYPE_U8X16] = NULL
    },
    [true] = {
        [EVOASM_KERNEL_IO_VAL_TYPE_I64X1] = evoasm_x64_vmovq_rm64_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_U64X1] = evoasm_x64_vmovq_rm64_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_F32X1] = evoasm_x64_vmovss_m32_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_F64X1] = evoasm_x64_vmovsd_m64_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_I64X2] = evoasm_x64_vmovdqa_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_U64X2] = evoasm_x64_vmovdqa_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_F64X2] = evoasm_x64_vmovapd_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_I32X4] = evoasm_x64_vmovaps_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_U32X4] = evoasm_x64_vmovaps_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_F32X4] = evoasm_x64_vmovaps_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_F64x4] = evoasm_x64_vmovapd_ymmm256_ymm,
        [EVOASM_KERNEL_IO_VAL_TYPE_I16X8] = evoasm_x64_movdqa_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_U16X8] = evoasm_x64_movdqa_xmmm128_xmm,
        [EVOASM_KERNEL_IO_VAL_TYPE_F32X8] = evoasm_x64_vmovaps_ymmm256_ymm,
        [EVOASM_KERNEL_IO_VAL_TYPE_I8X16] = evoasm_x64_vmovdqa_ymmm256_ymm,
        [EVOASM_KERNEL_IO_VAL_TYPE_U8X16] = evoasm_x64_vmovdqa_ymmm256_ymm
    }
};

static evoasm_success_t
evoasm_kernel_x64_emit_input_reg_load(evoasm_kernel_t *kernel,
                                      evoasm_x64_reg_id_t input_reg_id,
                                      evoasm_buf_t *buf,
                                      evoasm_kernel_io_val_t *arg,
                                      evoasm_kernel_io_val_type_t arg_type,
                                      evoasm_kernel_io_val_t **loaded_arg,
                                      bool force_load) {

  evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(input_reg_id);
  evoasm_x64_params_t params = {0};

  bool have_avx = evoasm_x64_have_avx();

  evoasm_log_debug("emitting _input register initialization of register %d to value %"
                       PRId64, input_reg_id, arg->i64[0]);

  switch(reg_type) {
    case EVOASM_X64_REG_TYPE_GP: {
      if(force_load) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_X64_SCRATCH_REG1);
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) arg);
        EVOASM_X64_ENC(mov_r64_imm64);

        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_SCRATCH_REG1);
        EVOASM_X64_ENC(mov_r64_rm64);
      } else {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        /*FIXME: hard-coded arg type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) arg->i64[0]);
        EVOASM_X64_ENC(mov_r64_imm64);
      }
      break;
    }
    case EVOASM_X64_REG_TYPE_XMM: {
      /* load address of arg into tmp_reg */
      if(*loaded_arg != arg) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_X64_SCRATCH_REG1);
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) arg);
        EVOASM_X64_ENC(mov_r64_imm64);
        *loaded_arg = arg;
      }

      assert((uintptr_t) arg % 16 == 0);

      evoasm_x64_inst_enc_func_t enc_func = xmm_load_funcs[have_avx][arg_type];

      if(evoasm_unlikely(enc_func == NULL)) {
        evoasm_error(EVOASM_ERROR_TYPE_KERNEL, EVOASM_ERROR_CODE_NONE,
                     "value type %s is not supported on this system",  evoasm_kernel_io_val_type_get_name(arg_type));
        return false;
      }

      /* load into xmm via address in tmp_reg */
      EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
      EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_SCRATCH_REG1);

      {
        evoasm_x64_enc_ctx_t enc_ctx = {
            .params = params,
            .buf_ref = {
                .data = (buf)->data,
                .pos = &(buf->pos)
            }
        };

        enc_func(&enc_ctx);
      }

      break;
    }
    case EVOASM_X64_REG_TYPE_RFLAGS:
      kernel->reset_rflags = true;
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
evoasm_kernel_x64_emit_input_load(evoasm_kernel_t *kernel,
                                  evoasm_kernel_input_t *input,
                                  size_t tuple_idx,
                                  bool set_io_mapping) {

//  evoasm_kernel_io_val_t *input_vals = input->vals + tuple_idx * input->arity;

  evoasm_kernel_io_val_t *loaded_arg = NULL;
  evoasm_buf_t *buf = kernel->buf;

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

  evoasm_bitmap64_t used_args = {0};
  size_t non_fitting_arg_counter = 0;

  {
//    size_t input_reg_idx = 0;
    for(evoasm_x64_reg_id_t input_reg = (evoasm_x64_reg_id_t) 0; input_reg < EVOASM_X64_REG_NONE; input_reg++) {
      if(!kernel->x64.reg_info.reg_info[input_reg].input) continue;

      size_t arg_idx;

      if(set_io_mapping) {
        evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(input_reg);
        size_t reg_bytesize = evoasm_x64_reg_type_get_bytesize(reg_type);

        size_t largest_fitting_arg_idx = 0;
        size_t largest_fitting_arg_bytesize = 0;

        if(evoasm_bitmap64_popcount(&used_args) == input->arity) {
          evoasm_bitmap64_clear(&used_args);
        }

        for(size_t i = 0; i < input->arity; i++) {
          if(evoasm_bitmap_get((evoasm_bitmap_t *) &used_args, i)) continue;

          evoasm_kernel_io_val_type_t arg_type = evoasm_kernel_io_get_type_(input, i);
          size_t arg_bytesize = evoasm_kernel_io_val_type_get_bytesize(arg_type);

          if(reg_bytesize >= arg_bytesize && arg_bytesize > largest_fitting_arg_bytesize) {
            largest_fitting_arg_bytesize = arg_bytesize;
            largest_fitting_arg_idx = i;
          }
        }

        if(largest_fitting_arg_bytesize == 0) {
          arg_idx = non_fitting_arg_counter++;
        } else {
          arg_idx = largest_fitting_arg_idx;
        }

        evoasm_bitmap_set((evoasm_bitmap_t *) &used_args, arg_idx);
        kernel->x64.reg_input_mapping[input_reg] = (uint8_t) arg_idx;

      } else {
        arg_idx = kernel->x64.reg_input_mapping[input_reg];
      }

      evoasm_kernel_io_val_t *arg = evoasm_kernel_io_get_val_(input, tuple_idx, arg_idx);
      evoasm_kernel_io_val_type_t arg_type = evoasm_kernel_io_get_type_(input, arg_idx);

      EVOASM_TRY(error, evoasm_kernel_x64_emit_input_reg_load, kernel, input_reg, buf, arg, arg_type, &loaded_arg,
                 false);
    }
  }

#ifdef EVOASM_ENABLE_PARANOID_MODE
  EVOASM_TRY(error, evoasm_x64_emit_push, EVOASM_X64_SCRATCH_REG1, buf);
  for(evoasm_x64_reg_id_t non_input_reg = (evoasm_x64_reg_id_t) EVOASM_X64_REG_A;
      non_input_reg < EVOASM_X64_REG_15; non_input_reg++) {
    if(kernel->x64.reg_info.reg_info[non_input_reg].input) continue;
    if(non_input_reg == EVOASM_X64_REG_SP) continue;

    evoasm_kernel_io_val_t *tuple = &kernel->rand_vals[non_input_reg];
    EVOASM_TRY(error, evoasm_kernel_x64_emit_input_reg_load, kernel, non_input_reg, buf, tuple, NULL, true);
  }
  EVOASM_TRY(error, evoasm_x64_emit_pop, EVOASM_X64_SCRATCH_REG1, buf);
#endif

  if(kernel->reset_rflags) {
    EVOASM_TRY(error, evoasm_kernel_x64_emit_rflags_reset, kernel);
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_kernel_x64_emit_body(evoasm_kernel_t *kernel) {

  evoasm_buf_t *buf = kernel->buf;
  evoasm_buf_ref_t buf_ref = {
      .data = buf->data,
      .pos = &buf->pos
  };

  assert(kernel->size > 0);

  kernel->buf_pos_body_start = (uint16_t) buf->pos;

  for(size_t i = 0; i < kernel->size; i++) {
    evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
    kernel->exception_mask = kernel->exception_mask | inst->exceptions;
    EVOASM_TRY(error, evoasm_x64_inst_enc_basic_, inst, &kernel->x64.params[i], &buf_ref);
  }

  kernel->buf_pos_body_end = (uint16_t) buf->pos;


  return true;
error:
  return false;
}

//static evoasm_success_t
//evoasm_kernel_x64_emit_kernels(evoasm_kernel_t *kernel, bool set_io_mapping) {
//  evoasm_buf_t *buf = kernel->buf;
//  evoasm_kernel_t *kernel;
//  size_t n_kernels = kernel->topo.size;
//  uint32_t *transn_link_addrs[EVOASM_PROGRAM_TOPO_MAX_SIZE][EVOASM_X64_JMP_COND_NONE + 1] = {0};
//  uint8_t *kernel_addrs[EVOASM_PROGRAM_TOPO_MAX_SIZE];
//  uint32_t *guard_link_addrs[EVOASM_PROGRAM_TOPO_MAX_SIZE];
//  size_t term_kernel_idx = evoasm_kernel_get_term_kernel_idx(kernel);
//
//  kernel->buf_pos_kernels_start = (uint16_t) buf->pos;
//
//  assert(n_kernels > 0);
//
//  /* emit */
//  for(size_t i = 0; i < n_kernels; i++) {
//    /* unreachable */
//    if(!evoasm_kernel_is_used_kernel(kernel, i)) continue;
//
//    kernel = &kernel->kernels[i];
//
//    kernel_addrs[i] = evoasm_buf_get_pos_addr_(buf);
//    kernel->buf_pos_body_start[i] = (uint16_t) buf->pos;
//
//    EVOASM_TRY(error, evoasm_kernel_x64_emit_kernel, kernel, kernel, buf);
//
//    if(n_kernels > 1 && i != term_kernel_idx) {
//      EVOASM_TRY(error, evoasm_kernel_x64_emit_cycle_guard, kernel, kernel,
//                 buf, &guard_link_addrs[i], set_io_mapping);
//
//      EVOASM_TRY(error, evoasm_kernel_x64_emit_cond_transns, kernel, kernel, buf,
//                 transn_link_addrs[i], set_io_mapping);
//    }
//
//    uint8_t *default_transn_load_addr;
//    EVOASM_TRY(error, evoasm_kernel_x64_emit_default_transn, kernel, kernel, buf,
//               transn_link_addrs[i], &default_transn_load_addr, set_io_mapping);
//
//    kernel->buf_pos_body_end[i] = (uint16_t) buf->pos;
//  }
//
//  if(n_kernels > 1) {
//    /* link linkations */
//    for(size_t i = 0; i < n_kernels; i++) {
//      if(!evoasm_kernel_is_used_kernel(kernel, i)) continue;
//
//      for(size_t j = 0; j < EVOASM_X64_JMP_COND_NONE + 1; j++) {
//        size_t succ_kernel_idx = kernel->topo.succs[i][j];
//        if(succ_kernel_idx != UINT8_MAX) {
//          assert(evoasm_kernel_is_used_kernel(kernel, succ_kernel_idx));
//          uint32_t *jmp_link_addr = transn_link_addrs[i][j];
//          if(jmp_link_addr != NULL) {
//            assert(*jmp_link_addr == 0xdeadbeef);
//            uint8_t *succ_kernel_addr = kernel_addrs[succ_kernel_idx];
//            EVOASM_X64_LINK_ADDR32(jmp_link_addr, succ_kernel_addr);
//          }
//        }
//      }
//
//      if(guard_link_addrs[i] != NULL) {
//        /* link the guard - on failure jump to default transn (i.e. where it is loaded) */
//        EVOASM_X64_LINK_ADDR32(guard_link_addrs[i], kernel_addrs[evoasm_kernel_get_term_kernel_idx(kernel)]);
//      }
//    }
//
////      if(guard_jmp_link_addr) {
////        /* link the guard - on failure jump to default transn (i.e. where it is loaded) */
////        EVOASM_X64_LINK_ADDR32(guard_jmp_link_addr, default_transn_load_addr);
////      }
//
//
//    /* link term linkation (jump to epilog) */
//
//
////    {
////      uint32_t *term_jmp_link_addr =
////          transn_link_addrs[program->topo.backbone_len - 1][EVOASM_X64_JMP_COND_NONE];
////
////      if(term_jmp_link_addr != NULL) {
////        /* link term kernel */
////        EVOASM_X64_LINK_ADDR32(term_jmp_link_addr, evoasm_buf_get_pos_addr_(buf));
////      }
////    }
//  }
//
//  kernel->buf_pos_kernels_end = (uint16_t) buf->pos;
//  return true;
//error:
//enc_failed:
//  return false;
//}


static evoasm_success_t
evoasm_kernel_x64_emit_reset_and_call(evoasm_kernel_t *kernel) {

  evoasm_buf_t *buf = kernel->buf;

  {
    uint32_t rel = (uint32_t) (kernel->buf_pos_body_start - (evoasm_buf_get_pos_(kernel->buf) + 5));
    evoasm_x64_params_t params = {0};
    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, rel);
    EVOASM_X64_ENC(call_rel32);
  }

  return true;

enc_failed:
  return false;
}


static evoasm_success_t
evoasm_kernel_x64_emit_runs(evoasm_kernel_t *kernel,
                            evoasm_kernel_input_t *input,
                            size_t win_off,
                            size_t win_size,
                            bool io_mapping) {

  size_t n_tuples = evoasm_kernel_input_get_n_tuples(input);
  win_size = EVOASM_MIN(n_tuples, win_size);

  for(size_t i = 0; i < win_size; i++) {
    size_t tuple_idx = (win_off + i) % n_tuples;
    EVOASM_TRY(error, evoasm_kernel_x64_emit_input_load, kernel,
               input, tuple_idx, io_mapping);

    EVOASM_TRY(error, evoasm_kernel_x64_emit_reset_and_call, kernel);
    EVOASM_TRY(error, evoasm_kernel_x64_emit_output_store, kernel, tuple_idx);
  }

  return true;

error:
  return false;
}

#define EVOASM_X64_GET_LINK_ADDR32(buf) ((uint32_t *)((buf)->data + (buf)->pos - 4))
#define EVOASM_X64_LINK_ADDR32(label, val) \
do { (*(label) = (uint32_t)((uint8_t *)(val) - ((uint8_t *)(label) + 4)));} while(0);

static evoasm_success_t
evoasm_kernel_x64_emit(evoasm_kernel_t *kernel,
                       evoasm_kernel_input_t *input,
                       size_t win_off,
                       size_t win_size,
                       evoasm_kernel_emit_flags_t emit_flags) {

  bool set_io_mapping = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;
  bool only_runs = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_ONLY_RUNS;
  bool no_runs = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_NO_RUNS;
  bool preserve_output_regs = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_PRESERVE_OUTPUT_REGS;
  evoasm_buf_t *buf = kernel->buf;

  if(!only_runs) {
    uint32_t *start_jmp_link_addr;

    evoasm_buf_reset(buf);

    EVOASM_TRY(error, evoasm_kernel_x64_prepare, kernel, preserve_output_regs);
    EVOASM_TRY(error, evoasm_x64_emit_func_prolog, EVOASM_X64_ABI_SYSV, buf);

    {
      evoasm_x64_params_t params = {0};
      EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
      EVOASM_X64_ENC(jmp_rel32);
    }

    start_jmp_link_addr = EVOASM_X64_GET_LINK_ADDR32(buf);

    EVOASM_TRY(error, evoasm_kernel_x64_emit_body, kernel);

    {
      evoasm_x64_params_t params = {0};
      EVOASM_X64_ENC(ret);
    }

    kernel->buf_pos_epilog_start = (uint16_t) evoasm_buf_get_pos_(buf);
    EVOASM_TRY(error, evoasm_x64_emit_func_epilog, EVOASM_X64_ABI_SYSV, buf);
    kernel->buf_pos_epilog_end = (uint16_t) evoasm_buf_get_pos_(buf);

    EVOASM_X64_LINK_ADDR32(start_jmp_link_addr, evoasm_buf_get_pos_addr_(buf))

  } else {
    evoasm_buf_set_pos_(buf, kernel->buf_pos_epilog_end);
  }

  if(!no_runs) {
    EVOASM_TRY(error, evoasm_kernel_x64_emit_runs, kernel, input, win_off, win_size,
               set_io_mapping);

    {
      evoasm_x64_params_t params = {0};
      EVOASM_X64_SET(EVOASM_X64_PARAM_REL, (evoasm_param_val_t) (kernel->buf_pos_epilog_start - (buf->pos + 5)));
      EVOASM_X64_ENC(jmp_rel32);
    }
  }

  return true;

enc_failed:
error:
  return false;
}


typedef enum {
  EVOASM_METRIC_ABSDIFF,
  EVOASM_METRIC_NONE
} evoasm_metric;

static void
evoasm_kernel_update_dist_mat(evoasm_kernel_t *kernel,
                              evoasm_kernel_output_t *output,
                              size_t width,
                              size_t height,
                              size_t tuple_idx,
                              double *dist_mat,
                              evoasm_metric metric) {
  evoasm_kernel_io_val_t *io_vals = output->vals + tuple_idx * output->arity;

  for(size_t i = 0; i < height; i++) {
    evoasm_kernel_io_val_t *expected_val = &io_vals[i];
    evoasm_kernel_io_val_type_t tuple_type = (evoasm_kernel_io_val_type_t) output->types[i];
    double expected_val_dbl[16];
    size_t expected_val_dbl_len;
    expected_val_dbl_len = evoasm_kernel_io_val_to_dbl(expected_val, tuple_type, expected_val_dbl);

    for(size_t j = 0; j < width; j++) {
      evoasm_kernel_io_val_t *actual_val = &kernel->output_vals[tuple_idx * width + j];
      //uint8_t output_size = kernel->output_sizes[j];
      //switch(output_size) {
      //
      //}
      // FIXME: output is essentially just a bitstring and could be anything
      // an integer (both, signed or unsigned) a float or double.
      // Moreover, a portion of the output value could
      // hold the correct answer (e.g. lower 8 or 16 bits etc.).
      // For now we use the tuple output type and assume signedness.
      // This needs to be fixed.

      double actual_val_dbl[16];
      size_t actual_val_dbl_len = evoasm_kernel_io_val_to_dbl(actual_val, tuple_type, actual_val_dbl);
      (void) actual_val_dbl_len;

      switch(metric) {
        default:
        case EVOASM_METRIC_ABSDIFF: {
          double dist = 0;
          for(size_t k = 0; k < expected_val_dbl_len; k++) {
            dist += fabs(actual_val_dbl[k] - expected_val_dbl[k]);
          }
          dist_mat[i * width + j] += dist;
          break;
        }
      }
    }
  }
}

static void
evoasm_kernel_log_output(evoasm_kernel_t *kernel,
                         evoasm_kernel_output_t *output,
                         uint_fast8_t *const matching,
                         evoasm_log_level_t log_level) {

  size_t n_tuples = evoasm_kernel_output_get_n_tuples(output);
  size_t height = output->arity;
  size_t width = kernel->n_output_regs;

  evoasm_log(log_level, EVOASM_LOG_TAG, "OUTPUT MATRICES:\n");

  for(size_t i = 0; i < width; i++) {
    evoasm_log(log_level, EVOASM_LOG_TAG, " %s  ", evoasm_x64_get_reg_name(kernel->x64.output_regs[i]));
  }

  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");

  for(size_t i = 0; i < n_tuples; i++) {
    for(size_t j = 0; j < height; j++) {

      evoasm_kernel_io_val_t *target_val = evoasm_kernel_io_get_val_(output, i, j);
      evoasm_log(log_level, EVOASM_LOG_TAG, "%ld (%f)\t| ", target_val->i64[0], target_val->f64[0]);

      for(size_t k = 0; k < width; k++) {
        bool matched = matching[j] == k;
        evoasm_kernel_io_val_t *val = &kernel->output_vals[i * width + k];

        if(matched) {
          evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[1m ");
        }
        evoasm_log(log_level, EVOASM_LOG_TAG, " %ld (%f)\t ", val->i64[0], val->f64[0]);
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
evoasm_kernel_log_dist_mat(evoasm_kernel_t *kernel,
                           size_t width,
                           size_t height,
                           double *dist_mat,
                           uint_fast8_t *matching,
                           evoasm_log_level_t log_level) {

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
evoasm_kernel_match(evoasm_kernel_t *kernel,
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
    /*evoasm_kernel_log_dist_mat(kernel,
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
evoasm_kernel_calc_stable_matching(evoasm_kernel_t *kernel,
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
      evoasm_kernel_log_dist_mat(kernel,
                                 width,
                                 height,
                                 dist_mat,
                                 matching,
                                 EVOASM_LOG_LEVEL_DEBUG);
      evoasm_assert_not_reached();
    }
  }
}

static evoasm_loss_t
evoasm_kernel_calc_loss(evoasm_kernel_t *kernel,
                        size_t width,
                        size_t height,
                        size_t n_tuples,
                        double *dist_mat,
                        uint_fast8_t *matching) {
  double scale = 1.0 / (double) (height * n_tuples);
  double loss = 0.0;

  for(size_t i = 0; i < height; i++) {
    loss += (scale * dist_mat[i * width + matching[i]]);
  }

  return (evoasm_loss_t) loss;
}

static void
evoasm_kernel_build_dist_mat(evoasm_kernel_t *kernel,
                             evoasm_kernel_output_t *output,
                             size_t win_off,
                             size_t win_size,
                             size_t height,
                             double *dist_mat,
                             evoasm_metric metric) {

  size_t n_tuples = evoasm_kernel_output_get_n_tuples(output);
  size_t width = kernel->n_output_regs;
  size_t dist_mat_len = width * height;

  for(size_t i = 0; i < dist_mat_len; i++) {
    dist_mat[i] = 0.0;
  }

  for(size_t i = 0; i < win_size; i++) {
    size_t tuple_idx = (win_off + i) % n_tuples;
    evoasm_kernel_update_dist_mat(kernel, output, width, height, tuple_idx, dist_mat,
                                  EVOASM_METRIC_ABSDIFF);


  }
}

static evoasm_loss_t
evoasm_kernel_assess(evoasm_kernel_t *kernel,
                     evoasm_kernel_output_t *output,
                     size_t win_off,
                     size_t win_size) {

  {
    size_t n_tuples = evoasm_kernel_output_get_n_tuples(output);
    win_size = EVOASM_MIN(n_tuples, win_size);
  }

  size_t height = output->arity;
  size_t width = kernel->n_output_regs;
  double *dist_mat = evoasm_alloca(width * height * sizeof(double));
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));
  evoasm_loss_t loss;

  evoasm_kernel_build_dist_mat(kernel, output, win_off, win_size,
                               height, dist_mat, EVOASM_METRIC_ABSDIFF);

  if(height == 1) {
    /* COMMON FAST-PATH */
    if(!evoasm_kernel_match(kernel, width, dist_mat, matching)) {
      goto no_matching;
    }
  } else {
    evoasm_kernel_calc_stable_matching(kernel, height, dist_mat, matching);
  }

  for(size_t i = 0; i < height; i++) {
    switch(kernel->arch_info->id) {
      case EVOASM_ARCH_X64: {
        kernel->output_reg_mapping[i] = kernel->x64.output_regs[matching[i]];
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }


//  evoasm_kernel_log_dist_mat(kernel,
//                              width,
//                              height,
//                              dist_mat,
//                              matching,
//                              EVOASM_LOG_LEVEL_FATAL);
//
//  evoasm_kernel_log_output(kernel,
//                                    output,
//                                    matching,
//                                    EVOASM_LOG_LEVEL_FATAL);


  loss = evoasm_kernel_calc_loss(kernel, width, height, win_size, dist_mat, matching);
  return loss;

no_matching:
  return INFINITY;

}

static inline evoasm_loss_t
evoasm_kernel_eval_(evoasm_kernel_t *kernel,
                    evoasm_kernel_output_t *output,
                    size_t output_off,
                    size_t output_size) {

  evoasm_loss_t loss;

//  evoasm_kernel_log(kernel, EVOASM_LOG_LEVEL_FATAL);

  if(evoasm_unlikely(kernel->n_output_regs == 0)) {
    evoasm_log_info("kernel %p has no output", (void *) kernel);
    return INFINITY;
  }

  evoasm_signal_set_exception_mask(kernel->exception_mask);

#ifdef EVOASM_ENABLE_PARANOID_MODE
  for(size_t i = 0; i < kernel->topo.size; i++) {
    evoasm_kernel_t *kernel = &kernel->kernels[i];
    for(size_t j = 0; j < EVOASM_X64_REG_NONE; j++) {
      kernel->rand_vals[j].i64 = rand() | (rand() << (rand() % 24));
    }
  }
#endif

//  fprintf(stderr, "\n");
//  for(size_t i = 0; i < EVOASM_PROGRAM_TOPO_MAX_SIZE; i++) {
//    for(size_t j = 0; j < EVOASM_PROGRAM_TOPO_MAX_CONDS; j++) {
//      fprintf(stderr, "%d ", kernel->topo.succs[i][j]);
//    }
//    fprintf(stderr, "\n");
//  }
//
//  fprintf(stderr, "EXEC: %d\n", kernel->topo.cycle_bitmap);

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(kernel->buf);
    loss = evoasm_kernel_assess(kernel, output, output_off, output_size);
  } else {
    evoasm_log_fatal("kernel %p signaled", (void *) kernel);
    loss = INFINITY;
  }

  evoasm_signal_clear_exception_mask();

  return loss;
}

evoasm_loss_t
evoasm_kernel_eval(evoasm_kernel_t *kernel,
                   evoasm_kernel_output_t *output,
                   size_t win_off,
                   size_t win_size) {

//  evoasm_kernel_log(kernel, EVOASM_LOG_LEVEL_FATAL);

  evoasm_loss_t loss = evoasm_kernel_eval_(kernel, output, win_off, win_size);

#ifdef EVOASM_ENABLE_PARANOID_MODE
  for(size_t i = 0; i < 10; i++) {
    bool timed_out_;
    evoasm_loss_t loss_ = evoasm_kernel_eval_(kernel, output, win_off, win_size, &timed_out_);

    if(loss_ != loss || *timed_out != timed_out_) {
      evoasm_kernel_log(kernel, EVOASM_LOG_LEVEL_WARN);
      evoasm_buf_log(kernel->buf, EVOASM_LOG_LEVEL_WARN);
    }
    assert(loss_ == loss && *timed_out == timed_out_);
  }
#endif

  return loss;
}

static evoasm_success_t
evoasm_kernel_load_output(evoasm_kernel_t *kernel,
                          evoasm_kernel_input_t *input,
                          evoasm_kernel_output_t *loaded_output) {

  size_t width = kernel->n_output_regs;
  evoasm_kernel_output_t *kernel_output = &kernel->_output;
  size_t height = kernel_output->arity;
  size_t n_tuples = evoasm_kernel_input_get_n_tuples(input);
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));

  for(size_t i = 0; i < height; i++) {
    for(size_t j = 0; j < kernel->n_output_regs; j++) {
      if(kernel->output_reg_mapping[i] == kernel->x64.output_regs[j]) {
        matching[i] = (uint_fast8_t) j;
        goto next;
      }
    }
    evoasm_log_fatal("kernel kernel_output reg %d not found in kernel kernel_output regs",
                     kernel->output_reg_mapping[i]);
    evoasm_assert_not_reached();
next:;
  }

  *loaded_output = *kernel_output;
  loaded_output->n_tuples = (uint16_t) n_tuples;
  EVOASM_TRY_ALLOC_N(error, calloc, loaded_output->vals, n_tuples * height);

  for(size_t i = 0; i < n_tuples; i++) {
    for(size_t j = 0; j < height; j++) {
      loaded_output->vals[i * height + j] = kernel->output_vals[i * width + matching[j]];
    }
  }

#if EVOASM_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
  evoasm_kernel_log_output(kernel,
                           loaded_output,
                           matching,
                           EVOASM_LOG_LEVEL_DEBUG);
#endif

  return true;

error:
  return false;
}

evoasm_success_t
evoasm_kernel_run(evoasm_kernel_t *kernel,
                  evoasm_kernel_input_t *input,
                  evoasm_kernel_output_t *output) {

  bool retval = true;

  if(input->arity != kernel->_input.arity) {
    evoasm_error(EVOASM_ERROR_TYPE_KERNEL, EVOASM_ERROR_CODE_NONE,
                 "arity mismatch (%d for %d)", input->arity, kernel->_input.arity);
    return false;
  }

  size_t n_tuples = evoasm_kernel_input_get_n_tuples(input);
  if(n_tuples > kernel->max_tuples) {
    evoasm_error(EVOASM_ERROR_TYPE_KERNEL, EVOASM_ERROR_CODE_NONE,
                 "Maximum number of input/output tuples exceeded (%zu > %d)", n_tuples, kernel->max_tuples);
    return false;
  }

  for(size_t i = 0; i < input->arity; i++) {
    if(input->types[i] != kernel->_input.types[i]) {
      evoasm_error(EVOASM_ERROR_TYPE_KERNEL, EVOASM_ERROR_CODE_NONE,
                   "type mismatch (%s != %s)", evoasm_kernel_io_val_type_get_name(input->types[i]),
                                               evoasm_kernel_io_val_type_get_name(kernel->_input.types[i]));
      return false;
    }
  }

  evoasm_kernel_emit_flags_t emit_flags = EVOASM_PROGRAM_EMIT_FLAG_ONLY_RUNS;
  EVOASM_TRY(error, evoasm_kernel_emit, kernel, input, 0, SIZE_MAX, emit_flags);

  evoasm_buf_log(kernel->buf, EVOASM_LOG_LEVEL_DEBUG);
  evoasm_signal_set_exception_mask(kernel->exception_mask);

  if(!evoasm_buf_protect(kernel->buf, EVOASM_MPROT_MODE_RX)) {
    evoasm_assert_not_reached();
  }

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(kernel->buf);
    EVOASM_TRY(error_clear, evoasm_kernel_load_output, kernel, input, output);
  } else {
    evoasm_log_debug("signaled\n");
    output->n_tuples = 0;
  }

  if(!evoasm_buf_protect(kernel->buf, EVOASM_MPROT_MODE_RW)) {
    evoasm_assert_not_reached();
  }

done:
  evoasm_signal_clear_exception_mask();
  return retval;

error_clear:
  retval = false;
  goto done;

error:
  return false;
}

evoasm_success_t
evoasm_kernel_emit(evoasm_kernel_t *kernel,
                   evoasm_kernel_input_t *input,
                   size_t win_off,
                   size_t win_size,
                   evoasm_kernel_emit_flags_t emit_flags) {
  switch(kernel->arch_info->id) {
    case EVOASM_ARCH_X64: {
      return evoasm_kernel_x64_emit(kernel, input, win_off, win_size, emit_flags);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static size_t
evoasm_kernel_x64_find_writers(evoasm_kernel_t *kernel,
                               size_t reader_inst_idx, evoasm_x64_reg_id_t reg_id,
                               evoasm_x64_operand_t *op, size_t *writers) {

  if(reader_inst_idx == 0) {
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
  evoasm_bitmap_max_kernel_size_t inst_bitmap;
  evoasm_bitmap_max_output_regs_t output_regs_bitmap;
  struct {
    evoasm_x64_operand_t x64[EVOASM_X64_REG_NONE];
  } output_reg_operands;
} evoasm_kernel_intron_elim_ctx_t;


#define EVOASM_LOG_INTRON_ELIM(...) evoasm_log(EVOASM_LOG_LEVEL_DEBUG, "kernel:intron_elim", __VA_ARGS__)

static void
evoasm_kernel_x64_mark_writers(evoasm_kernel_t *kernel, size_t inst_idx,
                               evoasm_x64_operand_t *op, evoasm_kernel_intron_elim_ctx_t *ctx) {
  size_t writer_inst_idxs[EVOASM_KERNEL_MAX_SIZE];

  EVOASM_LOG_INTRON_ELIM("Marking writers [%zu]\n", inst_idx);

  evoasm_x64_reg_id_t reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, inst_idx);
  assert(reg_id != EVOASM_X64_REG_IP);

  size_t writers_len = evoasm_kernel_x64_find_writers(kernel, inst_idx, reg_id, op, writer_inst_idxs);

  EVOASM_LOG_INTRON_ELIM("Marking %zu writers to %s ---------------------\n",
                         writers_len, evoasm_x64_get_reg_name(reg_id));

  if(reg_id == EVOASM_X64_REG_RFLAGS) {
    for(size_t l = 0; l < EVOASM_X64_RFLAGS_FLAG_NONE; l++) {
      if(EVOASM_X64_RFLAGS_FLAGS_GET(op->read_flags, l)) {
        EVOASM_LOG_INTRON_ELIM("\tRFLAG: %s\n", evoasm_x64_rflags_flag_get_name(l));
      }
    }
  }

  for(size_t i = 0; i < writers_len; i++) {

    size_t writer_inst_idx = writer_inst_idxs[i];
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx->inst_bitmap;
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

        evoasm_kernel_x64_mark_writers(kernel, writer_inst_idx, op, ctx);
      }
    }
  }

  EVOASM_LOG_INTRON_ELIM("---------------------------------\n");
}

static evoasm_success_t
evoasm_kernel_mark(evoasm_kernel_t *kernel, evoasm_kernel_t *dst_kernel,
                   evoasm_kernel_intron_elim_ctx_t *ctx) {

  EVOASM_LOG_INTRON_ELIM("Marking kernel\n");

  for(evoasm_x64_reg_id_t reg_id = (evoasm_x64_reg_id_t) 0; reg_id < EVOASM_X64_REG_NONE; reg_id++) {
    evoasm_x64_operand_t *output_reg_operand = &ctx->output_reg_operands.x64[reg_id];
    if(evoasm_bitmap_get((evoasm_bitmap_t *) &ctx->output_regs_bitmap, reg_id)) {
      EVOASM_LOG_INTRON_ELIM("Marking kernel, output reg %s\n", evoasm_x64_get_reg_name(reg_id));
      assert(output_reg_operand->implicit);
      evoasm_kernel_x64_mark_writers(kernel, kernel->size, output_reg_operand, ctx);

      dst_kernel->x64.output_regs[dst_kernel->n_output_regs++] = reg_id;

      evoasm_bitmap_unset((evoasm_bitmap_t *) &ctx->output_regs_bitmap, reg_id);
    }
  }

  return true;
}

evoasm_success_t
evoasm_kernel_elim_introns(evoasm_kernel_t *kernel, evoasm_kernel_t *dst_kernel) {
  evoasm_kernel_intron_elim_ctx_t ctx = {0};

  EVOASM_TRY(error, evoasm_kernel_init,
             dst_kernel,
             kernel->arch_info,
             kernel->max_kernel_size,
             kernel->max_tuples,
             kernel->recur_limit,
             false);

  for(size_t i = 0; i < kernel->_output.arity; i++) {
    evoasm_x64_reg_id_t output_reg = (evoasm_x64_reg_id_t) kernel->output_reg_mapping[i];
    evoasm_x64_reg_type_t output_reg_type = evoasm_x64_get_reg_type(output_reg);

    evoasm_x64_operand_t *output_reg_operand = &ctx.output_reg_operands.x64[output_reg];

    evoasm_bitmap_set((evoasm_bitmap_t *) &ctx.output_regs_bitmap, output_reg);

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
        size_t reg_size = evoasm_x64_reg_type_get_bytesize(output_reg_type);
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

  EVOASM_TRY(error, evoasm_kernel_mark, kernel, dst_kernel, &ctx);

  {
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx.inst_bitmap;

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
      dst_kernel->n_input_regs = kernel->n_input_regs;
    }

    assert(dst_kernel->n_output_regs > 0);
  }

  if(dst_kernel != kernel) {
    dst_kernel->_input = kernel->_input;
    dst_kernel->_output = kernel->_output;
    memcpy(dst_kernel->x64.reg_input_mapping, kernel->x64.reg_input_mapping, sizeof(kernel->x64.reg_input_mapping));
    memcpy(dst_kernel->output_reg_mapping, kernel->output_reg_mapping, sizeof(kernel->output_reg_mapping));
  }

  evoasm_kernel_emit_flags_t emit_flags =
      EVOASM_PROGRAM_EMIT_FLAG_NO_RUNS |
      EVOASM_PROGRAM_EMIT_FLAG_PRESERVE_OUTPUT_REGS;

  EVOASM_TRY(error, evoasm_kernel_emit, dst_kernel, NULL, 0, SIZE_MAX, emit_flags);

  return true;
error:
  return false;
}

#undef EVOASM_LOG_INTRON_ELIM


#define EVOASM_PROGRAM_PROLOG_EPILOG_SIZE UINT32_C(2048)
#define EVOASM_PROGRAM_TRANSITION_SIZE UINT32_C(512)


evoasm_success_t
evoasm_kernel_init(evoasm_kernel_t *kernel,
                   evoasm_arch_info_t *arch_info,
                   size_t max_kernel_size,
                   size_t max_tuples,
                   size_t recur_limit,
                   bool shallow) {

  static evoasm_kernel_t zero_kernel = {0};

  *kernel = zero_kernel;
  kernel->arch_info = arch_info;
  kernel->recur_limit = (uint32_t) recur_limit;
  kernel->shallow = shallow;
  kernel->max_kernel_size = (uint16_t) max_kernel_size;
  kernel->max_tuples = (uint16_t) max_tuples;

  size_t body_buf_size = max_kernel_size * kernel->arch_info->max_inst_len;
  size_t buf_size = max_tuples * (body_buf_size + EVOASM_PROGRAM_PROLOG_EPILOG_SIZE);

  EVOASM_TRY(error, evoasm_buf_init, &kernel->_buf, EVOASM_BUF_TYPE_MMAP, buf_size);
  kernel->buf = &kernel->_buf;

  EVOASM_TRY(error, evoasm_buf_protect, &kernel->_buf,
             EVOASM_MPROT_MODE_RWX);

  size_t output_vals_len = max_tuples * EVOASM_KERNEL_MAX_OUTPUT_REGS;

  EVOASM_TRY_ALLOC(error, calloc, kernel->output_vals, output_vals_len, sizeof(evoasm_kernel_io_val_t));

  if(!shallow) {
    EVOASM_TRY_ALLOC(error, calloc, kernel->insts, max_kernel_size, sizeof(kernel->insts[0]));
    switch(kernel->arch_info->id) {
      case EVOASM_ARCH_X64: {
        EVOASM_TRY_ALLOC(error, calloc, kernel->x64.params, max_kernel_size, sizeof(kernel->x64.params[0]));
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }

  return true;

error:
  EVOASM_TRY_WARN(evoasm_kernel_destroy, kernel);
  return false;
}

void
evoasm_kernel_log(evoasm_kernel_t *kernel, evoasm_log_level_t log_level) {
  if(_evoasm_log_level > log_level) return;

  switch(kernel->arch_info->id) {
    case EVOASM_ARCH_X64:
      for(size_t i = 0; i < kernel->size; i++) {
        evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
        evoasm_x64_basic_params_t *params = &kernel->x64.params[i];

        char buf[1024];
        evoasm_x64_sprint_inst(inst, params, buf, EVOASM_ARRAY_LEN(buf));
        evoasm_log(log_level, EVOASM_LOG_TAG, "%s", buf);
      }
      break;
    default:
      evoasm_assert_not_reached();
  }
}

evoasm_kernel_io_val_type_t
evoasm_kernel_get_input_type(evoasm_kernel_t *kernel, size_t arg_idx) {
  return evoasm_kernel_io_get_type_(&kernel->_input, arg_idx);
}

evoasm_kernel_io_val_type_t
evoasm_kernel_get_output_type(evoasm_kernel_t *kernel, size_t arg_idx) {
  return evoasm_kernel_io_get_type_(&kernel->_output, arg_idx);
}

size_t
evoasm_kernel_get_input_arity(evoasm_kernel_t *kernel, size_t arg_idx) {
  return kernel->_input.arity;
}

size_t
evoasm_kernel_get_output_arity(evoasm_kernel_t *kernel, size_t arg_idx) {
  return kernel->_output.arity;
}

EVOASM_DEF_ALLOC_FREE_FUNCS(kernel)
