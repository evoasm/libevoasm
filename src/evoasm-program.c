/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-signal.h"
#include "evoasm-program.h"
#include "evoasm-arch.h"
#include "evoasm.h"
#include "evoasm-x64.h"


EVOASM_DEF_LOG_TAG("program")

static inline double
evoasm_program_io_val_to_dbl(evoasm_program_io_val_t io_val, evoasm_program_io_val_type_t example_type) {
  switch(example_type) {
    case EVOASM_PROGRAM_IO_VAL_TYPE_F64:
      return io_val.f64;
    case EVOASM_PROGRAM_IO_VAL_TYPE_I64:
      return (double) io_val.i64;
    default:
      evoasm_log_fatal("unsupported example type %d", example_type);
      evoasm_assert_not_reached();
  }
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
          evoasm_free(kernel->params.x64);
          break;
        default:
          evoasm_assert_not_reached();
      }
    }

  }

  evoasm_free(program->jmp_offs);
  evoasm_free(program->jmp_conds);
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


int
evoasm_program_get_jmp_off(evoasm_program_t *program, size_t pos) {
  return program->jmp_offs[pos];
}


bool
evoasm_program_is_input_reg(evoasm_program_t *program, size_t kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->reg_info.x64.regs[reg_id].input;
    default:
      evoasm_assert_not_reached();
  }
}

bool
evoasm_program_is_output_reg(evoasm_program_t *program, size_t kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->reg_info.x64.regs[reg_id].output;
    default:
      evoasm_assert_not_reached();
  }
}

#define EVOASM_PROGRAM_TMP_REG_X64 EVOASM_X64_REG_14

static evoasm_success_t
evoasm_program_x64_emit_rflags_reset(evoasm_program_t *program) {
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = program->buf;

  evoasm_log_debug("emitting RFLAGS reset");
  EVOASM_X64_ENC(pushfq);
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_REG_SP);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM, 0);
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


static evoasm_success_t
evoasm_program_x64_emit_output_store(evoasm_program_t *program,
                                     size_t example_idx) {

  evoasm_x64_params_t params = {0};
  evoasm_kernel_t *kernel = &program->kernels[program->size - 1];
  evoasm_buf_t *buf = program->buf;

  for(size_t i = 0; i < kernel->n_output_regs; i++) {
    evoasm_x64_reg_id_t reg_id = kernel->output_regs.x64[i];
    evoasm_program_io_val_t *val_addr = &program->output_vals[(example_idx * kernel->n_output_regs) + i];
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
  evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[inst_idx]);

  if(op->param_idx < inst->n_params) {
    return (evoasm_x64_reg_id_t) evoasm_x64_basic_params_get_(&kernel->params.x64[inst_idx],
                                                              (evoasm_x64_param_id_t) inst->params[op->param_idx].id);
  } else if(op->reg_id < EVOASM_X64_REG_NONE) {
    return (evoasm_x64_reg_id_t) op->reg_id;
  } else {
    evoasm_assert_not_reached();
    return EVOASM_X64_REG_NONE;
  }
}

typedef struct {
  bool high_byte_reg : 1;
  uint64_t mask;
  size_t size;
} evoasm_x64_reg_write_acc_t;


static void
evoasm_x64_reg_write_acc_update(evoasm_x64_reg_write_acc_t *reg_write_acc,
                                evoasm_x64_operand_t *op, evoasm_x64_basic_params_t *params) {
  if(reg_write_acc->size < EVOASM_X64_OPERAND_SIZE_NONE) {
    reg_write_acc->size = EVOASM_MAX(reg_write_acc->size, op->size1);
  } else {
    reg_write_acc->size = op->size1;
  }

  reg_write_acc->mask |= op->write_mask;
  reg_write_acc->high_byte_reg |= params->reg0_high_byte || params->reg1_high_byte;
}


static bool
evoasm_x64_reg_write_acc_is_dirty_read(evoasm_x64_reg_write_acc_t *reg_write_acc, evoasm_x64_operand_t *op,
                                       evoasm_x64_basic_params_t *params) {
  bool dirty_read;
  bool high_byte_reg = params->reg0_high_byte || params->reg1_high_byte;

  assert(reg_write_acc->size <= EVOASM_X64_OPERAND_SIZE_NONE);
  if(reg_write_acc->size == EVOASM_X64_OPERAND_SIZE_NONE) {
    return true;
  }

  if(op->reg_type == EVOASM_X64_REG_TYPE_GP) {
    /* 32bit writes clear the whole register */
    if(reg_write_acc->size >= EVOASM_X64_OPERAND_SIZE_32) {
      dirty_read = false;
    } else {
      if(op->size1 == EVOASM_X64_OPERAND_SIZE_8 &&
         reg_write_acc->size == EVOASM_X64_OPERAND_SIZE_8) {
        dirty_read = high_byte_reg != reg_write_acc->high_byte_reg;
      } else {
        dirty_read = reg_write_acc->size < op->size1;
      }
    }
  } else if(op->reg_type == EVOASM_X64_REG_TYPE_XMM) {
    uint64_t mask;
    if(op->size1 == EVOASM_X64_OPERAND_SIZE_128) {
      mask = EVOASM_X64_BITMASK_0_127;
    } else {
      mask = EVOASM_X64_BITMASK_ALL;
    }
    dirty_read = ((mask & (~reg_write_acc->mask)) != 0);
  } else {
    dirty_read = false;
  }

  return dirty_read;
}

static bool
evoasm_kernel_is_writing_inst_x64(evoasm_kernel_t *kernel, size_t inst_idx, evoasm_reg_id_t reg_id,
                                  evoasm_x64_reg_write_acc_t *reg_write_acc) {
  evoasm_x64_inst_t *x64_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[inst_idx]);

  for(size_t i = 0; i < x64_inst->n_operands; i++) {
    evoasm_x64_operand_t *op = &x64_inst->operands[i];
    evoasm_x64_reg_id_t op_reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, inst_idx);
    evoasm_x64_basic_params_t *x64_basic_params = &kernel->params.x64[inst_idx];

    if(op->written && op_reg_id == reg_id &&
       evoasm_x64_reg_write_acc_is_dirty_read(reg_write_acc, op, x64_basic_params)) {
      evoasm_x64_reg_write_acc_update(reg_write_acc, op, x64_basic_params);
      return true;
    }
  }
  return false;
}


static void
evoasm_x64_reg_write_acc_init(evoasm_x64_reg_write_acc_t *reg_write_acc) {
  static evoasm_x64_reg_write_acc_t zero_reg_write_acc = {0};
  *reg_write_acc = zero_reg_write_acc;

  reg_write_acc->size = EVOASM_X64_OPERAND_SIZE_NONE;
}

static void
evoasm_program_x64_prepare_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel) {
  /* NOTE: output register are register that are written to
   *       _input registers are register that are read from without
   *       a previous write
   */
  evoasm_x64_reg_write_acc_t reg_write_accs[EVOASM_X64_REG_NONE];
  for(int i = 0; i < EVOASM_X64_REG_NONE; i++) {
    evoasm_x64_reg_write_acc_init(&reg_write_accs[i]);
  }

  for(size_t i = 0; i < kernel->size; i++) {
    evoasm_x64_inst_t *x64_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[i]);
    evoasm_x64_basic_params_t *x64_basic_params = &kernel->params.x64[i];

    for(size_t j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if(op->type == EVOASM_X64_OPERAND_TYPE_REG ||
         op->type == EVOASM_X64_OPERAND_TYPE_RM) {

        if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
          if(op->read) {
            program->reset_rflags = true;
          } else if(op->written) {
            kernel->reg_info.x64.written_flags = (kernel->reg_info.x64.written_flags | op->flags) & EVOASM_X64_RFLAGS_FLAGS_BITSIZE;
            kernel->reg_info.x64.regs[op->reg_id].written = true;
          }
        } else {
          evoasm_x64_reg_id_t reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, (uint16_t) i);
          evoasm_kernel_x64_reg_info_reg_t *reg_info = &kernel->reg_info.x64.regs[reg_id];
          evoasm_x64_reg_write_acc_t *reg_write_acc = &reg_write_accs[reg_id];

          /*
           * Conditional writes (cond_written) might or might not do the write.
           */

          if(op->read || op->cond_written) {
            if(!reg_info->input) {
              // has not been written before, might contain garbage
              bool dirty_read;

              /* the writer rank check is needed for the following case
               * inst regX (operand1, written), regX (operand2, read)
               *
               * The first operand marks regX as written. The read in the second
               * operand, however, is dirty, since the write has not yet occurred at this point.
               */

              if(reg_info->written && reg_info->writer_rank < i) {
                dirty_read = evoasm_x64_reg_write_acc_is_dirty_read(reg_write_acc, op, x64_basic_params);
              } else {
                dirty_read = true;
              }

              if(dirty_read) {
                reg_info->input = true;
                kernel->n_input_regs++;
              }
            }
          }

          if(op->written) {

            if(!reg_info->written) {
              reg_info->written = true;
              reg_info->output = true;
              reg_info->writer_rank = (uint16_t) i;
              kernel->output_regs.x64[kernel->n_output_regs] = reg_id;
              kernel->n_output_regs++;
            }

            evoasm_x64_reg_write_acc_update(reg_write_acc, op, x64_basic_params);
          }
        }
      }
    }
  }

  assert(kernel->n_output_regs <= EVOASM_KERNEL_MAX_OUTPUT_REGS);
  assert(kernel->n_input_regs <= EVOASM_KERNEL_MAX_INPUT_REGS);
}

static void
evoasm_program_x64_prepare(evoasm_program_t *program) {
  for(size_t i = 0; i < program->size; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    evoasm_program_x64_prepare_kernel(program, kernel);
  }

}

static evoasm_success_t
evoasm_program_x64_emit_input_load(evoasm_program_t *program,
                                   evoasm_program_io_val_t *input_vals,
                                   evoasm_program_io_val_type_t *types,
                                   size_t in_arity,
                                   bool set_io_mapping) {


  evoasm_program_io_val_t *loaded_example = NULL;
  evoasm_x64_reg_id_t input_reg_id;
  size_t input_reg_idx;
  evoasm_buf_t *buf = program->buf;
  evoasm_kernel_t *kernel = &program->kernels[0];

  evoasm_log_debug("n _input regs %d", kernel->n_input_regs);
#if 1
  for(input_reg_id = (evoasm_x64_reg_id_t) 13; input_reg_id < 19; input_reg_id++) {
    if(input_reg_id == EVOASM_X64_REG_SP) continue;
    evoasm_x64_params_t params = {0};
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
    /*FIXME: hard-coded example type */
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, 0);
    EVOASM_X64_ENC(mov_r64_imm64);
  }
#endif

  for(input_reg_id = (evoasm_x64_reg_id_t) 0, input_reg_idx = 0; input_reg_idx < kernel->n_input_regs; input_reg_id++) {
    if(!kernel->reg_info.x64.regs[input_reg_id].input) continue;

    size_t example_idx;

    if(set_io_mapping) {
      example_idx = input_reg_idx % in_arity;
      program->reg_inputs.x64[input_reg_id] = (uint8_t) example_idx;
    } else {
      example_idx = program->reg_inputs.x64[input_reg_id];
    }

    evoasm_program_io_val_t *example = &input_vals[example_idx];
    evoasm_x64_params_t params = {0};
    evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(input_reg_id);

    evoasm_log_debug("emitting _input register initialization of register %d to value %"
                         PRId64, input_reg_id, example->i64);

    switch(reg_type) {
      case EVOASM_X64_REG_TYPE_GP: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        /*FIXME: hard-coded example type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) example->i64);
        EVOASM_X64_ENC(mov_r64_imm64);
        break;
      }
      case EVOASM_X64_REG_TYPE_XMM: {
        /* load address of example into tmp_reg */
        if(loaded_example != example) {
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_PROGRAM_TMP_REG_X64);
          EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) &example->f64);
          EVOASM_X64_ENC(mov_r64_imm64);
          loaded_example = example;
        }

        /* load into xmm via address in tmp_reg */
        /*FIXME: hard-coded example type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_PROGRAM_TMP_REG_X64);
        EVOASM_X64_ENC(movsd_xmm_xmmm64);
        break;
      }
      default:
        evoasm_log_fatal("non-gpr register type (%d) (unimplemented)", reg_type);
        evoasm_assert_not_reached();
    }

    input_reg_idx++;
  }

  if(program->reset_rflags) {
    EVOASM_TRY(error, evoasm_program_x64_emit_rflags_reset, program);
  }
  return true;

error:
enc_failed:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit_kernel_transition(evoasm_program_t *program,
                                          evoasm_kernel_t *kernel,
                                          evoasm_kernel_t *target_kernel,
                                          evoasm_buf_t *buf,
                                          size_t trans_idx,
                                          bool set_io_mapping) {
  size_t input_reg_idx;
  evoasm_x64_reg_id_t input_reg_id;

  assert(kernel->n_output_regs > 0);

  for(input_reg_id = (evoasm_x64_reg_id_t) 0, input_reg_idx = 0; input_reg_id < EVOASM_X64_REG_NONE; input_reg_id++) {
    if(!target_kernel->reg_info.x64.regs[input_reg_id].input) continue;

    evoasm_x64_reg_id_t output_reg_id;

    if(set_io_mapping) {
      size_t output_reg_idx = input_reg_idx % kernel->n_output_regs;
      output_reg_id = kernel->output_regs.x64[output_reg_idx];

      kernel->reg_info.x64.regs[input_reg_id].trans_regs[trans_idx] = output_reg_id;
    } else {
      output_reg_id = kernel->reg_info.x64.regs[input_reg_id].trans_regs[trans_idx];
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
    input_reg_idx++;
  }

  return true;

enc_failed:
  return false;
}

#define EVOASM_BUF_PHI_GET(buf) ((uint32_t *)((buf)->data + (buf)->pos - 4))
#define EVOASM_BUF_PHI_SET(label, val) \
do { (*(label) = (uint32_t)((uint8_t *)(val) - ((uint8_t *)(label) + 4)));} while(0);
#define EVOASM_BUF_POS_ADDR(buf) (buf->data + buf->pos)

#define EVOASM_PROGRAM_X64_N_JMP_INSTS 16

static evoasm_success_t
evoasm_program_x64_emit_kernel_transitions(evoasm_program_t *program,
                                           evoasm_kernel_t *kernel,
                                           evoasm_kernel_t *next_kernel,
                                           evoasm_kernel_t *branch_kernel,
                                           evoasm_buf_t *buf,
                                           uint32_t **branch_kernel_phi,
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
  uint32_t *branch_phi = NULL;
  uint32_t *counter_phi = NULL;

  if(program->recur_limit == 0) goto next_transition;

  evoasm_inst_id_t jmp_inst_id = jmp_insts[program->jmp_conds[kernel->idx] % EVOASM_PROGRAM_X64_N_JMP_INSTS];

  if(kernel->reg_info.x64.regs[EVOASM_X64_REG_RFLAGS].written) {
    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_OF)) {
      if(jmp_inst_id == EVOASM_X64_INST_JO_REL32 || jmp_inst_id == EVOASM_X64_INST_JNO_REL32) goto branch_transition;
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_SF)) {
      if(jmp_inst_id == EVOASM_X64_INST_JS_REL32 || jmp_inst_id == EVOASM_X64_INST_JNS_REL32) goto branch_transition;
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_ZF)) {
      if(jmp_inst_id == EVOASM_X64_INST_JE_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JNE_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JBE_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JLE_REL32) {
        goto branch_transition;
      }
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_CF)) {
      if(jmp_inst_id == EVOASM_X64_INST_JB_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JAE_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JBE_REL32) {
        goto branch_transition;
      }
    }

    if((EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_ZF)) &&
        (EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_CF))) {
      if(jmp_inst_id == EVOASM_X64_INST_JA_REL32) goto branch_transition;
    }

    if((EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_SF)) &&
        (EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_OF))) {

      if(jmp_inst_id == EVOASM_X64_INST_JL_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JGE_REL32 ||
         jmp_inst_id == EVOASM_X64_INST_JLE_REL32 ||
         ((EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_ZF)) && jmp_inst_id == EVOASM_X64_INST_JG_REL32)) {
        goto branch_transition;
      }
    }

    if(EVOASM_X64_RFLAGS_FLAGS_GET(kernel->reg_info.x64.written_flags, EVOASM_X64_RFLAGS_FLAG_PF)) {
      if(jmp_inst_id == EVOASM_X64_INST_JP_REL32 || jmp_inst_id == EVOASM_X64_INST_JNP_REL32) goto branch_transition;
    }
  }
  /* kernel does not write to required jump flag, ignore jmp_off and emit next kernel */
  goto next_transition;

#if 0
  /*FIXME: only 8bit possible, check and activate if feasable*/
  if(kernel->reg_info.x64.regs[EVOASM_X64_REG_C].written) {
    jmp_insts[possible_jmp_insts_len++] = EVOASM_X64_INST_JECXZ_JRCXZ_REL8;
  }
#endif

branch_transition:
  {
    evoasm_buf_ref_t buf_ref = {
        .data = buf->data,
        .pos = &buf->pos
    };
    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_TRY(error, evoasm_x64_enc_, (evoasm_x64_inst_id_t) jmp_inst_id, &params, &buf_ref);
    branch_phi = EVOASM_BUF_PHI_GET(buf);
    assert(*branch_phi == 0xdeadbeef);

    if(branch_kernel->idx <= kernel->idx) {
      /* back jump, guard with counter */

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

      counter_phi = EVOASM_BUF_PHI_GET(buf);
      assert(*counter_phi == 0xdeadbeef);

      EVOASM_X64_ENC(inc_rm32);
    }

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transition, program,
               kernel, branch_kernel, buf, 1, set_io_mapping);

    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_X64_ENC(jmp_rel32);

    *branch_kernel_phi = EVOASM_BUF_PHI_GET(buf);
    assert(**branch_kernel_phi == 0xdeadbeef);

    if(branch_phi != NULL) {
      EVOASM_BUF_PHI_SET(branch_phi, EVOASM_BUF_POS_ADDR(buf));
    }

    if(counter_phi != NULL) {
      EVOASM_BUF_PHI_SET(counter_phi, EVOASM_BUF_POS_ADDR(buf));
    }
  }

next_transition:
  if(next_kernel != NULL) {
    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transition, program,
               kernel, next_kernel, buf, 0, set_io_mapping);
  }

  evoasm_buf_log(buf, EVOASM_LOG_LEVEL_DEBUG);

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
    EVOASM_TRY(error, evoasm_x64_inst_enc_basic_, inst, &kernel->params.x64[i], &buf_ref);
  }
  return true;
error:
  return false;
}


static size_t
evoasm_program_branch_kernel_idx(evoasm_program_t *program, size_t idx) {
  return (size_t) EVOASM_CLAMP((int) idx + program->jmp_offs[idx], 0, program->size - 1);
}

static evoasm_success_t
evoasm_program_x64_emit_program_kernels(evoasm_program_t *program, bool set_io_mapping) {
  evoasm_buf_t *buf = program->body_buf;
  evoasm_kernel_t *kernel, *next_kernel, *branch_kernel;
  size_t program_size = program->size;
  uint32_t *branch_phis[EVOASM_PROGRAM_MAX_SIZE] = {0};
  uint8_t *kernel_addrs[EVOASM_PROGRAM_MAX_SIZE];

  evoasm_buf_reset(buf);

  assert(program_size > 0);

  for(size_t i = 0; i < program_size; i++) {
    kernel = &program->kernels[i];

    kernel_addrs[i] = buf->data + buf->pos;
    kernel->buf_start = (uint16_t) buf->pos;

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel, program, kernel, buf);

    if(i < program_size - 1) {
      next_kernel = &program->kernels[i + 1];
    } else {
      next_kernel = NULL;
    }

    size_t branch_kernel_idx = evoasm_program_branch_kernel_idx(program, i);
    assert(branch_kernel_idx < program->size);
    branch_kernel = &program->kernels[branch_kernel_idx];

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transitions, program, kernel,
               next_kernel, branch_kernel, buf, &branch_phis[i], set_io_mapping);

    kernel->buf_end = (uint16_t) buf->pos;
  }

  for(size_t i = 0; i < program_size; i++) {
    size_t branch_kernel_idx = evoasm_program_branch_kernel_idx(program, i);
    uint32_t *branch_phi = branch_phis[i];
    if(branch_phi != NULL) {
      uint8_t *branch_kernel_addr = kernel_addrs[branch_kernel_idx];
      assert(*branch_phi == 0xdeadbeef);
      EVOASM_BUF_PHI_SET(branch_phi, branch_kernel_addr);
    }
  }

  return true;
error:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit_io_load_store(evoasm_program_t *program,
                                      evoasm_program_input_t *input,
                                      bool io_mapping) {
  size_t n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(input);

  evoasm_buf_reset(program->buf);
  EVOASM_TRY(error, evoasm_x64_emit_func_prolog, EVOASM_X64_ABI_SYSV, program->buf);

  for(size_t i = 0; i < n_examples; i++) {
    evoasm_program_io_val_t *input_vals = input->vals + i * input->arity;
    EVOASM_TRY(error, evoasm_program_x64_emit_input_load, program, input_vals, input->types, input->arity,
               io_mapping);
    size_t r = evoasm_buf_append(program->buf, program->body_buf);
    assert(r == 0);
    EVOASM_TRY(error, evoasm_program_x64_emit_output_store, program, i);
  }

  EVOASM_TRY(error, evoasm_x64_emit_func_epilog, EVOASM_X64_ABI_SYSV, program->buf);
  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit(evoasm_program_t *program,
                        evoasm_program_input_t *input,
                        evoasm_program_emit_flags_t emit_flags) {

  bool set_io_mapping = emit_flags & EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;

  if(emit_flags & EVOASM_PROGRAM_EMIT_FLAG_PREPARE) {
    evoasm_program_x64_prepare(program);
  }

  if(emit_flags & EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS) {
    EVOASM_TRY(error, evoasm_program_x64_emit_program_kernels, program, set_io_mapping);
  }

  if(emit_flags & EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE) {
    EVOASM_TRY(error, evoasm_program_x64_emit_io_load_store, program, input, set_io_mapping);
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
                               size_t example_idx,
                               double *dist_mat,
                               evoasm_metric metric) {
  size_t width = kernel->n_output_regs;
  evoasm_program_io_val_t *io_vals = output->vals + example_idx * output->arity;

  for(size_t i = 0; i < height; i++) {
    evoasm_program_io_val_t io_val = io_vals[i];
    evoasm_program_io_val_type_t example_type = output->types[i];
    double io_val_dbl = evoasm_program_io_val_to_dbl(io_val, example_type);

    for(size_t j = 0; j < width; j++) {
      evoasm_program_io_val_t output_val = program->output_vals[example_idx * width + j];
      //uint8_t output_size = program->output_sizes[j];
      //switch(output_size) {
      //
      //}
      // FIXME: output is essentially just a bitstring and could be anything
      // an integer (both, signed or unsigned) a float or double.
      // Moreover, a portion of the output value could
      // hold the correct answer (e.g. lower 8 or 16 bits etc.).
      // For now we use the example output type and assume signedness.
      // This needs to be fixed.
      double output_val_dbl = evoasm_program_io_val_to_dbl(output_val, example_type);

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

  size_t n_examples = EVOASM_PROGRAM_OUTPUT_N_EXAMPLES(output);
  size_t height = output->arity;
  size_t width = kernel->n_output_regs;

  evoasm_log(log_level, EVOASM_LOG_TAG, "OUTPUT MATRICES:\n");

  for(size_t i = 0; i < width; i++) {
    evoasm_log(log_level, EVOASM_LOG_TAG, " %d  ", program->output_regs[i]);
  }

  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");

  for(size_t i = 0; i < n_examples; i++) {
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
                         double *dist_mat,
                         uint_fast8_t *matching) {
  size_t width = kernel->n_output_regs;
  double scale = 1.0 / (double) width;
  double loss = 0.0;

  for(size_t i = 0; i < height; i++) {
    loss += (scale * dist_mat[i * width + matching[i]]);
  }

  return (evoasm_loss_t) loss;
}


static evoasm_loss_t
evoasm_program_assess(evoasm_program_t *program,
                      evoasm_program_output_t *output) {

  size_t n_examples = EVOASM_PROGRAM_OUTPUT_N_EXAMPLES(output);
  size_t height = output->arity;
  evoasm_kernel_t *kernel = &program->kernels[program->size - 1];
  size_t width = kernel->n_output_regs;
  size_t dist_mat_len = (size_t) (width * height);
  double *dist_mat = evoasm_alloca(dist_mat_len * sizeof(double));
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));
  evoasm_loss_t loss;

  for(size_t i = 0; i < dist_mat_len; i++) {
    dist_mat[i] = 0.0;
  }

  if(height == 1) {
    /* COMMON FAST-PATH */
    for(size_t i = 0; i < n_examples; i++) {
      evoasm_program_update_dist_mat(program, kernel, output, 1, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    if(evoasm_program_match(program, width, dist_mat, matching)) {
      loss = evoasm_program_calc_loss(program, kernel, 1, dist_mat, matching);
    } else {
      loss = INFINITY;
    }
  } else {
    for(size_t i = 0; i < n_examples; i++) {
      evoasm_program_update_dist_mat(program, kernel, output, height, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    evoasm_program_calc_stable_matching(program, kernel, height, dist_mat, matching);
    loss = evoasm_program_calc_loss(program, kernel, height, dist_mat, matching);
  }


  for(size_t i = 0; i < height; i++) {
    switch(program->arch_info->id) {
      case EVOASM_ARCH_X64: {
        program->output_regs[i] = kernel->output_regs.x64[matching[i]];
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
  if(loss == 0.0) {
    evoasm_program_log_program_output(program,
                                      kernel,
                                      output,
                                      matching,
                                      EVOASM_LOG_LEVEL_INFO);
  }
#endif

  return loss;
}

static void
evoasm_program_reset_recur_counters(evoasm_program_t *program) {
  memset(program->recur_counters, 0, sizeof(program->recur_counters[0]) * program->size);
}

evoasm_loss_t
evoasm_program_eval(evoasm_program_t *program,
                    evoasm_program_output_t *output) {

  evoasm_kernel_t *kernel = &program->kernels[program->size - 1];
  evoasm_loss_t loss;

  if(evoasm_unlikely(kernel->n_output_regs == 0)) {
    return INFINITY;
  }

  evoasm_program_reset_recur_counters(program);

  evoasm_signal_set_exception_mask(program->exception_mask);

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(program->buf);
    loss = evoasm_program_assess(program, output);
  } else {
    evoasm_log_debug("program %p signaled", (void *) program);
    loss = INFINITY;
  }
  return loss;
}

static evoasm_program_output_t *
evoasm_program_load_output(evoasm_program_t *program,
                           evoasm_kernel_t *kernel,
                           evoasm_program_input_t *input) {

  size_t width = kernel->n_output_regs;
  evoasm_program_output_t *output = &program->_output;
  size_t height = output->arity;
  size_t n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(input);
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));

  evoasm_program_output_t *load_output = evoasm_program_io_alloc(
      (uint16_t) (EVOASM_PROGRAM_INPUT_N_EXAMPLES(input) * height));

  for(size_t i = 0; i < height; i++) {
    for(size_t j = 0; j < kernel->n_output_regs; j++) {
      if(program->output_regs[i] == kernel->output_regs.x64[j]) {
        matching[i] = (uint_fast8_t) j;
        goto next;
      }
    }
    evoasm_log_fatal("program output reg %d not found in kernel output regs", program->output_regs[i]);
    evoasm_assert_not_reached();
next:;
  }

  for(size_t i = 0; i < n_examples; i++) {
    for(size_t j = 0; j < height; j++) {
      load_output->vals[i * height + j] = program->output_vals[i * width + matching[j]];
    }
  }

  load_output->arity = output->arity;
  memcpy(load_output->types, output->types, EVOASM_ARY_LEN(output->types));

//#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_INFO

  evoasm_program_log_program_output(program,
                                    kernel,
                                    load_output,
                                    matching,
                                    EVOASM_LOG_LEVEL_WARN);
//#endif
  return load_output;
}

evoasm_program_output_t *
evoasm_program_run(evoasm_program_t *program,
                   evoasm_program_input_t *input) {
  evoasm_kernel_t *kernel = &program->kernels[program->size - 1];
  evoasm_program_output_t *output;

  if(input->arity != program->_input.arity) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE, NULL,
                 "example arity mismatch (%d for %d)", input->arity, program->_input.arity);
    return NULL;
  }

  size_t n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(input);
  if(n_examples > program->max_examples) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE, NULL,
                 "Maximum number of examples exceeded (%zu > %d)", n_examples, program->max_examples);
    return NULL;
  }

  for(size_t i = 0; i < input->arity; i++) {
    if(input->types[i] != program->_input.types[i]) {
      evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE, NULL,
                   "example type mismatch (%d != %d)", input->types[i], program->_input.types[i]);
      return NULL;
    }
  }

  evoasm_program_emit_flags_t emit_flags = EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE;
  if(!evoasm_program_emit(program, input, emit_flags)) {
    return NULL;
  }

  evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_DEBUG);
  evoasm_signal_install((evoasm_arch_id_t) program->arch_info->id, program->exception_mask);

  if(!evoasm_buf_protect(program->buf, EVOASM_MPROT_MODE_RX)) {
    evoasm_assert_not_reached();
  }

  evoasm_program_reset_recur_counters(program);

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(program->buf);
    output = evoasm_program_load_output(program,
                                        kernel,
                                        input);
  } else {
    evoasm_log_debug("signaled\n");
    output = NULL;
  }

  if(!evoasm_buf_protect(program->buf, EVOASM_MPROT_MODE_RW)) {
    evoasm_assert_not_reached();
  }

  evoasm_signal_uninstall();

  return output;
}

evoasm_success_t
evoasm_program_emit(evoasm_program_t *program,
                    evoasm_program_input_t *input,
                    evoasm_program_emit_flags_t emit_flags) {
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64: {
      return evoasm_program_x64_emit(program, input,
                                     emit_flags);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_program_unprepare_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel) {
  kernel->n_input_regs = 0;
  kernel->n_output_regs = 0;

  static evoasm_kernel_reg_info_t zero_reg_info = {0};
  kernel->reg_info = zero_reg_info;
}

void
evoasm_program_unprepare(evoasm_program_t *program) {
  for(size_t i = 0; i < program->size; i++) {
    evoasm_program_unprepare_kernel(program, &program->kernels[i]);
  }
}

static size_t
evoasm_program_x64_find_writers_(evoasm_program_t *program, evoasm_kernel_t *kernel, evoasm_reg_id_t reg_id,
                                 size_t idx, size_t *writers) {
  size_t len = 0;
  for(int i = (int) idx; i >= 0; i--) {
    evoasm_x64_reg_write_acc_t reg_write_acc;
    evoasm_x64_reg_write_acc_init(&reg_write_acc);

    if(evoasm_kernel_is_writing_inst_x64(kernel, (size_t) i, reg_id, &reg_write_acc)) {
      writers[len++] = (size_t) i;
    }
  }
  return len;
}

static size_t
evoasm_program_x64_find_writers(evoasm_program_t *program, evoasm_kernel_t *kernel,
                                evoasm_reg_id_t reg_id, size_t idx, size_t *writers) {

  return evoasm_program_x64_find_writers_(program, kernel, reg_id, idx, writers);
}

typedef struct {
  bool change;
  evoasm_bitmap1024_t inst_bitmaps[EVOASM_PROGRAM_MAX_SIZE];
  evoasm_bitmap256_t output_reg_bitmaps[EVOASM_PROGRAM_MAX_SIZE];
} evoasm_program_intron_elimination_ctx;

static void
evoasm_program_x64_mark_writers(evoasm_program_t *program, evoasm_kernel_t *kernel,
                                evoasm_reg_id_t reg_id, size_t idx, evoasm_program_intron_elimination_ctx *ctx) {
  size_t writers[16];

  size_t writers_len = evoasm_program_x64_find_writers(program, kernel, reg_id, idx, writers);

  if(writers_len > 0) {
    for(size_t i = 0; i < writers_len; i++) {
      size_t writer_idx = writers[i];
      evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx->inst_bitmaps[kernel->idx];
      if(evoasm_bitmap_get(inst_bitmap, writer_idx)) continue;

      evoasm_x64_inst_t *x64_inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) kernel->insts[writer_idx]);
      evoasm_bitmap_set(inst_bitmap, writer_idx);
      ctx->change = true;

      for(size_t j = 0; j < x64_inst->n_operands; j++) {
        evoasm_x64_operand_t *op = &x64_inst->operands[j];
        evoasm_x64_reg_id_t op_reg_id = evoasm_kernel_get_operand_reg_id_x64(kernel, op, (uint16_t) writer_idx);

        if(op->read) {
          if(writer_idx > 0) {
            evoasm_program_x64_mark_writers(program, kernel, op_reg_id, writer_idx - 1u, ctx);
          }

          if(kernel->reg_info.x64.regs[op_reg_id].input) {
            size_t trans_kernels_idxs[] = {kernel->idx + 1u,
                                           evoasm_program_branch_kernel_idx(program, i)};
            for(size_t k = 0; k < EVOASM_ARY_LEN(trans_kernels_idxs); k++) {
              //evoasm_kernel_t *trans_kernel = &program->kernels[trans_kernels_idxs[k]];
              for(size_t l = 0; l < EVOASM_X64_REG_NONE; l++) {
                if(kernel->reg_info.x64.regs[l].trans_regs[k] == op_reg_id) {
                  evoasm_bitmap_set((evoasm_bitmap_t *) &ctx->output_reg_bitmaps[trans_kernels_idxs[k]], l);
                }
              }
            }
          } else {
          }
        }
      }
    }
  }
}

static void
evoasm_program_mark_writers(evoasm_program_t *program, evoasm_kernel_t *kernel,
                            evoasm_reg_id_t reg_id, size_t index, evoasm_program_intron_elimination_ctx *ctx) {
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64: {
      evoasm_program_x64_mark_writers(program, kernel, reg_id, index, ctx);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static evoasm_success_t
evoasm_program_mark_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel,
                           evoasm_program_intron_elimination_ctx *ctx) {
  for(size_t i = 0; i < EVOASM_X64_REG_NONE; i++) {
    evoasm_bitmap_t *bitmap = (evoasm_bitmap_t *) &ctx->output_reg_bitmaps[kernel->idx];
    if(evoasm_bitmap_get(bitmap, i)) {
      evoasm_program_mark_writers(program, kernel, (evoasm_reg_id_t) i, (size_t) (kernel->size - 1),
                                  ctx);
    }
  }

  return true;
}

evoasm_success_t
evoasm_program_eliminate_introns(evoasm_program_t *program, evoasm_program_t *dst_program) {
  size_t last_kernel_idx = (size_t) (program->size - 1);
  evoasm_program_intron_elimination_ctx ctx = {0};

  //evoasm_kernel_t *last_kernel = &program->kernels[last_kernel_idx];

  EVOASM_TRY(error, evoasm_program_init,
             dst_program,
             program->arch_info,
             program->size,
             program->kernels[0].size,
             program->max_examples,
             program->recur_limit,
             false);

  evoasm_bitmap_t *output_bitmap = (evoasm_bitmap_t *) &ctx.output_reg_bitmaps[last_kernel_idx];
  for(size_t i = 0; i < program->_output.arity; i++) {
    evoasm_bitmap_set(output_bitmap, program->output_regs[i]);
  }

  do {
    ctx.change = false;
    for(int i = (int) last_kernel_idx; i >= 0; i--) {
      EVOASM_TRY(error, evoasm_program_mark_kernel, program,
                 &program->kernels[i], &ctx);
    }
  } while(ctx.change);

  /* sweep */
  for(size_t i = 0; i <= last_kernel_idx; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    evoasm_kernel_t *dst_kernel = &dst_program->kernels[i];
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx.inst_bitmaps[i];

    size_t k = 0;
    for(size_t j = 0; j < kernel->size; j++) {
      if(evoasm_bitmap_get(inst_bitmap, j)) {
        dst_kernel->insts[k] = kernel->insts[j];
        dst_kernel->params.x64[k] = kernel->params.x64[j];
        k++;
      }
    }

    if(dst_kernel != kernel) {
      dst_kernel->reg_info = kernel->reg_info;
      dst_kernel->output_regs = kernel->output_regs;
      dst_kernel->n_input_regs = kernel->n_input_regs;
      dst_kernel->n_output_regs = kernel->n_output_regs;
    }
  }

  if(dst_program != program) {
    dst_program->_input = program->_input;
    dst_program->_output = program->_output;
    memcpy(dst_program->output_regs, program->output_regs, sizeof(program->output_regs));
    EVOASM_MEMCPY_N(dst_program->jmp_offs, program->jmp_offs, program->size);
    EVOASM_MEMCPY_N(dst_program->jmp_conds, program->jmp_conds, program->size);
  }

  evoasm_program_emit_flags_t emit_flags =
      EVOASM_PROGRAM_EMIT_FLAG_PREPARE |
      EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS;

  EVOASM_TRY(error, evoasm_program_emit, dst_program, NULL, emit_flags);

  return true;
error:
  return false;
}


#define EVOASM_PROGRAM_PROLOG_EPILOG_SIZE UINT32_C(1024)
#define EVOASM_PROGRAM_TRANSITION_SIZE UINT32_C(512)


evoasm_success_t
evoasm_program_init(evoasm_program_t *program,
                    evoasm_arch_info_t *arch_info,
                    size_t program_size,
                    size_t kernel_size,
                    size_t max_examples,
                    size_t recur_limit,
                    bool shallow) {

  static evoasm_program_t zero_program = {0};
  size_t n_transitions = program_size - 1u;

  *program = zero_program;
  program->arch_info = arch_info;
  program->recur_limit = (uint32_t) recur_limit;
  program->shallow = shallow;
  program->size = (uint16_t) program_size;
  program->max_examples = (uint16_t) max_examples;

  size_t body_buf_size =
      (size_t) (n_transitions * EVOASM_PROGRAM_TRANSITION_SIZE
                + program_size * kernel_size * program->arch_info->max_inst_len);

  size_t buf_size = max_examples * (body_buf_size + EVOASM_PROGRAM_PROLOG_EPILOG_SIZE);

  EVOASM_TRY(error, evoasm_buf_init, &program->_buf, EVOASM_BUF_TYPE_MMAP, buf_size);
  program->buf = &program->_buf;

  EVOASM_TRY(error, evoasm_buf_init, &program->_body_buf, EVOASM_BUF_TYPE_MALLOC, body_buf_size);
  program->body_buf = &program->_body_buf;

  EVOASM_TRY(error, evoasm_buf_protect, &program->_buf,
             EVOASM_MPROT_MODE_RWX);

  size_t output_vals_len = max_examples * EVOASM_KERNEL_MAX_OUTPUT_REGS;

  EVOASM_TRY_ALLOC(error, calloc, program->output_vals, output_vals_len, sizeof(evoasm_program_io_val_t));
  EVOASM_TRY_ALLOC(error, calloc, program->kernels, program_size, sizeof(evoasm_kernel_t));
  EVOASM_TRY_ALLOC(error, calloc, program->recur_counters, program_size, sizeof(uint32_t));
  EVOASM_TRY_ALLOC(error, calloc, program->jmp_conds, program_size, sizeof(uint8_t));
  EVOASM_TRY_ALLOC(error, calloc, program->jmp_offs, program_size, sizeof(int16_t));

  for(uint16_t i = 0; i < program_size; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];

    kernel->idx = i;
    kernel->size = (uint16_t) kernel_size;

    if(!shallow) {
      EVOASM_TRY_ALLOC(error, calloc, kernel->insts, kernel_size, sizeof(kernel->insts[0]));
      switch(program->arch_info->id) {
        case EVOASM_ARCH_X64: {
          EVOASM_TRY_ALLOC(error, calloc, kernel->params.x64, kernel_size, sizeof(kernel->params.x64[0]));
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
  if(_evoasm_min_log_level > log_level) return;

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
  if(_evoasm_min_log_level > log_level) return;

  evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Program: size: %d", program->size);

  for(size_t i = 0; i < program->size; i++)
  {
    evoasm_kernel_log(&program->kernels[i], (evoasm_arch_id_t) program->arch_info->id, log_level);
  }
  evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
}

EVOASM_DEF_ALLOC_FREE_FUNCS(program)
