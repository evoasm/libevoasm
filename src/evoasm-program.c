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

  unsigned i;
  bool retval = true;

  for(i = 0; i < program->kernel_count; i++) {
    if(!program->shallow) {
      evoasm_free(program->kernels[i].insts);
      switch(program->arch_info->id) {
        case EVOASM_ARCH_X64:
          evoasm_free(program->kernels[i].params.x64);
          break;
        default:
          evoasm_assert_not_reached();
      }
    }
  }

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

evoasm_success_t
evoasm_program_clone(evoasm_program_t *program, evoasm_program_t *cloned_program) {
  unsigned i = 0;

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

  for(; i < program->params->kernel_count; i++) {
    evoasm_kernel_t *orig_kernel = &program->kernels[i];
    evoasm_kernel_t *cloned_kernel = &cloned_program->kernels[i];
    *cloned_kernel = *orig_kernel;

    size_t params_size = sizeof(evoasm_kernel_params_t) + orig_kernel->params->kernel_count * sizeof(evoasm_kernel_param_t);
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

evoasm_success_t
evoasm_program_destroy(evoasm_program_t *program) {
  return evoasm_program_destroy_(program, program->params->kernel_count);
}

evoasm_buf_t *
evoasm_program_get_buf(evoasm_program_t *program, bool body) {
  if(body) {
    return program->body_buf;
  } else {
    return program->buf;
  }
}

evoasm_kernel_count_t
evoasm_program_get_kernel_count(evoasm_program_t *program) {
  return program->params->kernel_count;
}

size_t
evoasm_program_get_kernel_code(evoasm_program_t *program, unsigned kernel_idx, const uint8_t **code) {
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


unsigned
evoasm_program_get_kernel_alt_succ(evoasm_program_t *program, unsigned kernel_idx) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  return kernel->params->alt_succ_idx;
}


bool
evoasm_program_is_input_reg(evoasm_program_t *program, unsigned kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->reg_info.x64[reg_id].input;
    default:
      evoasm_assert_not_reached();
  }
}

bool
evoasm_program_is_output_reg(evoasm_program_t *program, unsigned kernel_idx, evoasm_reg_id_t reg_id) {
  evoasm_kernel_t *kernel = &program->kernels[kernel_idx];
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64:
      return kernel->reg_info.x64[reg_id].output;
    default:
      evoasm_assert_not_reached();
  }
}

#define _EVOASM_X64_REG_TMP EVOASM_X64_REG_14

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

static evoasm_success_t
evoasm_program_x64_emit_mxcsr_reset(evoasm_program_t *program) {
  static uint32_t default_mxcsr_val = 0x1f80;
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = program->buf;

  evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) &default_mxcsr_val;
  evoasm_x64_reg_id_t reg_tmp0 = _EVOASM_X64_REG_TMP;

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
                                 unsigned example_index) {

  evoasm_x64_params_t params = {0};
  evoasm_kernel_t *kernel = &program->kernels[program->params->kernel_count - 1];
  evoasm_buf_t *buf = program->buf;
  unsigned i;

  for(i = 0; i < kernel->n_output_regs; i++) {
    evoasm_x64_reg_id_t reg_id = kernel->output_regs.x64[i];
    evoasm_program_io_val_t *val_addr = &program->output_vals[(example_index * kernel->n_output_regs) + i];
    evoasm_x64_reg_type_t reg_type = evoasm_x64_reg_type(reg_id);

    evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) val_addr;

    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, _EVOASM_X64_REG_TMP);
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
    EVOASM_X64_ENC(mov_r64_imm64);

    switch(reg_type) {
      case EVOASM_X64_REG_TYPE_GP: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, _EVOASM_X64_REG_TMP);
        EVOASM_X64_ENC(mov_rm64_r64);
        break;
      }
      case EVOASM_X64_REG_TYPE_XMM: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, _EVOASM_X64_REG_TMP);
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
evoasm_op_x64_reg_id(evoasm_x64_operand_t *op, evoasm_kernel_param_t *param) {
  evoasm_x64_inst_t *inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);

  if(op->param_idx < inst->n_params) {
    return (evoasm_x64_reg_id_t) _evoasm_x64_basic_params_get(&param->x64.params,
                                                              (evoasm_x64_param_id_t) inst->params[op->param_idx].id);
  } else if(op->reg_id < EVOASM_X64_N_REGS) {
    return (evoasm_x64_reg_id_t) op->reg_id;
  } else {
    evoasm_assert_not_reached();
    return 0;
  }
}

typedef struct {
  bool high_byte_reg : 1;
  unsigned mask;
  unsigned size;
} evoasm_x64_reg_write_acc_t;


static void
evoasm_x64_reg_write_acc_update(evoasm_x64_reg_write_acc_t *reg_write_acc,
                                evoasm_x64_operand_t *op, evoasm_kernel_param_t *param) {
  if(reg_write_acc->size < EVOASM_X64_N_OPERAND_SIZES) {
    reg_write_acc->size = EVOASM_MAX(reg_write_acc->size, op->size1);
  } else {
    reg_write_acc->size = op->size1;
  }

  reg_write_acc->mask |= op->write_mask;
  reg_write_acc->high_byte_reg |= param->x64.params.reg0_high_byte || param->x64.params.reg1_high_byte;
}


static bool
evoasm_x64_reg_write_acc_is_dirty_read(evoasm_x64_reg_write_acc_t *reg_write_acc, evoasm_x64_operand_t *op,
                                       evoasm_kernel_param_t *param) {
  bool uncovered_acc;
  bool high_byte_reg = param->x64.params.reg0_high_byte || param->x64.params.reg1_high_byte;

  assert(reg_write_acc->size <= EVOASM_X64_N_OPERAND_SIZES);
  if(reg_write_acc->size == EVOASM_X64_N_OPERAND_SIZES) {
    return true;
  }

  if(op->reg_type == EVOASM_X64_REG_TYPE_GP) {
    /* 32bit writes clear the whole register */
    if(reg_write_acc->size >= EVOASM_X64_OPERAND_SIZE_32) {
      uncovered_acc = false;
    } else {
      if(op->size1 == EVOASM_X64_OPERAND_SIZE_8 &&
         reg_write_acc->size == EVOASM_X64_OPERAND_SIZE_8) {
        uncovered_acc = high_byte_reg != reg_write_acc->high_byte_reg;
      } else {
        uncovered_acc = reg_write_acc->size < op->size1;
      }
    }
  } else if(op->reg_type == EVOASM_X64_REG_TYPE_XMM) {
    unsigned mask;
    if(op->size1 == EVOASM_X64_OPERAND_SIZE_128) {
      mask = EVOASM_X64_BIT_MASK_0_127;
    } else {
      mask = EVOASM_X64_BIT_MASK_ALL;
    }
    uncovered_acc = ((mask & (~reg_write_acc->mask)) != 0);
  } else {
    uncovered_acc = false;
  }

  return uncovered_acc;
}

static bool
evoasm_kernel_param_x64_is_writer(evoasm_kernel_param_t *param, evoasm_reg_id_t reg_id,
                                  evoasm_x64_reg_write_acc_t *reg_write_acc) {
  evoasm_x64_inst_t *x64_inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);
  unsigned i;

  for(i = 0; i < x64_inst->n_operands; i++) {
    evoasm_x64_operand_t *op = &x64_inst->operands[i];
    evoasm_x64_reg_id_t op_reg_id = evoasm_op_x64_reg_id(op, param);

    if(op->written && op_reg_id == reg_id && evoasm_x64_reg_write_acc_is_dirty_read(reg_write_acc, op, param)) {
      evoasm_x64_reg_write_acc_update(reg_write_acc, op, param);
      return true;
    }
  }
  return false;
}


static void
evoasm_x64_reg_write_acc_init(evoasm_x64_reg_write_acc_t *reg_write_acc) {
  static evoasm_x64_reg_write_acc_t zero_reg_write_acc = {0};
  *reg_write_acc = zero_reg_write_acc;

  reg_write_acc->size = EVOASM_X64_N_OPERAND_SIZES;
}

static void
evoasm_program_x64_prepare_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel) {
  unsigned i, j;

  /* NOTE: output register are register that are written to
   *       _input registers are register that are read from without
   *       a previous write
   */
  evoasm_kernel_params_t *kernel_params = kernel->params;

  evoasm_x64_reg_write_acc_t reg_write_accs[EVOASM_X64_N_REGS];
  for(i = 0; i < EVOASM_X64_N_REGS; i++) {
    evoasm_x64_reg_write_acc_init(&reg_write_accs[i]);
  }

  for(i = 0; i < kernel_params->kernel_count; i++) {
    evoasm_kernel_param_t *param = &kernel_params->params[i];
    evoasm_x64_inst_t *x64_inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);

    for(j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if(op->type == EVOASM_X64_OPERAND_TYPE_REG ||
         op->type == EVOASM_X64_OPERAND_TYPE_RM) {

        if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
          if(op->read) {
            program->reset_rflags = true;
          } else if(op->written) {
            kernel->reg_info.x64[op->reg_id].written = true;
          }
        } else {
          evoasm_x64_reg_id_t reg_id = evoasm_op_x64_reg_id(op, param);
          evoasm_kernel_x64_reg_info_t *reg_info = &kernel->reg_info.x64[reg_id];
          evoasm_x64_reg_write_acc_t *reg_write_acc = &reg_write_accs[reg_id];

          /*
           * Conditional writes (cond_written) might or might not do the write.
           */

          if(op->read || op->cond_written) {
            if(!reg_info->input) {
              // has not been written before, might contain garbage
              bool dirty_read;

              if(!reg_info->written) {
                dirty_read = true;
              } else {
                dirty_read = evoasm_x64_reg_write_acc_is_dirty_read(reg_write_acc, op, param);
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
              kernel->output_regs.x64[kernel->n_output_regs] = reg_id;
              kernel->n_output_regs++;
            }

            evoasm_x64_reg_write_acc_update(reg_write_acc, op, param);
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
  unsigned i;
  for(i = 0; i < program->params->kernel_count; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    evoasm_program_x64_prepare_kernel(program, kernel);
  }

}

static evoasm_success_t
evoasm_program_x64_emit_input_load(evoasm_program_t *program,
                               evoasm_kernel_t *kernel,
                               evoasm_program_io_val_t *input_vals,
                               evoasm_program_io_val_type_t *types,
                               unsigned in_arity,
                               bool set_io_mapping) {


  evoasm_program_io_val_t *loaded_example = NULL;
  evoasm_x64_reg_id_t input_reg_id;
  unsigned input_reg_idx;
  evoasm_buf_t *buf = program->buf;

  evoasm_log_debug("n _input regs %d", kernel->n_input_regs);
#if 1
  for(input_reg_id = (evoasm_x64_reg_id_t) 9; input_reg_id < 25; input_reg_id++) {
    if(input_reg_id == EVOASM_X64_REG_SP) continue;
    evoasm_x64_params_t params = {0};
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
    /*FIXME: hard-coded example type */
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, 0);
    EVOASM_X64_ENC(mov_r64_imm64);
  }
#endif

  for(input_reg_id = (evoasm_x64_reg_id_t) 0, input_reg_idx = 0; input_reg_idx < kernel->n_input_regs; input_reg_id++) {
    if(!kernel->reg_info.x64[input_reg_id].input) continue;

    unsigned example_idx;

    if(set_io_mapping) {
      example_idx = input_reg_idx % in_arity;
      program->reg_inputs.x64[input_reg_id] = (uint8_t) example_idx;
    } else {
      example_idx = program->reg_inputs.x64[input_reg_id];
    }

    evoasm_program_io_val_t *example = &input_vals[example_idx];
    evoasm_x64_params_t params = {0};
    evoasm_x64_reg_type_t reg_type = evoasm_x64_reg_type(input_reg_id);

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
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, _EVOASM_X64_REG_TMP);
          EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) &example->f64);
          EVOASM_X64_ENC(mov_r64_imm64);
          loaded_example = example;
        }

        /* load into xmm via address in tmp_reg */
        /*FIXME: hard-coded example type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, _EVOASM_X64_REG_TMP);
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
                                      unsigned trans_idx,
                                      bool set_io_mapping) {
  unsigned input_reg_idx;
  evoasm_x64_reg_id_t input_reg_id;

  assert(kernel->n_output_regs > 0);

  for(input_reg_id = (evoasm_x64_reg_id_t) 0, input_reg_idx = 0; input_reg_id < EVOASM_X64_N_REGS; input_reg_id++) {
    if(!target_kernel->reg_info.x64[input_reg_id].input) continue;

    evoasm_x64_reg_id_t output_reg_id;

    if(set_io_mapping) {
      unsigned output_reg_idx = input_reg_idx % kernel->n_output_regs;
      output_reg_id = kernel->output_regs.x64[output_reg_idx];

      kernel->reg_info.x64[input_reg_id].trans_regs[trans_idx] = output_reg_id;
    } else {
      output_reg_id = kernel->reg_info.x64[input_reg_id].trans_regs[trans_idx];
    }

    evoasm_x64_reg_type_t output_reg_type = evoasm_x64_reg_type(output_reg_id);
    evoasm_x64_reg_type_t input_reg_type = evoasm_x64_reg_type(input_reg_id);
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

#define _EVOASM_BUF_PHI_GET(buf) ((uint32_t *)((buf)->data + (buf)->pos - 4))
#define _EVOASM_BUF_PHI_SET(label, val) \
do { (*(label) = (uint32_t)((uint8_t *)(val) - ((uint8_t *)(label) + 4)));} while(0);
#define _EVOASM_BUF_POS_ADDR(buf) (buf->data + buf->pos)

static evoasm_success_t
evoasm_program_x64_emit_kernel_transitions(evoasm_program_t *program,
                                       evoasm_kernel_t *kernel,
                                       evoasm_kernel_t *next_kernel,
                                       evoasm_kernel_t *branch_kernel,
                                       evoasm_buf_t *buf,
                                       uint32_t **branch_kernel_phi,
                                       bool set_io_mapping) {

  unsigned jmp_insts_len = 0;
  evoasm_inst_id_t jmp_insts[32];
  bool jbe = false;
  bool jle = false;
  evoasm_x64_params_t params = {0};
  uint32_t *branch_phi = NULL;
  uint32_t *counter_phi = NULL;

  if(program->recur_limit == 0) goto next_trans;

  if(kernel->reg_info.x64[EVOASM_X64_REG_OF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JO_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNO_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_SF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JS_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNS_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_ZF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JE_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNS_REL32;

    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JBE_REL32;
    jbe = true;

    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JLE_REL32;
    jle = true;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_CF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JB_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JAE_REL32;

    if(!jbe) {
      jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JBE_REL32;
    }
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_ZF].written &&
     kernel->reg_info.x64[EVOASM_X64_REG_CF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JA_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_SF].written &&
     kernel->reg_info.x64[EVOASM_X64_REG_OF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JL_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JGE_REL32;

    if(!jle) {
      jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JLE_REL32;
    }

    if(kernel->reg_info.x64[EVOASM_X64_REG_ZF].written) {
      jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JG_REL32;
    }
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_CF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JB_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JAE_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_PF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JP_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNP_REL32;
  }

#if 0
  /*FIXME: only 8bit possible, check and activate if feasable*/
  if(kernel->reg_info.x64[EVOASM_X64_REG_C].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JECXZ_JRCXZ_REL8;
  }
#endif

  if(jmp_insts_len > 0 && jmp_insts_len < (unsigned) (kernel->params->kernel_count - 1)) {
    evoasm_buf_ref_t buf_ref = {
        .data = buf->data,
        .pos = &buf->pos
    };
    evoasm_inst_id_t jmp_inst_id = jmp_insts[kernel->params->jmp_selector % jmp_insts_len];
    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_TRY(error, _evoasm_x64_enc, (evoasm_x64_inst_id_t) jmp_inst_id, &params, &buf_ref);
    branch_phi = _EVOASM_BUF_PHI_GET(buf);
    assert(*branch_phi == 0xdeadbeef);

    if(branch_kernel->idx <= kernel->idx) {
      /* back jump, guard with counter */

      uint32_t *counter = &program->recur_counters[kernel->idx];
      uintptr_t addr_imm = (uintptr_t) counter;

      EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, _EVOASM_X64_REG_TMP);
      EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) addr_imm);
      EVOASM_X64_ENC(mov_r64_imm64);

      EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, _EVOASM_X64_REG_TMP);
      EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, program->recur_limit);
      EVOASM_X64_ENC(cmp_rm32_imm32);

      EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
      EVOASM_X64_ENC(jge_rel32);

      counter_phi = _EVOASM_BUF_PHI_GET(buf);
      assert(*counter_phi == 0xdeadbeef);

      EVOASM_X64_ENC(inc_rm32);
    }

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transition, program,
               kernel, branch_kernel, buf, 1, set_io_mapping);

    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_X64_ENC(jmp_rel32);

    *branch_kernel_phi = _EVOASM_BUF_PHI_GET(buf);
    assert(**branch_kernel_phi == 0xdeadbeef);
  }

  if(branch_phi != NULL) {
    _EVOASM_BUF_PHI_SET(branch_phi, _EVOASM_BUF_POS_ADDR(buf));
  }

  if(counter_phi != NULL) {
    _EVOASM_BUF_PHI_SET(counter_phi, _EVOASM_BUF_POS_ADDR(buf));
  }

next_trans:

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
  unsigned i;
  evoasm_buf_ref_t buf_ref = {
      .data = buf->data,
      .pos = &buf->pos
  };

  evoasm_kernel_params_t *kernel_params = kernel->params;

  assert(kernel_params->kernel_count > 0);
  for(i = 0; i < kernel_params->kernel_count; i++) {
    evoasm_x64_inst_t *inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) kernel_params->params[i].x64.inst);
    evoasm_x64_inst_t *x64_inst = (evoasm_x64_inst_t *) inst;
    program->exception_mask = program->exception_mask | x64_inst->exceptions;
    EVOASM_TRY(error, _evoasm_x64_inst_enc_basic,
               inst,
               &kernel_params->params[i].x64.params, &buf_ref);
  }
  return true;
error:
  return false;
}


static evoasm_success_t
evoasm_program_x64_emit_program_kernels(evoasm_program_t *program, bool set_io_mapping) {
  unsigned i;
  evoasm_buf_t *buf = program->body_buf;
  evoasm_program_params_t *program_params = program->params;
  evoasm_kernel_t *kernel, *next_kernel, *branch_kernel;
  unsigned size = program_params->kernel_count;
  uint32_t *branch_phis[EVOASM_PROGRAM_MAX_SIZE] = {0};
  uint8_t *kernel_addrs[EVOASM_PROGRAM_MAX_SIZE];

  evoasm_buf_reset(buf);

  assert(size > 0);

  for(i = 0; i < size; i++) {
    kernel = &program->kernels[i];

    kernel_addrs[i] = buf->data + buf->pos;
    kernel->buf_start = (uint16_t) buf->pos;

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel, program, kernel, buf);

    if(i < size - 1) {
      next_kernel = &program->kernels[i + 1];
    } else {
      next_kernel = NULL;
    }

    assert(kernel->params->alt_succ_idx < program->params->kernel_count);
    branch_kernel = &program->kernels[kernel->params->alt_succ_idx];

    EVOASM_TRY(error, evoasm_program_x64_emit_kernel_transitions, program, kernel,
               next_kernel, branch_kernel, buf, &branch_phis[i], set_io_mapping);

    kernel->buf_end = (uint16_t) buf->pos;
  }

  for(i = 0; i < size; i++) {
    uint32_t *branch_phi = branch_phis[i];
    if(branch_phi != NULL) {
      kernel = &program->kernels[i];
      uint8_t *branch_kernel_addr = kernel_addrs[kernel->params->alt_succ_idx];
      assert(*branch_phi == 0xdeadbeef);
      _EVOASM_BUF_PHI_SET(branch_phi, branch_kernel_addr);
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
  unsigned i;
  unsigned n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(input);
  evoasm_kernel_t *kernel = &program->kernels[0];

  evoasm_buf_reset(program->buf);
  EVOASM_TRY(error, evoasm_x64_func_prolog, program->buf, EVOASM_X64_ABI_SYSV);

  for(i = 0; i < n_examples; i++) {
    evoasm_program_io_val_t *input_vals = input->vals + i * input->arity;
    EVOASM_TRY(error, evoasm_program_x64_emit_input_load, program, kernel, input_vals, input->types, input->arity, io_mapping);
    {
      size_t r = evoasm_buf_append(program->buf, program->body_buf);
      assert(r == 0);
    }
    EVOASM_TRY(error, evoasm_program_x64_emit_output_store, program, i);
  }

  EVOASM_TRY(error, evoasm_x64_func_epilog, program->buf, EVOASM_X64_ABI_SYSV);
  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_program_x64_emit(evoasm_program_t *program,
                    evoasm_program_input_t *input,
                    bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping) {

  if(prepare) {
    evoasm_program_x64_prepare(program);
  }

  if(emit_kernels) {
    EVOASM_TRY(error, evoasm_program_x64_emit_program_kernels, program, set_io_mapping);
  }

  if(emit_io_load_store) {
    EVOASM_TRY(error, evoasm_program_x64_emit_io_load_store, program, input, set_io_mapping);
  }

  evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_DEBUG);


  return true;

error:
  return false;
}


typedef enum {
  EVOASM_METRIC_ABSDIFF,
  EVOASM_N_METRICS
} evoasm_metric;

static inline void
evoasm_program_update_dist_mat(evoasm_program_t *program,
                           evoasm_kernel_t *kernel,
                           evoasm_program_output_t *output,
                           unsigned height,
                           unsigned example_index,
                           double *dist_mat,
                           evoasm_metric metric) {
  unsigned i, j;
  unsigned width = kernel->n_output_regs;
  evoasm_program_io_val_t *io_vals = output->vals + example_index * output->arity;

  for(i = 0; i < height; i++) {
    evoasm_program_io_val_t io_val = io_vals[i];
    evoasm_program_io_val_type_t example_type = output->types[i];
    double io_val_dbl = evoasm_program_io_val_to_dbl(io_val, example_type);

    for(j = 0; j < width; j++) {
      evoasm_program_io_val_t output_val = program->output_vals[example_index * width + j];
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

  unsigned n_examples = EVOASM_PROGRAM_OUTPUT_N_EXAMPLES(output);
  unsigned height = output->arity;
  unsigned width = kernel->n_output_regs;
  unsigned i, j, k;

  evoasm_log(log_level, EVOASM_LOG_TAG, "OUTPUT MATRICES:\n");

  for(i = 0; i < width; i++) {
    evoasm_log(log_level, EVOASM_LOG_TAG, " %d  ", program->output_regs[i]);
  }

  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");

  for(i = 0; i < n_examples; i++) {
    for(j = 0; j < height; j++) {
      for(k = 0; k < width; k++) {
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
                             unsigned height,
                             double *dist_mat,
                             uint_fast8_t *matching,
                             evoasm_log_level_t log_level) {

  unsigned width = kernel->n_output_regs;
  unsigned i, j;

  evoasm_log(log_level, EVOASM_LOG_TAG, "DIST MATRIX: (%d, %d)\n", height, width);
  for(i = 0; i < height; i++) {
    for(j = 0; j < width; j++) {
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
                 unsigned width,
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

  if(EVOASM_LIKELY(best_index != UINT_FAST8_MAX)) {
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
                                unsigned height,
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

    if(EVOASM_LIKELY(best_index != UINT_FAST8_MAX)) {
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
                     unsigned height,
                     double *dist_mat,
                     uint_fast8_t *matching) {
  unsigned i;
  unsigned width = kernel->n_output_regs;
  double scale = 1.0 / width;
  evoasm_loss_t loss = 0.0;

  for(i = 0; i < height; i++) {
    loss += scale * dist_mat[i * width + matching[i]];
  }

  return loss;
}

evoasm_loss_t
evoasm_program_assess(evoasm_program_t *program,
                  evoasm_program_output_t *output) {

  unsigned i;
  unsigned n_examples = EVOASM_PROGRAM_OUTPUT_N_EXAMPLES(output);
  unsigned height = output->arity;
  evoasm_kernel_t *kernel = &program->kernels[program->params->kernel_count - 1];
  unsigned width = kernel->n_output_regs;
  size_t dist_mat_len = (size_t) (width * height);
  double *dist_mat = evoasm_alloca(dist_mat_len * sizeof(double));
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));
  evoasm_loss_t loss;

  for(i = 0; i < dist_mat_len; i++) {
    dist_mat[i] = 0.0;
  }

  if(height == 1) {
    /* COMMON FAST-PATH */
    for(i = 0; i < n_examples; i++) {
      evoasm_program_update_dist_mat(program, kernel, output, 1, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    if(evoasm_program_match(program, width, dist_mat, matching)) {
      loss = evoasm_program_calc_loss(program, kernel, 1, dist_mat, matching);
    } else {
      loss = INFINITY;
    }
  } else {
    for(i = 0; i < n_examples; i++) {
      evoasm_program_update_dist_mat(program, kernel, output, height, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    evoasm_program_calc_stable_matching(program, kernel, height, dist_mat, matching);
    loss = evoasm_program_calc_loss(program, kernel, height, dist_mat, matching);
  }


  for(i = 0; i < height; i++) {
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
                              EVOASM_LOG_LEVEL_DEBUG);
  }
#endif

  return loss;
}

static evoasm_program_output_t *
evoasm_program_load_output(evoasm_program_t *program,
                       evoasm_kernel_t *kernel,
                       evoasm_program_input_t *input) {

  unsigned i, j;
  unsigned width = kernel->n_output_regs;
  evoasm_program_output_t *output = &program->_output;
  unsigned height = output->arity;
  unsigned n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(input);
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));

  evoasm_program_output_t *load_output = evoasm_program_io_alloc((uint16_t) (EVOASM_PROGRAM_INPUT_N_EXAMPLES(input) * height));

  for(i = 0; i < height; i++) {
    for(j = 0; j < kernel->n_output_regs; j++) {
      if(program->output_regs[i] == kernel->output_regs.x64[j]) {
        matching[i] = (uint_fast8_t) j;
        goto next;
      }
    }
    evoasm_log_fatal("program output reg %d not found in kernel output regs", program->output_regs[i]);
    evoasm_assert_not_reached();
next:;
  }

  for(i = 0; i < n_examples; i++) {
    for(j = 0; j < height; j++) {
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
  unsigned i;
  evoasm_kernel_t *kernel = &program->kernels[program->params->kernel_count - 1];
  evoasm_program_output_t *output;

  if(input->arity != program->_input.arity) {
    evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                     "example arity mismatch (%d for %d)", input->arity, program->_input.arity);
    return NULL;
  }

  for(i = 0; i < input->arity; i++) {
    if(input->types[i] != program->_input.types[i]) {
      evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                       "example type mismatch (%d != %d)", input->types[i], program->_input.types[i]);
      return NULL;
    }
  }

  program->output_vals = evoasm_alloca(EVOASM_PROGRAM_OUTPUT_VALS_SIZE(input));

  if(!evoasm_program_emit(program, input, false, program->need_emit, true, false)) {
    return NULL;
  }

  program->need_emit = false;

  if(kernel->n_output_regs == 0) {
    return NULL;
  }

  evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_DEBUG);
  evoasm_signal_install((evoasm_arch_id_t) program->arch_info->id, program->exception_mask);

  if(!evoasm_buf_protect(program->buf, EVOASM_MPROT_RX)) {
    evoasm_assert_not_reached();
  }

  if(EVOASM_SIGNAL_TRY()) {
    evoasm_buf_exec(program->buf);
    output = evoasm_program_load_output(program,
                                    kernel,
                                    input);
  } else {
    evoasm_log_debug("signaled\n");
    output = NULL;
  }

  if(!evoasm_buf_protect(program->buf, EVOASM_MPROT_RW)) {
    evoasm_assert_not_reached();
  }

  evoasm_signal_uninstall();

  program->output_vals = NULL;

  return output;
}

evoasm_success_t
evoasm_program_emit(evoasm_program_t *program,
                evoasm_program_input_t *input,
                bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping) {
  switch(program->arch_info->id) {
    case EVOASM_ARCH_X64: {
      return evoasm_program_x64_emit(program, input,
                                 prepare, emit_kernels, emit_io_load_store, set_io_mapping);
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

static void
evoasm_program_unprepare(evoasm_program_t *program) {
  unsigned i;
  for(i = 0; i < program->params->kernel_count; i++) {
    evoasm_program_unprepare_kernel(program, &program->kernels[i]);
  }
}

static unsigned
evoasm_program_x64_find_writers_(evoasm_program_t *program, evoasm_kernel_t *kernel, evoasm_reg_id_t reg_id,
                             unsigned index, unsigned *writers) {
  unsigned len = 0;
  unsigned i, j;

  for(i = 0; i <= index; i++) {
    j = index - i;

    evoasm_kernel_param_t *param = &kernel->params->params[j];
    evoasm_x64_reg_write_acc_t reg_write_acc;
    evoasm_x64_reg_write_acc_init(&reg_write_acc);

    if(evoasm_kernel_param_x64_is_writer(param, reg_id, &reg_write_acc)) {
      writers[len++] = j;
    }
  }
  return len;
}

static unsigned
evoasm_program_x64_find_writers(evoasm_program_t *program, evoasm_kernel_t *kernel,
                            evoasm_reg_id_t reg_id, unsigned index, unsigned *writers) {

  return evoasm_program_x64_find_writers_(program, kernel, reg_id, index, writers);
}

typedef struct {
  bool change;
  evoasm_bitmap512_t inst_bitmaps[EVOASM_PROGRAM_MAX_SIZE];
  evoasm_bitmap256_t output_reg_bitmaps[EVOASM_PROGRAM_MAX_SIZE];
} _evoasm_program_intron_elimination_ctx;

static void
evoasm_program_x64_mark_writers(evoasm_program_t *program, evoasm_kernel_t *kernel,
                            evoasm_reg_id_t reg_id, unsigned index, _evoasm_program_intron_elimination_ctx *ctx) {
  unsigned i, j, k, l;
  unsigned writers[16];

  unsigned writers_len = evoasm_program_x64_find_writers(program, kernel, reg_id, index, writers);

  if(writers_len > 0) {
    for(i = 0; i < writers_len; i++) {
      unsigned writer_idx = writers[i];
      evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx->inst_bitmaps[kernel->idx];
      if(evoasm_bitmap_get(inst_bitmap, writer_idx)) continue;

      evoasm_kernel_param_t *param = &kernel->params->params[writer_idx];
      evoasm_x64_inst_t *x64_inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);
      evoasm_bitmap_set(inst_bitmap, writer_idx);
      ctx->change = true;

      for(j = 0; j < x64_inst->n_operands; j++) {
        evoasm_x64_operand_t *op = &x64_inst->operands[j];
        evoasm_x64_reg_id_t op_reg_id = evoasm_op_x64_reg_id(op, param);

        if(op->read) {
          if(writer_idx > 0) {
            evoasm_program_x64_mark_writers(program, kernel, op_reg_id, writer_idx - 1, ctx);
          }

          if(kernel->reg_info.x64[op_reg_id].input) {
            unsigned trans_kernels_idcs[] = {(unsigned) (kernel->idx + 1),
                                             kernel->params->alt_succ_idx};
            for(k = 0; k < EVOASM_ARY_LEN(trans_kernels_idcs); k++) {
              //evoasm_kernel_t *trans_kernel = &program->kernels[trans_kernels_idcs[k]];
              for(l = 0; l < EVOASM_X64_N_REGS; l++) {
                if(kernel->reg_info.x64[l].trans_regs[k] == op_reg_id) {
                  evoasm_bitmap_set((evoasm_bitmap_t *) &ctx->output_reg_bitmaps[trans_kernels_idcs[k]], l);
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
                        evoasm_reg_id_t reg_id, unsigned index, _evoasm_program_intron_elimination_ctx *ctx) {
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
evoasm_program_mark_kernel(evoasm_program_t *program, evoasm_kernel_t *kernel, _evoasm_program_intron_elimination_ctx *ctx) {
  unsigned i;

  for(i = 0; i < EVOASM_X64_N_REGS; i++) {
    evoasm_bitmap_t *bitmap = (evoasm_bitmap_t *) &ctx->output_reg_bitmaps[kernel->idx];
    if(evoasm_bitmap_get(bitmap, i)) {
      evoasm_program_mark_writers(program, kernel, (evoasm_reg_id_t) i, (unsigned) (kernel->params->kernel_count - 1), ctx);
    }
  }

  return true;
}

evoasm_success_t
evoasm_program_eliminate_introns(evoasm_program_t *program) {
  unsigned i, j;
  unsigned last_kernel_idx = (unsigned) (program->params->kernel_count - 1);
  //evoasm_kernel_t *last_kernel = &program->kernels[last_kernel_idx];

  _evoasm_program_intron_elimination_ctx ctx = {0};

  {
    evoasm_bitmap_t *output_bitmap = (evoasm_bitmap_t *) &ctx.output_reg_bitmaps[last_kernel_idx];
    for(i = 0; i < program->_output.arity; i++) {
      evoasm_bitmap_set(output_bitmap, program->output_regs[i]);
    }
  }

  do {
    i = last_kernel_idx;
    ctx.change = false;
    for(i = 0; i <= last_kernel_idx; i++) {
      j = last_kernel_idx - i;
      EVOASM_TRY(error, evoasm_program_mark_kernel, program,
                 &program->kernels[j], &ctx);
    }
  } while(ctx.change);

  /* sweep */
  for(i = 0; i <= last_kernel_idx; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    unsigned k;
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx.inst_bitmaps[i];

    for(k = 0, j = 0; j < kernel->params->kernel_count; j++) {
      if(evoasm_bitmap_get(inst_bitmap, j)) {
        kernel->params->params[k++] = kernel->params->params[j];
      }
    }
    kernel->params->kernel_count = (evoasm_kernel_count_t) k;
  }

  /* program is already prepared, must be reset before doing it again */
  evoasm_program_unprepare(program);

  /* reemit, but keep previous mappings */
  if(!evoasm_program_emit(program, NULL, true, true, false, false)) {
    return false;
  }

  return true;
error:
  return false;
}


#define EVOASM_PROGRAM_PROLOG_EPILOG_SIZE UINT32_C(1024)
#define EVOASM_PROGRAM_TRANSITION_SIZE UINT32_C(512)

evoasm_success_t
evoasm_program_init(evoasm_program_t *program,
                    evoasm_arch_info_t *arch_info,
                    evoasm_program_io_t *program_input,
                    evoasm_kernel_count_t kernel_count,
                    evoasm_kernel_size_t kernel_size,
                    uint32_t recur_limit) {
  unsigned i = 0;

  static evoasm_program_t zero_program = {0};
  unsigned n_transitions = (unsigned) kernel_count - 1;
  unsigned n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(program_input);

  *program = zero_program;
  program->arch_info = arch_info;
  program->recur_limit = recur_limit;
  program->shallow = true;

  size_t body_buf_size =
      (size_t) (n_transitions * EVOASM_PROGRAM_TRANSITION_SIZE
                + kernel_count * kernel_size * arch_info->max_inst_len);

  size_t buf_size = n_examples * (body_buf_size + EVOASM_PROGRAM_PROLOG_EPILOG_SIZE);

  EVOASM_TRY(error, evoasm_buf_init, &program->_buf, EVOASM_BUF_TYPE_MMAP, buf_size);
  program->buf = &program->_buf;

  EVOASM_TRY(error, evoasm_buf_init, &program->_body_buf, EVOASM_BUF_TYPE_MALLOC, body_buf_size);
  program->buf = &program->_body_buf;

  EVOASM_TRY(error, evoasm_buf_protect, &program->_buf,
             EVOASM_MPROT_RWX);

  size_t output_vals_len = EVOASM_PROGRAM_OUTPUT_VALS_LEN(program_input);
  EVOASM_TRY_CALLOC(error, program->output_vals, output_vals_len, sizeof(evoasm_program_io_val_t));

  EVOASM_TRY_CALLOC(error, program->kernels, kernel_count, sizeof(evoasm_kernel_t));
  EVOASM_TRY_CALLOC(error, program->recur_counters, kernel_count, sizeof(uint32_t));
  for(; i < kernel_count; i++) {
    evoasm_kernel_t *kernel = &program->kernels[i];
    kernel->idx = (evoasm_kernel_count_t) i;
  }

error:
  evoasm_program_destroy(program);
}



_EVOASM_DEF_ALLOC_FREE_FUNCS(program)
