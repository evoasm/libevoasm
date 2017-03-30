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

#include "evoasm-x64.h"
#include "evoasm.h"
#include "evoasm-signal.h"
#include "evoasm-param.h"

EVOASM_DEF_LOG_TAG("x64")

extern evoasm_arch_info_t evoasm_arch_infos[EVOASM_ARCH_NONE];

static evoasm_arch_info_t evoasm_arch_x64 = {
    EVOASM_ARCH_X64,
    EVOASM_X64_PARAM_NONE,
    EVOASM_X64_JMP_COND_NONE,
    15,
    EVOASM_X64_INST_NONE,
    0ull
};

uint8_t evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_NONE] = {0};

static evoasm_x64_reg_id_t evoasm_x64_sysv_callee_save_regs[] = {
    EVOASM_X64_REG_BP,
    EVOASM_X64_REG_B,
    EVOASM_X64_REG_12,
    EVOASM_X64_REG_13,
    EVOASM_X64_REG_14,
    EVOASM_X64_REG_15,
};

const char *evoasm_x64_get_basic_param_name(evoasm_x64_basic_param_id_t id);

static evoasm_success_t
evoasm_x64_func_emit_prolog_or_epilog(evoasm_x64_abi_t abi, evoasm_buf_t *buf, bool prolog) {
  size_t regs_len = EVOASM_ARRAY_LEN(evoasm_x64_sysv_callee_save_regs);
  evoasm_x64_params_t params = {0};

  for(size_t i = 0; i < regs_len; i++) {
    evoasm_x64_reg_id_t reg = evoasm_x64_sysv_callee_save_regs[prolog ? i : (regs_len - 1 - i)];
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg);

    if(prolog) {
      EVOASM_X64_ENC(push_r64);
    } else {
      EVOASM_X64_ENC(pop_r64);
    }
  }

  if(!prolog) {
    EVOASM_X64_ENC(ret);
  }

  return true;

enc_failed:
  return false;
}

evoasm_success_t
evoasm_x64_emit_func_prolog(evoasm_x64_abi_t abi, evoasm_buf_t *buf) {
  return evoasm_x64_func_emit_prolog_or_epilog(abi, buf, true);
}

evoasm_success_t
evoasm_x64_emit_func_epilog(evoasm_x64_abi_t abi, evoasm_buf_t *buf) {
  return evoasm_x64_func_emit_prolog_or_epilog(abi, buf, false);
}

evoasm_success_t
evoasm_x64_init() {
  extern evoasm_arch_id_t evoasm_current_arch;

  uint64_t features;
  EVOASM_TRY(cpuid_failed, evoasm_x64_get_features, &features);

  evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_GP] = 8;
  evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_RFLAGS] = 8;
  evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_IP] = 8;
  evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_MXCSR] = 4;

#ifdef EVOASM_X64_ENABLE_AVX512
  uint64_t avx512 = EVOASM_X64_FEATURE_AVX512F |
                    EVOASM_X64_FEATURE_AVX512DQ |
                    EVOASM_X64_FEATURE_AVX512IFMA |
                    EVOASM_X64_FEATURE_AVX512PF |
                    EVOASM_X64_FEATURE_AVX512ER |
                    EVOASM_X64_FEATURE_AVX512CD |
                    EVOASM_X64_FEATURE_AVX512BW |
                    EVOASM_X64_FEATURE_AVX512VL;

  if(x64->features & avx512) {
    evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_XMM] = 64;
    evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_ZMM] = 64;
  }
  else
#endif
  if(features & EVOASM_X64_FEATURE_AVX2) {
    evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_XMM] = 32;
  } else {
    evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_XMM] = 16;
  }

  evoasm_arch_x64.features = features;
  evoasm_current_arch = EVOASM_ARCH_X64;
  evoasm_arch_infos[EVOASM_ARCH_X64] = evoasm_arch_x64;

  evoasm_signal_install();

  return true;

cpuid_failed:
  return false;
}

evoasm_x64_inst_t *
evoasm_x64_inst(evoasm_x64_inst_id_t inst_id) {
  return evoasm_x64_inst_(inst_id);
}

evoasm_success_t
evoasm_x64_inst_enc(evoasm_x64_inst_t *inst, evoasm_x64_params_t *params, evoasm_buf_ref_t *buf_ref) {
  return evoasm_x64_inst_enc_(inst, params, buf_ref);
}

evoasm_success_t
evoasm_x64_inst_enc_basic(evoasm_x64_inst_t *inst, evoasm_x64_basic_params_t *params, evoasm_buf_ref_t *buf_ref) {
  return evoasm_x64_inst_enc_basic_(inst, params, buf_ref);
}

evoasm_success_t
evoasm_x64_enc(evoasm_x64_inst_id_t inst_id, evoasm_x64_params_t *params, evoasm_buf_ref_t *buf_ref) {
  return evoasm_x64_enc_(inst_id, params, buf_ref);
}

evoasm_success_t
evoasm_x64_enc_basic(evoasm_x64_inst_id_t inst_id, evoasm_x64_basic_params_t *params, evoasm_buf_ref_t *buf_ref) {
  return evoasm_x64_enc_basic_(inst_id, params, buf_ref);
}

evoasm_x64_operand_t *
evoasm_x64_inst_get_operand(evoasm_x64_inst_t *inst, size_t idx) {
  return &inst->operands[idx];
}

size_t
evoasm_x64_inst_get_n_operands(evoasm_x64_inst_t *inst) {
  return inst->n_operands;
}

#define EVOASM_X64_OPERAND_DEF_GETTER(field, type) EVOASM_DEF_GETTER(x64_operand, field, type)
#define EVOASM_X64_OPERAND_DEF_BOOL_GETTER(field) EVOASM_DEF_BOOL_GETTER(x64_operand, field)

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(read)

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(written)

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(implicit)

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(maybe_written)

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(mnem)

EVOASM_X64_OPERAND_DEF_GETTER(word, evoasm_x64_operand_word_t)

EVOASM_X64_OPERAND_DEF_GETTER(type, evoasm_x64_operand_type_t)

EVOASM_X64_OPERAND_DEF_GETTER(reg_type, evoasm_x64_reg_type_t)

EVOASM_X64_OPERAND_DEF_GETTER(imm, int8_t)

EVOASM_X64_OPERAND_DEF_GETTER(param_idx, size_t)


evoasm_x64_reg_id_t
evoasm_x64_operand_get_reg_id(evoasm_x64_operand_t *operand) {
  return evoasm_x64_operand_get_reg_id_(operand);
}

evoasm_x64_operand_size_t
evoasm_x64_operand_get_size(evoasm_x64_operand_t *operand) {
  return (evoasm_x64_operand_size_t) operand->size;
}

evoasm_x64_operand_size_t
evoasm_x64_operand_get_reg_size(evoasm_x64_operand_t *operand) {
  return evoasm_x64_operand_get_reg_size_(operand);
}

evoasm_x64_operand_size_t
evoasm_x64_operand_get_index_reg_size(evoasm_x64_operand_t *operand) {
  return (evoasm_x64_operand_size_t) operand->size;
}

evoasm_x64_operand_size_t evoasm_x64_operand_get_mem_size(evoasm_x64_operand_t *operand) {
  if(operand->type != EVOASM_X64_OPERAND_TYPE_MEM && operand->type != EVOASM_X64_OPERAND_TYPE_RM &&
     operand->type != EVOASM_X64_OPERAND_TYPE_VSIB) {
    return EVOASM_X64_OPERAND_SIZE_NONE;
  }

  switch(operand->word) {
    case EVOASM_X64_OPERAND_WORD_LB:
    case EVOASM_X64_OPERAND_WORD_HB:
      return EVOASM_X64_OPERAND_SIZE_8;
    case EVOASM_X64_OPERAND_WORD_W:
      return EVOASM_X64_OPERAND_SIZE_16;
    case EVOASM_X64_OPERAND_WORD_DW:
      return EVOASM_X64_OPERAND_SIZE_32;
    case EVOASM_X64_OPERAND_WORD_LQW:
    case EVOASM_X64_OPERAND_WORD_HQW:
      return EVOASM_X64_OPERAND_SIZE_64;
    case EVOASM_X64_OPERAND_WORD_DQW:
      return EVOASM_X64_OPERAND_SIZE_128;
    case EVOASM_X64_OPERAND_WORD_VW:
      switch(evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_XMM]) {
        case 16:
          return EVOASM_X64_OPERAND_SIZE_128;
        case 32:
          return EVOASM_X64_OPERAND_SIZE_256;
        case 64:
          return EVOASM_X64_OPERAND_SIZE_512;
        default:
          evoasm_assert_not_reached();
      }
    default:
      evoasm_assert_not_reached();
  }
}

evoasm_param_t *
evoasm_x64_inst_get_param(evoasm_x64_inst_t *inst, size_t idx) {
  return &inst->params[idx];
}

size_t
evoasm_x64_inst_get_n_params(evoasm_x64_inst_t *inst) {
  return inst->n_params;
}

bool
evoasm_x64_inst_is_basic(evoasm_x64_inst_t *inst) {
  return inst->basic_enc_func != NULL;
}

const char *
evoasm_x64_inst_get_mnem(evoasm_x64_inst_t *inst) {
  return (const char *) inst->mnem;
}

void
evoasm_x64_params_init(evoasm_x64_params_t *params) {
  static evoasm_x64_params_t zero_params = {0};
  *params = zero_params;
}

void
evoasm_x64_basic_params_init(evoasm_x64_basic_params_t *params) {
  static evoasm_x64_basic_params_t zero_params = {0};
  *params = zero_params;
}

static bool
evoasm_x64_is_useful_inst(evoasm_x64_inst_id_t inst) {
  switch(inst) {
    case EVOASM_X64_INST_CRC32_R32_RM8:
    case EVOASM_X64_INST_CRC32_R32_RM16:
    case EVOASM_X64_INST_CRC32_R32_RM32:
    case EVOASM_X64_INST_CRC32_R64_RM8:
    case EVOASM_X64_INST_CRC32_R64_RM64:
    case EVOASM_X64_INST_CPUID:
    case EVOASM_X64_INST_RDRAND_R16:
    case EVOASM_X64_INST_RDRAND_R32:
    case EVOASM_X64_INST_RDRAND_R64:
    case EVOASM_X64_INST_RDSEED_R16:
    case EVOASM_X64_INST_RDSEED_R32:
    case EVOASM_X64_INST_RDSEED_R64:
    case EVOASM_X64_INST_AESDEC_XMM_XMMM128:
    case EVOASM_X64_INST_AESDECLAST_XMM_XMMM128:
    case EVOASM_X64_INST_AESENC_XMM_XMMM128:
    case EVOASM_X64_INST_AESENCLAST_XMM_XMMM128:
    case EVOASM_X64_INST_AESIMC_XMM_XMMM128:
    case EVOASM_X64_INST_AESKEYGENASSIST_XMM_XMMM128_IMM8:
    case EVOASM_X64_INST_LOOP_REL8:
    case EVOASM_X64_INST_LOOPE_REL8:
    case EVOASM_X64_INST_LOOPNE_REL8:
      return false;
    default:
      return true;
  }
}

size_t
evoasm_x64_insts(uint64_t flags, uint64_t features, uint64_t operand_types, uint64_t reg_types,
                 evoasm_x64_inst_id_t *insts) {
  size_t len = 0;
  bool include_useless = (flags & EVOASM_X64_INSTS_FLAG_INCLUDE_USELESS) != 0;
  bool only_basic = (flags & EVOASM_X64_INSTS_FLAG_ONLY_BASIC) != 0;

  for(size_t i = 0; i < EVOASM_X64_INST_NONE; i++) {
    if(!include_useless && !evoasm_x64_is_useful_inst((evoasm_x64_inst_id_t) i)) {

      evoasm_x64_inst_t *inst = (evoasm_x64_inst_t *) &EVOASM_X64_INSTS_VAR_NAME[i];
      evoasm_log_debug("skipping inst %s (useless)\n", evoasm_x64_inst_get_mnem(inst));

      goto skip;
    }

    evoasm_x64_inst_t *inst = (evoasm_x64_inst_t *) &EVOASM_X64_INSTS_VAR_NAME[i];
    if(only_basic && !evoasm_x64_inst_is_basic(inst)) {
      evoasm_log_debug("skipping inst %s (non basic)\n", evoasm_x64_inst_get_mnem(inst));
      goto skip;
    }

    if((inst->features & ~features) != 0) {
      evoasm_log_debug("skipping inst %s (features)\n", evoasm_x64_inst_get_mnem(inst));
      goto skip;
    }

    if(!include_useless && inst->n_operands == 0) {
      evoasm_log_debug("skipping inst %s (no operands)\n", evoasm_x64_inst_get_mnem(inst));
      goto skip;
    }

    for(size_t j = 0; j < inst->n_operands; j++) {
      evoasm_x64_operand_t *operand = &inst->operands[j];

      if(((1ull << operand->type) & operand_types) == 0) {
        evoasm_log_debug("skipping inst %s (operand type)\n", evoasm_x64_inst_get_mnem(inst));
        goto skip;
      }

      if(operand->type == EVOASM_X64_OPERAND_TYPE_REG ||
         operand->type == EVOASM_X64_OPERAND_TYPE_RM) {
        if(!include_useless && operand->reg_type != EVOASM_X64_REG_TYPE_RFLAGS &&
           (operand->reg_id == EVOASM_X64_REG_SP ||
            operand->reg_id == EVOASM_X64_REG_IP)) {

          evoasm_log_debug("skipping inst %s (ip, sp)\n", evoasm_x64_inst_get_mnem(inst));
          goto skip;
        }

        if(((1ull << operand->reg_type) & reg_types) == 0) {
          evoasm_log_debug("skipping inst %s (reg type)\n", evoasm_x64_inst_get_mnem(inst));
          goto skip;
        }
      }
    }

    insts[len++] = (evoasm_x64_inst_id_t) i;

skip:;
  }
  return len;
}


static uint64_t *
evoasm_x64_cpu_state_get_reg_data(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_reg_id_t reg) {
  switch(reg) {
    case EVOASM_X64_REG_A:
      return cpu_state->rax;
    case EVOASM_X64_REG_C:
      return cpu_state->rcx;
    case EVOASM_X64_REG_D:
      return cpu_state->rdx;
    case EVOASM_X64_REG_B:
      return cpu_state->rbx;
    case EVOASM_X64_REG_SP:
      return cpu_state->rsp;
    case EVOASM_X64_REG_BP:
      return cpu_state->rbp;
    case EVOASM_X64_REG_SI:
      return cpu_state->rsi;
    case EVOASM_X64_REG_DI:
      return cpu_state->rdi;
    case EVOASM_X64_REG_8:
      return cpu_state->r8;
    case EVOASM_X64_REG_9:
      return cpu_state->r9;
    case EVOASM_X64_REG_10:
      return cpu_state->r10;
    case EVOASM_X64_REG_11:
      return cpu_state->r11;
    case EVOASM_X64_REG_12:
      return cpu_state->r12;
    case EVOASM_X64_REG_13:
      return cpu_state->r13;
    case EVOASM_X64_REG_14:
      return cpu_state->r14;
    case EVOASM_X64_REG_15:
      return cpu_state->r15;
    case EVOASM_X64_REG_MM0:
      return cpu_state->mm0;
    case EVOASM_X64_REG_MM1:
      return cpu_state->mm1;
    case EVOASM_X64_REG_MM2:
      return cpu_state->mm2;
    case EVOASM_X64_REG_MM3:
      return cpu_state->mm3;
    case EVOASM_X64_REG_MM4:
      return cpu_state->mm4;
    case EVOASM_X64_REG_MM5:
      return cpu_state->mm5;
    case EVOASM_X64_REG_MM6:
      return cpu_state->mm6;
    case EVOASM_X64_REG_MM7:
      return cpu_state->mm7;
    case EVOASM_X64_REG_XMM0:
      return cpu_state->xmm0;
    case EVOASM_X64_REG_XMM1:
      return cpu_state->xmm1;
    case EVOASM_X64_REG_XMM2:
      return cpu_state->xmm2;
    case EVOASM_X64_REG_XMM3:
      return cpu_state->xmm3;
    case EVOASM_X64_REG_XMM4:
      return cpu_state->xmm4;
    case EVOASM_X64_REG_XMM5:
      return cpu_state->xmm5;
    case EVOASM_X64_REG_XMM6:
      return cpu_state->xmm6;
    case EVOASM_X64_REG_XMM7:
      return cpu_state->xmm7;
    case EVOASM_X64_REG_XMM8:
      return cpu_state->xmm8;
    case EVOASM_X64_REG_XMM9:
      return cpu_state->xmm9;
    case EVOASM_X64_REG_XMM10:
      return cpu_state->xmm10;
    case EVOASM_X64_REG_XMM11:
      return cpu_state->xmm11;
    case EVOASM_X64_REG_XMM12:
      return cpu_state->xmm12;
    case EVOASM_X64_REG_XMM13:
      return cpu_state->xmm13;
    case EVOASM_X64_REG_XMM14:
      return cpu_state->xmm14;
    case EVOASM_X64_REG_XMM15:
      return cpu_state->xmm15;
    case EVOASM_X64_REG_ZMM16:
      return cpu_state->zmm16;
    case EVOASM_X64_REG_ZMM17:
      return cpu_state->zmm17;
    case EVOASM_X64_REG_ZMM18:
      return cpu_state->zmm18;
    case EVOASM_X64_REG_ZMM19:
      return cpu_state->zmm19;
    case EVOASM_X64_REG_ZMM20:
      return cpu_state->zmm20;
    case EVOASM_X64_REG_ZMM21:
      return cpu_state->zmm21;
    case EVOASM_X64_REG_ZMM22:
      return cpu_state->zmm22;
    case EVOASM_X64_REG_ZMM23:
      return cpu_state->zmm23;
    case EVOASM_X64_REG_ZMM24:
      return cpu_state->zmm24;
    case EVOASM_X64_REG_ZMM25:
      return cpu_state->zmm25;
    case EVOASM_X64_REG_ZMM26:
      return cpu_state->zmm26;
    case EVOASM_X64_REG_ZMM27:
      return cpu_state->zmm27;
    case EVOASM_X64_REG_ZMM28:
      return cpu_state->zmm28;
    case EVOASM_X64_REG_ZMM29:
      return cpu_state->zmm29;
    case EVOASM_X64_REG_ZMM30:
      return cpu_state->zmm30;
    case EVOASM_X64_REG_ZMM31:
      return cpu_state->zmm31;
    case EVOASM_X64_REG_RFLAGS:
      return cpu_state->rflags;
    case EVOASM_X64_REG_IP:
      return cpu_state->ip;
    case EVOASM_X64_REG_MXCSR:
      return cpu_state->mxcsr;
    default:
      evoasm_assert_not_reached();
  }
}

static evoasm_success_t
evoasm_x64_emit_rip_load_store(uint8_t *data,
                               evoasm_x64_reg_id_t tmp_reg1,
                               evoasm_x64_reg_id_t tmp_reg2,
                               evoasm_buf_t *buf,
                               bool load) {

  evoasm_x64_params_t params = {0};

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg1);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);

  if(load) {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg1);
    EVOASM_X64_ENC(jmp_rm64);
  } else {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg2);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_REG_IP);
    EVOASM_X64_ENC(lea_r64_m64);

    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg1);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, tmp_reg2);
    EVOASM_X64_ENC(mov_rm64_r64);
  }
  return true;

enc_failed:
  return false;
}

static evoasm_success_t
evoasm_x64_emit_pop_push(evoasm_x64_reg_id_t reg_id, evoasm_buf_t *buf, bool pop) {
  evoasm_x64_params_t params = {0};
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg_id);
  if(pop) {
    EVOASM_X64_ENC(pop_r64);
  } else {
    EVOASM_X64_ENC(push_r64);
  }

  return true;

enc_failed:
  return false;
}

evoasm_success_t
evoasm_x64_emit_pop(evoasm_x64_reg_id_t reg_id, evoasm_buf_t *buf) {
  return evoasm_x64_emit_pop_push(reg_id, buf, true);
}

evoasm_success_t
evoasm_x64_emit_push(evoasm_x64_reg_id_t reg_id, evoasm_buf_t *buf) {
  return evoasm_x64_emit_pop_push(reg_id, buf, false);
}

static evoasm_success_t
evoasm_x64_emit_rflags_load_store(uint8_t *data,
                                  evoasm_x64_reg_id_t tmp_reg1,
                                  evoasm_x64_reg_id_t tmp_reg2,
                                  evoasm_buf_t *buf,
                                  bool load) {

  evoasm_x64_params_t params = {0};


  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg1);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);

  if(load) {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg2);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg1);
    EVOASM_X64_ENC(mov_r64_rm64);
    EVOASM_TRY(enc_failed, evoasm_x64_emit_push, tmp_reg2, buf);
    EVOASM_X64_ENC(popfq);
  } else {
    EVOASM_X64_ENC(pushfq);
    EVOASM_TRY(enc_failed, evoasm_x64_emit_pop, tmp_reg2, buf);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg1);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, tmp_reg2);
    EVOASM_X64_ENC(mov_rm64_r64);
  }

  return true;

enc_failed:
  return false;
}


static evoasm_success_t
evoasm_x64_emit_mm_load_store(evoasm_reg_id_t reg,
                              uint8_t *data,
                              evoasm_x64_reg_id_t tmp_reg,
                              evoasm_buf_t *buf,
                              bool load) {

  evoasm_x64_params_t params = {0};
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);


  if(load) {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
    EVOASM_X64_ENC(movq_mm_mmm64);
  } else {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg);
    EVOASM_X64_ENC(movq_mmm64_mm);
  }

  return true;

enc_failed:
  return false;
}

static evoasm_success_t
evoasm_x64_emit_gp_load_store(evoasm_reg_id_t reg,
                              uint8_t *data,
                              evoasm_x64_reg_id_t tmp_reg,
                              evoasm_buf_t *buf,
                              bool load) {

  evoasm_x64_params_t params = {0};
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);


  if(load) {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
    EVOASM_X64_ENC(mov_r64_rm64);
  } else {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg);
    EVOASM_X64_ENC(mov_rm64_r64);
  }

  return true;

enc_failed:
  return false;
}

static evoasm_success_t
evoasm_x64_emit_xmm_load_store(evoasm_reg_id_t reg,
                               uint8_t *data,
                               evoasm_x64_reg_id_t tmp_reg,
                               evoasm_buf_t *buf,
                               bool load) {

  evoasm_x64_params_t params = {0};
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);

  if(load) {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
  } else {
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg);
  }

  if(evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_XMM] == 32) {
    if(load) {
      EVOASM_X64_ENC(vmovdqa_ymm_ymmm256);
    } else {
      EVOASM_X64_ENC(vmovdqa_ymmm256_ymm);
    }
  }
#ifdef EVOASM_X64_ENABLE_AVX512
    else if(evoasm_x64_reg_type_bytesizes[EVOASM_X64_REG_TYPE_XMM] == 64) {
      goto unsupported;
    }
#endif
  else {
    if(load) {
      EVOASM_X64_ENC(movdqa_xmm_xmmm128);
    } else {
      EVOASM_X64_ENC(movdqa_xmmm128_xmm);
    }
  }

  return true;

enc_failed:
  return false;
}


static evoasm_success_t
evoasm_x64_emit_mxcsr_load_store(uint8_t *data,
                                 evoasm_x64_reg_id_t tmp_reg,
                                 evoasm_buf_t *buf,
                                 bool load) {

  evoasm_x64_params_t params = {0};

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg);
  if(load) {
    EVOASM_X64_ENC(ldmxcsr_m32);
  } else {
    EVOASM_X64_ENC(stmxcsr_m32);
  }
  return true;

enc_failed:
  return false;
}


static evoasm_success_t
evoasm_x64_emit_load_store(evoasm_x64_reg_id_t reg_id,
                           uint8_t *data,
                           evoasm_x64_reg_id_t tmp_reg1,
                           evoasm_x64_reg_id_t tmp_reg2,
                           evoasm_buf_t *buf,
                           bool load) {

  evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(reg_id);

  switch(reg_type) {
    case EVOASM_X64_REG_TYPE_GP: {
      EVOASM_TRY(enc_failed, evoasm_x64_emit_gp_load_store, reg_id, data, tmp_reg1, buf, load);
      break;
    }
    case EVOASM_X64_REG_TYPE_XMM: {
      EVOASM_TRY(enc_failed, evoasm_x64_emit_xmm_load_store, reg_id, data, tmp_reg1, buf, load);
      break;
    }
    case EVOASM_X64_REG_TYPE_MM: {
      EVOASM_TRY(enc_failed, evoasm_x64_emit_mm_load_store, reg_id, data, tmp_reg1, buf, load);
      break;
    }
    case EVOASM_X64_REG_TYPE_IP: {
      EVOASM_TRY(enc_failed, evoasm_x64_emit_rip_load_store, data, tmp_reg1, tmp_reg2, buf, load);
      break;
    }
    case EVOASM_X64_REG_TYPE_RFLAGS: {
      EVOASM_TRY(enc_failed, evoasm_x64_emit_rflags_load_store, data, tmp_reg1, tmp_reg2, buf, load);
      break;
    }
    case EVOASM_X64_REG_TYPE_MXCSR: {
      EVOASM_TRY(enc_failed, evoasm_x64_emit_mxcsr_load_store, data, tmp_reg1, buf, load);
      break;
    }
    default: {
#ifdef EVOASM_X64_ENABLE_AVX512
      unsupported:
#endif
      evoasm_log_fatal("non-gpr register type (%d) (unimplemented)", reg_type);
      evoasm_assert_not_reached();
    }
  }

  return true;

enc_failed:
  return false;
}

void
evoasm_x64_cpu_state_set(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_reg_id_t reg, const uint64_t *data,
                         size_t len) {
  size_t bytes_len = EVOASM_MIN(evoasm_x64_reg_type_bytesizes[evoasm_x64_get_reg_type(reg)], len * sizeof(uint64_t));
  memcpy(evoasm_x64_cpu_state_get_reg_data(cpu_state, reg), data, bytes_len);

  if(reg == EVOASM_X64_REG_RFLAGS) {
    /* Mask away dangerous and useless flags */
    cpu_state->rflags[0] &= 0x8c5;
  }
}

void
evoasm_x64_cpu_state_memset(evoasm_x64_cpu_state_t *cpu_state, int value) {
  memset(cpu_state, value, sizeof(evoasm_x64_cpu_state_t));
}

size_t
evoasm_x64_cpu_state_get(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_reg_id_t reg, evoasm_x64_operand_word_t word,
                         uint64_t *data, size_t len) {
  size_t size = evoasm_x64_reg_type_bytesizes[evoasm_x64_get_reg_type(reg)];
  size_t cpy_len = EVOASM_MIN(len * sizeof(uint64_t), size);
  memcpy(data, evoasm_x64_cpu_state_get_reg_data(cpu_state, reg), cpy_len);

  size_t n_elems = EVOASM_MAX(1, cpy_len / sizeof(uint64_t));
  size_t clear_from_idx = n_elems;

  if(reg == EVOASM_X64_REG_RFLAGS) {
    /* Mask away dangerous and useless flags */
    data[0] &= 0x8c5;
  }

  switch(word) {
    case EVOASM_X64_OPERAND_WORD_LB:
      data[0] &= 0x00FF;
      clear_from_idx = 1;
      break;
    case EVOASM_X64_OPERAND_WORD_HB:
      data[0] &= 0xFF00;
      clear_from_idx = 1;
      break;
    case EVOASM_X64_OPERAND_WORD_W:
      data[0] &= 0xFFFF;
      clear_from_idx = 1;
      break;
    case EVOASM_X64_OPERAND_WORD_DW:
      data[0] &= 0xFFFFFFFF;
      clear_from_idx = 1;
      break;
    case EVOASM_X64_OPERAND_WORD_LQW:
      data[0] &= 0xFFFFFFFFFFFFFFFF;
      clear_from_idx = 1;
      break;
    case EVOASM_X64_OPERAND_WORD_HQW:
      data[0] = 0;
      clear_from_idx = 2;
      break;
    case EVOASM_X64_OPERAND_WORD_DQW:
      clear_from_idx = 2;
      break;
    case EVOASM_X64_OPERAND_WORD_VW:
      break;
    case EVOASM_X64_OPERAND_WORD_NONE:
      break;
    default:
      evoasm_assert_not_reached();
  }

  for(size_t i = clear_from_idx; i < n_elems; i++) data[i] = 0;

  return n_elems;
}

bool
evoasm_x64_cpu_state_get_rflags_flag(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_rflags_flag_t flag) {
  uint64_t rflags = cpu_state->rflags[0];
  uint64_t mask = evoasm_x64_get_rflags_flag_mask_(flag);
  return (rflags & mask) != 0;
}

void
evoasm_x64_cpu_state_clone(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_cpu_state_t *cloned_cpu_state) {
  *cloned_cpu_state = *cpu_state;
}

static_assert(CHAR_BIT == 8, "CHAR_BIT must be 8");

void
evoasm_x64_cpu_state_xor(evoasm_x64_cpu_state_t *cpu_state,
                         evoasm_x64_cpu_state_t *other_cpu_state,
                         evoasm_x64_cpu_state_t *xored_cpu_state) {
  size_t size = sizeof(evoasm_x64_cpu_state_t);
  uint8_t *data = (uint8_t *) cpu_state;
  uint8_t *other_data = (uint8_t *) other_cpu_state;
  uint8_t *xored_data = (uint8_t *) xored_cpu_state;

  for(size_t i = 0; i < size; i++) {
    xored_data[i] = data[i] ^ other_data[i];
  }
}

void
evoasm_x64_cpu_state_init(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_cpu_state_flags_t flags) {
  static evoasm_x64_cpu_state_t zero_cpu_state = {0};
  *cpu_state = zero_cpu_state;
  cpu_state->flags = flags;
}


EVOASM_DEF_EMPTY_DESTROY_FUNC(x64_cpu_state)


evoasm_x64_cpu_state_t *
evoasm_x64_cpu_state_alloc() {
  return evoasm_aligned_alloc(32, sizeof(evoasm_x64_cpu_state_t));
}

void
evoasm_x64_cpu_state_free(evoasm_x64_cpu_state_t *cpu_state) {
  evoasm_free(cpu_state);
}

evoasm_success_t
evoasm_x64_cpu_state_emit_load_store(evoasm_x64_cpu_state_t *cpu_state,
                                     evoasm_buf_t *buf, bool load) {

  bool ip = cpu_state->flags & EVOASM_X64_CPU_STATE_FLAG_IP;
  bool sp = cpu_state->flags & EVOASM_X64_CPU_STATE_FLAG_SP;
  bool mxcsr = cpu_state->flags & EVOASM_X64_CPU_STATE_FLAG_MXCSR;
  bool rflags = cpu_state->flags & EVOASM_X64_CPU_STATE_FLAG_RFLAGS;

  static const evoasm_x64_reg_id_t tmp_reg1 = EVOASM_X64_REG_14;
  static const evoasm_x64_reg_id_t tmp_reg2 = EVOASM_X64_REG_15;

  EVOASM_TRY(enc_failed, evoasm_x64_emit_push, tmp_reg1, buf);
  EVOASM_TRY(enc_failed, evoasm_x64_emit_push, tmp_reg2, buf);

  for(evoasm_x64_reg_id_t reg_id = (evoasm_x64_reg_id_t) 0; reg_id < EVOASM_X64_REG_NONE; reg_id++) {
    if(reg_id == tmp_reg1 || reg_id == tmp_reg2) continue;
#ifndef EVOASM_X64_ENABLE_AVX512
    if(reg_id >= EVOASM_X64_REG_ZMM16) continue;
#endif

    if(!ip && reg_id == EVOASM_X64_REG_IP) continue;
    if(!sp && reg_id == EVOASM_X64_REG_SP) continue;
    if(!mxcsr && reg_id == EVOASM_X64_REG_MXCSR) continue;
    if(!rflags && reg_id == EVOASM_X64_REG_RFLAGS) continue;

    uint8_t *data = (uint8_t *) evoasm_x64_cpu_state_get_reg_data(cpu_state, reg_id);
    EVOASM_TRY(enc_failed, evoasm_x64_emit_load_store, reg_id, data, tmp_reg1, tmp_reg2, buf, load);
  }

  EVOASM_TRY(enc_failed, evoasm_x64_emit_pop, tmp_reg2, buf);
  {
    uint8_t *data = (uint8_t *) evoasm_x64_cpu_state_get_reg_data(cpu_state, tmp_reg2);
    EVOASM_TRY(enc_failed, evoasm_x64_emit_load_store, tmp_reg2, data, tmp_reg1, EVOASM_X64_REG_NONE, buf, load);
  }

  EVOASM_TRY(enc_failed, evoasm_x64_emit_pop, tmp_reg1, buf);
  EVOASM_TRY(enc_failed, evoasm_x64_emit_push, tmp_reg2, buf);
  {
    uint8_t *data = (uint8_t *) evoasm_x64_cpu_state_get_reg_data(cpu_state, tmp_reg1);
    EVOASM_TRY(enc_failed, evoasm_x64_emit_load_store, tmp_reg1, data, tmp_reg2, EVOASM_X64_REG_NONE, buf, load);
  }
  EVOASM_TRY(enc_failed, evoasm_x64_emit_pop, tmp_reg2, buf);

  return true;

enc_failed:
  return false;

}

evoasm_success_t
evoasm_x64_cpu_state_emit_load(evoasm_x64_cpu_state_t *cpu_state, evoasm_buf_t *buf) {
  return evoasm_x64_cpu_state_emit_load_store(cpu_state, buf, true);
}

evoasm_success_t
evoasm_x64_cpu_state_emit_store(evoasm_x64_cpu_state_t *cpu_state, evoasm_buf_t *buf) {
  return evoasm_x64_cpu_state_emit_load_store(cpu_state, buf, false);
}

EVOASM_DEF_ALLOC_FREE_FUNCS(x64_params)

EVOASM_DEF_ALLOC_FREE_FUNCS(x64_basic_params)

const char *
evoasm_x64_get_rflags_flag_name(evoasm_x64_rflags_flag_t flag) {
  switch(flag) {
    case EVOASM_X64_RFLAGS_FLAG_OF:
      return "OF";
    case EVOASM_X64_RFLAGS_FLAG_SF:
      return "SF";
    case EVOASM_X64_RFLAGS_FLAG_ZF:
      return "ZF";
    case EVOASM_X64_RFLAGS_FLAG_PF:
      return "PF";
    case EVOASM_X64_RFLAGS_FLAG_CF:
      return "CF";
    default:
      evoasm_assert_not_reached();
  }
}

int
evoasm_x64_sprint_inst(evoasm_x64_inst_t *inst, evoasm_x64_basic_params_t *params, char *buf, size_t len) {

#define EVOASM_X64_SPRINT_INST_SNPRINTF(format, ...) \
  off += EVOASM_MAX(0, snprintf(buf + off, len - (size_t) off, format, __VA_ARGS__))

  const char *mnem = evoasm_x64_inst_get_mnem(inst);
  int off = 0;

  EVOASM_X64_SPRINT_INST_SNPRINTF("%s\t(", mnem);
  for(evoasm_x64_basic_param_id_t i = (evoasm_x64_basic_param_id_t) 0; i < EVOASM_X64_BASIC_PARAM_NONE; i++) {
    const char *param_name = evoasm_x64_get_basic_param_name_(i);
    evoasm_x64_param_type_t param_type = evoasm_x64_get_basic_param_type_(i);
    int64_t param_val = evoasm_x64_basic_params_get_(params, i);

    EVOASM_X64_SPRINT_INST_SNPRINTF("%s:", param_name);

    switch(param_type) {
      case EVOASM_X64_PARAM_TYPE_BOOL:
        EVOASM_X64_SPRINT_INST_SNPRINTF("%s", param_val == 0 ? "false" : "true");
        break;
      case EVOASM_X64_PARAM_TYPE_UINT1:
      case EVOASM_X64_PARAM_TYPE_INT3:
      case EVOASM_X64_PARAM_TYPE_INT4:
      case EVOASM_X64_PARAM_TYPE_INT8:
      case EVOASM_X64_PARAM_TYPE_INT32:
      case EVOASM_X64_PARAM_TYPE_INT64:
        EVOASM_X64_SPRINT_INST_SNPRINTF("%"PRId64, param_val);
        break;
      case EVOASM_X64_PARAM_TYPE_REG:
        EVOASM_X64_SPRINT_INST_SNPRINTF("%s", evoasm_x64_get_reg_name((evoasm_x64_reg_id_t) param_val));
        break;
      case EVOASM_X64_PARAM_TYPE_ADDR_SIZE: {
        const char *addr_size;
        switch((evoasm_x64_addr_size_t) param_val) {
          case EVOASM_X64_ADDR_SIZE_64:
            addr_size = "64";
            break;
          case EVOASM_X64_ADDR_SIZE_32:
            addr_size = "32";
            break;
          case EVOASM_X64_ADDR_SIZE_NONE:
            addr_size = "none";
            break;
          default:
            evoasm_assert_not_reached();
        }
        EVOASM_X64_SPRINT_INST_SNPRINTF("%s", addr_size);
        break;
      }
      case EVOASM_X64_PARAM_TYPE_SCALE: {
        const char *scale;
        switch((evoasm_x64_scale_t) param_val) {
          case EVOASM_X64_SCALE_1:
            scale = "1";
            break;
          case EVOASM_X64_SCALE_2:
            scale = "2";
            break;
          case EVOASM_X64_SCALE_4:
            scale = "4";
            break;
          case EVOASM_X64_SCALE_8:
            scale = "8";
            break;
          case EVOASM_X64_SCALE_NONE:
            scale = "none";
            break;
          default:
            evoasm_assert_not_reached();
        }
        EVOASM_X64_SPRINT_INST_SNPRINTF("%s", scale);
        break;
      }
      case EVOASM_X64_PARAM_TYPE_NONE:
        EVOASM_X64_SPRINT_INST_SNPRINTF("%s", "none");
        break;
      default:
        evoasm_assert_not_reached();
    }

    if(i < inst->n_params - 1u) {
      EVOASM_X64_SPRINT_INST_SNPRINTF("%s", ", ");
    }
  }
  EVOASM_X64_SPRINT_INST_SNPRINTF("%s", ")");
  return off;
}

