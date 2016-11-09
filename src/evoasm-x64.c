/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-x64.h"
#include "evoasm.h"

EVOASM_DEF_LOG_TAG("x64")

uint8_t evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_NONE] = {0};

static evoasm_x64_reg_id_t evoasm_x64_sysv_callee_save_regs[] = {
    EVOASM_X64_REG_BP,
    EVOASM_X64_REG_B,
    EVOASM_X64_REG_12,
    EVOASM_X64_REG_13,
    EVOASM_X64_REG_14,
    EVOASM_X64_REG_15,
};

static evoasm_success_t
evoasm_x64_func_prolog_or_epilog(evoasm_buf_t *buf, evoasm_x64_abi_t abi, bool prolog) {
  size_t regs_len = EVOASM_ARY_LEN(evoasm_x64_sysv_callee_save_regs);
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
evoasm_x64_func_prolog(evoasm_buf_t *buf, evoasm_x64_abi_t abi) {
  return evoasm_x64_func_prolog_or_epilog(buf, abi, true);
}

evoasm_success_t
evoasm_x64_func_epilog(evoasm_buf_t *buf, evoasm_x64_abi_t abi) {
  return evoasm_x64_func_prolog_or_epilog(buf, abi, false);
}

evoasm_success_t
evoasm_x64_init() {
  extern evoasm_arch_info_t _evoasm_arch_infos[EVOASM_ARCH_NONE];
  uint64_t features;
  EVOASM_TRY(cpuid_failed, evoasm_x64_get_features, &features);

  evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_GP] = 8;

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
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] = 64;
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_ZMM] = 64;
  }
  else
#endif
  if(features & EVOASM_X64_FEATURE_AVX2) {
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] = 32;
  } else {
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] = 16;
  }

  _evoasm_arch_infos[EVOASM_ARCH_X64].features = features;

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

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(cond_written)

EVOASM_X64_OPERAND_DEF_BOOL_GETTER(mnem)

EVOASM_X64_OPERAND_DEF_GETTER(write_mask, evoasm_x64_bitmask_t)

EVOASM_X64_OPERAND_DEF_GETTER(type, evoasm_x64_operand_type_t)

EVOASM_X64_OPERAND_DEF_GETTER(reg_type, evoasm_x64_reg_type_t)

EVOASM_X64_OPERAND_DEF_GETTER(reg_id, evoasm_x64_reg_id_t)

EVOASM_X64_OPERAND_DEF_GETTER(imm, int8_t)

EVOASM_X64_OPERAND_DEF_GETTER(param_idx, size_t)

evoasm_x64_operand_size_t evoasm_x64_operand_get_size(evoasm_x64_operand_t *operand) {
  if(operand->size1 < EVOASM_X64_OPERAND_SIZE_NONE) return operand->size1;
  if(operand->size2 < EVOASM_X64_OPERAND_SIZE_NONE) return operand->size2;
  return EVOASM_X64_OPERAND_SIZE_NONE;
}

evoasm_x64_operand_size_t evoasm_x64_operand_get_reg_size(evoasm_x64_operand_t *operand) {
  return (evoasm_x64_operand_size_t) operand->size1;
}

evoasm_x64_operand_size_t evoasm_x64_operand_get_index_reg_size(evoasm_x64_operand_t *operand) {
  return (evoasm_x64_operand_size_t) operand->size1;
}

evoasm_x64_operand_size_t evoasm_x64_operand_get_mem_size(evoasm_x64_operand_t *operand) {
  return (evoasm_x64_operand_size_t) operand->size2;
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

size_t
evoasm_x64_insts(uint64_t flags, uint64_t features, uint64_t operand_types, uint64_t reg_types,
                 evoasm_x64_inst_id_t *insts) {
  size_t len = 0;
  bool search = (flags & EVOASM_X64_INSTS_FLAG_SEARCH) != 0;

  for(size_t i = 0; i < EVOASM_X64_INST_NONE; i++) {
    if(search && (i == EVOASM_X64_INST_CRC32_R32_RM8 ||
                  i == EVOASM_X64_INST_CRC32_R32_RM16 ||
                  i == EVOASM_X64_INST_CRC32_R32_RM32 ||
                  i == EVOASM_X64_INST_CRC32_R64_RM8 ||
                  i == EVOASM_X64_INST_CRC32_R64_RM64 ||
                  i == EVOASM_X64_INST_CPUID ||
                  i == EVOASM_X64_INST_RDRAND_R16 ||
                  i == EVOASM_X64_INST_RDRAND_R32 ||
                  i == EVOASM_X64_INST_RDRAND_R64 ||
                  i == EVOASM_X64_INST_RDSEED_R16 ||
                  i == EVOASM_X64_INST_RDSEED_R32 ||
                  i == EVOASM_X64_INST_RDSEED_R64 ||
                  i == EVOASM_X64_INST_AESDEC_XMM_XMMM128 ||
                  i == EVOASM_X64_INST_AESDECLAST_XMM_XMMM128 ||
                  i == EVOASM_X64_INST_AESENC_XMM_XMMM128 ||
                  i == EVOASM_X64_INST_AESENCLAST_XMM_XMMM128 ||
                  i == EVOASM_X64_INST_AESIMC_XMM_XMMM128 ||
                  i == EVOASM_X64_INST_AESKEYGENASSIST_XMM_XMMM128_IMM8))
      goto skip;

    evoasm_x64_inst_t *inst = (evoasm_x64_inst_t *) &EVOASM_X64_INSTS_VAR_NAME[i];

    if(search && !evoasm_x64_inst_is_basic(inst)) goto skip;

    if((inst->features & ~features) != 0) goto skip;

    if(search && inst->n_operands == 0) goto skip;

    for(size_t j = 0; j < inst->n_operands; j++) {
      evoasm_x64_operand_t *operand = &inst->operands[j];

      if(((1ull << operand->type) & operand_types) == 0) goto skip;

      if(operand->type == EVOASM_X64_OPERAND_TYPE_REG ||
         operand->type == EVOASM_X64_OPERAND_TYPE_RM) {
        if((flags & EVOASM_X64_INSTS_FLAG_SEARCH) &&
           (operand->reg_id == EVOASM_X64_REG_SP ||
            operand->reg_id == EVOASM_X64_REG_IP))
          goto skip;

        if(((1ull << operand->reg_type) & reg_types) == 0) goto skip;
      }
    }

    insts[len++] = (evoasm_x64_inst_id_t) i;
skip:;
  }
  return len;
}


static uint8_t *
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
    default:
      evoasm_assert_not_reached();
  }
}

static evoasm_success_t
evoasm_x64_emit_load_store(evoasm_x64_reg_id_t reg_id,
                           uint8_t *data,
                           evoasm_x64_reg_id_t tmp_reg_id,
                           evoasm_buf_t *buf,
                           bool load) {

  evoasm_x64_params_t params = {0};
  evoasm_x64_reg_type_t reg_type = evoasm_x64_get_reg_type(reg_id);

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, tmp_reg_id);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, tmp_reg_id);
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);

  switch(reg_type) {
    case EVOASM_X64_REG_TYPE_GP: {
      if(load) {
        EVOASM_X64_ENC(mov_r64_rm64);
      } else {
        EVOASM_X64_ENC(mov_rm64_r64);
      }
      break;
    }
    case EVOASM_X64_REG_TYPE_XMM: {
      if(evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] == 32) {
        if(load) {
          EVOASM_X64_ENC(vmovdqa_ymm_ymmm256);
        } else {
          EVOASM_X64_ENC(vmovdqa_ymmm256_ymm);
        }
      }
#ifdef EVOASM_X64_ENABLE_AVX512
        else if(evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] == 64) {
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
      break;
    }
    case EVOASM_X64_REG_TYPE_MM: {
      if(load) {
        EVOASM_X64_ENC(movsd_xmm_xmmm64);
      } else {
        EVOASM_X64_ENC(movsd_xmmm64_xmm);
      }
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

evoasm_success_t
evoasm_x64_emit_load(evoasm_x64_reg_id_t reg_id, uint8_t *data, evoasm_x64_reg_id_t tmp_reg_id,
                     evoasm_buf_t *buf) {

  return evoasm_x64_emit_load_store(reg_id, data, tmp_reg_id, buf, true);
}

evoasm_success_t
evoasm_x64_emit_store(evoasm_x64_reg_id_t reg_id, uint8_t *data, evoasm_x64_reg_id_t tmp_reg_id,
                      evoasm_buf_t *buf) {
  return evoasm_x64_emit_load_store(reg_id, data, tmp_reg_id, buf, false);
}


static evoasm_success_t
evoasm_x64_emit_pop_push(evoasm_x64_reg_id_t reg_id, evoasm_buf_t *buf, bool pop) {
  evoasm_x64_params_t params = {0};
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg_id);
  if(pop) {
    EVOASM_X64_ENC(push_r64);
  } else {
    EVOASM_X64_ENC(pop_r64);
  }

  return true;

enc_failed:
  return false;
}

static evoasm_success_t
evoasm_x64_emit_pop(evoasm_x64_reg_id_t reg_id, evoasm_buf_t *buf) {
  return evoasm_x64_emit_pop_push(reg_id, buf, true);
}

static evoasm_success_t
evoasm_x64_emit_push(evoasm_x64_reg_id_t reg_id, evoasm_buf_t *buf) {
  return evoasm_x64_emit_pop_push(reg_id, buf, false);
}

static evoasm_success_t
evoasm_x64_emit_rflags_load_store(uint8_t *data,
                                  evoasm_buf_t *buf,
                                  bool load) {

  evoasm_x64_params_t params = {0};

  EVOASM_TRY(enc_failed, evoasm_x64_emit_push, EVOASM_X64_REG_SP, buf);
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_X64_REG_SP);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) data);
  EVOASM_X64_ENC(mov_r64_imm64);

  if(load) {
    EVOASM_X64_ENC(popfq);
  } else {
    EVOASM_X64_ENC(pushfq);
  }

  EVOASM_TRY(enc_failed, evoasm_x64_emit_pop, EVOASM_X64_REG_SP, buf);
  return true;

enc_failed:
  return false;
}

void
evoasm_x64_cpu_state_set(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_reg_id_t reg_id, const uint8_t *data, size_t len) {
  len = EVOASM_MIN(evoasm_x64_reg_type_sizes[evoasm_x64_get_reg_type(reg_id)], len);
  memcpy(evoasm_x64_cpu_state_get_reg_data(cpu_state, reg_id), data, len);
}

void
evoasm_x64_cpu_state_memset(evoasm_x64_cpu_state_t *cpu_state, int value) {
  memset(cpu_state, value, sizeof(evoasm_x64_cpu_state_t));
}

size_t
evoasm_x64_cpu_state_get(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_reg_id_t reg_id, const uint8_t **data) {
  size_t len = evoasm_x64_reg_type_sizes[evoasm_x64_get_reg_type(reg_id)];
  *data = evoasm_x64_cpu_state_get_reg_data(cpu_state, reg_id);
  return len;
}

bool
evoasm_x64_cpu_state_get_rflags_flag(evoasm_x64_cpu_state_t *cpu_state, evoasm_x64_rflags_flag_t flag) {
  /* silence strict-aliasing warning */
  union {
    uint64_t *u64;
    uint8_t *u8;
  } ptr;

  ptr.u8 = cpu_state->rflags;
  uint64_t rflags = *ptr.u64;

  switch(flag) {
    case EVOASM_X64_RFLAGS_FLAG_OF:
      return (rflags & (1 << 11)) != 0;
    case EVOASM_X64_RFLAGS_FLAG_SF:
      return (rflags & (1 << 7)) != 0;
    case EVOASM_X64_RFLAGS_FLAG_ZF:
      return (rflags & (1 << 6)) != 0;
    case EVOASM_X64_RFLAGS_FLAG_PF:
      return (rflags & (1 << 2)) != 0;
    case EVOASM_X64_RFLAGS_FLAG_CF:
      return (rflags & (1 << 0)) != 0;
    default:
      evoasm_assert_not_reached();
  }
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

EVOASM_DEF_ZERO_INIT_FUNC(x64_cpu_state)
EVOASM_DEF_EMPTY_DESTROY_FUNC(x64_cpu_state)
EVOASM_DEF_ALLOC_FREE_FUNCS(x64_cpu_state)

evoasm_success_t
evoasm_x64_cpu_state_emit_load_store(evoasm_x64_cpu_state_t *cpu_state, evoasm_buf_t *buf, bool load) {
  static const evoasm_x64_reg_id_t tmp_reg_id = EVOASM_X64_REG_14;
  for(evoasm_x64_reg_id_t reg_id = (evoasm_x64_reg_id_t) 0; reg_id < EVOASM_X64_REG_NONE; reg_id++) {
    uint8_t *data = evoasm_x64_cpu_state_get_reg_data(cpu_state, reg_id);

    switch(reg_id) {
      case EVOASM_X64_REG_IP:
        continue;
      case EVOASM_X64_REG_RFLAGS:
        EVOASM_TRY(enc_failed, evoasm_x64_emit_rflags_load_store, data, buf, load);
        break;
      default:
        EVOASM_TRY(enc_failed, evoasm_x64_emit_load_store, reg_id, data, tmp_reg_id, buf, load);

        if(reg_id == tmp_reg_id) {
          EVOASM_TRY(enc_failed, evoasm_x64_emit_push, reg_id, buf);
        }
    }
  }
  EVOASM_TRY(enc_failed, evoasm_x64_emit_pop, tmp_reg_id, buf);

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
