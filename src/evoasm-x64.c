/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-x64.h"
#include "evoasm.h"

//static const char *_evoasm_log_tag = "x64";

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
    }
    else {
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
  EVOASM_TRY(cpuid_failed, evoasm_x64_features, &features);

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

EVOASM_X64_OPERAND_DEF_GETTER(write_mask, evoasm_x64_bit_mask_t)
EVOASM_X64_OPERAND_DEF_GETTER(type, evoasm_x64_operand_type_t)
EVOASM_X64_OPERAND_DEF_GETTER(reg_type, evoasm_x64_reg_type_t)
EVOASM_X64_OPERAND_DEF_GETTER(reg_id, evoasm_x64_reg_id_t)
EVOASM_X64_OPERAND_DEF_GETTER(imm, int8_t)
EVOASM_X64_OPERAND_DEF_GETTER(param_idx, size_t)

evoasm_x64_operand_size_t evoasm_x64_operand_get_size(evoasm_x64_operand_t *operand) {
  if(operand->size1 < EVOASM_X64_N_OPERAND_SIZES) return operand->size1;
  if(operand->size2 < EVOASM_X64_N_OPERAND_SIZES) return operand->size2;
  return EVOASM_X64_N_OPERAND_SIZES;
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

uint16_t
evoasm_x64_insts(uint64_t flags, uint64_t features, uint64_t operand_types, uint64_t reg_types, evoasm_x64_inst_id_t *insts) {
  uint16_t len = 0;
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
                  i == EVOASM_X64_INST_AESKEYGENASSIST_XMM_XMMM128_IMM8)) goto skip;

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
            operand->reg_id == EVOASM_X64_REG_IP)) goto skip;

        if(((1ull << operand->reg_type) & reg_types) == 0) goto skip;
      }
    }

    insts[len++] = (evoasm_x64_inst_id_t) i;
skip:;
  }
  return len;
}

EVOASM_DEF_ALLOC_FREE_FUNCS(x64_params)
EVOASM_DEF_ALLOC_FREE_FUNCS(x64_basic_params)
