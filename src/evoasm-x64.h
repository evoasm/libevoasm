/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdint.h>
#include "evoasm-error.h"
#include "evoasm-alloc.h"
#include "evoasm-arch.h"
#include "evoasm-domain.h"

#include "gen/evoasm-x64-enums.h"
#include "gen/evoasm-x64-params.h"

typedef struct {
  evoasm_buf_ref_t buf_ref;
  struct {
    bool encode_rex : 1;
  } shared_vars;
  union {
    evoasm_x64_params_t params;
    evoasm_x64_basic_params_t basic_params;
  };
} evoasm_x64_enc_ctx_t;

#include "gen/evoasm-x64-misc.h"


typedef enum {
  EVOASM_X64_INSTS_FLAG_SEARCH = (1 << 0),
} evoasm_x64_insts_flags_t;

typedef enum {
  EVOASM_X64_OPERAND_SIZE_1,
  EVOASM_X64_OPERAND_SIZE_8,
  EVOASM_X64_OPERAND_SIZE_16,
  EVOASM_X64_OPERAND_SIZE_32,
  EVOASM_X64_OPERAND_SIZE_64,
  EVOASM_X64_OPERAND_SIZE_128,
  EVOASM_X64_OPERAND_SIZE_256,
  EVOASM_X64_OPERAND_SIZE_512,
  EVOASM_X64_OPERAND_SIZE_NONE,
} evoasm_x64_operand_size_t;

#define EVOASM_X64_OPERAND_SIZE_BITSIZE 3
#define EVOASM_X64_OPERAND_SIZE_BITSIZE_OPT 4

typedef struct {
  uint8_t rflags[8];
  uint8_t rax[8];
  uint8_t rcx[8];
  uint8_t rdx[8];
  uint8_t rbx[8];
  uint8_t rsp[8];
  uint8_t rbp[8];
  uint8_t rsi[8];
  uint8_t rdi[8];
  uint8_t r8[8];
  uint8_t r9[8];
  uint8_t r10[8];
  uint8_t r11[8];
  uint8_t r12[8];
  uint8_t r13[8];
  uint8_t r14[8];
  uint8_t r15[8];
  uint8_t mm0[8];
  uint8_t mm1[8];
  uint8_t mm2[8];
  uint8_t mm3[8];
  uint8_t mm4[8];
  uint8_t mm5[8];
  uint8_t mm6[8];
  uint8_t mm7[8];
  uint8_t xmm0[64];
  uint8_t xmm1[64];
  uint8_t xmm2[64];
  uint8_t xmm3[64];
  uint8_t xmm4[64];
  uint8_t xmm5[64];
  uint8_t xmm6[64];
  uint8_t xmm7[64];
  uint8_t xmm8[64];
  uint8_t xmm9[64];
  uint8_t xmm10[64];
  uint8_t xmm11[64];
  uint8_t xmm12[64];
  uint8_t xmm13[64];
  uint8_t xmm14[64];
  uint8_t xmm15[64];
  uint8_t zmm16[64];
  uint8_t zmm17[64];
  uint8_t zmm18[64];
  uint8_t zmm19[64];
  uint8_t zmm20[64];
  uint8_t zmm21[64];
  uint8_t zmm22[64];
  uint8_t zmm23[64];
  uint8_t zmm24[64];
  uint8_t zmm25[64];
  uint8_t zmm26[64];
  uint8_t zmm27[64];
  uint8_t zmm28[64];
  uint8_t zmm29[64];
  uint8_t zmm30[64];
  uint8_t zmm31[64];
} evoasm_x64_cpu_state_t;

typedef struct {
  unsigned read: 1;
  unsigned written: 1;
  unsigned undefined: 1;
  unsigned cond_written: 1;
  unsigned implicit: 1;
  unsigned mnem: 1;
  unsigned param_idx: EVOASM_X64_PARAM_IDX_BITSIZE;
  unsigned type: EVOASM_X64_OPERAND_TYPE_BITSIZE;
  unsigned size1: EVOASM_X64_OPERAND_SIZE_BITSIZE_OPT;
  unsigned size2: EVOASM_X64_OPERAND_SIZE_BITSIZE_OPT;
  unsigned reg_type: EVOASM_X64_REG_TYPE_BITSIZE_OPT;
  unsigned write_mask: EVOASM_X64_BIT_MASK_BITSIZE;
  union {
    uint8_t reg_id;
    int8_t imm;
  };
} evoasm_x64_operand_t;

typedef bool (*evoasm_x64_inst_enc_func_t)(evoasm_x64_enc_ctx_t *ctx);

typedef struct {
  uint8_t n_operands;
  uint16_t id;
  uint16_t n_params;
  uint32_t exceptions;
  uint32_t flags;
  uint64_t features;
  evoasm_param_t *params;
  evoasm_x64_inst_enc_func_t enc_func;
  evoasm_x64_inst_enc_func_t basic_enc_func;
  evoasm_x64_operand_t *operands;
  char *mnem;
} evoasm_x64_inst_t;


#define EVOASM_X64_ENC(inst) \
  do { \
    evoasm_x64_enc_ctx_t enc_ctx = { \
      .params = params, \
      .buf_ref = { \
        .data = (buf)->data, \
        .pos = &(buf->pos)  \
      } \
    }; \
    EVOASM_TRY(enc_failed, evoasm_x64_##inst, &enc_ctx); \
  } while(0);

#define EVOASM_X64_SET(param, val) \
  evoasm_x64_params_set_(&params, param, val)

#define EVOASM_X64_UNSET(param) \
  evoasm_x64_params_unset_(&params, param)

typedef enum {
  EVOASM_X64_ABI_SYSV
} evoasm_x64_abi_t;

#include "gen/evoasm-x64-insts.h"

static inline evoasm_success_t
evoasm_x64_inst_enc_(evoasm_x64_inst_t *inst, evoasm_x64_params_t *params, evoasm_buf_ref_t *buf_ref) {
  evoasm_x64_enc_ctx_t enc_ctx = {
      .params = *params,
      .buf_ref = *buf_ref
  };
  return inst->enc_func(&enc_ctx);
}

static inline evoasm_success_t
evoasm_x64_inst_enc_basic_(evoasm_x64_inst_t *inst, evoasm_x64_basic_params_t *params, evoasm_buf_ref_t *buf_ref) {
  evoasm_x64_enc_ctx_t enc_ctx = {
      .basic_params = *params,
      .buf_ref = *buf_ref
  };
  return inst->basic_enc_func(&enc_ctx);
}

extern const evoasm_x64_inst_t *EVOASM_X64_INSTS_VAR_NAME;

static inline evoasm_x64_inst_t *
evoasm_x64_inst_(evoasm_x64_inst_id_t inst_id) {
  return (evoasm_x64_inst_t *) &EVOASM_X64_INSTS_VAR_NAME[inst_id];
}

static inline evoasm_success_t
evoasm_x64_enc_(evoasm_x64_inst_id_t inst_id, evoasm_x64_params_t *params, evoasm_buf_ref_t *buf_ref) {
  evoasm_x64_inst_t *inst = evoasm_x64_inst_(inst_id);
  return evoasm_x64_inst_enc_(inst, params, buf_ref);
}

static inline evoasm_success_t
evoasm_x64_enc_basic_(evoasm_x64_inst_id_t inst_id, evoasm_x64_basic_params_t *params, evoasm_buf_ref_t *buf_ref) {
  evoasm_x64_inst_t *inst = evoasm_x64_inst_(inst_id);
  return evoasm_x64_inst_enc_basic_(inst, params, buf_ref);
}

evoasm_success_t
evoasm_x64_func_prolog(evoasm_buf_t *buf, evoasm_x64_abi_t abi);

evoasm_success_t
evoasm_x64_func_epilog(evoasm_buf_t *buf, evoasm_x64_abi_t abi);

const char *
evoasm_x64_inst_get_mnem(evoasm_x64_inst_t *inst);
