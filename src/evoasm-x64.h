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
  uint64_t ip[1];
  uint64_t rflags[1];
  uint64_t rax[1];
  uint64_t rcx[1];
  uint64_t rdx[1];
  uint64_t rbx[1];
  uint64_t rsp[1];
  uint64_t rbp[1];
  uint64_t rsi[1];
  uint64_t rdi[1];
  uint64_t r8[1];
  uint64_t r9[1];
  uint64_t r10[1];
  uint64_t r11[1];
  uint64_t r12[1];
  uint64_t r13[1];
  uint64_t r14[1];
  uint64_t r15[1];
  uint64_t mm0[1];
  uint64_t mm1[1];
  uint64_t mm2[1];
  uint64_t mm3[1];
  uint64_t mm4[1];
  uint64_t mm5[1];
  uint64_t mm6[1];
  uint64_t mm7[1];
  uint64_t xmm0[8];
  uint64_t xmm1[8];
  uint64_t xmm2[8];
  uint64_t xmm3[8];
  uint64_t xmm4[8];
  uint64_t xmm5[8];
  uint64_t xmm6[8];
  uint64_t xmm7[8];
  uint64_t xmm8[8];
  uint64_t xmm9[8];
  uint64_t xmm10[8];
  uint64_t xmm11[8];
  uint64_t xmm12[8];
  uint64_t xmm13[8];
  uint64_t xmm14[8];
  uint64_t xmm15[8];
  uint64_t zmm16[8];
  uint64_t zmm17[8];
  uint64_t zmm18[8];
  uint64_t zmm19[8];
  uint64_t zmm20[8];
  uint64_t zmm21[8];
  uint64_t zmm22[8];
  uint64_t zmm23[8];
  uint64_t zmm24[8];
  uint64_t zmm25[8];
  uint64_t zmm26[8];
  uint64_t zmm27[8];
  uint64_t zmm28[8];
  uint64_t zmm29[8];
  uint64_t zmm30[8];
  uint64_t zmm31[8];
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
  unsigned read_mask: EVOASM_X64_BITMASK_BITSIZE;
  unsigned write_mask: EVOASM_X64_BITMASK_BITSIZE;
  unsigned undefined_mask: EVOASM_X64_BITMASK_BITSIZE;
  unsigned cond_write_mask: EVOASM_X64_BITMASK_BITSIZE;
  unsigned flags : EVOASM_X64_OPERAND_MAX_FLAGS_BITSIZE;
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
