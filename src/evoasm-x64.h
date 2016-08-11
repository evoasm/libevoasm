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

#include "gen/evoasm-x64-enums.h"

typedef struct {
  bool encode_rex;
} evoasm_x64_shared_vars_t;

typedef struct {
  evoasm_arch_ctx_t base;
  uint64_t features;
  evoasm_x64_shared_vars_t shared_vars;
} evoasm_x64_ctx_t;

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
  EVOASM_X64_N_OPERAND_SIZES,
} evoasm_x64_operand_size_t;

#define EVOASM_X64_OPERAND_SIZE_BITSIZE 3
#define EVOASM_X64_OPERAND_SIZE_BITSIZE_WITH_N 4

typedef struct {
  unsigned read: 1;
  unsigned written: 1;
  unsigned undefined: 1;
  unsigned cond_written: 1;
  unsigned implicit: 1;
  unsigned mnem: 1;
  unsigned param_idx: EVOASM_X64_PARAM_IDX_BITSIZE;
  unsigned type: EVOASM_X64_OPERAND_TYPE_BITSIZE;
  unsigned size1: EVOASM_X64_OPERAND_SIZE_BITSIZE_WITH_N;
  unsigned size2: EVOASM_X64_OPERAND_SIZE_BITSIZE_WITH_N;
  unsigned reg_type: EVOASM_X64_REG_TYPE_BITSIZE_WITH_N;
  unsigned write_mask: EVOASM_X64_BIT_MASK_BITSIZE;
  union {
    uint8_t reg_id;
    int8_t imm;
  };
} evoasm_x64_operand_t;

typedef bool (*evoasm_x64_inst_enc_func_t)(evoasm_x64_ctx_t *x64, evoasm_inst_param_val_t *param_vals,
                                           evoasm_bitmap_t *set_params);

typedef struct {
  uint8_t n_operands;
  uint16_t id;
  uint16_t n_params;
  uint32_t exceptions;
  uint32_t flags;
  uint64_t features;
  evoasm_inst_param_t *params;
  evoasm_x64_inst_enc_func_t enc_func;
  evoasm_x64_operand_t *operands;
  char *mnem;
} evoasm_x64_inst_t;


#define EVOASM_X64_ENC(inst) \
  EVOASM_TRY(enc_failed, evoasm_x64_##inst, x64_ctx, params.vals, (evoasm_bitmap_t *) &params.set)

#define EVOASM_X64_SET(param, val) \
  evoasm_inst_params_set(params.vals, (evoasm_bitmap_t *) &params.set, param, val)

#define EVOASM_X64_UNSET(param) \
  evoasm_inst_params_unset(params.vals, (evoasm_bitmap_t *) &params.set, param)

typedef enum {
  EVOASM_X64_ABI_SYSV
} evoasm_x64_abi_t;

#include "gen/evoasm-x64-insts.h"

static inline evoasm_success_t
_evoasm_x64_inst_enc(evoasm_x64_inst_t *inst, evoasm_x64_ctx_t *x64,
                     evoasm_inst_param_val_t *param_vals, evoasm_bitmap_t *set_params) {
  return inst->enc_func(x64, param_vals, set_params);
}

extern const evoasm_x64_inst_t *_EVOASM_X64_INSTS_VAR_NAME;

static inline evoasm_x64_inst_t *
_evoasm_x64_inst(evoasm_x64_inst_id_t inst_id) {
  return (evoasm_x64_inst_t *) &_EVOASM_X64_INSTS_VAR_NAME[inst_id];
}

static inline evoasm_success_t
_evoasm_x64_ctx_enc(evoasm_x64_ctx_t *x64, evoasm_x64_inst_id_t inst_id, evoasm_inst_param_val_t *param_vals,
                    evoasm_bitmap_t *set_params) {
  evoasm_x64_inst_t *inst = _evoasm_x64_inst(inst_id);
  return _evoasm_x64_inst_enc(inst, x64, param_vals, set_params);
}

typedef struct {
  _EVOASM_INST_PARAMS_HEADER
  evoasm_inst_param_val_t vals[EVOASM_X64_N_INST_PARAMS];
} evoasm_x64_params_t;

_Static_assert(EVOASM_X64_N_INST_PARAMS <= EVOASM_ARCH_MAX_PARAMS,
                "Too much parameters. Redeclar EVOASM_ARCH_MAX_PARAMS and evoasm_arch_params_bitmap.");


static inline int64_t
evoasm_x64_disp_size(evoasm_inst_param_val_t *param_vals, evoasm_bitmap_t *set_params) {
  evoasm_inst_param_val_t val = param_vals[EVOASM_X64_INST_PARAM_DISP];
  if(!evoasm_bitmap_get(set_params, EVOASM_X64_INST_PARAM_DISP)) return 0;
  if(val >= INT8_MIN && val <= INT8_MAX) return 8;
  if(val >= INT32_MIN && val <= INT32_MAX) return 32;
  return 0;
}

void
evoasm_x64_ctx_destroy(evoasm_x64_ctx_t *x64_ctx);

evoasm_success_t
evoasm_x64_ctx_init(evoasm_x64_ctx_t *x64_ctx);

evoasm_success_t
evoasm_x64_func_prolog(evoasm_x64_ctx_t *x64_ctx, evoasm_buf_t *buf, evoasm_x64_abi_t abi);

evoasm_success_t
evoasm_x64_func_epilog(evoasm_x64_ctx_t *x64_ctx, evoasm_buf_t *buf, evoasm_x64_abi_t abi);
