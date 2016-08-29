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
#include "evoasm-param.h"
#include "evoasm-buf.h"
#include "evoasm-log.h"

#define EVOASM_ARCH_BUF_CAPA 32
#define EVOASM_ARCH_MAX_PARAMS 32

typedef uint8_t evoasm_reg_id_t;
#define EVOASM_REG_ID_MAX UINT8_MAX
typedef uint16_t evoasm_inst_id_t;

typedef enum {
  EVOASM_ARCH_X64
} evoasm_arch_id_t;

typedef struct {
  evoasm_arch_id_t id : 8;
  uint16_t n_insts;
  uint8_t n_params;
  uint8_t max_inst_len;
} evoasm_arch_info_t;

typedef enum {
  EVOASM_ENC_ERROR_CODE_NOT_ENCODABLE = EVOASM_N_ERROR_CODES,
  EVOASM_ENC_ERROR_CODE_MISSING_PARAM,
  EVOASM_ENC_ERROR_CODE_INVALID_ACCESS,
  EVOASM_ENC_ERROR_CODE_MISSING_FEATURE,
} evoasm_enc_error_code_t;

typedef struct {
  uint8_t reg;
  uint8_t param;
  uint16_t inst;
} evoasm_enc_error_data_t;

_Static_assert(sizeof(evoasm_error_data_t) >= sizeof(evoasm_enc_error_data_t), "evoasm_enc_error_data_t exceeds evoasm_error_data_t size limit");

typedef struct {
  EVOASM_ERROR_HEADER
  evoasm_enc_error_data_t data;
} evoasm_enc_error_t;


#if 0
static inline void
evoasm_enc_ctx_write_access(evoasm_buf_ref_t *enc_ctx, evoasm_bitmap_t *acc, evoasm_reg_id_t reg) {
  evoasm_bitmap_set(acc, (unsigned) reg);
}

static inline void
evoasm_enc_ctx_undefined_access(evoasm_buf_ref_t *enc_ctx, evoasm_bitmap_t *acc, evoasm_reg_id_t reg) {
  evoasm_bitmap_unset(acc, (unsigned) reg);
}

static inline evoasm_success_t
_evoasm_enc_ctx_read_access(evoasm_buf_ref_t *enc_ctx, evoasm_bitmap_t *acc, evoasm_reg_id_t reg,
                             evoasm_inst_id_t inst, const char *file, unsigned line) {
  if(!evoasm_bitmap_get(acc, (unsigned) reg)) {
    evoasm_enc_error_data_t error_data = {
      .reg = (uint8_t) reg,
      .inst = (uint16_t) inst,
      .arch = enc_ctx
    };
    evoasm_set_error(EVOASM_ERROR_TYPE_ENC, EVOASM_ENC_ERROR_CODE_INVALID_ACCESS, &error_data, file, line, "read access violation");
    return false;
  }
  return true;
}
#define evoasm_arch_read_access(arch, acc, reg, inst) _evoasm_arch_read_access(arch, acc, reg, inst, __FILE__, __LINE__)
#endif

