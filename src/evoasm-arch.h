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

#pragma once

#include <stdint.h>
#include <gen/evoasm-x64-enums.h>

#include "evoasm-error.h"
#include "evoasm-param.h"
#include "evoasm-buf.h"
#include "evoasm-log.h"

#define EVOASM_ARCH_MAX_PARAMS 32

typedef uint8_t evoasm_reg_id_t;
#define EVOASM_REG_ID_MAX UINT8_MAX

typedef uint16_t evoasm_inst_id_t;

typedef enum {
  EVOASM_ARCH_X64,
  EVOASM_ARCH_NONE
} evoasm_arch_id_t;

typedef struct {
  uint8_t id;
  uint8_t n_params;
  uint8_t max_inst_len;
  uint16_t n_insts;
  uint64_t features;
} evoasm_arch_info_t;


typedef enum {
  EVOASM_ARCH_ERROR_CODE_NOT_ENCODABLE,
  EVOASM_ARCH_ERROR_CODE_MISSING_PARAM,
  EVOASM_ARCH_ERROR_CODE_MISSING_FEATURE,
} evoasm_arch_error_code_t;

typedef struct {
  uint8_t reg;
  uint8_t param;
  uint16_t inst;
} evoasm_enc_error_data_t;

typedef struct {
  EVOASM_ERROR_HEADER
  evoasm_enc_error_data_t data;
} evoasm_enc_error_t;

_Static_assert(sizeof(evoasm_error_data_t) >= sizeof(evoasm_enc_error_data_t), "evoasm_enc_error_data_t exceeds evoasm_error_data_t size limit");

evoasm_arch_info_t *
evoasm_get_arch_info(evoasm_arch_id_t arch_id);

evoasm_arch_id_t
evoasm_get_current_arch();

#if 0
static inline void
evoasm_enc_ctx_write_access(evoasm_buf_ref_t *arch_id, evoasm_bitmap_t *acc, evoasm_reg_id_t reg) {
  evoasm_bitmap_set(acc, (size_t) reg);
}

static inline void
evoasm_enc_ctx_undefined_access(evoasm_buf_ref_t *arch_id, evoasm_bitmap_t *acc, evoasm_reg_id_t reg) {
  evoasm_bitmap_unset(acc, (size_t) reg);
}

static inline evoasm_success_t
evoasm_enc_ctx_read_access_(evoasm_buf_ref_t *arch_id, evoasm_bitmap_t *acc, evoasm_reg_id_t reg,
                             evoasm_inst_id_t inst, const char *file, unsigned line) {
  if(!evoasm_bitmap_get(acc, (size_t) reg)) {
    evoasm_enc_error_data_t error_data = {
      .reg = (uint8_t) reg,
      .inst = (uint16_t) inst,
      .arch = arch_id
    };
    evoasm_error(EVOASM_ERROR_TYPE_ENC, EVOASM_ENC_ERROR_CODE_INVALID_ACCESS, &error_data, file, line, "read access violation");
    return false;
  }
  return true;
}
#define evoasm_arch_read_access(arch, acc, reg, inst) evoasm_arch_read_access_(arch, acc, reg, inst, __FILE__, __LINE__)
#endif

