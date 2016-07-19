#pragma once

#include <stdint.h>

#include "evoasm-error.h"
#include "evoasm-param.h"
#include "evoasm-buf.h"
#include "evoasm-log.h"

#define EVOASM_ARCH_BUF_CAPA 32
#define EVOASM_ARCH_MAX_PARAMS 64

typedef uint8_t evoasm_reg_id_t;
#define EVOASM_REG_ID_MAX UINT8_MAX
typedef uint16_t evoasm_inst_id_t;

typedef enum {
  EVOASM_OPERAND_SIZE_1,
  EVOASM_OPERAND_SIZE_8,
  EVOASM_OPERAND_SIZE_16,
  EVOASM_OPERAND_SIZE_32,
  EVOASM_OPERAND_SIZE_64,
  EVOASM_OPERAND_SIZE_128,
  EVOASM_OPERAND_SIZE_256,
  EVOASM_OPERAND_SIZE_512,
  EVOASM_N_OPERAND_SIZES,
} evoasm_operand_size_t;

#define EVOASM_OPERAND_SIZE_BITSIZE 3
#define EVOASM_OPERAND_SIZE_BITSIZE_WITH_N 4

struct evoasm_arch;
struct evoasm_inst;

typedef enum {
  EVOASM_ARCH_INSTS_FLAG_SEARCH = (1 << 0),
} evoasm_arch_insts_flags_t;
#define EVOASM_N_INSTS_FLAGS 1

typedef uint16_t (*evoasm_arch_insts_func_t)(struct evoasm_arch *arch, evoasm_inst_id_t *insts, evoasm_arch_insts_flags_t flags);
typedef evoasm_success_t (*evoasm_arch_enc_func_t)(struct evoasm_arch *arch, evoasm_inst_id_t inst, evoasm_arch_param_val_t *param_vals, evoasm_bitmap_t *set_params);

typedef enum {
  EVOASM_ARCH_X64
} evoasm_arch_id_t;

typedef struct {
  evoasm_arch_id_t id : 8;
  uint16_t n_insts;
  uint8_t n_params;
  uint8_t max_inst_len;
} evoasm_arch_cls_t;

typedef enum {
  EVOASM_ARCH_ERROR_CODE_NOT_ENCODABLE = EVOASM_N_ERROR_CODES,
  EVOASM_ARCH_ERROR_CODE_MISSING_PARAM,
  EVOASM_ARCH_ERROR_CODE_INVALID_ACCESS,
  EVOASM_ARCH_ERROR_CODE_MISSING_FEATURE,
} evoasm_arch_error_code_t;

struct evoasm_arch_t;

typedef struct {
  struct evoasm_arch *arch;
  uint8_t reg;
  uint8_t param;
  uint16_t inst;
} evoasm_arch_error_data_t;

_Static_assert(sizeof(evoasm_error_data_t) >= sizeof(evoasm_arch_error_data_t), "evoasm_arch_error_data_t exceeds evoasm_error_data_t size limit");

typedef struct {
  EVOASM_ERROR_HEADER
  evoasm_arch_error_data_t data;
} evoasm_arch_error_t;

typedef struct evoasm_arch {
  evoasm_arch_cls_t *cls;
  uint8_t buf_end;
  uint8_t buf_start;
  uint8_t buf[EVOASM_ARCH_BUF_CAPA];
  void *user_data;
  /* must have a bit for every
   * writable register    */
  evoasm_bitmap128_t acc;
} evoasm_arch_t;

#define EVOASM_INST_HEADER \
  evoasm_inst_id_t id; \
  uint16_t params_len; \
  evoasm_arch_param_t *params; \

void
evoasm_arch_reset(evoasm_arch_t *arch);

void
evoasm_arch_init(evoasm_arch_t *arch, evoasm_arch_cls_t *cls);

void
evoasm_arch_destroy(evoasm_arch_t *arch);

size_t
evoasm_arch_save(evoasm_arch_t *arch, evoasm_buf_t *buf);

static inline void
evoasm_arch_write8(evoasm_arch_t *arch, int64_t datum) {
  uint8_t new_end = (uint8_t)(arch->buf_end + 1);
  *((uint8_t *)(arch->buf + arch->buf_end)) = (uint8_t) datum;
  arch->buf_end = new_end;
}

static inline void
evoasm_arch_write16(evoasm_arch_t *arch, int64_t datum) {
  uint8_t new_end = (uint8_t)(arch->buf_end + 2);
  *((int16_t *)(arch->buf + arch->buf_end)) = (int16_t) datum;
  arch->buf_end = new_end;
}

static inline void
evoasm_arch_write32(evoasm_arch_t *arch, int64_t datum) {
  uint8_t new_end = (uint8_t)(arch->buf_end + 4);
  *((int32_t *)(arch->buf + arch->buf_end)) = (int32_t) datum;
  arch->buf_end = new_end;
}

static inline void
evoasm_arch_write64(evoasm_arch_t *arch, int64_t datum) {
  uint8_t new_end = (uint8_t)(arch->buf_end + 8);
  *((int64_t *)(arch->buf + arch->buf_end)) = (int64_t) datum;
  arch->buf_end = new_end;
}

static inline void
evoasm_arch_write_access(evoasm_arch_t *arch, evoasm_bitmap_t *acc, evoasm_reg_id_t reg) {
  evoasm_bitmap_set(acc, (unsigned) reg);
}

static inline void
evoasm_arch_undefined_access(evoasm_arch_t *arch, evoasm_bitmap_t *acc, evoasm_reg_id_t reg) {
  evoasm_bitmap_unset(acc, (unsigned) reg);
}

static inline evoasm_success_t
_evoasm_arch_read_access(evoasm_arch_t *arch, evoasm_bitmap_t *acc, evoasm_reg_id_t reg, evoasm_inst_id_t inst, const char *file, unsigned line) {
  if(!evoasm_bitmap_get(acc, (unsigned) reg)) {
    evoasm_arch_error_data_t error_data = {
      .reg = (uint8_t) reg,
      .inst = (uint16_t) inst,
      .arch = arch
    };
    evoasm_set_error(EVOASM_ERROR_TYPE_ARCH, EVOASM_ARCH_ERROR_CODE_INVALID_ACCESS, &error_data, file, line, "read access violation");
    return false;
  }
  return true;
}

#define evoasm_arch_read_access(arch, acc, reg, inst) _evoasm_arch_read_access(arch, acc, reg, inst, __FILE__, __LINE__)
