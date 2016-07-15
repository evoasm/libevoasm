#pragma once

#include <stdint.h>
#include "evoasm-bitmap.h"
#include "evoasm-misc.h"

#define EVOASM_ARCH_PARAM_VAL_FORMAT PRId64
#define EVOASM_ARCH_PARAM_FORMAT PRIu32

#define _EVOASM_ARCH_PARAMS_HEADER \
  evoasm_arch_params_bitmap_t set;

typedef int64_t evoasm_arch_param_val_t;
typedef uint8_t evoasm_arch_param_id_t;
typedef evoasm_bitmap64_t evoasm_arch_params_bitmap_t;

typedef struct {
  _EVOASM_ARCH_PARAMS_HEADER
  evoasm_arch_param_val_t vals[];
} evoasm_arch_params_t;

typedef struct {
  evoasm_arch_param_id_t id;
  evoasm_domain_t *domain;
} evoasm_arch_param_t;

static inline void
evoasm_arch_params_set(evoasm_arch_param_val_t *vals, evoasm_bitmap_t *set_params, evoasm_arch_param_id_t param, evoasm_arch_param_val_t val) {
  vals[param] = val;
  evoasm_bitmap_set(set_params, param);
}

static inline void
evoasm_arch_params_unset(evoasm_arch_param_val_t *vals, evoasm_bitmap_t *set_params, evoasm_arch_param_id_t param) {
  vals[param] = 0;
  evoasm_bitmap_unset(set_params, param);
}
