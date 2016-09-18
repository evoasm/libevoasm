/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-alloc.h"
#include "evoasm-adf-io.h"
#include <stdarg.h>

static const char * const _evoasm_example_type_names[] = {
    "i64",
    "u64",
    "f64"
};

evoasm_adf_io_t *
evoasm_adf_io_alloc(uint16_t len) {
  evoasm_adf_io_t *adf_io = evoasm_malloc(sizeof(evoasm_adf_io_t) + len * sizeof(evoasm_adf_io_val_t));
  adf_io->len = len;

  return adf_io;
}

evoasm_success_t
evoasm_adf_io_init(evoasm_adf_io_t *adf_io, uint8_t arity, ...) {
  va_list args;
  unsigned i;
  bool retval = true;
  adf_io->arity = arity;

  va_start(args, arity);
  for(i = 0; i < adf_io->len; i++) {
    unsigned type_idx = i % arity;
    evoasm_adf_io_val_type_t type = va_arg(args, evoasm_adf_io_val_type_t);
    evoasm_adf_io_val_t val;
    switch(type) {
      case EVOASM_ADF_IO_VAL_TYPE_F64:
        val.f64 = va_arg(args, double);
        break;
      case EVOASM_ADF_IO_VAL_TYPE_I64:
        val.i64 = va_arg(args, int64_t);
        break;
      case EVOASM_ADF_IO_VAL_TYPE_U64:
        val.u64 = va_arg(args, uint64_t);
        break;
      default:
        evoasm_assert_not_reached();
    }

    adf_io->vals[i] = val;

    if(i >= arity) {
      evoasm_adf_io_val_type_t prev_type = adf_io->types[type_idx];

      if(prev_type != type) {
        evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                         NULL, "Example value type mismatch (previously %s, now %s)",
                         _evoasm_example_type_names[prev_type], _evoasm_example_type_names[type]);
        evoasm_free(adf_io);
        retval = false;
        goto done;
      }
    }
    adf_io->types[type_idx] = type;
  }


done:
  va_end(args);
  return retval;
}

double
evoasm_adf_io_value_f64(evoasm_adf_io_t *adf_io, unsigned idx) {
  return adf_io->vals[idx].f64;
}

int64_t
evoasm_adf_io_value_i64(evoasm_adf_io_t *adf_io, unsigned idx) {
  return adf_io->vals[idx].i64;
}

void
evoasm_adf_io_destroy(evoasm_adf_io_t *adf_io) {

}

evoasm_adf_io_val_type_t
evoasm_adf_io_type(evoasm_adf_io_t *adf_io, unsigned idx) {
  return adf_io->types[idx % adf_io->arity];
}

_EVOASM_DEF_FREE_FUNC(adf_io)

_EVOASM_DEF_FIELD_READER(adf_io, arity, uint8_t)
_EVOASM_DEF_FIELD_READER(adf_io, len, uint16_t)

