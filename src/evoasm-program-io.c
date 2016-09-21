/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-alloc.h"
#include "evoasm-program-io.h"
#include <stdarg.h>

static const char * const _evoasm_example_type_names[] = {
    "i64",
    "u64",
    "f64"
};

evoasm_program_io_t *
evoasm_program_io_alloc(uint16_t len) {
  evoasm_program_io_t *program_io = evoasm_malloc(sizeof(evoasm_program_io_t) + len * sizeof(evoasm_program_io_val_t));
  program_io->len = len;

  return program_io;
}

evoasm_success_t
evoasm_program_io_init(evoasm_program_io_t *program_io, uint8_t arity, ...) {
  va_list args;
  unsigned i;
  bool retval = true;
  program_io->arity = arity;

  va_start(args, arity);
  for(i = 0; i < program_io->len; i++) {
    unsigned type_idx = i % arity;
    evoasm_program_io_val_type_t type = va_arg(args, evoasm_program_io_val_type_t);
    evoasm_program_io_val_t val;
    switch(type) {
      case EVOASM_PROGRAM_IO_VAL_TYPE_F64:
        val.f64 = va_arg(args, double);
        break;
      case EVOASM_PROGRAM_IO_VAL_TYPE_I64:
        val.i64 = va_arg(args, int64_t);
        break;
      case EVOASM_PROGRAM_IO_VAL_TYPE_U64:
        val.u64 = va_arg(args, uint64_t);
        break;
      default:
        evoasm_assert_not_reached();
    }

    program_io->vals[i] = val;

    if(i >= arity) {
      evoasm_program_io_val_type_t prev_type = program_io->types[type_idx];

      if(prev_type != type) {
        evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                         NULL, "Example value type mismatch (previously %s, now %s)",
                         _evoasm_example_type_names[prev_type], _evoasm_example_type_names[type]);
        evoasm_free(program_io);
        retval = false;
        goto done;
      }
    }
    program_io->types[type_idx] = type;
  }


done:
  va_end(args);
  return retval;
}

double
evoasm_program_io_value_f64(evoasm_program_io_t *program_io, unsigned idx) {
  return program_io->vals[idx].f64;
}

int64_t
evoasm_program_io_value_i64(evoasm_program_io_t *program_io, unsigned idx) {
  return program_io->vals[idx].i64;
}

void
evoasm_program_io_destroy(evoasm_program_io_t *program_io) {

}

evoasm_program_io_val_type_t
evoasm_program_io_type(evoasm_program_io_t *program_io, unsigned idx) {
  return program_io->types[idx % program_io->arity];
}

_EVOASM_DEF_FREE_FUNC(program_io)

_EVOASM_DEF_FIELD_READER(program_io, arity, uint8_t)
_EVOASM_DEF_FIELD_READER(program_io, len, uint16_t)

