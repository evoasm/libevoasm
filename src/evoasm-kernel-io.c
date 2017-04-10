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

#include "evoasm-alloc.h"
#include "evoasm-kernel-io.h"
#include <stdarg.h>

static const char *const _evoasm_example_type_names[] = {
    "i64",
    "u64",
    "f64"
};

evoasm_kernel_io_t *
evoasm_kernel_io_alloc(size_t len) {
  evoasm_kernel_io_t *kernel_io = evoasm_malloc(sizeof(evoasm_kernel_io_t) + len * sizeof(evoasm_kernel_io_val_t));
  kernel_io->len = (uint16_t) len;

  return kernel_io;
}

evoasm_success_t
evoasm_kernel_io_init(evoasm_kernel_io_t *kernel_io, size_t arity, ...) {
  va_list args;
  bool retval = true;

  if(arity > EVOASM_PROGRAM_IO_MAX_ARITY) {
    evoasm_error(EVOASM_ERROR_TYPE_PROGRAM, EVOASM_ERROR_CODE_NONE,
                 "Maximum arity exceeded (%zu > %d)", arity, EVOASM_PROGRAM_IO_MAX_ARITY);
    retval = false;
    goto done;
  }

  kernel_io->arity = (uint8_t) arity;

  va_start(args, arity);
  for(size_t i = 0; i < kernel_io->len; i++) {
    size_t type_idx = i % arity;
    evoasm_kernel_io_val_type_t type = va_arg(args, evoasm_kernel_io_val_type_t);
    evoasm_kernel_io_val_t val;
    switch(type) {
      case EVOASM_KERNEL_IO_VAL_TYPE_F64:
        val.f64 = va_arg(args, double);
        break;
      case EVOASM_KERNEL_IO_VAL_TYPE_I64:
        val.i64 = va_arg(args, int64_t);
        break;
      case EVOASM_KERNEL_IO_VAL_TYPE_U64:
        val.u64 = va_arg(args, uint64_t);
        break;
      default:
        evoasm_assert_not_reached();
    }

    kernel_io->vals[i] = val;

    if(i >= arity) {
      evoasm_kernel_io_val_type_t prev_type = kernel_io->types[type_idx];

      if(prev_type != type) {
        evoasm_error(EVOASM_ERROR_TYPE_PROGRAM, EVOASM_ERROR_CODE_NONE,
                     "Example value type mismatch (previously %s, now %s)",
                     _evoasm_example_type_names[prev_type], _evoasm_example_type_names[type]);
        retval = false;
        goto done;
      }
    }
    kernel_io->types[type_idx] = type;
  }


done:
  va_end(args);
  return retval;
}

double
evoasm_kernel_io_get_value_f64(evoasm_kernel_io_t *kernel_io, size_t idx) {
  return kernel_io->vals[idx].f64;
}

int64_t
evoasm_kernel_io_get_value_i64(evoasm_kernel_io_t *kernel_io, size_t idx) {
  return kernel_io->vals[idx].i64;
}

void
evoasm_kernel_io_destroy(evoasm_kernel_io_t *kernel_io) {

}

evoasm_kernel_io_val_type_t
evoasm_kernel_io_get_type(evoasm_kernel_io_t *kernel_io, size_t idx) {
  return kernel_io->types[idx % kernel_io->arity];
}

EVOASM_DEF_FREE_FUNC(kernel_io)

EVOASM_DEF_GETTER(kernel_io, arity, size_t)

EVOASM_DEF_GETTER(kernel_io, len, size_t)

