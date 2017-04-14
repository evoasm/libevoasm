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


EVOASM_DEF_ALLOC_FREE_FUNCS(kernel_io)


evoasm_success_t
evoasm_kernel_io_init(evoasm_kernel_io_t *kernel_io, size_t arity, evoasm_kernel_io_val_type_t *types) {
  static evoasm_kernel_io_t zero_kernel_io = {0};
  *kernel_io = zero_kernel_io;

  if(arity > EVOASM_PROGRAM_IO_MAX_ARITY) {
    evoasm_error(EVOASM_ERROR_TYPE_KERNEL, EVOASM_ERROR_CODE_NONE,
                 "Maximum arity exceeded (%zu > %d)", arity, EVOASM_PROGRAM_IO_MAX_ARITY);
    goto error;
  }

  kernel_io->arity = (uint8_t) arity;

  for(size_t i = 0; i < arity; i++) {
    kernel_io->types[i] = types[i];
  }

  size_t n_vals = evoasm_kernel_io_get_n_vals(kernel_io);

  EVOASM_TRY_ALLOC_N(error, calloc, kernel_io->vals, n_vals);

  return true;

error:
  return false;
}

#define EVOASM_KERNEL_IO_DEF_VAL_SETTER(type_name, c_type) \
  void \
  evoasm_kernel_io_set_val_## type_name (evoasm_kernel_io_t *kernel_io, size_t tuple_idx, size_t val_idx, size_t elem_idx, c_type val) { \
    kernel_io->vals[val_idx].type_name[elem_idx] = val; \
  }

#define EVOASM_KERNEL_IO_DEF_VAL_GETTER(type_name, c_type) \
  c_type \
  evoasm_kernel_io_get_val_## type_name (evoasm_kernel_io_t *kernel_io, size_t tuple_idx, size_t val_idx, size_t elem_idx) { \
    return kernel_io->vals[val_idx].type_name[elem_idx]; \
  }

#define EVOASM_KERNEL_IO_DEF_VAL_GETTER_SETTER(type_name, c_type) \
  EVOASM_KERNEL_IO_DEF_VAL_SETTER(type_name, c_type) \
  EVOASM_KERNEL_IO_DEF_VAL_GETTER(type_name, c_type) \


EVOASM_KERNEL_IO_DEF_VAL_GETTER_SETTER(f32, float)

EVOASM_KERNEL_IO_DEF_VAL_GETTER_SETTER(f64, double)

EVOASM_KERNEL_IO_DEF_VAL_GETTER_SETTER(i64, int64_t)

EVOASM_KERNEL_IO_DEF_VAL_GETTER_SETTER(u64, uint64_t)

void
evoasm_kernel_io_destroy(evoasm_kernel_io_t *kernel_io) {
  evoasm_free(kernel_io->vals);
}

evoasm_kernel_io_val_type_t
evoasm_kernel_io_get_type(evoasm_kernel_io_t *kernel_io, size_t arg_idx) {
  return evoasm_kernel_io_get_type_(kernel_io, arg_idx);
}

size_t
evoasm_kernel_io_val_type_get_len(evoasm_kernel_io_val_type_t io_val_type) {
  switch(io_val_type) {
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X1:
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X2:
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64x4:
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X8:
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X16:
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X16:
      return 16;
    default:
      evoasm_assert_not_reached();
  }
}

evoasm_kernel_io_val_type_t
evoasm_kernel_io_val_type_get_elem_type(evoasm_kernel_io_val_type_t io_val_type) {
  switch(io_val_type) {

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X1:
      return io_val_type;

    case EVOASM_KERNEL_IO_VAL_TYPE_I64X2:
      return EVOASM_KERNEL_IO_VAL_TYPE_I64X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_U64X2:
      return EVOASM_KERNEL_IO_VAL_TYPE_U64X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_F64X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64x4:
      return EVOASM_KERNEL_IO_VAL_TYPE_F64X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_I32X4:
      return EVOASM_KERNEL_IO_VAL_TYPE_I32X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_U32X4:
      return EVOASM_KERNEL_IO_VAL_TYPE_U32X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_F32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X8:
      return EVOASM_KERNEL_IO_VAL_TYPE_F32X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_I16X8:
      return EVOASM_KERNEL_IO_VAL_TYPE_I16X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_U16X8:
      return EVOASM_KERNEL_IO_VAL_TYPE_U16X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_I8X16:
      return EVOASM_KERNEL_IO_VAL_TYPE_I8X1;

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X16:
      return EVOASM_KERNEL_IO_VAL_TYPE_U8X1;

     default:
      evoasm_assert_not_reached();
  }
}

EVOASM_DEF_GETTER(kernel_io, arity, size_t)

