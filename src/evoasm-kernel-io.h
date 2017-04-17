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

#define EVOASM_PROGRAM_IO_MAX_ARITY 8

typedef enum {
  EVOASM_KERNEL_IO_VAL_TYPE_U8X1,
  EVOASM_KERNEL_IO_VAL_TYPE_I8X1,
  EVOASM_KERNEL_IO_VAL_TYPE_U8X2,
  EVOASM_KERNEL_IO_VAL_TYPE_I8X2,
  EVOASM_KERNEL_IO_VAL_TYPE_U8X4,
  EVOASM_KERNEL_IO_VAL_TYPE_I8X4,
  EVOASM_KERNEL_IO_VAL_TYPE_U8X8,
  EVOASM_KERNEL_IO_VAL_TYPE_I8X8,
  EVOASM_KERNEL_IO_VAL_TYPE_I8X16,
  EVOASM_KERNEL_IO_VAL_TYPE_U8X16,
  EVOASM_KERNEL_IO_VAL_TYPE_I8X32,
  EVOASM_KERNEL_IO_VAL_TYPE_U8X32,

  EVOASM_KERNEL_IO_VAL_TYPE_U16X1,
  EVOASM_KERNEL_IO_VAL_TYPE_I16X1,
  EVOASM_KERNEL_IO_VAL_TYPE_U16X2,
  EVOASM_KERNEL_IO_VAL_TYPE_I16X2,
  EVOASM_KERNEL_IO_VAL_TYPE_U16X4,
  EVOASM_KERNEL_IO_VAL_TYPE_I16X4,
  EVOASM_KERNEL_IO_VAL_TYPE_U16X8,
  EVOASM_KERNEL_IO_VAL_TYPE_I16X8,
  EVOASM_KERNEL_IO_VAL_TYPE_U16X16,
  EVOASM_KERNEL_IO_VAL_TYPE_I16X16,

  EVOASM_KERNEL_IO_VAL_TYPE_U32X1,
  EVOASM_KERNEL_IO_VAL_TYPE_I32X1,
  EVOASM_KERNEL_IO_VAL_TYPE_U32X2,
  EVOASM_KERNEL_IO_VAL_TYPE_I32X2,
  EVOASM_KERNEL_IO_VAL_TYPE_U32X4,
  EVOASM_KERNEL_IO_VAL_TYPE_I32X4,
  EVOASM_KERNEL_IO_VAL_TYPE_U32X8,
  EVOASM_KERNEL_IO_VAL_TYPE_I32X8,

  EVOASM_KERNEL_IO_VAL_TYPE_I64X1,
  EVOASM_KERNEL_IO_VAL_TYPE_U64X1,
  EVOASM_KERNEL_IO_VAL_TYPE_I64X2,
  EVOASM_KERNEL_IO_VAL_TYPE_U64X2,
  EVOASM_KERNEL_IO_VAL_TYPE_I64X4,
  EVOASM_KERNEL_IO_VAL_TYPE_U64X4,

  EVOASM_KERNEL_IO_VAL_TYPE_F32X1,
  EVOASM_KERNEL_IO_VAL_TYPE_F32X2,
  EVOASM_KERNEL_IO_VAL_TYPE_F32X4,
  EVOASM_KERNEL_IO_VAL_TYPE_F32X8,

  EVOASM_KERNEL_IO_VAL_TYPE_F64X1,
  EVOASM_KERNEL_IO_VAL_TYPE_F64X2,
  EVOASM_KERNEL_IO_VAL_TYPE_F64X4,

  EVOASM_KERNEL_IO_VAL_TYPE_NONE,
} evoasm_kernel_io_val_type_t;



typedef union {
  int64_t i64[2];
  uint64_t u64[2];
  int32_t i32[4];
  uint32_t u32[4];
  int16_t i16[8];
  int16_t u16[8];
  int8_t i8[16];
  uint8_t u8[16];
  double f64[4];
  float f32[8];
} evoasm_kernel_io_val_t;

typedef struct {
  uint16_t n_tuples;
  uint8_t arity;
  uint8_t types[EVOASM_PROGRAM_IO_MAX_ARITY];
  evoasm_kernel_io_val_t *vals;
} evoasm_kernel_io_t;

#define EVOASM_KERNEL_OUTPUT_MAX_ARITY EVOASM_PROGRAM_IO_MAX_ARITY
#define EVOASM_KERNEL_INPUT_MAX_ARITY EVOASM_PROGRAM_IO_MAX_ARITY

typedef evoasm_kernel_io_t evoasm_kernel_output_t;
typedef evoasm_kernel_io_t evoasm_kernel_input_t;

evoasm_success_t
evoasm_kernel_io_init(evoasm_kernel_io_t *kernel_io, size_t arity, size_t n_tuples, evoasm_kernel_io_val_type_t *types);

static inline size_t
evoasm_kernel_io_get_n_tuples_(evoasm_kernel_io_t *kernel_io) {
  return kernel_io->n_tuples;
}

static inline size_t
evoasm_kernel_io_get_n_vals_(evoasm_kernel_io_t *kernel_io) {
  return (size_t)(kernel_io->n_tuples * kernel_io->arity);
}

static inline evoasm_kernel_io_val_t *
evoasm_kernel_io_get_val_(evoasm_kernel_io_t *kernel_io, size_t tuple_idx, size_t val_idx) {
  return &kernel_io->vals[tuple_idx * kernel_io->arity + val_idx];
}

static inline evoasm_kernel_io_val_type_t
evoasm_kernel_io_get_type_(evoasm_kernel_io_t *kernel_io, size_t idx) {
  return (evoasm_kernel_io_val_type_t) kernel_io->types[idx];
}

#define evoasm_kernel_input_get_n_tuples evoasm_kernel_io_get_n_tuples_
#define evoasm_kernel_output_get_n_tuples evoasm_kernel_io_get_n_tuples_


EVOASM_DECL_ALLOC_FREE_FUNCS(kernel_io)


void
evoasm_kernel_io_destroy(evoasm_kernel_io_t *kernel_io);

#define evoasm_kernel_output_destroy(program_output) \
  evoasm_kernel_io_destroy((evoasm_kernel_io *)program_output)

static inline size_t
evoasm_kernel_io_val_type_get_bytesize(evoasm_kernel_io_val_type_t io_val_type) {
  switch(io_val_type) {
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X1: return 1;

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X1: return 2;

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X1: return 4;

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X1:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X1: return 8;

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X16:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X16:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X2:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X2: return 16;

    case EVOASM_KERNEL_IO_VAL_TYPE_U8X32:
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X32:
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X16:
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X16:
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X4:
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X8:
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X4: return 32;

    default: evoasm_assert_not_reached();
  }
}

const char *
evoasm_kernel_io_val_type_get_name(evoasm_kernel_io_val_type_t io_val_type);

static inline size_t
evoasm_kernel_io_val_to_dbl(evoasm_kernel_io_val_t *io_val, evoasm_kernel_io_val_type_t io_val_type, double *dbls) {
  switch(io_val_type) {
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X1:
      dbls[0] = (double) io_val->u8[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X1:
      dbls[0] = (double) io_val->i8[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X2:
      dbls[0] = (double) io_val->u8[0];
      dbls[1] = (double) io_val->u8[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X2:
      dbls[0] = (double) io_val->i8[0];
      dbls[1] = (double) io_val->i8[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X4:
      dbls[0] = (double) io_val->u8[0];
      dbls[1] = (double) io_val->u8[1];
      dbls[2] = (double) io_val->u8[2];
      dbls[3] = (double) io_val->u8[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X4:
      dbls[0] = (double) io_val->i8[0];
      dbls[1] = (double) io_val->i8[1];
      dbls[2] = (double) io_val->i8[2];
      dbls[3] = (double) io_val->i8[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X8:
      dbls[0] = (double) io_val->u8[0];
      dbls[1] = (double) io_val->u8[1];
      dbls[2] = (double) io_val->u8[2];
      dbls[3] = (double) io_val->u8[3];
      dbls[4] = (double) io_val->u8[4];
      dbls[5] = (double) io_val->u8[5];
      dbls[6] = (double) io_val->u8[6];
      dbls[7] = (double) io_val->u8[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X8:
      dbls[0] = (double) io_val->i8[0];
      dbls[1] = (double) io_val->i8[1];
      dbls[2] = (double) io_val->i8[2];
      dbls[3] = (double) io_val->i8[3];
      dbls[4] = (double) io_val->i8[4];
      dbls[5] = (double) io_val->i8[5];
      dbls[6] = (double) io_val->i8[6];
      dbls[7] = (double) io_val->i8[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X16:
      dbls[0] = (double) io_val->i8[0];
      dbls[1] = (double) io_val->i8[1];
      dbls[2] = (double) io_val->i8[2];
      dbls[3] = (double) io_val->i8[3];
      dbls[4] = (double) io_val->i8[4];
      dbls[5] = (double) io_val->i8[5];
      dbls[6] = (double) io_val->i8[6];
      dbls[7] = (double) io_val->i8[7];
      dbls[8] = (double) io_val->i8[8];
      dbls[9] = (double) io_val->i8[9];
      dbls[10] = (double) io_val->i8[10];
      dbls[11] = (double) io_val->i8[11];
      dbls[12] = (double) io_val->i8[12];
      dbls[13] = (double) io_val->i8[13];
      dbls[14] = (double) io_val->i8[14];
      dbls[15] = (double) io_val->i8[15];
      return 16;
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X16:
      dbls[0] = (double) io_val->u8[0];
      dbls[1] = (double) io_val->u8[1];
      dbls[2] = (double) io_val->u8[2];
      dbls[3] = (double) io_val->u8[3];
      dbls[4] = (double) io_val->u8[4];
      dbls[5] = (double) io_val->u8[5];
      dbls[6] = (double) io_val->u8[6];
      dbls[7] = (double) io_val->u8[7];
      dbls[8] = (double) io_val->u8[8];
      dbls[9] = (double) io_val->u8[9];
      dbls[10] = (double) io_val->u8[10];
      dbls[11] = (double) io_val->u8[11];
      dbls[12] = (double) io_val->u8[12];
      dbls[13] = (double) io_val->u8[13];
      dbls[14] = (double) io_val->u8[14];
      dbls[15] = (double) io_val->u8[15];
      return 16;
    case EVOASM_KERNEL_IO_VAL_TYPE_I8X32:
      dbls[0] = (double) io_val->i8[0];
      dbls[1] = (double) io_val->i8[1];
      dbls[2] = (double) io_val->i8[2];
      dbls[3] = (double) io_val->i8[3];
      dbls[4] = (double) io_val->i8[4];
      dbls[5] = (double) io_val->i8[5];
      dbls[6] = (double) io_val->i8[6];
      dbls[7] = (double) io_val->i8[7];
      dbls[8] = (double) io_val->i8[8];
      dbls[9] = (double) io_val->i8[9];
      dbls[10] = (double) io_val->i8[10];
      dbls[11] = (double) io_val->i8[11];
      dbls[12] = (double) io_val->i8[12];
      dbls[13] = (double) io_val->i8[13];
      dbls[14] = (double) io_val->i8[14];
      dbls[15] = (double) io_val->i8[15];
      dbls[16] = (double) io_val->i8[16];
      dbls[17] = (double) io_val->i8[17];
      dbls[18] = (double) io_val->i8[18];
      dbls[19] = (double) io_val->i8[19];
      dbls[20] = (double) io_val->i8[20];
      dbls[21] = (double) io_val->i8[21];
      dbls[22] = (double) io_val->i8[22];
      dbls[23] = (double) io_val->i8[23];
      dbls[24] = (double) io_val->i8[24];
      dbls[25] = (double) io_val->i8[25];
      dbls[26] = (double) io_val->i8[26];
      dbls[27] = (double) io_val->i8[27];
      dbls[28] = (double) io_val->i8[28];
      dbls[29] = (double) io_val->i8[29];
      dbls[30] = (double) io_val->i8[30];
      dbls[31] = (double) io_val->i8[31];
      return 32;
    case EVOASM_KERNEL_IO_VAL_TYPE_U8X32:
      dbls[0] = (double) io_val->u8[0];
      dbls[1] = (double) io_val->u8[1];
      dbls[2] = (double) io_val->u8[2];
      dbls[3] = (double) io_val->u8[3];
      dbls[4] = (double) io_val->u8[4];
      dbls[5] = (double) io_val->u8[5];
      dbls[6] = (double) io_val->u8[6];
      dbls[7] = (double) io_val->u8[7];
      dbls[8] = (double) io_val->u8[8];
      dbls[9] = (double) io_val->u8[9];
      dbls[10] = (double) io_val->u8[10];
      dbls[11] = (double) io_val->u8[11];
      dbls[12] = (double) io_val->u8[12];
      dbls[13] = (double) io_val->u8[13];
      dbls[14] = (double) io_val->u8[14];
      dbls[15] = (double) io_val->u8[15];
      dbls[16] = (double) io_val->u8[16];
      dbls[17] = (double) io_val->u8[17];
      dbls[18] = (double) io_val->u8[18];
      dbls[19] = (double) io_val->u8[19];
      dbls[20] = (double) io_val->u8[20];
      dbls[21] = (double) io_val->u8[21];
      dbls[22] = (double) io_val->u8[22];
      dbls[23] = (double) io_val->u8[23];
      dbls[24] = (double) io_val->u8[24];
      dbls[25] = (double) io_val->u8[25];
      dbls[26] = (double) io_val->u8[26];
      dbls[27] = (double) io_val->u8[27];
      dbls[28] = (double) io_val->u8[28];
      dbls[29] = (double) io_val->u8[29];
      dbls[30] = (double) io_val->u8[30];
      dbls[31] = (double) io_val->u8[31];
      return 32;
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X1:
      dbls[0] = (double) io_val->u16[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X1:
      dbls[0] = (double) io_val->i16[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X2:
      dbls[0] = (double) io_val->u16[0];
      dbls[1] = (double) io_val->u16[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X2:
      dbls[0] = (double) io_val->i16[0];
      dbls[1] = (double) io_val->i16[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X4:
      dbls[0] = (double) io_val->u16[0];
      dbls[1] = (double) io_val->u16[1];
      dbls[2] = (double) io_val->u16[2];
      dbls[3] = (double) io_val->u16[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X4:
      dbls[0] = (double) io_val->i16[0];
      dbls[1] = (double) io_val->i16[1];
      dbls[2] = (double) io_val->i16[2];
      dbls[3] = (double) io_val->i16[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X8:
      dbls[0] = (double) io_val->u16[0];
      dbls[1] = (double) io_val->u16[1];
      dbls[2] = (double) io_val->u16[2];
      dbls[3] = (double) io_val->u16[3];
      dbls[4] = (double) io_val->u16[4];
      dbls[5] = (double) io_val->u16[5];
      dbls[6] = (double) io_val->u16[6];
      dbls[7] = (double) io_val->u16[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X8:
      dbls[0] = (double) io_val->i16[0];
      dbls[1] = (double) io_val->i16[1];
      dbls[2] = (double) io_val->i16[2];
      dbls[3] = (double) io_val->i16[3];
      dbls[4] = (double) io_val->i16[4];
      dbls[5] = (double) io_val->i16[5];
      dbls[6] = (double) io_val->i16[6];
      dbls[7] = (double) io_val->i16[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_U16X16:
      dbls[0] = (double) io_val->u16[0];
      dbls[1] = (double) io_val->u16[1];
      dbls[2] = (double) io_val->u16[2];
      dbls[3] = (double) io_val->u16[3];
      dbls[4] = (double) io_val->u16[4];
      dbls[5] = (double) io_val->u16[5];
      dbls[6] = (double) io_val->u16[6];
      dbls[7] = (double) io_val->u16[7];
      dbls[8] = (double) io_val->u16[8];
      dbls[9] = (double) io_val->u16[9];
      dbls[10] = (double) io_val->u16[10];
      dbls[11] = (double) io_val->u16[11];
      dbls[12] = (double) io_val->u16[12];
      dbls[13] = (double) io_val->u16[13];
      dbls[14] = (double) io_val->u16[14];
      dbls[15] = (double) io_val->u16[15];
      return 16;
    case EVOASM_KERNEL_IO_VAL_TYPE_I16X16:
      dbls[0] = (double) io_val->i16[0];
      dbls[1] = (double) io_val->i16[1];
      dbls[2] = (double) io_val->i16[2];
      dbls[3] = (double) io_val->i16[3];
      dbls[4] = (double) io_val->i16[4];
      dbls[5] = (double) io_val->i16[5];
      dbls[6] = (double) io_val->i16[6];
      dbls[7] = (double) io_val->i16[7];
      dbls[8] = (double) io_val->i16[8];
      dbls[9] = (double) io_val->i16[9];
      dbls[10] = (double) io_val->i16[10];
      dbls[11] = (double) io_val->i16[11];
      dbls[12] = (double) io_val->i16[12];
      dbls[13] = (double) io_val->i16[13];
      dbls[14] = (double) io_val->i16[14];
      dbls[15] = (double) io_val->i16[15];
      return 16;
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X1:
      dbls[0] = (double) io_val->u32[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X1:
      dbls[0] = (double) io_val->i32[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X2:
      dbls[0] = (double) io_val->u32[0];
      dbls[1] = (double) io_val->u32[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X2:
      dbls[0] = (double) io_val->i32[0];
      dbls[1] = (double) io_val->i32[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X4:
      dbls[0] = (double) io_val->u32[0];
      dbls[1] = (double) io_val->u32[1];
      dbls[2] = (double) io_val->u32[2];
      dbls[3] = (double) io_val->u32[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X4:
      dbls[0] = (double) io_val->i32[0];
      dbls[1] = (double) io_val->i32[1];
      dbls[2] = (double) io_val->i32[2];
      dbls[3] = (double) io_val->i32[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_U32X8:
      dbls[0] = (double) io_val->u32[0];
      dbls[1] = (double) io_val->u32[1];
      dbls[2] = (double) io_val->u32[2];
      dbls[3] = (double) io_val->u32[3];
      dbls[4] = (double) io_val->u32[4];
      dbls[5] = (double) io_val->u32[5];
      dbls[6] = (double) io_val->u32[6];
      dbls[7] = (double) io_val->u32[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_I32X8:
      dbls[0] = (double) io_val->i32[0];
      dbls[1] = (double) io_val->i32[1];
      dbls[2] = (double) io_val->i32[2];
      dbls[3] = (double) io_val->i32[3];
      dbls[4] = (double) io_val->i32[4];
      dbls[5] = (double) io_val->i32[5];
      dbls[6] = (double) io_val->i32[6];
      dbls[7] = (double) io_val->i32[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X1:
      dbls[0] = (double) io_val->i64[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X1:
      dbls[0] = (double) io_val->u64[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X2:
      dbls[0] = (double) io_val->i64[0];
      dbls[1] = (double) io_val->i64[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X2:
      dbls[0] = (double) io_val->u64[0];
      dbls[1] = (double) io_val->u64[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_I64X4:
      dbls[0] = (double) io_val->i64[0];
      dbls[1] = (double) io_val->i64[1];
      dbls[2] = (double) io_val->i64[2];
      dbls[3] = (double) io_val->i64[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_U64X4:
      dbls[0] = (double) io_val->u64[0];
      dbls[1] = (double) io_val->u64[1];
      dbls[2] = (double) io_val->u64[2];
      dbls[3] = (double) io_val->u64[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X1:
      dbls[0] = (double) io_val->f32[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X2:
      dbls[0] = (double) io_val->f32[0];
      dbls[1] = (double) io_val->f32[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X4:
      dbls[0] = (double) io_val->f32[0];
      dbls[1] = (double) io_val->f32[1];
      dbls[2] = (double) io_val->f32[2];
      dbls[3] = (double) io_val->f32[3];
      return 4;
    case EVOASM_KERNEL_IO_VAL_TYPE_F32X8:
      dbls[0] = (double) io_val->f32[0];
      dbls[1] = (double) io_val->f32[1];
      dbls[2] = (double) io_val->f32[2];
      dbls[3] = (double) io_val->f32[3];
      dbls[4] = (double) io_val->f32[4];
      dbls[5] = (double) io_val->f32[5];
      dbls[6] = (double) io_val->f32[6];
      dbls[7] = (double) io_val->f32[7];
      return 8;
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X1:
      dbls[0] = (double) io_val->f64[0];
      return 1;
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X2:
      dbls[0] = (double) io_val->f64[0];
      dbls[1] = (double) io_val->f64[1];
      return 2;
    case EVOASM_KERNEL_IO_VAL_TYPE_F64X4:
      dbls[0] = (double) io_val->f64[0];
      dbls[1] = (double) io_val->f64[1];
      dbls[2] = (double) io_val->f64[2];
      dbls[3] = (double) io_val->f64[3];
      return 4;
    default:
      evoasm_assert_not_reached();
  }
}
