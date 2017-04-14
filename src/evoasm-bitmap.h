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
#include <stdbool.h>
#include <stdlib.h>

#define EVOASM_BITMAP_DEF_IDX_VARS(key) \
  size_t size = sizeof(uint64_t) * 8;\
  size_t ary_idx = ((size_t) key) / size;\
  size_t bit_idx = ((size_t) key) % size;

typedef struct {
  uint64_t data[1];
} evoasm_bitmap64_t;

typedef struct {
  uint64_t data[2];
} evoasm_bitmap128_t;

typedef struct {
  uint64_t data[4];
} evoasm_bitmap256_t;

typedef struct {
  uint64_t data[8];
} evoasm_bitmap512_t;

typedef struct {
  uint64_t data[16];
} evoasm_bitmap1024_t;

typedef uint64_t evoasm_bitmap_t;

#define EVOASM_BITMAP_BYTESIZE(n_bits) (sizeof(evoasm_bitmap64_t) + EVOASM_DIV_ROUND_UP(n_bits - 64u, 64u) * sizeof(uint64_t))

static inline void
evoasm_bitmap_set(evoasm_bitmap_t *bitmap, size_t idx) {
  EVOASM_BITMAP_DEF_IDX_VARS(idx);
  bitmap[ary_idx] |= (1ull << bit_idx);
}

static inline void
evoasm_bitmap_unset(evoasm_bitmap_t *bitmap, size_t idx) {
  EVOASM_BITMAP_DEF_IDX_VARS(idx);
  /* unset values must be 0*/
  bitmap[ary_idx] &= ~(1ull << bit_idx);
}

static inline void
evoasm_bitmap_set_to(evoasm_bitmap_t *bitmap, size_t idx, bool value) {
  EVOASM_BITMAP_DEF_IDX_VARS(idx);
  bitmap[ary_idx] |= ((uint64_t)(value) << bit_idx);
  bitmap[ary_idx] &= ~((uint64_t)(!value) << bit_idx);
}

static inline bool
evoasm_bitmap_get(evoasm_bitmap_t *bitmap, size_t idx) {
  EVOASM_BITMAP_DEF_IDX_VARS(idx);
  return (bitmap[ary_idx] & (1ull << bit_idx)) != 0;
}

static inline void
evoasm_bitmap_set64(evoasm_bitmap_t *bitmap, size_t idx, uint64_t bits) {
  EVOASM_BITMAP_DEF_IDX_VARS(idx);
  (void) bit_idx;
  bitmap[ary_idx] = bits;
}

static inline void
evoasm_bitmap_or64(evoasm_bitmap_t *bitmap, size_t idx, uint64_t bits) {
  EVOASM_BITMAP_DEF_IDX_VARS(idx);
  (void) bit_idx;
  bitmap[ary_idx] |= bits;
}


#define EVOASM_BITMAP_DEF_IS_ZERO(width) \
  static inline bool evoasm_bitmap ## width ## _is_zero(evoasm_bitmap##width##_t *bitmap) { \
    for(size_t i = 0; i < width / 64; i++) {\
      if(bitmap->data[i] != 0) return false;\
    }\
    return true;\
  }

#define EVOASM_BITMAP_DEF_UNOP(name, width, op) \
  static inline void evoasm_bitmap ## width ## _ ## name (evoasm_bitmap##width##_t *bitmap, evoasm_bitmap##width##_t *result) { \
    for(size_t i = 0; i < width / 64; i++) {\
      result->data[i] = op bitmap->data[i];\
    }\
  }

#define EVOASM_BITMAP_DEF_BINOP(name, width, op) \
  static inline void evoasm_bitmap ## width ## _ ## name (evoasm_bitmap##width##_t *bitmap1, evoasm_bitmap##width##_t *bitmap2, evoasm_bitmap##width##_t *result) { \
    for(size_t i = 0; i < width / 64; i++) {\
      result->data[i] = bitmap1->data[i] op bitmap2->data[i];\
    }\
  }

#define EVOASM_BITMAP_DEF_EQL(width) \
  static inline bool evoasm_bitmap ## width ## _ ## eql (evoasm_bitmap##width##_t *bitmap1, evoasm_bitmap##width##_t *bitmap2) { \
    for(size_t i = 0; i < width / 64; i++) {\
      if(bitmap1->data[i] != bitmap2->data[i]) return false;\
    } \
    return true;\
  }


#define EVOASM_BITMAP_DEF_CLEAR(width) \
  static inline void evoasm_bitmap ## width ## _ ## clear (evoasm_bitmap##width##_t *bitmap) { \
    for(size_t i = 0; i < width / 64; i++) {\
      bitmap->data[i] = 0;\
    } \
  }

#ifdef __GNUC__
#  define EVOASM_BITMAP_DEF_POPCOUNT(width) \
    static inline size_t evoasm_bitmap ## width ## _ ## popcount (evoasm_bitmap##width##_t *bitmap) { \
      size_t c = 0; \
      size_t i;\
      for(i = 0; i < width / 64; i++) {\
        c += (size_t) __builtin_popcountll(bitmap->data[i]);\
      } \
      return c;\
    }
#else
#  define EVOASM_BITMAP_DEF_POPCOUNT(width) \
    static inline size_t evoasm_bitmap_t ## width ## _ ## popcount (evoasm_bitmap##width##_t *bitmap) { \
      size_t c = 0, i;\
      for(i = 0; i < width / 64; i++) {\
        uint64_t x = bitmap->data[i]; \
        for(; x > 0; x &= x - 1) c++;\
      } \
      return c;\
    }
#endif

EVOASM_BITMAP_DEF_UNOP(not, 128, ~)
EVOASM_BITMAP_DEF_BINOP(and, 128, &)
EVOASM_BITMAP_DEF_BINOP(or, 128, |)
EVOASM_BITMAP_DEF_BINOP(andn, 128, &~)
EVOASM_BITMAP_DEF_POPCOUNT(128)
EVOASM_BITMAP_DEF_EQL(128)

EVOASM_BITMAP_DEF_UNOP(not, 64, ~)
EVOASM_BITMAP_DEF_BINOP(and, 64, &)
EVOASM_BITMAP_DEF_BINOP(or, 64, |)
EVOASM_BITMAP_DEF_POPCOUNT(64)
EVOASM_BITMAP_DEF_EQL(64)
EVOASM_BITMAP_DEF_CLEAR(64)

EVOASM_BITMAP_DEF_BINOP(andn, 512, &~)
EVOASM_BITMAP_DEF_IS_ZERO(512)
EVOASM_BITMAP_DEF_IS_ZERO(64)

EVOASM_BITMAP_DEF_EQL(1024)
