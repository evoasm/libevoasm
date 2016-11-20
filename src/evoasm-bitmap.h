/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define EVOASM_BITMAP_IDX_DECLS(key) \
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

static inline void
evoasm_bitmap_set(evoasm_bitmap_t *bitmap, size_t idx) {
  EVOASM_BITMAP_IDX_DECLS(idx);
  bitmap[ary_idx] |= (1ull << bit_idx);
}

static inline void
evoasm_bitmap_unset(evoasm_bitmap_t *bitmap, size_t idx) {
  EVOASM_BITMAP_IDX_DECLS(idx);
  /* unset values must be 0*/
  bitmap[ary_idx] &= ~(1ull << bit_idx);
}

static inline bool
evoasm_bitmap_get(evoasm_bitmap_t *bitmap, size_t idx) {
  EVOASM_BITMAP_IDX_DECLS(idx);
  return (bitmap[ary_idx] & (1ull << bit_idx)) != 0;
}

static inline void
evoasm_bitmap_set64(evoasm_bitmap_t *bitmap, size_t idx, uint64_t bits) {
  EVOASM_BITMAP_IDX_DECLS(idx);
  (void) bit_idx;
  bitmap[ary_idx] = bits;
}

#define EVOASM_BITMAP_DECL_IS_ZERO(width) \
  static inline bool evoasm_bitmap ## width ## _is_zero(evoasm_bitmap##width##_t *bitmap) { \
    size_t i;\
    for(i = 0; i < width / 64; i++) {\
      if(bitmap->data[i] != 0) return false;\
    }\
    return true;\
  }

#define EVOASM_BITMAP_DECL_UNOP(name, width, op) \
  static inline void evoasm_bitmap ## width ## _ ## name (evoasm_bitmap##width##_t *bitmap, evoasm_bitmap##width##_t *result) { \
    size_t i;\
    for(i = 0; i < width / 64; i++) {\
      result->data[i] = op bitmap->data[i];\
    }\
  }

#define EVOASM_BITMAP_DECL_BINOP(name, width, op) \
  static inline void evoasm_bitmap ## width ## _ ## name (evoasm_bitmap##width##_t *bitmap1, evoasm_bitmap##width##_t *bitmap2, evoasm_bitmap##width##_t *result) { \
    size_t i;\
    for(i = 0; i < width / 64; i++) {\
      result->data[i] = bitmap1->data[i] op bitmap2->data[i];\
    }\
  }

#define EVOASM_BITMAP_DECL_EQL(width) \
  static inline bool evoasm_bitmap ## width ## _ ## eql (evoasm_bitmap##width##_t *bitmap1, evoasm_bitmap##width##_t *bitmap2) { \
    size_t i;\
    for(i = 0; i < width / 64; i++) {\
      if(bitmap1->data[i] != bitmap2->data[i]) return false;\
    } \
    return true;\
  }


#ifdef __GNUC__
#  define EVOASM_BITMAP_DECL_POPCOUNT(width) \
    static inline size_t evoasm_bitmap ## width ## _ ## popcount (evoasm_bitmap##width##_t *bitmap) { \
      size_t c = 0; \
      size_t i;\
      for(i = 0; i < width / 64; i++) {\
        c += (size_t) __builtin_popcountll(bitmap->data[i]);\
      } \
      return c;\
    }
#else
#  define EVOASM_BITMAP_DECL_POPCOUNT(width) \
    static inline size_t evoasm_bitmap_t ## width ## _ ## popcount (evoasm_bitmap##width##_t *bitmap) { \
      size_t c = 0, i;\
      for(i = 0; i < width / 64; i++) {\
        uint64_t x = bitmap->data[i]; \
        for(; x > 0; x &= x - 1) c++;\
      } \
      return c;\
    }
#endif

EVOASM_BITMAP_DECL_UNOP(not, 128, ~)
EVOASM_BITMAP_DECL_BINOP(and, 128, &)
EVOASM_BITMAP_DECL_BINOP(or, 128, |)
EVOASM_BITMAP_DECL_BINOP(andn, 128, &~)
EVOASM_BITMAP_DECL_POPCOUNT(128)
EVOASM_BITMAP_DECL_EQL(128)

EVOASM_BITMAP_DECL_UNOP(not, 64, ~)
EVOASM_BITMAP_DECL_BINOP(and, 64, &)
EVOASM_BITMAP_DECL_BINOP(or, 64, |)
EVOASM_BITMAP_DECL_POPCOUNT(64)
EVOASM_BITMAP_DECL_EQL(64)

EVOASM_BITMAP_DECL_BINOP(andn, 512, &~)
EVOASM_BITMAP_DECL_IS_ZERO(512)

EVOASM_BITMAP_DECL_EQL(1024)
