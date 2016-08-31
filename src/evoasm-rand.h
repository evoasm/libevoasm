/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-error.h"
#include "evoasm-log.h"


typedef struct {
  uint64_t data[16];
} evoasm_prng64_seed_t;

typedef struct {
  uint32_t data[4];
} evoasm_prng32_seed_t;

typedef struct evoasm_prng64 {
  /* xorshift1024star */
  evoasm_prng64_seed_t s;
  int p;
} evoasm_prng64_t;

typedef struct evoasm_prng32 {
  /* xorshift128 */
  evoasm_prng32_seed_t s;
  int p;
} evoasm_prng32_t;

void
evoasm_prng64_init(evoasm_prng64_t *prng, evoasm_prng64_seed_t *seed);

void
evoasm_prng64_destroy(evoasm_prng64_t *prng);

void
evoasm_prng32_init(evoasm_prng32_t *prng, evoasm_prng32_seed_t *seed);

void
evoasm_prng32_destroy(evoasm_prng32_t *prng);

/* From: https://en.wikipedia.org/wiki/Xorshift */
static inline uint64_t
evoasm_prng64_rand(evoasm_prng64_t *prng) {
  uint64_t *s = prng->s.data;
  const uint64_t s0 = s[prng->p];
  uint64_t s1 = s[prng->p = (prng->p + 1) & 15];
  s1 ^= s1 << 31; // a
  s[prng->p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30); // b,c
  return s[prng->p] * UINT64_C(1181783497276652981);
}

static inline uint32_t
evoasm_prng32_rand(evoasm_prng32_t *prng) {
  uint32_t *s = prng->s.data;
  uint32_t t = s[0];
  t ^= t << 11;
  t ^= t >> 8;
  s[0] = s[1]; s[1] = s[2]; s[2] = s[3];
  s[3] ^= s[3] >> 19;
  s[3] ^= t;
  return s[3];
}

static inline int64_t
evoasm_prng64_rand_between(evoasm_prng64_t *prng, int64_t min, int64_t max) {
  return min + (int64_t)(evoasm_prng64_rand(prng) % (uint64_t)(max - min + 1ll));
}

static inline int32_t
evoasm_prng32_rand_between(evoasm_prng32_t *prng, int32_t min, int32_t max) {
  return min + (int32_t)(evoasm_prng32_rand(prng) % (uint32_t)(max - min + 1ll));
}

static inline int64_t
evoasm_log2(int64_t num) {
  uint64_t log = 0;
  while (num >>= 1) ++log;
  return (int64_t)log;
}

