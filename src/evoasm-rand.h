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

#include "evoasm-error.h"
#include "evoasm-log.h"

#define EVOASM_PRNG_SEED_LEN 16

typedef struct {
  uint64_t data[EVOASM_PRNG_SEED_LEN];
} evoasm_prng_state_t;

typedef struct evoasm_prng64 {
  /* xorshift1024star */
  evoasm_prng_state_t state;
  size_t p;
} evoasm_prng_t;

void
evoasm_prng_init(evoasm_prng_t *prng, const evoasm_prng_state_t *seed);

void
evoasm_prng_destroy(evoasm_prng_t *prng);


/* From: https://en.wikipedia.org/wiki/Xorshift */
static inline uint64_t
evoasm_prng_rand64_(evoasm_prng_t *prng) {
  uint64_t *s = prng->state.data;
  const uint64_t s0 = s[prng->p];
  uint64_t s1 = s[prng->p = (prng->p + 1) & 15];
  s1 ^= s1 << 31; // a
  s[prng->p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30); // b,c
  return (s[prng->p] * UINT64_C(1181783497276652981)) - 1;
}

static inline uint32_t
evoasm_prng_rand32_(evoasm_prng_t *prng) {
  return (uint32_t) (evoasm_prng_rand64_(prng) & UINT32_MAX);
}

static inline uint16_t
evoasm_prng_rand16_(evoasm_prng_t *prng) {
  return (uint16_t) (evoasm_prng_rand64_(prng) & UINT16_MAX);
}

static inline uint8_t
evoasm_prng_rand8_(evoasm_prng_t *prng) {
  return (uint8_t) (evoasm_prng_rand64_(prng) & UINT8_MAX);
}

static inline float
evoasm_prng_randf_(evoasm_prng_t *prng) {
  return (float) evoasm_prng_rand32_(prng) / (float) UINT32_MAX;
}

static inline int64_t
evoasm_prng_rand_between_(evoasm_prng_t *prng, int64_t min, int64_t bound) {
  return min + (int64_t)(evoasm_prng_rand64_(prng) % (uint64_t)(bound - min));
}
