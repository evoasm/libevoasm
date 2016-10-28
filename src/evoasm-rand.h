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

#define EVOASM_PRNG_SEED_LEN 16

typedef struct {
  uint64_t data[EVOASM_PRNG_SEED_LEN];
} evoasm_prng_state_t;

typedef struct evoasm_prng64 {
  /* xorshift1024star */
  evoasm_prng_state_t state;
  int p;
} evoasm_prng_t;

void
evoasm_prng_init(evoasm_prng_t *prng, evoasm_prng_state_t *seed);

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
evoasm_prng_rand_between_(evoasm_prng_t *prng, int64_t min, int64_t max) {
  return min + (int64_t)(evoasm_prng_rand64_(prng) % (uint64_t)(max - min + 1ll));
}
