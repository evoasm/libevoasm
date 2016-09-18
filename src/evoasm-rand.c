/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm.h"
#include "evoasm-util.h"
#include "evoasm-rand.h"

EVOASM_DEF_LOG_TAG("rand")

_EVOASM_DEF_ALLOC_FREE_FUNCS(prng)

void
evoasm_prng_init(evoasm_prng_t *prng, evoasm_prng_state_t *seed) {
  prng->state = *seed;
  prng->p = 0;
}

void
evoasm_prng_destroy(evoasm_prng_t *prng) {
}

uint64_t
evoasm_prng_rand64(evoasm_prng_t *prng) {
  return _evoasm_prng_rand64(prng);
}

uint32_t
evoasm_prng_rand32(evoasm_prng_t *prng) {
  return _evoasm_prng_rand32(prng);
}

uint16_t
evoasm_prng_rand16(evoasm_prng_t *prng) {
  return _evoasm_prng_rand16(prng);
}

uint8_t
evoasm_prng_rand8(evoasm_prng_t *prng) {
  return _evoasm_prng_rand8(prng);
}

int64_t
evoasm_prng_rand_between(evoasm_prng_t *prng, int64_t min, int64_t max) {
  return _evoasm_prng_rand_between(prng, min, max);
}

