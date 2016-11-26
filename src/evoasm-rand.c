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

#include "evoasm.h"
#include "evoasm-util.h"
#include "evoasm-rand.h"

EVOASM_DEF_LOG_TAG("rand")

EVOASM_DEF_ALLOC_FREE_FUNCS(prng)

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
  return evoasm_prng_rand64_(prng);
}

uint32_t
evoasm_prng_rand32(evoasm_prng_t *prng) {
  return evoasm_prng_rand32_(prng);
}

uint16_t
evoasm_prng_rand16(evoasm_prng_t *prng) {
  return evoasm_prng_rand16_(prng);
}

uint8_t
evoasm_prng_rand8(evoasm_prng_t *prng) {
  return evoasm_prng_rand8_(prng);
}

float
evoasm_prng_randf(evoasm_prng_t *prng) {
  return evoasm_prng_randf_(prng);
}

int64_t
evoasm_prng_rand_between(evoasm_prng_t *prng, int64_t min, int64_t max) {
  return evoasm_prng_rand_between_(prng, min, max);
}

