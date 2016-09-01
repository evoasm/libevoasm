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

EVOASM_DECL_LOG_TAG("rand")

void
evoasm_prng_init(evoasm_prng_t *prng, evoasm_prng_seed_t *seed) {
  prng->s = *seed;
}

void
evoasm_prng_destroy(evoasm_prng_t *prng) {
}

