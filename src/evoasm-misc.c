/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm.h"
#include "evoasm-util.h"
#include "evoasm-misc.h"

EVOASM_DECL_LOG_TAG("misc")

void
evoasm_prng64_init(evoasm_prng64_t *prng, evoasm_prng64_seed_t *seed) {
  prng->s = *seed;
}

void
evoasm_prng64_destroy(evoasm_prng64_t *prng) {
}

void
evoasm_prng32_init(evoasm_prng32_t *prng, evoasm_prng32_seed_t *seed) {
  prng->s = *seed;
}

void
evoasm_prng32_destroy(evoasm_prng32_t *prng) {
}

void
evoasm_domain_log(evoasm_domain_t *domain, evoasm_log_level log_level) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      unsigned i;
      evoasm_enum_t *enm = (evoasm_enum_t *) domain;
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Enum%d( ", enm->len);
      for (i = 0; i < enm->len; i++) {
        evoasm_log(log_level, EVOASM_LOG_TAG, "  %" PRId64 " ", enm->vals[i]);
      }
      evoasm_log(log_level, EVOASM_LOG_TAG, " )");
      break;
    }
    case EVOASM_DOMAIN_TYPE_INTERVAL: {
      evoasm_interval_t *interval = (evoasm_interval_t *) domain;
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Interval(%" PRId64 "..%" PRId64 ")", interval->min, interval->max);
      break;
    }
    case EVOASM_DOMAIN_TYPE_INTERVAL64:
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Interval(INT64_MIN..INT64_MAX)");
      break;
    default:
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Domain INVALID");
  }
}
