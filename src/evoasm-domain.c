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

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include "evoasm-domain.h"
#include "evoasm-alloc.h"
#include "evoasm-param.h"

EVOASM_DEF_LOG_TAG("domain")

void
evoasm_domain_log(evoasm_domain_t *domain, evoasm_log_level_t log_level) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enum_domain = (evoasm_enum_domain_t *) domain;
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Enum%d( ", enum_domain->len);
      for(size_t i = 0; i < enum_domain->len; i++) {
        evoasm_log(log_level, EVOASM_LOG_TAG, "  %" PRId64 " ", enum_domain->vals[i]);
      }
      evoasm_log(log_level, EVOASM_LOG_TAG, " )");
      break;
    }
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *interval = (evoasm_range_domain_t *) domain;
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Interval(%" PRId64 "..%" PRId64 ")", interval->min, interval->max);
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT64:
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Interval(INT64_MIN..INT64_MAX)");
      break;
    default:
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Domain INVALID");
  }
}


void
evoasm_domain_get_bounds(evoasm_domain_t *domain, int64_t *min, int64_t *max) {
  evoasm_domain_get_bounds_(domain, min, max);
}

evoasm_domain_type_t
evoasm_domain_get_type(evoasm_domain_t *domain) {
  return (evoasm_domain_type_t) domain->type;
}

size_t
evoasm_enum_domain_get_len(evoasm_enum_domain_t *enum_domain) {
  return enum_domain->len;
}

int64_t
evoasm_enum_domain_get_val(evoasm_enum_domain_t *enum_domain, size_t idx) {
  return enum_domain->vals[idx];
}

int64_t
evoasm_domain_rand(evoasm_domain_t *domain, evoasm_prng_t *prng) {
  return evoasm_domain_rand_(domain, prng);
}

EVOASM_DEF_ALLOC_FREE_FUNCS(domain)

evoasm_success_t
evoasm_domain_init(evoasm_domain_t *domain, evoasm_domain_type_t type, ...) {
  va_list args;
  va_start(args, type);

  domain->type = type;

  switch(type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enum_domain = (evoasm_enum_domain_t *) domain;
      size_t len = va_arg(args, size_t);
      enum_domain->len = (uint16_t) len;

      if(len > EVOASM_ENUM_DOMAIN_LEN_MAX) {
        evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
                         NULL, "Exceeded maximum enumeration domain length (%d > %d)",
                         enum_domain->len, EVOASM_ENUM_DOMAIN_LEN_MAX);
        return false;
      }

      for(size_t i = 0; i < len; i++) {
        enum_domain->vals[i] = va_arg(args, int64_t);
      }
      break;
    }
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *range_domain = (evoasm_range_domain_t *) domain;
      range_domain->min = va_arg(args, int64_t);
      range_domain->max = va_arg(args, int64_t);
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT64:
    case EVOASM_DOMAIN_TYPE_INT32:
    case EVOASM_DOMAIN_TYPE_INT16:
    case EVOASM_DOMAIN_TYPE_INT8:
      break;
    default:
      evoasm_assert_not_reached();

  }
  va_end(args);

  return true;
}
