//
// Created by jap on 8/31/16.
//

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
      unsigned i;
      evoasm_enum_domain_t *enum_domain = (evoasm_enum_domain_t *) domain;
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Enum%d( ", enum_domain->len);
      for (i = 0; i < enum_domain->len; i++) {
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
evoasm_domain_min_max(evoasm_domain_t *domain, int64_t *min, int64_t *max) {
  _evoasm_domain_min_max(domain, min, max);
}

evoasm_domain_type_t
evoasm_domain_type(evoasm_domain_t *domain) {
  return domain->type;
}

unsigned
evoasm_enum_domain_len(evoasm_enum_domain_t *enum_domain) {
  return enum_domain->len;
}

int64_t
evoasm_enum_domain_val(evoasm_enum_domain_t *enum_domain, unsigned index) {
  return enum_domain->vals[index];
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(domain)

evoasm_success_t
evoasm_domain_init(evoasm_domain_t *domain, evoasm_domain_type_t type, ...) {
  va_list args;
  va_start(args, type);

  domain->type = type;

  switch(type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enum_domain = (evoasm_enum_domain_t *) domain;
      unsigned len = va_arg(args, unsigned);
      unsigned i;

      enum_domain->len = (uint16_t) len;

      if(len > EVOASM_ENUM_DOMAIN_LEN_MAX) {
        evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                         NULL, "Exceeded maximum enumeration domain length (%d > %d)",
                         enum_domain->len, EVOASM_ENUM_DOMAIN_LEN_MAX);
        return false;
      }

      for(i = 0; i < len; i++) {
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
