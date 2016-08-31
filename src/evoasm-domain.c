//
// Created by jap on 8/31/16.
//

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "evoasm-domain.h"

EVOASM_DECL_LOG_TAG("domain")

void
evoasm_domain_log(evoasm_domain_t *domain, evoasm_log_level_t log_level) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      unsigned i;
      evoasm_enum_domain_t *enm = (evoasm_enum_domain_t *) domain;
      evoasm_log(log_level, EVOASM_LOG_TAG, "Evoasm::Enum%d( ", enm->len);
      for (i = 0; i < enm->len; i++) {
        evoasm_log(log_level, EVOASM_LOG_TAG, "  %" PRId64 " ", enm->vals[i]);
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
