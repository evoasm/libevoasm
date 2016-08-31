//
// Created by jap on 8/31/16.
//

#pragma once

#include "evoasm-rand.h"

#define _EVOASM_DECL_ENUM_DOMAIN_TYPE(l) \
  typedef struct { \
    uint8_t type; \
    uint16_t len; \
    int64_t vals[l]; \
  } evoasm_enum ## l ## _domain_t;

#define EVOASM_ENUM_DOMAIN_VALS_SIZE(len) ((size_t)(len) * sizeof(int64_t))
#define EVOASM_ENUM_DOMAIN_SIZE(len) (sizeof(evoasm_enum_domain_t) + EVOASM_ENUM_DOMAIN_VALS_SIZE(len))

typedef enum {
  EVOASM_DOMAIN_TYPE_ENUM,
  EVOASM_DOMAIN_TYPE_RANGE,
  EVOASM_DOMAIN_TYPE_INT64,
  EVOASM_DOMAIN_TYPE_INT32,
  EVOASM_DOMAIN_TYPE_INT16,
  EVOASM_DOMAIN_TYPE_INT8,
  EVOASM_N_DOMAIN_TYPES
} evoasm_domain_type_t;

typedef struct {
  uint8_t type;
} evoasm_int64_domain_t;

typedef evoasm_int64_domain_t evoasm_int32_domain_t;
typedef evoasm_int64_domain_t evoasm_int16_domain_t;
typedef evoasm_int64_domain_t evoasm_int8_domain_t;

typedef struct {
  uint8_t type;
  int64_t min;
  int64_t max;
} evoasm_range_domain_t;

typedef struct {
  uint8_t type;
  uint16_t len;
  int64_t vals[];
} evoasm_enum_domain_t;

_EVOASM_DECL_ENUM_DOMAIN_TYPE(2)
_EVOASM_DECL_ENUM_DOMAIN_TYPE(3)
_EVOASM_DECL_ENUM_DOMAIN_TYPE(4)
_EVOASM_DECL_ENUM_DOMAIN_TYPE(8)
_EVOASM_DECL_ENUM_DOMAIN_TYPE(11)
_EVOASM_DECL_ENUM_DOMAIN_TYPE(16)

/* evoasm_domain_t must be as large
 * as biggest enum
 */
typedef evoasm_enum16_domain_t evoasm_domain_t;

static inline int64_t
evoasm_domain_rand(evoasm_domain_t *domain, evoasm_prng64_t *prng, evoasm_prng32_t *prng) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *interval = (evoasm_range_domain_t *) domain;
      return evoasm_prng64_rand_between(prng, interval->min, interval->max);
    }
    case EVOASM_DOMAIN_TYPE_INT64: {
      return (int64_t) evoasm_prng64_rand(prng);
    }
    case EVOASM_DOMAIN_TYPE_INT32: {
      return (int64_t) (int32_t) (evoasm_prng64_rand(prng) & UINT32_MAX);
    }
    case EVOASM_DOMAIN_TYPE_INT16: {
      return (int64_t) (int16_t) (evoasm_prng64_rand(prng) & UINT16_MAX);
    }
    case EVOASM_DOMAIN_TYPE_INT8: {
      return (int64_t) (int8_t) (evoasm_prng64_rand(prng) & UINT8_MAX);
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enm = (evoasm_enum_domain_t *) domain;
      return enm->vals[evoasm_prng64_rand(prng) % enm->len];
    }
    default:
      evoasm_assert_not_reached();
      return 0;
  }
}

static inline void
evoasm_domain_clone(evoasm_domain_t *restrict domain, evoasm_domain_t *restrict domain_dst) {
  domain_dst->type = domain->type;

  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *interval = (evoasm_range_domain_t *) domain;
      evoasm_range_domain_t *interval_dst = (evoasm_range_domain_t *) domain_dst;
      interval_dst->min = interval->min;
      interval_dst->max = interval->max;
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT64:
    case EVOASM_DOMAIN_TYPE_INT32:
    case EVOASM_DOMAIN_TYPE_INT16:
    case EVOASM_DOMAIN_TYPE_INT8:
      break;
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enm = (evoasm_enum_domain_t *) domain;
      evoasm_enum_domain_t *enm_dst = (evoasm_enum_domain_t *) domain_dst;
      enm_dst->len = enm->len;
      memcpy(enm_dst->vals, enm->vals, EVOASM_ENUM_DOMAIN_VALS_SIZE(enm->len));
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}


static inline void
evoasm_domain_intersect(evoasm_domain_t *restrict domain1, evoasm_domain_t *restrict domain2,
                        evoasm_domain_t *restrict domain_dst) {

  if(domain1->type == EVOASM_DOMAIN_TYPE_ENUM && domain2->type == EVOASM_DOMAIN_TYPE_ENUM) {
    unsigned i = 0, j = 0;
    evoasm_enum_domain_t *enum1 = (evoasm_enum_domain_t *) domain1;
    evoasm_enum_domain_t *enum2 = (evoasm_enum_domain_t *) domain2;
    evoasm_enum_domain_t *enum_dst = (evoasm_enum_domain_t *) domain_dst;

    enum_dst->len = 0;
    /*
     * NOTE: vals are sorted (INC)
     */

    while(i < enum1->len && j < enum2->len) {
      int64_t v1 = enum1->vals[i];
      int64_t v2 = enum2->vals[j];

      if(v1 < v2) {
        i++;
      } else if(v2 < v1) {
        j++;
      } else {
        enum_dst->vals[enum_dst->len++] = v1;
        i++;
        j++;
      }
    }

    return;
  }

  if(domain2->type == EVOASM_DOMAIN_TYPE_ENUM) {
    evoasm_domain_t *temp_domain = domain1;
    domain1 = domain2;
    domain2 = temp_domain;
  }

  int64_t min1, max1, min2, max2;

  switch(domain2->type) {
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *range_domain2 = (evoasm_range_domain_t *) domain2;
      min2 = range_domain2->min;
      max2 = range_domain2->max;
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT8:
      min2 = INT8_MIN;
      max2 = INT8_MAX;
      break;
    case EVOASM_DOMAIN_TYPE_INT16:
      min2 = INT16_MIN;
      max2 = INT16_MAX;
      break;
    case EVOASM_DOMAIN_TYPE_INT32:
      min2 = INT32_MIN;
      max2 = INT32_MAX;
      break;
    case EVOASM_DOMAIN_TYPE_INT64:
      min2 = INT64_MIN;
      max2 = INT64_MAX;
      break;
    default:
      evoasm_assert_not_reached();
  }

  switch(domain1->type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      unsigned i;
      evoasm_enum_domain_t *enum_domain_dst = (evoasm_enum_domain_t *) domain_dst;
      evoasm_enum_domain_t *enum_domain1 = (evoasm_enum_domain_t *) domain1;

      enum_domain_dst->len = 0;
      for(i = 0; i < enum_domain1->len; i++) {
        if(enum_domain1->vals[i] >= min2 && enum_domain1->vals[i] <= max2) {
          enum_domain_dst->vals[enum_domain_dst->len++] = enum_domain1->vals[i];
        }
      }
      return;
    }
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *range_domain1 = (evoasm_range_domain_t *) domain1;
      min1 = range_domain1->min;
      max1 = range_domain1->max;
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT8: {
      min1 = INT8_MIN;
      max1 = INT8_MAX;
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT16: {
      min1 = INT16_MIN;
      max1 = INT16_MAX;
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT32: {
      min1 = INT32_MIN;
      max1 = INT32_MAX;
      break;
    }
    case EVOASM_DOMAIN_TYPE_INT64: {
      min1 = INT64_MIN;
      max1 = INT64_MAX;
      break;
    }
    default:
      evoasm_assert_not_reached();
  }

  evoasm_range_domain_t *range_domain_dst = (evoasm_range_domain_t *) domain_dst;
  range_domain_dst->min = EVOASM_MAX(min1, min2);
  range_domain_dst->max = EVOASM_MIN(max1, max2);
}

static inline bool
evoasm_domain_contains(evoasm_domain_t *domain, int64_t val) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *interval = (evoasm_range_domain_t *) domain;
      return val >= interval->min && val <= interval->max;
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      unsigned i;
      evoasm_enum_domain_t *enm = (evoasm_enum_domain_t *) domain;
      for(i = 0; i < enm->len; i++) {
        if(enm->vals[i] == val) return true;
      }
      return false;
    }
    default:
      evoasm_assert_not_reached();
      return false;
  }
}

static inline bool
evoasm_domain_empty(evoasm_domain_t *domain) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_ENUM:
      return ((evoasm_enum_domain_t *) domain)->len == 0;
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *interval = (evoasm_range_domain_t *) domain;
      return interval->min >= interval->max;
    }
    case EVOASM_DOMAIN_TYPE_INT64:
    case EVOASM_DOMAIN_TYPE_INT32:
    case EVOASM_DOMAIN_TYPE_INT16:
    case EVOASM_DOMAIN_TYPE_INT8:
      return false;
    default:
      evoasm_assert_not_reached();
  }
  return false;
}

void
evoasm_domain_log(evoasm_domain_t *domain, evoasm_log_level_t log_level);
