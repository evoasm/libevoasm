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

#include "evoasm-rand.h"

#define EVOASM_DOMAIN_HEADER \
   uint8_t type : 3; \

#define EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(l) \
  typedef struct { \
    EVOASM_DOMAIN_HEADER \
    uint16_t len; \
    int64_t vals[l]; \
  } evoasm_enum ## l ## _domain_t;

#define EVOASM_ENUM_DOMAIN_VALS_SIZE(len) ((size_t)(len) * sizeof(int64_t))
#define EVOASM_ENUM_DOMAIN_SIZE(len) (sizeof(evoasm_enum_domain_t) + EVOASM_ENUM_DOMAIN_VALS_SIZE(len))

typedef enum {
  EVOASM_DOMAIN_FLAG_INT64 = 1 << 0,
  EVOASM_DOMAIN_FLAG_INT32 = 1 << 1,
  EVOASM_DOMAIN_FLAG_INT16 = 1 << 2,
  EVOASM_DOMAIN_FLAG_INT8 = 1 << 3,
} evoasm_domain_flags;

#define EVOASM_DOMAIN_FLAGS_NONE 0

typedef enum {
  EVOASM_DOMAIN_TYPE_ENUM,
  EVOASM_DOMAIN_TYPE_RANGE,
  EVOASM_DOMAIN_TYPE_NONE
} evoasm_domain_type_t;

typedef enum {
  EVOASM_RANGE_DOMAIN_TYPE_INT8,
  EVOASM_RANGE_DOMAIN_TYPE_INT16,
  EVOASM_RANGE_DOMAIN_TYPE_INT32,
  EVOASM_RANGE_DOMAIN_TYPE_INT64,
  EVOASM_RANGE_DOMAIN_TYPE_CUSTOM,
} evoasm_range_domain_type_t;

typedef struct {
  EVOASM_DOMAIN_HEADER
  uint8_t range_type;
  int64_t min;
  int64_t max;
} evoasm_range_domain_t;

typedef struct {
  EVOASM_DOMAIN_HEADER
  uint16_t len;
  int64_t vals[];
} evoasm_enum_domain_t;

EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(2)
EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(3)
EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(4)
EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(8)
EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(11)
EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(13)
EVOASM_DOMAIN_DECL_ENUM_DOMAIN_STRUCT(16)

#define EVOASM_ENUM_DOMAIN_LEN_MAX 16

/* evoasm_domain_t must be as large
 * as biggest enum
 */
typedef evoasm_enum16_domain_t evoasm_domain_t;

static inline int64_t
evoasm_domain_rand_(evoasm_domain_t *domain, evoasm_prng_t *prng) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *range_domain = (evoasm_range_domain_t *) domain;
      switch(range_domain->range_type) {
        case EVOASM_RANGE_DOMAIN_TYPE_INT64: {
          return (int64_t) evoasm_prng_rand64_(prng);
        }
        case EVOASM_RANGE_DOMAIN_TYPE_INT32: {
          return (int32_t) evoasm_prng_rand32_(prng);
        }
        case EVOASM_RANGE_DOMAIN_TYPE_INT16: {
          return (int16_t) evoasm_prng_rand16_(prng);
        }
        case EVOASM_RANGE_DOMAIN_TYPE_INT8: {
          return (int8_t) evoasm_prng_rand8_(prng);
        }
        default:
          return evoasm_prng_rand_between_(prng, range_domain->min, range_domain->max + 1);
      }
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enm = (evoasm_enum_domain_t *) domain;
      return enm->vals[evoasm_prng_rand64_(prng) % enm->len];
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
      evoasm_range_domain_t *range = (evoasm_range_domain_t *) domain;
      evoasm_range_domain_t *range_dst = (evoasm_range_domain_t *) domain_dst;
      range_dst->min = range->min;
      range_dst->max = range->max;
      range_dst->range_type = range->range_type;
      break;
    }
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
evoasm_domain_get_bounds_(evoasm_domain_t *domain, int64_t *min, int64_t *max) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_domain_t *enum_domain = (evoasm_enum_domain_t *) domain;

      *min = enum_domain->vals[0];
      *max = enum_domain->vals[enum_domain->len];
      break;
    }
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *range_domain = (evoasm_range_domain_t *) domain;

      switch((evoasm_range_domain_type_t) range_domain->range_type) {
        case EVOASM_RANGE_DOMAIN_TYPE_INT8:
          *min = INT8_MIN;
          *max = INT8_MAX;
          break;
        case EVOASM_RANGE_DOMAIN_TYPE_INT16:
          *min = INT16_MIN;
          *max = INT16_MAX;
          break;
        case EVOASM_RANGE_DOMAIN_TYPE_INT32:
          *min = INT32_MIN;
          *max = INT32_MAX;
          break;
        case EVOASM_RANGE_DOMAIN_TYPE_INT64:
          *min = INT64_MIN;
          *max = INT64_MAX;
          break;
        default:
          *min = range_domain->min;
          *max = range_domain->max;
          break;
      }
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static inline uint64_t
evoasm_range_domain_get_size(evoasm_range_domain_t *range_domain) {
  switch((evoasm_range_domain_type_t) range_domain->range_type) {
    case EVOASM_RANGE_DOMAIN_TYPE_INT8: return UINT8_MAX;
    case EVOASM_RANGE_DOMAIN_TYPE_INT16: return UINT16_MAX;
    case EVOASM_RANGE_DOMAIN_TYPE_INT32: return UINT32_MAX;
    case EVOASM_RANGE_DOMAIN_TYPE_INT64: return UINT64_MAX;
    default: {
      return (uint64_t) (range_domain->max - range_domain->min);
    }
  }
}

static inline size_t
evoasm_range_domain_get_bitsize(evoasm_range_domain_t *range_domain) {
  switch((evoasm_range_domain_type_t) range_domain->range_type) {
    case EVOASM_RANGE_DOMAIN_TYPE_INT8: return 8;
    case EVOASM_RANGE_DOMAIN_TYPE_INT16: return 16;
    case EVOASM_RANGE_DOMAIN_TYPE_INT32: return 32;
    case EVOASM_RANGE_DOMAIN_TYPE_INT64: return 64;
    default: {
      uint64_t v = (uint64_t) EVOASM_MAX(EVOASM_ABS(range_domain->min),
                                         EVOASM_ABS(range_domain->max));

      size_t l = 0;
      while(v >>= 1) ++l;
      return l;
    }
  }
}

static inline void
evoasm_domain_intersect(evoasm_domain_t *domain1, evoasm_domain_t *domain2,
                        evoasm_domain_t *restrict domain_dst) {

  if(domain1 == domain2) {
    *domain_dst = *domain1;
    return;
  }

  if(domain1->type == EVOASM_DOMAIN_TYPE_ENUM && domain2->type == EVOASM_DOMAIN_TYPE_ENUM) {
    size_t i = 0, j = 0;
    evoasm_enum_domain_t *enum1 = (evoasm_enum_domain_t *) domain1;
    evoasm_enum_domain_t *enum2 = (evoasm_enum_domain_t *) domain2;
    evoasm_enum_domain_t *enum_dst = (evoasm_enum_domain_t *) domain_dst;

    enum_dst->len = 0;
    enum_dst->type = EVOASM_DOMAIN_TYPE_ENUM;
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

  evoasm_domain_get_bounds_(domain2, &min2, &max2);

  if(domain1->type == EVOASM_DOMAIN_TYPE_ENUM) {
    size_t i;
    evoasm_enum_domain_t *enum_domain_dst = (evoasm_enum_domain_t *) domain_dst;
    evoasm_enum_domain_t *enum_domain1 = (evoasm_enum_domain_t *) domain1;

    enum_domain_dst->type = EVOASM_DOMAIN_TYPE_ENUM;
    enum_domain_dst->len = 0;
    for(i = 0; i < enum_domain1->len; i++) {
      if(enum_domain1->vals[i] >= min2 && enum_domain1->vals[i] <= max2) {
        enum_domain_dst->vals[enum_domain_dst->len++] = enum_domain1->vals[i];
      }
    }
  } else {
    evoasm_range_domain_t *range_domain_dst = (evoasm_range_domain_t *) domain_dst;
    range_domain_dst->type = EVOASM_DOMAIN_TYPE_RANGE;

    evoasm_range_domain_t *range_domain1 = (evoasm_range_domain_t *) domain1;
    evoasm_range_domain_t *range_domain2 = (evoasm_range_domain_t *) domain2;

    if(range_domain1->range_type != EVOASM_RANGE_DOMAIN_TYPE_CUSTOM && range_domain2->range_type != EVOASM_RANGE_DOMAIN_TYPE_CUSTOM) {
      range_domain_dst->range_type = EVOASM_MIN(range_domain1->range_type, range_domain2->range_type);
    } else {
      range_domain_dst->range_type = EVOASM_RANGE_DOMAIN_TYPE_CUSTOM;

      evoasm_domain_get_bounds_(domain1, &min1, &max1);
      range_domain_dst->min = EVOASM_MAX(min1, min2);
      range_domain_dst->max = EVOASM_MIN(max1, max2);
    }
  }
}

static inline bool
evoasm_domain_contains(evoasm_domain_t *domain, int64_t val) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_RANGE: {
      int64_t min, max;
      evoasm_domain_get_bounds_(domain, &min, &max);
      return val >= min && val <= max;
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      size_t i;
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
evoasm_domain_is_empty(evoasm_domain_t *domain) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_ENUM:
      return ((evoasm_enum_domain_t *) domain)->len == 0;
    case EVOASM_DOMAIN_TYPE_RANGE: {
      evoasm_range_domain_t *range = (evoasm_range_domain_t *) domain;
      if(range->range_type == EVOASM_RANGE_DOMAIN_TYPE_CUSTOM) {
        return range->min >= range->max;
      } else {
        return false;
      }
    }
    default:
      evoasm_assert_not_reached();
  }
  return false;
}

void
evoasm_domain_log(evoasm_domain_t *domain, evoasm_log_level_t log_level);

