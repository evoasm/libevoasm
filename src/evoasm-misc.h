#pragma once

#include "evoasm-error.h"

#define _EVOASM_DOMAIN_HEADER \
  evoasm_domain_type_t type: 8; \
  unsigned index         :24;

#define _EVOASM_ENUM_HEADER \
  _EVOASM_DOMAIN_HEADER \
  uint16_t len;

#define _EVOASM_DECL_ENUM_TYPE(l) \
  typedef struct { \
    _EVOASM_ENUM_HEADER \
    int64_t vals[l]; \
  } evoasm_enum ## l ## _t;


#define EVOASM_ENUM_MAX_LEN 32

#define EVOASM_ENUM_VALS_SIZE(len) ((size_t)(len) * sizeof(int64_t))
#define EVOASM_ENUM_SIZE(len) (sizeof(evoasm_enum_t) + EVOASM_ENUM_VALS_SIZE(len))

typedef enum {
  EVOASM_DOMAIN_TYPE_ENUM,
  EVOASM_DOMAIN_TYPE_INTERVAL,
  EVOASM_DOMAIN_TYPE_INTERVAL64,
  EVOASM_N_DOMAIN_TYPES
} evoasm_domain_type_t;

typedef struct {
  _EVOASM_DOMAIN_HEADER
  int64_t pad[EVOASM_ENUM_MAX_LEN];
} evoasm_domain_t;

typedef struct {
  _EVOASM_DOMAIN_HEADER
  int64_t min;
  int64_t max;
} evoasm_interval_t;

typedef struct {
  _EVOASM_ENUM_HEADER
  int64_t vals[];
} evoasm_enum_t;

_EVOASM_DECL_ENUM_TYPE(2)
_EVOASM_DECL_ENUM_TYPE(3)
_EVOASM_DECL_ENUM_TYPE(4)
_EVOASM_DECL_ENUM_TYPE(8)
_EVOASM_DECL_ENUM_TYPE(11)
_EVOASM_DECL_ENUM_TYPE(16)

typedef struct {
  uint64_t data[16];
} evoasm_prng64_seed_t;

typedef struct {
  uint32_t data[4];
} evoasm_prng32_seed_t;

typedef struct evoasm_prng64 {
  /* xorshift1024star */
  evoasm_prng64_seed_t s;
  int p;
} evoasm_prng64_t;

typedef struct evoasm_prng32 {
  /* xorshift128 */
  evoasm_prng32_seed_t s;
  int p;
} evoasm_prng32_t;

void
evoasm_prng64_init(evoasm_prng64_t *prng, evoasm_prng64_seed_t *seed);

void
evoasm_prng64_destroy(evoasm_prng64_t *prng);

void
evoasm_prng32_init(evoasm_prng32_t *prng, evoasm_prng32_seed_t *seed);

void
evoasm_prng32_destroy(evoasm_prng32_t *prng);

/* From: https://en.wikipedia.org/wiki/Xorshift */
static inline uint64_t
evoasm_prng64_rand(evoasm_prng64_t *prng) {
  uint64_t *s = prng->s.data;
  const uint64_t s0 = s[prng->p];
  uint64_t s1 = s[prng->p = (prng->p + 1) & 15];
  s1 ^= s1 << 31; // a
  s[prng->p] = s1 ^ s0 ^ (s1 >> 11) ^ (s0 >> 30); // b,c
  return s[prng->p] * UINT64_C(1181783497276652981);
}

static inline uint32_t
evoasm_prng32_rand(evoasm_prng32_t *prng) {
  uint32_t *s = prng->s.data;
  uint32_t t = s[0];
  t ^= t << 11;
  t ^= t >> 8;
  s[0] = s[1]; s[1] = s[2]; s[2] = s[3];
  s[3] ^= s[3] >> 19;
  s[3] ^= t;
  return s[3];
}

static inline int64_t
evoasm_prng64_rand_between(evoasm_prng64_t *prng, int64_t min, int64_t max) {
  return min + (int64_t)(evoasm_prng64_rand(prng) % (uint64_t)(max - min + 1ll));
}

static inline int32_t
evoasm_prng32_rand_between(evoasm_prng32_t *prng, int32_t min, int32_t max) {
  return min + (int32_t)(evoasm_prng32_rand(prng) % (uint32_t)(max - min + 1ll));
}

static inline int64_t
evoasm_domain_rand(evoasm_domain_t *domain, evoasm_prng64_t *prng) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_INTERVAL: {
      evoasm_interval_t *interval = (evoasm_interval_t *) domain;
      return evoasm_prng64_rand_between(prng, interval->min, interval->max);
    }
    case EVOASM_DOMAIN_TYPE_INTERVAL64: {
      return (int64_t) evoasm_prng64_rand(prng);
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_t *enm = (evoasm_enum_t *) domain;
      return enm->vals[evoasm_prng64_rand(prng) % enm->len];
    }
    default:
      evoasm_assert_not_reached();
      return 0;
  }
}

static inline size_t
evoasm_domain_size(evoasm_domain_t *domain) {
  switch(domain->type){
    case EVOASM_DOMAIN_TYPE_INTERVAL:
    case EVOASM_DOMAIN_TYPE_INTERVAL64: return sizeof(evoasm_interval_t);
    case EVOASM_DOMAIN_TYPE_ENUM: return EVOASM_ENUM_SIZE(((evoasm_enum_t *) domain)->len);
    default:
      evoasm_assert_not_reached();
      return 0;
  }
}

static inline void
evoasm_domain_clone(evoasm_domain_t * restrict domain, evoasm_domain_t * restrict domain_dst) {
  domain_dst->type = domain->type;

  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_INTERVAL:
    case EVOASM_DOMAIN_TYPE_INTERVAL64: {
      evoasm_interval_t *interval = (evoasm_interval_t *) domain;
      evoasm_interval_t *interval_dst = (evoasm_interval_t *) domain_dst;
      interval_dst->min = interval->min;
      interval_dst->max = interval->max;
      break;
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      evoasm_enum_t *enm = (evoasm_enum_t *) domain;
      evoasm_enum_t *enm_dst = (evoasm_enum_t *) domain_dst;
      enm_dst->len = enm->len;
      memcpy(enm_dst->vals, enm->vals, EVOASM_ENUM_VALS_SIZE(enm->len));
      break;
    }
    default: evoasm_assert_not_reached();
  }
}


static inline void
evoasm_domain_intersect(evoasm_domain_t * restrict domain1, evoasm_domain_t * restrict domain2, evoasm_domain_t * restrict domain_dst) {

#define _EVOASM_DOMAIN_TYPES2(type_a, type_b) (int)(((type_a) << 8) | (type_b))

  switch(_EVOASM_DOMAIN_TYPES2(domain1->type, domain2->type)) {
    case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_INTERVAL, EVOASM_DOMAIN_TYPE_INTERVAL64):
    case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_INTERVAL, EVOASM_DOMAIN_TYPE_INTERVAL):
    case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_INTERVAL64, EVOASM_DOMAIN_TYPE_INTERVAL64):
    case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_INTERVAL64, EVOASM_DOMAIN_TYPE_INTERVAL): {
      evoasm_interval_t *interval1 = (evoasm_interval_t *) domain1;
      evoasm_interval_t *interval2 = (evoasm_interval_t *) domain2;
      evoasm_interval_t *interval_dst = (evoasm_interval_t *) domain_dst;

      interval_dst->min = EVOASM_MAX(interval1->min, interval2->min);
      interval_dst->max = EVOASM_MIN(interval1->max, interval2->max);
      break;
    }
    case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_ENUM, EVOASM_DOMAIN_TYPE_ENUM): {
      unsigned i = 0, j = 0;
      evoasm_enum_t *enum1 = (evoasm_enum_t *) domain1;
      evoasm_enum_t *enum2 = (evoasm_enum_t *) domain2;
      evoasm_enum_t *enum_dst = (evoasm_enum_t *) domain_dst;

      enum_dst->len = 0;
      /*
       * NOTE: vals are sorted (INC)
       */

      while(i < enum1->len && j < enum2->len) {
        int64_t v1 = enum1->vals[i];
        int64_t v2 = enum2->vals[j];

        if(v1 < v2) {
          i++;
        }
        else if(v2 < v1) {
          j++;
        }
        else {
          enum_dst->vals[enum_dst->len++] = v1;
          i++;
          j++;
        }
      }
      break;
    }
    {
      evoasm_enum_t *enm;
      evoasm_interval_t *interval;
      unsigned i;

      case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_ENUM, EVOASM_DOMAIN_TYPE_INTERVAL):
      case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_ENUM, EVOASM_DOMAIN_TYPE_INTERVAL64):
        enm = (evoasm_enum_t *) domain1;
        interval = (evoasm_interval_t *) domain2;
        goto intersect;
      case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_INTERVAL, EVOASM_DOMAIN_TYPE_ENUM):
      case _EVOASM_DOMAIN_TYPES2(EVOASM_DOMAIN_TYPE_INTERVAL64, EVOASM_DOMAIN_TYPE_ENUM):
        enm = (evoasm_enum_t *) domain2;
        interval = (evoasm_interval_t *) domain1;
    intersect: {
          evoasm_enum_t *enum_dst = (evoasm_enum_t *) domain_dst;
          enum_dst->len = 0;
          for(i = 0; i < enm->len; i++) {
            if(enm->vals[i] >= interval->min && enm->vals[i] <= interval->max) {
              enum_dst->vals[enum_dst->len++] = enm->vals[i];
            }
          }
        }
        break;
    }
    default:
      evoasm_assert_not_reached();
  }

#undef _EVOASM_DOMAIN_TYPES2
}

static inline bool
evoasm_domain_contains_p(evoasm_domain_t *domain, int64_t val) {
  switch(domain->type) {
    case EVOASM_DOMAIN_TYPE_INTERVAL: {
      evoasm_interval_t *interval = (evoasm_interval_t *) domain;
      return val >= interval->min && val <= interval->max;
    }
    case EVOASM_DOMAIN_TYPE_ENUM: {
      unsigned i;
      evoasm_enum_t *enm = (evoasm_enum_t *) domain;
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

static inline int64_t
evoasm_log2(int64_t num) {
  uint64_t log = 0;
  while (num >>= 1) ++log;
  return (int64_t)log;
}
