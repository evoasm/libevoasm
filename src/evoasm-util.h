/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once


#define EVOASM_MAX(a,b) (((a) > (b)) ? (a) : (b))
#define EVOASM_MIN(a,b) (((a) < (b)) ? (a) : (b))
#define EVOASM_CLAMP(x, min, max) (((x) > (max)) ? (max) : (((x) < (min)) ? (min) : (x)))

#define EVOASM_ALIGN_DOWN(s, a) ((s) &~ ((a) - 1))
#define EVOASM_ALIGN_UP(s, a) EVOASM_ALIGN_DOWN(((s) + (a) - 1), a)

#define EVOASM_ARY_LEN(ary) (sizeof(ary) / sizeof(ary[0]))

#ifdef __GNUC__
# define EVOASM_UNLIKELY(e) (__builtin_expect(e, 0))
# define EVOASM_LIKELY(e) (__builtin_expect(e, 1))
# define evoasm_used __attribute__((used))
#else
# define EVOASM_UNLIKELY(e) (e)
# define EVOASM_LIKELY(e) (e)
# define evoasm_used
#endif

#if defined(__GNUC__)
# define evoasm_check_return __attribute__((warn_unused_result))
# define evoasm_force_inline __attribute__((always_inline))
# define evoasm_pack(decl) decl __attribute__((__packed__))
#elif defined(_MSC_VER)
# define evoasm_check_return _Check_return_
# define evoasm_force_inline __forceinline
# define evoasm_pack(decl) __pragma(pack(push, 1)) decl __pragma(pack(pop))
#else
# define evoasm_check_return
#endif

#define _EVOASM_DEF_ALLOC_FUNC(type) \
  evoasm_##type##_t *evoasm_##type##_alloc() { return evoasm_malloc(sizeof(evoasm_##type##_t)); }

#define _EVOASM_DEF_FREE_FUNC(type) \
  void evoasm_##type##_free(evoasm_##type##_t *ptr) { evoasm_free(ptr); }

#define _EVOASM_DECL_ALLOC_FUNC(type) \
  evoasm_##type##_t *evoasm_##type##_alloc();

#define _EVOASM_DECL_FREE_FUNC(type) \
  void evoasm_##type##_free(evoasm_##type##_t *ptr);

#define _EVOASM_DEF_ALLOC_FREE_FUNCS(type) \
  _EVOASM_DEF_ALLOC_FUNC(type) \
  _EVOASM_DEF_FREE_FUNC(type) \


#define _EVOASM_DECL_ALLOC_FREE_FUNCS(type) \
  _EVOASM_DECL_ALLOC_FUNC(type) \
  _EVOASM_DECL_FREE_FUNC(type) \

#define _EVOASM_DEF_ZERO_INIT_FUNC(type) \
  void evoasm_##type##_init(evoasm_##type##_t *ptr) {\
    static evoasm_##type##_t zero = {0}; \
    *ptr = zero; \
  }

#define _EVOASM_DEF_FIELD_READER(type, field, field_type) \
  field_type evoasm_##type##_##field(evoasm_##type##_t *ptr) { \
    return (field_type) ptr->field; \
  }

#define _EVOASM_DEF_FIELD_WRITER(type, field, field_type) \
  void evoasm_##type##_set_##field(evoasm_##type##_t *ptr, field_type value) { \
    ptr->field = value; \
  }

#define _EVOASM_DEF_FIELD_ACCESSOR(type, field, field_type) \
  _EVOASM_DEF_FIELD_READER(type, field, field_type) \
  _EVOASM_DEF_FIELD_WRITER(type, field, field_type)

#if defined(__linux__) || defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
#define EVOASM_UNIX
#endif