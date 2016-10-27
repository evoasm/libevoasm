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
# define evoasm_align(align) __attribute__ ((aligned(align)))
#elif defined(_MSC_VER)
# define evoasm_check_return _Check_return_
# define evoasm_force_inline __forceinline
# define evoasm_pack(decl) __pragma(pack(push, 1)) decl __pragma(pack(pop))
# define evoasm_align(align) __declspec(align(align))
#else
# define evoasm_check_return
# define evoasm_force_inline
# define evoasm_pack(decl)
# define evoasm_align(align)
#endif

#define EVOASM_DEF_ALLOC_FUNC(type) \
  evoasm_##type##_t *evoasm_##type##_alloc() { return evoasm_malloc(sizeof(evoasm_##type##_t)); }

#define EVOASM_DEF_FREE_FUNC(type) \
  void evoasm_##type##_free(evoasm_##type##_t *ptr) { evoasm_free(ptr); }

#define EVOASM_DECL_ALLOC_FUNC(type) \
  evoasm_##type##_t *evoasm_##type##_alloc();

#define EVOASM_DECL_FREE_FUNC(type) \
  void evoasm_##type##_free(evoasm_##type##_t *ptr);

#define EVOASM_DEF_ALLOC_FREE_FUNCS(type) \
  EVOASM_DEF_ALLOC_FUNC(type) \
  EVOASM_DEF_FREE_FUNC(type) \

#define EVOASM_DECL_ALLOC_FREE_FUNCS(type) \
  EVOASM_DECL_ALLOC_FUNC(type) \
  EVOASM_DECL_FREE_FUNC(type) \

#define EVOASM_DEF_ZERO_INIT_FUNC(type) \
  void evoasm_##type##_init(evoasm_##type##_t *ptr) {\
    static evoasm_##type##_t zero = {0}; \
    *ptr = zero; \
  }

#define EVOASM_DEF_GETTER(type, field, field_type) \
  field_type evoasm_##type##_get_##field(evoasm_##type##_t *ptr) { \
    return (field_type) ptr->field; \
  }

#define EVOASM_DEF_BOOL_GETTER(type, field) \
  bool evoasm_##type##_is_##field(evoasm_##type##_t *ptr) { \
    return ptr->field; \
  }

#define EVOASM_DEF_SETTER(type, field, field_type) \
  void evoasm_##type##_set_##field(evoasm_##type##_t *ptr, field_type value) { \
    ptr->field = value; \
  }

#define EVOASM_DEF_GETTER_SETTER(type, field, field_type) \
  EVOASM_DEF_GETTER(type, field, field_type) \
  EVOASM_DEF_SETTER(type, field, field_type)

#define EVOASM_SWAP(type, a, b) do { type s = (a); (a) = (b); (b) = s;} while (0)

#if defined(__linux__) || defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
#define EVOASM_UNIX
#endif

#define EVOASM_CB_CONTINUE true
#define EVOASM_CB_STOP false
