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

#define EVOASM_MAX(a,b) (((a) > (b)) ? (a) : (b))
#define EVOASM_MIN(a,b) (((a) < (b)) ? (a) : (b))
#define EVOASM_CLAMP(x, min, max) (((x) > (max)) ? (max) : (((x) < (min)) ? (min) : (x)))

#define EVOASM_ALIGN_DOWN(s, a) ((s) - ((s) % a))
#define EVOASM_ALIGN_UP(s, a) EVOASM_ALIGN_DOWN(((s) + (a) - 1), a)

#define EVOASM_DIV_ROUND_UP(v, d) ((((v) + ((d) - 1))) / d)

#define EVOASM_ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#ifdef __GNUC__
# define evoasm_unlikely(e) (__builtin_expect(e, 0))
# define evoasm_likely(e) (__builtin_expect(e, 1))
# define evoasm_used __attribute__((used))
# define evoasm_printf(x, y) __attribute__((__format__(__printf__, x, y)))
#else
# define evoasm_unlikely(e) (e)
# define evoasm_likely(e) (e)
# define evoasm_used
# define evoasm_printf
#endif

#if defined(__GNUC__)
# define evoasm_check_return __attribute__((warn_unused_result))
# define evoasm_force_inline __attribute__((always_inline))
# define evoasm_packed(decl) decl __attribute__((__packed__))
# define evoasm_aligned(align) __attribute__ ((aligned(align)))
#elif defined(_MSC_VER)
# define evoasm_check_return _Check_return_
# define evoasm_force_inline __forceinline
# define evoasm_packed(decl) __pragma(pack(push, 1)) decl __pragma(pack(pop))
# define evoasm_aligned(align) __declspec(align(align))
#else
# define evoasm_check_return
# define evoasm_force_inline
# define evoasm_packed(decl)
# define evoasm_aligned(align)
#endif

#define EVOASM_MEMCPY_N(dst, src, n) memcpy(dst, src, (n) * sizeof(*(src)))
#define EVOASM_MEMSET_N(ptr, val, n) memset(ptr, val, (n) * sizeof(*(ptr)))

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

#define EVOASM_DEF_EMPTY_DESTROY_FUNC(type) \
  void evoasm_##type##_destroy(evoasm_##type##_t *ptr) {}

#define EVOASM_DEF_GETTER(type, field, value_type) \
  value_type evoasm_##type##_get_##field(evoasm_##type##_t *ptr) { \
    return (value_type) ptr->field; \
  }

#define EVOASM_DEF_BOOL_GETTER(type, field) \
  bool evoasm_##type##_is_##field(evoasm_##type##_t *ptr) { \
    return ptr->field; \
  }

#define EVOASM_DEF_SETTER(type, field, value_type, field_type) \
  void evoasm_##type##_set_##field(evoasm_##type##_t *ptr, value_type value) { \
    ptr->field = (field_type) value; \
  }

#define EVOASM_SWAP(type, a, b) do { type s = (a); (a) = (b); (b) = s;} while (0)

#if defined(__linux__) || defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
#define EVOASM_UNIX
#endif

#define EVOASM_CB_CONTINUE true
#define EVOASM_CB_STOP false
