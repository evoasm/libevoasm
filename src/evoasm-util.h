/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#define EVOASM_INT8_MAX  INT8_MAX
#define EVOASM_INT8_MIN  INT8_MIN
#define EVOASM_INT16_MAX INT16_MAX
#define EVOASM_INT16_MIN INT16_MIN
#define EVOASM_INT32_MAX INT32_MAX
#define EVOASM_INT32_MIN INT32_MIN
#define EVOASM_INT64_MAX INT64_MAX
#define EVOASM_INT64_MIN INT64_MIN


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
