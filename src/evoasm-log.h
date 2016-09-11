/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef int evoasm_log_level_t;
#define EVOASM_LOG_LEVEL_TRACE   0
#define EVOASM_LOG_LEVEL_DEBUG   1
#define EVOASM_LOG_LEVEL_INFO    2
#define EVOASM_LOG_LEVEL_WARN    3
#define EVOASM_LOG_LEVEL_ERROR   4
#define EVOASM_LOG_LEVEL_FATAL   5
#define EVOASM_N_LOG_LEVELS      6

#ifndef EVOASM_MIN_LOG_LEVEL
#  define EVOASM_MIN_LOG_LEVEL EVOASM_LOG_LEVEL_INFO
#endif

extern evoasm_log_level_t _evoasm_min_log_level;
extern FILE *          _evoasm_log_file;

#ifdef __GNUC__
#  define EVOASM_LOG_ATTRS __attribute__ ((format(printf, 3, 4)))
#else
#  define EVOASM_LOG_ATTRS
#endif

#define EVOASM_DECL_LOG_TAG(tag) evoasm_used static const char *_evoasm_log_tag = tag;
#define EVOASM_LOG_TAG _evoasm_log_tag

void
evoasm_log(evoasm_log_level_t level, const char *tag, const char *format, ...) EVOASM_LOG_ATTRS;

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_TRACE
#  define evoasm_trace(...) evoasm_log(EVOASM_LOG_LEVEL_TRACE, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_trace(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
#  define evoasm_debug(...) evoasm_log(EVOASM_LOG_LEVEL_DEBUG, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_debug(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_INFO
#  define evoasm_info(...) evoasm_log(EVOASM_LOG_LEVEL_INFO, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_info(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_WARN
#  define evoasm_warn(...) evoasm_log(EVOASM_LOG_LEVEL_WARN, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_warn(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_ERROR
#  define evoasm_error(...) evoasm_log(EVOASM_LOG_LEVEL_ERROR, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_error_t(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_FATAL
#  define evoasm_fatal(...) evoasm_log(EVOASM_LOG_LEVEL_FATAL, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_fatal(...)
#endif
