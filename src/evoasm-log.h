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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "evoasm-util.h"

typedef int evoasm_log_level_t;
#define EVOASM_LOG_LEVEL_TRACE   0
#define EVOASM_LOG_LEVEL_DEBUG   1
#define EVOASM_LOG_LEVEL_INFO    2
#define EVOASM_LOG_LEVEL_WARN    3
#define EVOASM_LOG_LEVEL_ERROR   4
#define EVOASM_LOG_LEVEL_FATAL   5
#define EVOASM_LOG_LEVEL_NONE      6

#ifndef EVOASM_MIN_LOG_LEVEL
#  define EVOASM_MIN_LOG_LEVEL EVOASM_LOG_LEVEL_INFO
#endif

extern evoasm_log_level_t _evoasm_min_log_level;
extern FILE *          _evoasm_log_file;

#define EVOASM_DEF_LOG_TAG(tag) evoasm_used static const char *_evoasm_log_tag = tag;
#define EVOASM_LOG_TAG _evoasm_log_tag

void
evoasm_log(evoasm_log_level_t level, const char *tag, const char *format, ...) evoasm_printf(3, 4);

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_TRACE
#  define evoasm_log_trace(...) evoasm_log(EVOASM_LOG_LEVEL_TRACE, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_log_trace(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
#  define evoasm_log_debug(...) evoasm_log(EVOASM_LOG_LEVEL_DEBUG, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_log_debug(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_INFO
#  define evoasm_log_info(...) evoasm_log(EVOASM_LOG_LEVEL_INFO, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_log_info(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_WARN
#  define evoasm_log_warn(...) evoasm_log(EVOASM_LOG_LEVEL_WARN, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_log_warn(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_ERROR
#  define evoasm_log_error(...) evoasm_log(EVOASM_LOG_LEVEL_ERROR, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_log_error(...)
#endif

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_FATAL
#  define evoasm_log_fatal(...) evoasm_log(EVOASM_LOG_LEVEL_FATAL, EVOASM_LOG_TAG, __VA_ARGS__)
#else
#  define evoasm_log_fatal(...)
#endif
