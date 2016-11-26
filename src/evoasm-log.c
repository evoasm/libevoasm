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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#else
#include <unistd.h>
#endif

#include "evoasm-log.h"
#include "evoasm-alloc.h"

evoasm_log_level_t _evoasm_min_log_level = EVOASM_LOG_LEVEL_WARN;
FILE *          _evoasm_log_file;

void
evoasm_set_min_log_level(evoasm_log_level_t min_log_level) {
  _evoasm_min_log_level = min_log_level;
}

static const char *const log_levels[EVOASM_LOG_LEVEL_NONE] = {
  "TRACE",
  "DEBUG",
  "INFO",
  "WARN",
  "ERROR",
  "FATAL"
};

static const char *const log_colors[EVOASM_LOG_LEVEL_NONE] = {
  "\x1b[30;1m",
  "\x1b[30;1m",
  "\x1b[32;1m",
  "\x1b[33;1m",
  "\x1b[31;1m",
  "\x1b[31;1m",
};


void
evoasm_log(evoasm_log_level_t level, const char *tag, const char *format, ...)
{
  if(level < _evoasm_min_log_level) return;

  va_list args;

  static const char *prefix = "evoasm:";
  static const char *sep1 = ":";
  static const char *sep2 = ": ";
  static const char *color_reset = "\x1b[0m";
  bool is_tty = isatty(fileno(_evoasm_log_file));

  size_t prefix_len = strlen(prefix);
  size_t color_len = is_tty ? strlen(log_colors[level]) : 0;
  size_t level_len = strlen(log_levels[level]);
  size_t color_reset_len = is_tty ? strlen(color_reset) : 0;
  size_t tag_len = strlen(tag);
  size_t sep1_len = strlen(sep1);
  size_t sep2_len = strlen(sep2);
  bool print_prefix = format[0] != ' ';
  const char *format_ = format + (print_prefix ? 0 : 1);
  size_t format_len = strlen(format_);
  bool print_new_line = format_[format_len - 1] != ' ';
  if(!print_new_line) format_len--;
  char *full_format = evoasm_alloca(prefix_len
                             + color_len
                             + level_len
                             + color_reset_len
                             + sep1_len
                             + tag_len
                             + sep2_len
                             + format_len
                             + 2);
  size_t i = 0;



#define __CPY(s, l) \
  memcpy(full_format + i, (s), (l)); i+= (l);

  if(print_prefix) {
    __CPY(prefix, prefix_len)
    __CPY(log_colors[level], color_len)
    __CPY(log_levels[level], level_len)
    __CPY(color_reset, color_reset_len)
    __CPY(sep1, sep1_len)
    __CPY(tag, tag_len)
    __CPY(sep2, sep2_len)
  }
  __CPY(format_, format_len)

#undef __CPY

  if(print_new_line) {
    full_format[i] = '\n'; i++;
  }
  full_format[i] = '\0'; i++;

  //fprintf(stderr, "printing '%s'\n", full_format);
  va_start(args, format);
  vfprintf(_evoasm_log_file, full_format, args);
  va_end(args);
}


