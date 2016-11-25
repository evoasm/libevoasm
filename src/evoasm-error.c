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

#include "evoasm-error.h"

_Thread_local evoasm_error_t evoasm_last_error;

void
evoasm_error_setv(evoasm_error_t *error, unsigned error_type, unsigned error_code,
                 void *error_data, const char *file,
                 unsigned line, const char *format, va_list args) {

  error->type = (uint16_t) error_type;
  error->code = (uint16_t) error_code;
  error->line = line;
  strncpy(error->filename, file, EVOASM_ERROR_MAX_FILENAME_LEN);
  vsnprintf(error->msg, EVOASM_ERROR_MAX_MSG_LEN, format, args);

  if(error_data != NULL) {
    memcpy(&error->data, error_data, sizeof(evoasm_error_data_t));
  }
}

evoasm_error_t *
evoasm_get_last_error() {
  return &evoasm_last_error;
}

void
evoasm_set_last_error(evoasm_error_t *error) {
  evoasm_last_error = *error;
}

void
evoasm_error_set(evoasm_error_t *error, unsigned error_type, unsigned error_code,
                void *error_data, const char *file,
                unsigned line, const char *format, ...) {
  va_list args;
  va_start(args, format);
  evoasm_error_setv(error, error_type, error_code,
                   error_data, file, line,
                   format, args);
  va_end(args);
}

EVOASM_DEF_GETTER(error, type, evoasm_error_type_t)
EVOASM_DEF_GETTER(error, code, evoasm_error_code_t)
EVOASM_DEF_GETTER(error, line, unsigned)
EVOASM_DEF_GETTER(error, filename, char *)
EVOASM_DEF_GETTER(error, msg, char *)

