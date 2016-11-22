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

#include <stdint.h>
#include "evoasm-bitmap.h"
#include "evoasm-domain.h"

#define EVOASM_PARAM_VAL_FORMAT PRId64
#define EVOASM_PARAM_FORMAT PRIu32

typedef int64_t evoasm_param_val_t;
typedef uint8_t evoasm_param_id_t;

typedef struct {
  evoasm_param_id_t id;
  evoasm_domain_t *domain;
} evoasm_param_t;
