/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <stdint.h>
#include "evoasm-bitmap.h"
#include "evoasm-misc.h"

#define EVOASM_PARAM_VAL_FORMAT PRId64
#define EVOASM_PARAM_FORMAT PRIu32

typedef int64_t evoasm_param_val_t;
typedef uint8_t evoasm_param_id_t;

typedef struct {
  evoasm_param_id_t id;
  evoasm_domain_t *domain;
} evoasm_param_t;
