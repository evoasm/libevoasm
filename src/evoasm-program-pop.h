/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-program-pop-params.h"
#include "evoasm-program.h"
#include "evoasm-pop.h"

typedef struct {
  evoasm_pop_t pop;
  evoasm_buf_t buf;
  evoasm_buf_t body_buf;
} evoasm_program_pop_t;


