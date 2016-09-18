/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-adf-deme-params.h"
#include "evoasm-adf.h"
#include "evoasm-deme.h"

typedef struct {
  evoasm_deme_t deme;
  evoasm_buf_t buf;
  evoasm_buf_t body_buf;
  evoasm_arch_info_t *arch_info;
  evoasm_adf_io_val_t *output_vals;
} evoasm_adf_deme_t;


