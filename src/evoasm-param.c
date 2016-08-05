/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-param.h"

evoasm_domain_t *
evoasm_inst_param_domain(evoasm_inst_param_t *inst_param) {
  return inst_param->domain;
}

evoasm_inst_param_id_t
evoasm_inst_param_id(evoasm_inst_param_t *inst_param) {
  return inst_param->id;
}


