/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-arch.h"

EVOASM_DECL_LOG_TAG("arch")

evoasm_arch_info_t _evoasm_arch_infos[] = {
    {
        EVOASM_ARCH_X64,
        EVOASM_X64_N_PARAMS,
        15,
        EVOASM_X64_N_INSTS,
        0ull
    }
};

evoasm_arch_info_t *
evoasm_arch_info(evoasm_arch_id_t arch_id) {
  return &_evoasm_arch_infos[arch_id];
}

#define _EVOASM_ARCH_INFO_DEF_FIELD_READER(field, type) \
type evoasm_arch_info_##field(evoasm_arch_info_t *arch_info) { \
  return (type) arch_info->field; \
}

_EVOASM_ARCH_INFO_DEF_FIELD_READER(id, evoasm_arch_id_t)
_EVOASM_ARCH_INFO_DEF_FIELD_READER(n_params, unsigned)
_EVOASM_ARCH_INFO_DEF_FIELD_READER(max_inst_len, unsigned)
_EVOASM_ARCH_INFO_DEF_FIELD_READER(n_insts, unsigned)
_EVOASM_ARCH_INFO_DEF_FIELD_READER(features, unsigned)


