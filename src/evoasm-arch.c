/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-arch.h"

EVOASM_DEF_LOG_TAG("arch")

evoasm_arch_info_t _evoasm_arch_infos[] = {
    {
        EVOASM_ARCH_X64,
        EVOASM_X64_PARAM_NONE,
        15,
        EVOASM_X64_INST_NONE,
        0ull
    }
};

evoasm_arch_info_t *
evoasm_get_arch_info(evoasm_arch_id_t arch_id) {
  return &_evoasm_arch_infos[arch_id];
}


#define EVOASM_ARCH_INFO_DEF_GETTER(field, type) EVOASM_DEF_GETTER(arch_info, field, type)

EVOASM_ARCH_INFO_DEF_GETTER(id, evoasm_arch_id_t)
EVOASM_ARCH_INFO_DEF_GETTER(n_params, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(max_inst_len, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(n_insts, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(features, uint64_t)


