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
        EVOASM_X64_N_INSTS,
        EVOASM_X64_N_PARAMS,
        15,
        0ull
    }
};

evoasm_arch_info_t *
evoasm_arch_info(evoasm_arch_id_t arch_id) {
  return &_evoasm_arch_infos[arch_id];
}


