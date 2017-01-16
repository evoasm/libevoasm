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

#include "evoasm-arch.h"

EVOASM_DEF_LOG_TAG("arch")

evoasm_arch_info_t evoasm_arch_infos[EVOASM_ARCH_NONE];
evoasm_arch_id_t evoasm_current_arch = EVOASM_ARCH_NONE;

evoasm_arch_info_t *
evoasm_get_arch_info(evoasm_arch_id_t arch_id) {
  return &evoasm_arch_infos[arch_id];
}

evoasm_arch_id_t
evoasm_get_current_arch() {
  return evoasm_current_arch;
}

#define EVOASM_ARCH_INFO_DEF_GETTER(field, type) EVOASM_DEF_GETTER(arch_info, field, type)

EVOASM_ARCH_INFO_DEF_GETTER(id, evoasm_arch_id_t)
EVOASM_ARCH_INFO_DEF_GETTER(n_conds, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(n_params, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(max_inst_len, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(n_insts, size_t)
EVOASM_ARCH_INFO_DEF_GETTER(features, uint64_t)


