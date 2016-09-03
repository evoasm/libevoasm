/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm.h"
#include "evoasm-log.h"
#include "evoasm-search.h"
#include "evoasm-x64.h"

void
evoasm_init(int argc, const char **argv, FILE *log_file) {
  if(log_file == NULL) log_file = stderr;
  _evoasm_log_file = log_file;
}

#define _EVOASM_DEFINE_ALLOC_FREE_FUNCS(type) \
evoasm_##type##_t *evoasm_##type##_alloc() { return evoasm_malloc(sizeof(evoasm_##type##_t)); }\
void evoasm_##type##_free(evoasm_##type##_t *ptr) { evoasm_free(ptr); }

_EVOASM_DEFINE_ALLOC_FREE_FUNCS(search)
_EVOASM_DEFINE_ALLOC_FREE_FUNCS(adf)
_EVOASM_DEFINE_ALLOC_FREE_FUNCS(buf_ref)

