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

#include "evoasm-util.h"
#include "evoasm-arch.h"
#include <stdint.h>

#ifdef EVOASM_UNIX

#include <setjmp.h>
#include <signal.h>

typedef struct  {
  volatile uint64_t exception_mask;
  volatile evoasm_arch_id_t arch_id;
  sigjmp_buf env;
  int last_exception;
} evoasm_signal_ctx_t;

extern _Thread_local evoasm_signal_ctx_t _evoasm_signal_ctx;

#define EVOASM_SIGNAL_TRY() (sigsetjmp(_evoasm_signal_ctx.env, 1) == 0)
#else
#error
#endif

#include "evoasm-arch.h"

int
evoasm_signal_get_last_exception();

void
evoasm_signal_uninstall();

void
evoasm_signal_install();

void
evoasm_signal_set_exception_mask(uint64_t exception_mask);

void
evoasm_signal_clear_exception_mask();
