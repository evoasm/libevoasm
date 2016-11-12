/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
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
  struct sigaction prev_action;
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
