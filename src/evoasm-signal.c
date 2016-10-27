/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-signal.h"

#ifdef EVOASM_UNIX

#define EVOASM_SIGNAL_EXCEPTION_SET(exc) (_evoasm_signal_ctx.exception_mask & (1 << exc))

_Thread_local evoasm_signal_ctx_t _evoasm_signal_ctx;

static void
evoasm_signal_handler(int sig, siginfo_t *siginfo, void *ctx) {
  bool handle = false;

  switch(_evoasm_signal_ctx.arch_id) {
    case EVOASM_ARCH_X64: {
      switch(sig) {
        case SIGFPE: {
          bool catch_div_by_zero = siginfo->si_code == FPE_INTDIV &&
                                   EVOASM_SIGNAL_EXCEPTION_SET(EVOASM_X64_EXCEPTION_DE);
          handle = catch_div_by_zero;
          break;
        }
        default:
          break;
      }
      break;
    }
    default:
      evoasm_assert_not_reached();
  }

  if(handle) {
    siglongjmp(_evoasm_signal_ctx.env, 1);
  } else {
    raise(sig);
  }
}

void
evoasm_signal_install(evoasm_arch_id_t arch_id, uint64_t exception_mask) {
  struct sigaction action = {0};

  _evoasm_signal_ctx.arch_id = (volatile evoasm_arch_id_t) arch_id;
  _evoasm_signal_ctx.exception_mask = exception_mask;

  action.sa_sigaction = evoasm_signal_handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO;

  if(sigaction(SIGFPE, &action, &_evoasm_signal_ctx.prev_action) < 0) {
    perror("sigaction");
    exit(1);
  }
}

void
evoasm_signal_set_exception_mask(uint64_t exception_mask) {
  _evoasm_signal_ctx.exception_mask = exception_mask;
}

void
evoasm_signal_uninstall() {
  if(sigaction(SIGFPE, &_evoasm_signal_ctx.prev_action, NULL) < 0) {
    perror("sigaction");
    exit(1);
  }
}

#else
#error
#endif
