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

#include "evoasm-signal.h"

#ifdef EVOASM_UNIX

#define EVOASM_SIGNAL_EXCEPTION_MASK_GET(exc) (_evoasm_signal_ctx.exception_mask & (1u << exc))

_Thread_local evoasm_signal_ctx_t _evoasm_signal_ctx;

static void
evoasm_signal_handler(int sig, siginfo_t *siginfo, void *ctx) {
  bool handle = false;

  switch(_evoasm_signal_ctx.arch_id) {
    case EVOASM_ARCH_X64: {
      switch(sig) {
        case SIGFPE: {
          int exception = EVOASM_X64_EXCEPTION_DE;
          bool catch_div_by_zero = siginfo->si_code == FPE_INTDIV &&
                                   EVOASM_SIGNAL_EXCEPTION_MASK_GET(exception);
          _evoasm_signal_ctx.last_exception = exception;
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
    evoasm_signal_uninstall();
    raise(sig);
  }
}

static struct sigaction prev_action;

void
evoasm_signal_install() {
  struct sigaction action = {0};

  evoasm_arch_id_t arch_id = evoasm_get_current_arch();
  assert(arch_id != EVOASM_ARCH_NONE);

  _evoasm_signal_ctx.arch_id = (volatile evoasm_arch_id_t) arch_id;
  _evoasm_signal_ctx.exception_mask = 0;
  _evoasm_signal_ctx.last_exception = 0;

  action.sa_sigaction = evoasm_signal_handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO;

  if(sigaction(SIGFPE, &action, &prev_action) < 0) {
    perror("sigaction");
    exit(1);
  }
}

void
evoasm_signal_set_exception_mask(uint64_t exception_mask) {
  _evoasm_signal_ctx.exception_mask = exception_mask;
}

void
evoasm_signal_clear_exception_mask() {
  _evoasm_signal_ctx.exception_mask = 0;
}

int
evoasm_signal_get_last_exception() {
  return _evoasm_signal_ctx.last_exception;
}

void
evoasm_signal_uninstall() {
  if(sigaction(SIGFPE, &prev_action, NULL) < 0) {
    perror("sigaction");
    exit(1);
  }
}

#else
#error
#endif
