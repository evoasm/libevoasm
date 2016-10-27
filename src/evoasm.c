/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm.h"
#include "evoasm-log.h"
#include "evoasm-x64.h"

void
evoasm_init(int argc, const char **argv, FILE *log_file) {
  if(log_file == NULL) log_file = stderr;
  _evoasm_log_file = log_file;
}

