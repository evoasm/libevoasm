/* vim: set filetype=c: */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <inttypes.h>

#include "evoasm-util.h"
#include "evoasm-log.h"
#include "evoasm-buf.h"
#include "evoasm-alloc.h"
#include "evoasm-arch.h"
#include "evoasm-error.h"

typedef enum {
  EVOASM_STRUCT_SEARCH,
  EVOASM_STRUCT_PROGRAM,
  EVOASM_STRUCT_X64,
  EVOASM_N_STRUCTS
} evoasm_struct_t;

extern size_t evoasm_struct_sizes[EVOASM_N_STRUCTS];

void
evoasm_init(int argc, const char **argv, FILE *log_file);

