#include "evoasm.h"
#include "evoasm-log.h"
#include "evoasm-search.h"
#include "evoasm-x64.h"

static size_t _evoasm_struct_sizes[EVOASM_N_STRUCTS];

void
evoasm_init(int argc, const char **argv, FILE *log_file) {
  if(log_file == NULL) log_file = stderr;
  evoasm_log_file = log_file;

  _evoasm_struct_sizes[EVOASM_STRUCT_SEARCH] = sizeof(evoasm_search_t);
  _evoasm_struct_sizes[EVOASM_STRUCT_PROGRAM] = sizeof(evoasm_program_t);
  _evoasm_struct_sizes[EVOASM_STRUCT_X64] = sizeof(evoasm_x64_t);
}

size_t
evoasm_struct_size(evoasm_struct_t strct) {
  return _evoasm_struct_sizes[strct];
}
