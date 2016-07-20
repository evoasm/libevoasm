#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "evoasm.h"
#include "evoasm-buf.h"
#include "evoasm-x64.h"

typedef double evoasm_loss_t;
typedef uint8_t evoasm_program_size_t;

#define EVOASM_KERNEL_SIZE_MAX UINT8_MAX
typedef uint8_t evoasm_kernel_size_t;
#define EVOASM_KERNEL_MAX_SIZE (EVOASM_KERNEL_SIZE_MAX - 1)

typedef enum {
  EVOASM_EXAMPLE_TYPE_I64,
  EVOASM_EXAMPLE_TYPE_U64,
  EVOASM_EXAMPLE_TYPE_F64,
} evoasm_example_type_t;

typedef union {
  double f64;
  int64_t i64;
  uint64_t u64;
} evoasm_example_val_t;

#define EVOASM_PROGRAM_IO_MAX_ARITY 8

typedef struct {
  uint8_t arity;
  uint16_t len;
  evoasm_example_val_t *vals;
  evoasm_example_type_t types[EVOASM_PROGRAM_IO_MAX_ARITY];
} evoasm_program_io_t;

#define EVOASM_PROGRAM_OUTPUT_MAX_ARITY EVOASM_PROGRAM_IO_MAX_ARITY
#define EVOASM_PROGRAM_INPUT_MAX_ARITY EVOASM_PROGRAM_IO_MAX_ARITY
typedef evoasm_program_io_t evoasm_program_output_t;
typedef evoasm_program_io_t evoasm_program_input_t;

#define EVOASM_PROGRAM_IO_N_EXAMPLES(program_io) ((uint16_t)((program_io)->len / (program_io)->arity))
#define EVOASM_PROGRAM_INPUT_N_EXAMPLES(program_input) EVOASM_PROGRAM_IO_N_EXAMPLES((evoasm_program_io_t *)program_input)
#define EVOASM_PROGRAM_OUTPUT_N_EXAMPLES(program_output) EVOASM_PROGRAM_IO_N_EXAMPLES((evoasm_program_io_t *)program_output)

typedef struct {
  evoasm_inst_id_t inst;
  evoasm_arch_params_bitmap_t set_params;
  evoasm_arch_param_val_t param_vals[EVOASM_ARCH_MAX_PARAMS];
} evoasm_kernel_param_t;

typedef struct {
  evoasm_kernel_size_t size;
  /* kernel executed next (jumped to)
   * Kernel terminates if EVOASM_KERNEL_SIZE_MAX 
   */
  evoasm_kernel_size_t branch_kernel_idx;
  uint8_t jmp_selector;
  evoasm_kernel_param_t params[];
} evoasm_kernel_params_t;

typedef struct {
  evoasm_program_size_t size;
} evoasm_program_params_t;

#define EVOASM_KERNEL_MAX_OUTPUT_REGS 254
#define EVOASM_KERNEL_MAX_INPUT_REGS 254
#define EVOASM_PROGRAM_MAX_SIZE 64

#define EVOASM_KERNEL_REG_INFO_N_TRANS_REGS 2

typedef struct {
  bool input : 1;
  bool written : 1;
  bool output : 1;
  evoasm_x64_reg_id_t trans_regs[EVOASM_KERNEL_REG_INFO_N_TRANS_REGS];
} evoasm_kernel_x64_reg_info_t;

typedef union {
  evoasm_kernel_x64_reg_info_t x64[EVOASM_X64_N_REGS];
} evoasm_kernel_reg_info_t;


typedef struct {
  evoasm_kernel_params_t *params;
  evoasm_kernel_reg_info_t reg_info;
  
  union {
    evoasm_x64_reg_id_t x64[EVOASM_KERNEL_MAX_OUTPUT_REGS];
  } output_regs;

  uint_fast8_t n_input_regs;
  uint_fast8_t n_output_regs;
  uint8_t idx;
  uint16_t buf_start;
  uint16_t buf_end;
} evoasm_kernel_t;

typedef struct {
  evoasm_inst_id_t *insts;
  evoasm_arch_param_id_t *params;
  evoasm_domain_t *domains[EVOASM_ARCH_MAX_PARAMS];
  evoasm_program_size_t min_program_size;
  evoasm_program_size_t max_program_size;
  evoasm_kernel_size_t min_kernel_size;
  evoasm_kernel_size_t max_kernel_size;
  uint32_t recur_limit;
  uint16_t insts_len;
  uint8_t params_len;
  uint32_t pop_size;
  uint32_t mut_rate;
  evoasm_program_input_t program_input;
  evoasm_program_output_t program_output;
  evoasm_prng64_seed_t seed64;
  evoasm_prng32_seed_t seed32;
  evoasm_loss_t max_loss;
} evoasm_search_params_t;


typedef struct {
  evoasm_arch_t *arch;
  evoasm_buf_t *buf;
  evoasm_buf_t *body_buf;
  uint32_t index;
  uint8_t in_arity;
  uint8_t out_arity;
  bool reset_rflags : 1;
  bool need_emit    : 1;
  void *_signal_ctx;
  uint32_t exception_mask;
  evoasm_example_type_t types[EVOASM_PROGRAM_OUTPUT_MAX_ARITY];
  evoasm_example_val_t *output_vals;
  evoasm_kernel_t kernels[EVOASM_PROGRAM_MAX_SIZE];
  uint32_t recur_counters[EVOASM_PROGRAM_MAX_SIZE];
  evoasm_program_params_t *params;
  evoasm_program_input_t _input;
  evoasm_program_output_t _output;
  evoasm_search_params_t *search_params;
  evoasm_reg_id_t output_regs[EVOASM_PROGRAM_IO_MAX_ARITY];
  
  union {
    /* register at index i has input i % input_arity */
    uint8_t x64[EVOASM_X64_N_REGS];
  } reg_inputs;

} evoasm_program_t;

#define EVOASM_SEARCH_ELITE_SIZE 4

typedef struct {
  evoasm_prng64_t prng64;
  evoasm_prng32_t prng32;
  evoasm_loss_t best_loss;
  evoasm_buf_t buf;
  evoasm_buf_t body_buf;

  uint32_t elite[EVOASM_SEARCH_ELITE_SIZE];
  uint8_t elite_pos;
  uint_fast8_t *matching;
  evoasm_example_val_t *output_vals;
  evoasm_loss_t *losses;
  unsigned char *programs;
  unsigned char *programs_main;
  unsigned char *programs_swap;
  unsigned char *programs_aux;
} evoasm_population_t;

#define EVOASM_EXAMPLES_MAX_ARITY 8
typedef struct {
  evoasm_example_type_t types[EVOASM_EXAMPLES_MAX_ARITY];
  uint16_t len;
  evoasm_example_val_t *vals;
  uint8_t in_arity;
  uint8_t out_arity;
} evoasm_examples_t;

typedef struct {
  evoasm_arch_t *arch;
  evoasm_population_t pop;
  evoasm_search_params_t params;
  evoasm_domain_t *domains;
} evoasm_search_t;

bool
evoasm_search_init(evoasm_search_t *search,
                   evoasm_arch_t *arch, evoasm_search_params_t *params);

bool
evoasm_search_destroy(evoasm_search_t *search);

typedef bool (*evoasm_search_result_func_t)(evoasm_program_t *program,
                                         evoasm_loss_t loss, void *user_data);

void
evoasm_search_start(evoasm_search_t *search, evoasm_search_result_func_t func, void *user_data);

bool
evoasm_program_run(evoasm_program_t *program,
                  evoasm_program_input_t *input,
                  evoasm_program_output_t *output);


evoasm_success_t
evoasm_program_clone(evoasm_program_t *program, evoasm_program_t *cloned_program);

evoasm_success_t
evoasm_program_destroy(evoasm_program_t *program);

void
evoasm_program_io_destroy(evoasm_program_io_t *program_io);

evoasm_success_t
evoasm_program_eliminate_introns(evoasm_program_t *program);

#define evoasm_program_output_destroy(program_output) \
  evoasm_program_io_destroy((evoasm_program_io *)program_output)

void
evoasm_program_output_regs(evoasm_program_t *program, evoasm_reg_id_t *output_regs, size_t *len);
