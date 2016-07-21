#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "evoasm.h"
#include "evoasm-buf.h"
#include "evoasm-x64.h"

typedef double evoasm_loss_t;
typedef uint8_t evoasm_adf_size_t;

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

#define EVOASM_ADF_IO_MAX_ARITY 8

typedef struct {
  uint8_t arity;
  uint16_t len;
  evoasm_example_val_t *vals;
  evoasm_example_type_t types[EVOASM_ADF_IO_MAX_ARITY];
} evoasm_adf_io_t;

#define EVOASM_ADF_OUTPUT_MAX_ARITY EVOASM_ADF_IO_MAX_ARITY
#define EVOASM_ADF_INPUT_MAX_ARITY EVOASM_ADF_IO_MAX_ARITY
typedef evoasm_adf_io_t evoasm_adf_output_t;
typedef evoasm_adf_io_t evoasm_adf_input_t;

#define EVOASM_ADF_IO_N_EXAMPLES(adf_io) ((uint16_t)((adf_io)->len / (adf_io)->arity))
#define EVOASM_ADF_INPUT_N_EXAMPLES(adf_input) EVOASM_ADF_IO_N_EXAMPLES((evoasm_adf_io_t *)adf_input)
#define EVOASM_ADF_OUTPUT_N_EXAMPLES(adf_output) EVOASM_ADF_IO_N_EXAMPLES((evoasm_adf_io_t *)adf_output)

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
  evoasm_adf_size_t size;
} evoasm_adf_params_t;

#define EVOASM_KERNEL_MAX_OUTPUT_REGS 254
#define EVOASM_KERNEL_MAX_INPUT_REGS 254
#define EVOASM_ADF_MAX_SIZE 64

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
  evoasm_adf_size_t min_adf_size;
  evoasm_adf_size_t max_adf_size;
  evoasm_kernel_size_t min_kernel_size;
  evoasm_kernel_size_t max_kernel_size;
  uint32_t recur_limit;
  uint16_t insts_len;
  uint8_t params_len;
  uint32_t pop_size;
  uint32_t mut_rate;
  evoasm_adf_input_t adf_input;
  evoasm_adf_output_t adf_output;
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
  evoasm_example_type_t types[EVOASM_ADF_OUTPUT_MAX_ARITY];
  evoasm_example_val_t *output_vals;
  evoasm_kernel_t kernels[EVOASM_ADF_MAX_SIZE];
  uint32_t recur_counters[EVOASM_ADF_MAX_SIZE];
  evoasm_adf_params_t *params;
  evoasm_adf_input_t _input;
  evoasm_adf_output_t _output;
  evoasm_search_params_t *search_params;
  evoasm_reg_id_t output_regs[EVOASM_ADF_IO_MAX_ARITY];
  evoasm_buf_t _buf;
  evoasm_buf_t _body_buf;

  union {
    /* register at index i has input i % input_arity */
    uint8_t x64[EVOASM_X64_N_REGS];
  } reg_inputs;

} evoasm_adf_t;

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
  unsigned char *adfs;
  unsigned char *adfs_main;
  unsigned char *adfs_swap;
  unsigned char *adfs_aux;
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

typedef bool (*evoasm_search_result_func_t)(evoasm_adf_t *adf,
                                         evoasm_loss_t loss, void *user_data);

void
evoasm_search_start(evoasm_search_t *search, evoasm_search_result_func_t func, void *user_data);

bool
evoasm_adf_run(evoasm_adf_t *adf,
               evoasm_adf_input_t *input,
               evoasm_adf_output_t *output);


evoasm_success_t
evoasm_adf_clone(evoasm_adf_t *adf, evoasm_adf_t *cloned_adf);

evoasm_success_t
evoasm_adf_destroy(evoasm_adf_t *adf);

void
evoasm_adf_io_destroy(evoasm_adf_io_t *adf_io);

evoasm_success_t
evoasm_adf_eliminate_introns(evoasm_adf_t *adf);

#define evoasm_adf_output_destroy(adf_output) \
  evoasm_adf_io_destroy((evoasm_adf_io *)adf_output)

void
evoasm_adf_output_regs(evoasm_adf_t *adf, evoasm_reg_id_t *output_regs, size_t *len);
