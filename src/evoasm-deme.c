//
// Created by jap on 9/16/16.
//

#if !defined(_DEFAULT_SOURCE)
#  define _DEFAULT_SOURCE
#endif

#if defined(__linux__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
#endif

#include "evoasm-deme.h"
#include "evoasm-error.h"
#include "evoasm-adf.h"

#include <stdalign.h>

EVOASM_DECL_LOG_TAG("deme")

#define _EVOASM_DEME_ADF_PARAMS_FULL(deme, adf_index, ptr) \
  ((evoasm_adf_params_t *)((unsigned char *)(deme)->ptr +\
  (adf_index) * EVOASM_ADF_SIZE(deme->params->max_adf_size, deme->params->max_kernel_size)))

#define _EVOASM_DEME_ADF_PARAMS(deme, adf_index) _EVOASM_DEME_ADF_PARAMS_FULL(deme, adf_index, main_adfs)

#define _EVOASM_ADF_PARAMS_KERNEL_PARAMS(adf_params, max_kernel_size, kernel_index) \
  ((evoasm_kernel_params_t *)((unsigned char *)(adf_params) + sizeof(evoasm_adf_params_t) + (kernel_index) * EVOASM_KERNEL_SIZE(max_kernel_size)))

#define EVOASM_ADF_OUTPUT_VALS_SIZE(io) \
      ((size_t)EVOASM_ADF_IO_N_EXAMPLES(io) * \
       (size_t)EVOASM_KERNEL_MAX_OUTPUT_REGS * \
       sizeof(evoasm_example_val_t))

#if (defined(__linux__) || defined(__unix__) || defined(__unix) || \
    (defined(__APPLE__) && defined(__MACH__)))

#define EVOASM_SEARCH_PROLOG_EPILOG_SIZE UINT32_C(1024)

#include <setjmp.h>
#include <stdio.h>
#include <signal.h>
#include <stdatomic.h>
#include <gen/evoasm-x64-params.h>

#define _EVOASM_SIGNAL_CONTEXT_TRY(signal_ctx) (sigsetjmp((signal_ctx)->env, 1) == 0)
#define _EVOASM_SEARCH_EXCEPTION_SET_P(exc) (_evoasm_signal_ctx->exception_mask & (1 << exc))

struct evoasm_signal_context {
  uint32_t exception_mask;
  sigjmp_buf env;
  struct sigaction prev_action;
  evoasm_arch_id_t arch_id;
};


_Thread_local volatile struct evoasm_signal_context *_evoasm_signal_ctx;

static void
_evoasm_signal_handler(int sig, siginfo_t *siginfo, void *ctx) {
  bool handle = false;

  atomic_signal_fence(memory_order_acquire);

  switch(_evoasm_signal_ctx->arch_id) {
    case EVOASM_ARCH_X64: {
      switch(sig) {
        case SIGFPE: {
          bool catch_div_by_zero = siginfo->si_code == FPE_INTDIV &&
                                   _EVOASM_SEARCH_EXCEPTION_SET_P(EVOASM_X64_EXCEPTION_DE);
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
    siglongjmp(*((jmp_buf *) &_evoasm_signal_ctx->env), 1);
  } else {
    raise(sig);
  }
}

static void
evoasm_signal_context_install(struct evoasm_signal_context *signal_ctx, evoasm_arch_id_t arch_id) {
  struct sigaction action = {0};

  signal_ctx->arch_id = arch_id;

  action.sa_sigaction = _evoasm_signal_handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO;

  if(sigaction(SIGFPE, &action, &signal_ctx->prev_action) < 0) {
    perror("sigaction");
    exit(1);
  }

  _evoasm_signal_ctx = signal_ctx;
  atomic_signal_fence(memory_order_release);
}

static void
evoasm_signal_context_uninstall(struct evoasm_signal_context *signal_ctx) {
  if(sigaction(SIGFPE, &signal_ctx->prev_action, NULL) < 0) {
    perror("sigaction");
    exit(1);
  }
}

#else
#error
#endif

static inline double
evoasm_example_val_to_dbl(evoasm_example_val_t example_val, evoasm_example_type_t example_type) {
  switch(example_type) {
    case EVOASM_EXAMPLE_TYPE_F64:
      return example_val.f64;
    case EVOASM_EXAMPLE_TYPE_I64:
      return (double) example_val.i64;
    default:
      evoasm_fatal("unsupported example type %d", example_type);
      evoasm_assert_not_reached();
  }
}

static bool
_evoasm_deme_destroy(evoasm_deme_t *deme, bool free_buf, bool free_body_buf) {
  bool retval = true;

  evoasm_free(deme->adfs);
  evoasm_free(deme->output_vals);
  evoasm_free(deme->matching);
  evoasm_free(deme->losses);
  evoasm_free(deme->error_counters);
  evoasm_free(deme->domains);

  if(free_buf) EVOASM_TRY(buf_free_failed, evoasm_buf_destroy, &deme->buf);

cleanup:
  if(free_body_buf) EVOASM_TRY(body_buf_failed, evoasm_buf_destroy, &deme->body_buf);
  return retval;

buf_free_failed:
  retval = false;
  goto cleanup;

body_buf_failed:
  return false;
}

evoasm_success_t
evoasm_deme_init_domains(evoasm_deme_t *deme) {
  unsigned i, j, k;
  evoasm_domain_t cloned_domain;

  size_t domains_len = (size_t) (deme->params->n_insts * deme->params->n_params);
  deme->domains = evoasm_calloc(domains_len,
                                sizeof(evoasm_domain_t));

  if(!deme->domains) goto fail;

  for(i = 0; i < deme->params->n_insts; i++) {
    evoasm_x64_inst_t *inst = _evoasm_x64_inst(deme->params->inst_ids[i]);
    for(j = 0; j < deme->params->n_params; j++) {
      evoasm_domain_t *inst_domain = &deme->domains[i * deme->params->n_params + j];
      evoasm_param_id_t param_id = deme->params->param_ids[j];
      for(k = 0; k < inst->n_params; k++) {
        evoasm_param_t *param = &inst->params[k];
        if(param->id == param_id) {
          evoasm_domain_t *user_domain = deme->params->domains[param_id];
          if(user_domain != NULL) {
            if(evoasm_domain_empty(user_domain)) goto empty_domain;

            evoasm_domain_clone(user_domain, &cloned_domain);
            evoasm_domain_intersect(&cloned_domain, param->domain, inst_domain);
            if(evoasm_domain_empty(inst_domain)) goto empty_domain;
          } else {
            evoasm_domain_clone(param->domain, inst_domain);
          }
          goto found;
        }
      }
      /* not found */
      inst_domain->type = EVOASM_N_DOMAIN_TYPES;
found:;
    }
  }

  /*
  for(i = 0; i < domains_len; i++) {
    evoasm_domain_log(&deme->domains[i], EVOASM_LOG_LEVEL_WARN);
  }*/

  return true;

fail:
  return false;

empty_domain:
  evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
                   NULL, "Empty domain");
  return false;
}


static evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme, evoasm_arch_id_t arch_id, evoasm_deme_params_t *params) {

  if(!evoasm_deme_params_valid(params)) {
    goto invalid_params;
  }

  uint32_t deme_len = params->size;
  unsigned i;

  static evoasm_deme_t zero_deme = {0};
  *deme = zero_deme;

  deme->arch_info = evoasm_arch_info(arch_id);
  deme->params = params;

  /* FIXME: find a way to calculate tighter bound */
  size_t body_buf_size = (size_t) (2 * params->max_adf_size * params->max_kernel_size *
                                   deme->arch_info->max_inst_len);
  unsigned n_examples = EVOASM_ADF_INPUT_N_EXAMPLES(params->adf_input);
  size_t buf_size = n_examples * (body_buf_size + EVOASM_SEARCH_PROLOG_EPILOG_SIZE);
  size_t adf_size = EVOASM_ADF_SIZE(params->max_adf_size, params->max_kernel_size);
  size_t swap_len = 2;

  deme->adfs = evoasm_calloc(deme_len + swap_len, adf_size);
  if(!deme->adfs) goto alloc_failed;

  deme->main_adfs = deme->adfs;
  deme->swap_adfs = deme->adfs + (params->size * adf_size);

  deme->output_vals = evoasm_malloc(EVOASM_ADF_OUTPUT_VALS_SIZE(params->adf_input));
  if(!deme->output_vals) goto alloc_failed;

  deme->matching = evoasm_malloc(params->adf_output->arity * sizeof(uint_fast8_t));
  if(!deme->matching) goto alloc_failed;

  deme->losses = (evoasm_loss_t *) evoasm_calloc(deme_len, sizeof(evoasm_loss_t));
  if(!deme->losses) goto alloc_failed;

  deme->best_loss = INFINITY;

  deme->error_counters = evoasm_calloc(n_examples, sizeof(uint64_t));
  if(!deme->error_counters) goto alloc_failed;
  deme->error_counter = 0;

  EVOASM_TRY(domains_init_failed, evoasm_deme_init_domains, deme);

  EVOASM_TRY(buf_alloc_failed, evoasm_buf_init, &deme->buf, EVOASM_BUF_TYPE_MMAP, buf_size);
  EVOASM_TRY(body_buf_alloc_failed, evoasm_buf_init, &deme->body_buf, EVOASM_BUF_TYPE_MALLOC, body_buf_size);

  EVOASM_TRY(prot_failed, evoasm_buf_protect, &deme->buf,
             EVOASM_MPROT_RWX);


  return true;

invalid_params:
  return false;

alloc_failed:
domains_init_failed:
buf_alloc_failed:
  _evoasm_deme_destroy(deme, false, false);
  return false;

body_buf_alloc_failed:
  _evoasm_deme_destroy(deme, true, false);
  return false;

prot_failed:
  _evoasm_deme_destroy(deme, true, true);
  return false;
}

static evoasm_success_t
evoasm_deme_destroy(evoasm_deme_t *deme) {
  return _evoasm_deme_destroy(deme, true, true);
}

#define EVOASM_SEARCH_X64_REG_TMP EVOASM_X64_REG_14


static evoasm_success_t
evoasm_adf_x64_emit_output_store(evoasm_adf_t *adf,
                                 unsigned example_index) {

  evoasm_x64_params_t params = {0};
  evoasm_kernel_t *kernel = &adf->kernels[adf->params->size - 1];
  evoasm_buf_t *buf = adf->buf;
  unsigned i;

  for(i = 0; i < kernel->n_output_regs; i++) {
    evoasm_x64_reg_id_t reg_id = kernel->output_regs.x64[i];
    evoasm_example_val_t *val_addr = &adf->output_vals[(example_index * kernel->n_output_regs) + i];
    evoasm_x64_reg_type_t reg_type = evoasm_x64_reg_type(reg_id);

    evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) val_addr;

    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_SEARCH_X64_REG_TMP);
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
    EVOASM_X64_ENC(mov_r64_imm64);

    switch(reg_type) {
      case EVOASM_X64_REG_TYPE_GP: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_SEARCH_X64_REG_TMP);
        EVOASM_X64_ENC(mov_rm64_r64);
        break;
      }
      case EVOASM_X64_REG_TYPE_XMM: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_SEARCH_X64_REG_TMP);
        EVOASM_X64_ENC(movsd_xmmm64_xmm);
        break;
      }
      default: {
        evoasm_assert_not_reached();
      }
    }
  }

  return true;

enc_failed:
  return false;
}

static void evoasm_deme_x64_seed_kernel_param(evoasm_deme_t *deme, evoasm_x64_kernel_param_t *kernel_param) {
  unsigned i;
  int64_t inst_idx = _evoasm_prng_rand_between(deme->params->prng, 0, deme->params->n_insts - 1);
  evoasm_inst_id_t inst = deme->params->inst_ids[inst_idx];

  kernel_param->inst = (unsigned) inst & EVOASM_X64_INST_BITMASK;

  /* set parameters */
  for(i = 0; i < deme->params->n_params; i++) {
    evoasm_domain_t *domain = &deme->domains[inst_idx * deme->params->n_params + i];
    if(domain->type < EVOASM_N_DOMAIN_TYPES) {
      evoasm_x64_param_id_t param_id = (evoasm_x64_param_id_t) deme->params->param_ids[i];
      evoasm_param_val_t param_val;

      param_val = (evoasm_param_val_t) evoasm_domain_rand(domain, deme->params->prng);
      _evoasm_x64_basic_params_set(&kernel_param->params, param_id, param_val);
    }
  }
}

static void
evoasm_deme_seed_kernel_param(evoasm_deme_t *deme, evoasm_kernel_param_t *kernel_param) {
  switch(deme->arch_info->id) {
    case EVOASM_ARCH_X64: {
      evoasm_deme_x64_seed_kernel_param(deme, &kernel_param->x64);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_deme_seed_kernel(evoasm_deme_t *deme, evoasm_kernel_params_t *kernel_params,
                        evoasm_adf_size_t adf_size) {
  unsigned i;

  evoasm_kernel_size_t kernel_size = (evoasm_kernel_size_t) _evoasm_prng_rand_between(deme->params->prng,
                                                                                      deme->params->min_kernel_size,
                                                                                      deme->params->max_kernel_size);

  assert(kernel_size > 0);
  kernel_params->size = kernel_size;
  kernel_params->jmp_selector = (uint8_t) _evoasm_prng_rand8(deme->params->prng);
  kernel_params->alt_succ_idx = (evoasm_kernel_size_t)
      _evoasm_prng_rand_between(deme->params->prng, 0, adf_size - 1);

  for(i = 0; i < kernel_size; i++) {
    evoasm_deme_seed_kernel_param(deme, &kernel_params->params[i]);
  }
}


static void
evoasm_deme_seed_adf(evoasm_deme_t *deme, unsigned adf_index) {
  unsigned i;

  evoasm_adf_params_t *adf_params = _EVOASM_DEME_ADF_PARAMS(deme, adf_index);
  evoasm_adf_size_t adf_size = (evoasm_adf_size_t) _evoasm_prng_rand_between(&deme->prng,
                                                                             deme->params->min_adf_size,
                                                                             deme->params->max_adf_size);

  assert(adf_size > 0);
  adf_params->size = adf_size;

  for(i = 0; i < adf_size; i++) {
    evoasm_kernel_params_t *kernel_params = _EVOASM_ADF_PARAMS_KERNEL_PARAMS(adf_params,
                                                                             deme->params->max_kernel_size,
                                                                             i);
    evoasm_deme_seed_kernel(deme, kernel_params, adf_size);
  }

}


void
evoasm_deme_seed(evoasm_deme_t *deme) {
  unsigned i;

  for(i = 0; i < deme->params->size; i++) {
    evoasm_deme_seed_adf(deme, i);
  }
}


static evoasm_success_t
evoasm_adf_x64_emit_rflags_reset(evoasm_adf_t *adf) {
  evoasm_x64_params_t params = {0};
  evoasm_buf_t *buf = adf->buf;

  evoasm_debug("emitting RFLAGS reset");
  EVOASM_X64_ENC(pushfq);
  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_X64_REG_SP);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM, 0);
  EVOASM_X64_ENC(mov_rm64_imm32);
  EVOASM_X64_ENC(popfq);

  return true;
enc_failed:
  return false;
}

static evoasm_success_t
evoasm_deme_x64_emit_mxcsr_reset(evoasm_deme_t *deme, evoasm_buf_t *buf) {
  static uint32_t default_mxcsr_val = 0x1f80;
  evoasm_x64_params_t params = {0};
  evoasm_param_val_t addr_imm = (evoasm_param_val_t) (uintptr_t) &default_mxcsr_val;

  evoasm_x64_reg_id_t reg_tmp0 = EVOASM_SEARCH_X64_REG_TMP;

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg_tmp0);
  EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, addr_imm);
  EVOASM_X64_ENC(mov_r32_imm32);

  EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, reg_tmp0);
  EVOASM_X64_ENC(ldmxcsr_m32);

  return true;
enc_failed:
  return false;
}


static evoasm_x64_reg_id_t
evoasm_op_x64_reg_id(evoasm_x64_operand_t *op, evoasm_kernel_param_t *param) {
  evoasm_x64_inst_t *inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);

  if(op->param_idx < inst->n_params) {
    return (evoasm_x64_reg_id_t) _evoasm_x64_basic_params_get(&param->x64.params,
                                                              (evoasm_x64_param_id_t) inst->params[op->param_idx].id);
  } else if(op->reg_id < EVOASM_X64_N_REGS) {
    return (evoasm_x64_reg_id_t) op->reg_id;
  } else {
    evoasm_assert_not_reached();
    return 0;
  }
}

typedef struct {
  bool high_byte_reg : 1;
  unsigned mask;
  unsigned size;
} evoasm_x64_reg_write_acc_t;

static void
evoasm_adf_unprepare_kernel(evoasm_adf_t *adf, evoasm_kernel_t *kernel) {
  kernel->n_input_regs = 0;
  kernel->n_output_regs = 0;

  static evoasm_kernel_reg_info_t zero_reg_info = {0};
  kernel->reg_info = zero_reg_info;
}

static void
evoasm_adf_unprepare(evoasm_adf_t *adf) {
  unsigned i;
  for(i = 0; i < adf->params->size; i++) {
    evoasm_adf_unprepare_kernel(adf, &adf->kernels[i]);
  }
}

static void
evoasm_x64_reg_write_acc_init(evoasm_x64_reg_write_acc_t *reg_write_acc) {
  static evoasm_x64_reg_write_acc_t zero_reg_write_acc = {0};
  *reg_write_acc = zero_reg_write_acc;

  reg_write_acc->size = EVOASM_X64_N_OPERAND_SIZES;
}

static void
evoasm_x64_reg_write_acc_update(evoasm_x64_reg_write_acc_t *reg_write_acc,
                                evoasm_x64_operand_t *op, evoasm_kernel_param_t *param) {
  if(reg_write_acc->size < EVOASM_X64_N_OPERAND_SIZES) {
    reg_write_acc->size = EVOASM_MAX(reg_write_acc->size, op->size1);
  } else {
    reg_write_acc->size = op->size1;
  }

  reg_write_acc->mask |= op->write_mask;
  reg_write_acc->high_byte_reg |= param->x64.params.reg0_high_byte || param->x64.params.reg1_high_byte;
}


static bool
evoasm_x64_reg_write_acc_is_dirty_read(evoasm_x64_reg_write_acc_t *reg_write_acc, evoasm_x64_operand_t *op,
                                       evoasm_kernel_param_t *param) {
  bool uncovered_acc;
  bool high_byte_reg = param->x64.params.reg0_high_byte || param->x64.params.reg1_high_byte;

  assert(reg_write_acc->size <= EVOASM_X64_N_OPERAND_SIZES);
  if(reg_write_acc->size == EVOASM_X64_N_OPERAND_SIZES) {
    return true;
  }

  if(op->reg_type == EVOASM_X64_REG_TYPE_GP) {
    /* 32bit writes clear the whole register */
    if(reg_write_acc->size >= EVOASM_X64_OPERAND_SIZE_32) {
      uncovered_acc = false;
    } else {
      if(op->size1 == EVOASM_X64_OPERAND_SIZE_8 &&
         reg_write_acc->size == EVOASM_X64_OPERAND_SIZE_8) {
        uncovered_acc = high_byte_reg != reg_write_acc->high_byte_reg;
      } else {
        uncovered_acc = reg_write_acc->size < op->size1;
      }
    }
  } else if(op->reg_type == EVOASM_X64_REG_TYPE_XMM) {
    unsigned mask;
    if(op->size1 == EVOASM_X64_OPERAND_SIZE_128) {
      mask = EVOASM_X64_BIT_MASK_0_127;
    } else {
      mask = EVOASM_X64_BIT_MASK_ALL;
    }
    uncovered_acc = ((mask & (~reg_write_acc->mask)) != 0);
  } else {
    uncovered_acc = false;
  }

  return uncovered_acc;
}


static void
evoasm_adf_x64_prepare_kernel(evoasm_adf_t *adf, evoasm_kernel_t *kernel) {
  unsigned i, j;

  /* NOTE: output register are register that are written to
   *       _input registers are register that are read from without
   *       a previous write
   */
  evoasm_kernel_params_t *kernel_params = kernel->params;

  evoasm_x64_reg_write_acc_t reg_write_accs[EVOASM_X64_N_REGS];
  for(i = 0; i < EVOASM_X64_N_REGS; i++) {
    evoasm_x64_reg_write_acc_init(&reg_write_accs[i]);
  }

  for(i = 0; i < kernel_params->size; i++) {
    evoasm_kernel_param_t *param = &kernel_params->params[i];
    evoasm_x64_inst_t *x64_inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);

    for(j = 0; j < x64_inst->n_operands; j++) {
      evoasm_x64_operand_t *op = &x64_inst->operands[j];

      if(op->type == EVOASM_X64_OPERAND_TYPE_REG ||
         op->type == EVOASM_X64_OPERAND_TYPE_RM) {

        if(op->reg_type == EVOASM_X64_REG_TYPE_RFLAGS) {
          if(op->read) {
            adf->reset_rflags = true;
          } else if(op->written) {
            kernel->reg_info.x64[op->reg_id].written = true;
          }
        } else {
          evoasm_x64_reg_id_t reg_id = evoasm_op_x64_reg_id(op, param);
          evoasm_kernel_x64_reg_info_t *reg_info = &kernel->reg_info.x64[reg_id];
          evoasm_x64_reg_write_acc_t *reg_write_acc = &reg_write_accs[reg_id];

          /*
           * Conditional writes (cond_written) might or might not do the write.
           */

          if(op->read || op->cond_written) {
            if(!reg_info->input) {
              // has not been written before, might contain garbage
              bool dirty_read;

              if(!reg_info->written) {
                dirty_read = true;
              } else {
                dirty_read = evoasm_x64_reg_write_acc_is_dirty_read(reg_write_acc, op, param);
              }

              if(dirty_read) {
                reg_info->input = true;
                kernel->n_input_regs++;
              }
            }
          }

          if(op->written) {

            if(!reg_info->written) {
              reg_info->written = true;
              reg_info->output = true;
              kernel->output_regs.x64[kernel->n_output_regs] = reg_id;
              kernel->n_output_regs++;
            }

            evoasm_x64_reg_write_acc_update(reg_write_acc, op, param);
          }
        }
      }
    }
  }

  assert(kernel->n_output_regs <= EVOASM_KERNEL_MAX_OUTPUT_REGS);
  assert(kernel->n_input_regs <= EVOASM_KERNEL_MAX_INPUT_REGS);
}

static void
evoasm_adf_x64_prepare(evoasm_adf_t *adf) {
  unsigned i;
  for(i = 0; i < adf->params->size; i++) {
    evoasm_kernel_t *kernel = &adf->kernels[i];
    evoasm_adf_x64_prepare_kernel(adf, kernel);
  }

}

static evoasm_success_t
evoasm_adf_x64_emit_input_load(evoasm_adf_t *adf,
                               evoasm_kernel_t *kernel,
                               evoasm_example_val_t *input_vals,
                               evoasm_example_type_t *types,
                               unsigned in_arity,
                               bool set_io_mapping) {


  evoasm_example_val_t *loaded_example = NULL;
  evoasm_x64_reg_id_t input_reg_id;
  unsigned input_reg_idx;
  evoasm_buf_t *buf = adf->buf;

  evoasm_debug("n _input regs %d", kernel->n_input_regs);
#if 1
  for(input_reg_id = (evoasm_x64_reg_id_t) 9; input_reg_id < 25; input_reg_id++) {
    if(input_reg_id == EVOASM_X64_REG_SP) continue;
    evoasm_x64_params_t params = {0};
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
    /*FIXME: hard-coded example type */
    EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, 0);
    EVOASM_X64_ENC(mov_r64_imm64);
  }
#endif

  for(input_reg_id = (evoasm_x64_reg_id_t) 0, input_reg_idx = 0; input_reg_idx < kernel->n_input_regs; input_reg_id++) {
    if(!kernel->reg_info.x64[input_reg_id].input) continue;

    unsigned example_idx;

    if(set_io_mapping) {
      example_idx = input_reg_idx % in_arity;
      adf->reg_inputs.x64[input_reg_id] = (uint8_t) example_idx;
    } else {
      example_idx = adf->reg_inputs.x64[input_reg_id];
    }

    evoasm_example_val_t *example = &input_vals[example_idx];
    evoasm_x64_params_t params = {0};
    evoasm_x64_reg_type_t reg_type = evoasm_x64_reg_type(input_reg_id);

    evoasm_debug("emitting _input register initialization of register %d to value %"
                     PRId64, input_reg_id, example->i64);

    switch(reg_type) {
      case EVOASM_X64_REG_TYPE_GP: {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        /*FIXME: hard-coded example type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) example->i64);
        EVOASM_X64_ENC(mov_r64_imm64);
        break;
      }
      case EVOASM_X64_REG_TYPE_XMM: {
        /* load address of example into tmp_reg */
        if(loaded_example != example) {
          EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_SEARCH_X64_REG_TMP);
          EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) (uintptr_t) &example->f64);
          EVOASM_X64_ENC(mov_r64_imm64);
          loaded_example = example;
        }

        /* load into xmm via address in tmp_reg */
        /*FIXME: hard-coded example type */
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_SEARCH_X64_REG_TMP);
        EVOASM_X64_ENC(movsd_xmm_xmmm64);
        break;
      }
      default:
        evoasm_fatal("non-gpr register type (%d) (unimplemented)", reg_type);
        evoasm_assert_not_reached();
    }

    input_reg_idx++;
  }

  if(adf->reset_rflags) {
    EVOASM_TRY(error, evoasm_adf_x64_emit_rflags_reset, adf);
  }
  return true;

error:
enc_failed:
  return false;
}

static evoasm_success_t
evoasm_adf_x64_emit_kernel_transition(evoasm_adf_t *adf,
                                      evoasm_kernel_t *kernel,
                                      evoasm_kernel_t *target_kernel,
                                      evoasm_buf_t *buf,
                                      unsigned trans_idx,
                                      bool set_io_mapping) {
  unsigned input_reg_idx;
  evoasm_x64_reg_id_t input_reg_id;

  assert(kernel->n_output_regs > 0);

  for(input_reg_id = (evoasm_x64_reg_id_t) 0, input_reg_idx = 0; input_reg_id < EVOASM_X64_N_REGS; input_reg_id++) {
    if(!target_kernel->reg_info.x64[input_reg_id].input) continue;

    evoasm_x64_reg_id_t output_reg_id;

    if(set_io_mapping) {
      unsigned output_reg_idx = input_reg_idx % kernel->n_output_regs;
      output_reg_id = kernel->output_regs.x64[output_reg_idx];

      kernel->reg_info.x64[input_reg_id].trans_regs[trans_idx] = output_reg_id;
    } else {
      output_reg_id = kernel->reg_info.x64[input_reg_id].trans_regs[trans_idx];
    }

    evoasm_x64_reg_type_t output_reg_type = evoasm_x64_reg_type(output_reg_id);
    evoasm_x64_reg_type_t input_reg_type = evoasm_x64_reg_type(input_reg_id);
    evoasm_x64_params_t params = {0};

    if(input_reg_id != output_reg_id) {
      if(output_reg_type == EVOASM_X64_REG_TYPE_GP &&
         input_reg_type == EVOASM_X64_REG_TYPE_GP) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
        EVOASM_X64_ENC(mov_r64_rm64);
      } else if(output_reg_type == EVOASM_X64_REG_TYPE_XMM &&
                input_reg_type == EVOASM_X64_REG_TYPE_XMM) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
        if(adf->arch_info->features & EVOASM_X64_FEATURE_AVX) {
          EVOASM_X64_ENC(vmovdqa_ymm_ymmm256);
        } else {
          EVOASM_X64_ENC(movdqa_xmm_xmmm128);
        }
      } else if(output_reg_type == EVOASM_X64_REG_TYPE_GP &&
                input_reg_type == EVOASM_X64_REG_TYPE_XMM) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
        if(adf->arch_info->features & EVOASM_X64_FEATURE_AVX) {
          EVOASM_X64_ENC(vmovq_xmm_rm64);
        } else {
          EVOASM_X64_ENC(movq_xmm_rm64);
        }
      } else if(output_reg_type == EVOASM_X64_REG_TYPE_XMM &&
                input_reg_type == EVOASM_X64_REG_TYPE_GP) {
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, input_reg_id);
        EVOASM_X64_SET(EVOASM_X64_PARAM_REG1, output_reg_id);
        if(adf->arch_info->features & EVOASM_X64_FEATURE_AVX) {
          EVOASM_X64_ENC(vmovq_rm64_xmm);
        } else {
          EVOASM_X64_ENC(movq_rm64_xmm);
        }
      } else {
        evoasm_assert_not_reached();
      }
    }
    input_reg_idx++;
  }

  return true;

enc_failed:
  return false;
}

#define _EVOASM_BUF_PHI_GET(buf) ((uint32_t *)((buf)->data + (buf)->pos - 4))
#define _EVOASM_BUF_PHI_SET(label, val) \
do { (*(label) = (uint32_t)((uint8_t *)(val) - ((uint8_t *)(label) + 4)));} while(0);
#define _EVOASM_BUF_POS_ADDR(buf) (buf->data + buf->pos)

static evoasm_success_t
evoasm_adf_x64_emit_kernel_transitions(evoasm_adf_t *adf,
                                       evoasm_kernel_t *kernel,
                                       evoasm_kernel_t *next_kernel,
                                       evoasm_kernel_t *branch_kernel,
                                       evoasm_buf_t *buf,
                                       uint32_t **branch_kernel_phi,
                                       bool set_io_mapping) {

  unsigned jmp_insts_len = 0;
  evoasm_inst_id_t jmp_insts[32];
  bool jbe = false;
  bool jle = false;
  evoasm_x64_params_t params = {0};
  uint32_t *branch_phi = NULL;
  uint32_t *counter_phi = NULL;

  if(adf->deme_params->recur_limit == 0) goto next_trans;

  if(kernel->reg_info.x64[EVOASM_X64_REG_OF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JO_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNO_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_SF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JS_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNS_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_ZF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JE_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNS_REL32;

    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JBE_REL32;
    jbe = true;

    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JLE_REL32;
    jle = true;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_CF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JB_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JAE_REL32;

    if(!jbe) {
      jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JBE_REL32;
    }
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_ZF].written &&
     kernel->reg_info.x64[EVOASM_X64_REG_CF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JA_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_SF].written &&
     kernel->reg_info.x64[EVOASM_X64_REG_OF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JL_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JGE_REL32;

    if(!jle) {
      jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JLE_REL32;
    }

    if(kernel->reg_info.x64[EVOASM_X64_REG_ZF].written) {
      jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JG_REL32;
    }
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_CF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JB_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JAE_REL32;
  }

  if(kernel->reg_info.x64[EVOASM_X64_REG_PF].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JP_REL32;
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JNP_REL32;
  }

#if 0
  /*FIXME: only 8bit possible, check and activate if feasable*/
  if(kernel->reg_info.x64[EVOASM_X64_REG_C].written) {
    jmp_insts[jmp_insts_len++] = EVOASM_X64_INST_JECXZ_JRCXZ_REL8;
  }
#endif

  if(jmp_insts_len > 0 && jmp_insts_len < (unsigned) (kernel->params->size - 1)) {
    evoasm_buf_ref_t buf_ref = {
        .data = buf->data,
        .pos = &buf->pos
    };
    evoasm_inst_id_t jmp_inst_id = jmp_insts[kernel->params->jmp_selector % jmp_insts_len];
    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_TRY(error, _evoasm_x64_enc, (evoasm_x64_inst_id_t) jmp_inst_id, &params, &buf_ref);
    branch_phi = _EVOASM_BUF_PHI_GET(buf);
    assert(*branch_phi == 0xdeadbeef);

    if(branch_kernel->idx <= kernel->idx) {
      /* back jump, guard with counter */

      uint32_t *counter = &adf->recur_counters[kernel->idx];
      uintptr_t addr_imm = (uintptr_t) counter;

      EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, EVOASM_SEARCH_X64_REG_TMP);
      EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, (evoasm_param_val_t) addr_imm);
      EVOASM_X64_ENC(mov_r64_imm64);

      EVOASM_X64_SET(EVOASM_X64_PARAM_REG_BASE, EVOASM_SEARCH_X64_REG_TMP);
      EVOASM_X64_SET(EVOASM_X64_PARAM_IMM0, adf->deme_params->recur_limit);
      EVOASM_X64_ENC(cmp_rm32_imm32);

      EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
      EVOASM_X64_ENC(jge_rel32);

      counter_phi = _EVOASM_BUF_PHI_GET(buf);
      assert(*counter_phi == 0xdeadbeef);

      EVOASM_X64_ENC(inc_rm32);
    }

    EVOASM_TRY(error, evoasm_adf_x64_emit_kernel_transition, adf,
               kernel, branch_kernel, buf, 1, set_io_mapping);

    EVOASM_X64_SET(EVOASM_X64_PARAM_REL, 0xdeadbeef);
    EVOASM_X64_ENC(jmp_rel32);

    *branch_kernel_phi = _EVOASM_BUF_PHI_GET(buf);
    assert(**branch_kernel_phi == 0xdeadbeef);
  }

  if(branch_phi != NULL) {
    _EVOASM_BUF_PHI_SET(branch_phi, _EVOASM_BUF_POS_ADDR(buf));
  }

  if(counter_phi != NULL) {
    _EVOASM_BUF_PHI_SET(counter_phi, _EVOASM_BUF_POS_ADDR(buf));
  }

next_trans:

  if(next_kernel != NULL) {
    EVOASM_TRY(error, evoasm_adf_x64_emit_kernel_transition, adf,
               kernel, next_kernel, buf, 0, set_io_mapping);
  }

  evoasm_buf_log(buf, EVOASM_LOG_LEVEL_DEBUG);

  return true;

error:
enc_failed:
  return false;
}


static evoasm_success_t
evoasm_adf_x64_emit_kernel(evoasm_adf_t *adf, evoasm_kernel_t *kernel, evoasm_buf_t *buf) {
  unsigned i;
  evoasm_buf_ref_t buf_ref = {
      .data = buf->data,
      .pos = &buf->pos
  };

  evoasm_kernel_params_t *kernel_params = kernel->params;

  assert(kernel_params->size > 0);
  for(i = 0; i < kernel_params->size; i++) {
    evoasm_x64_inst_t *inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) kernel_params->params[i].x64.inst);
    evoasm_x64_inst_t *x64_inst = (evoasm_x64_inst_t *) inst;
    adf->exception_mask = adf->exception_mask | x64_inst->exceptions;
    EVOASM_TRY(error, _evoasm_x64_inst_enc_basic,
               inst,
               &kernel_params->params[i].x64.params, &buf_ref);
  }
  return true;
error:
  return false;
}


static evoasm_success_t
evoasm_adf_x64_emit_adf_kernels(evoasm_adf_t *adf, bool set_io_mapping) {
  unsigned i;
  evoasm_buf_t *buf = adf->body_buf;
  evoasm_adf_params_t *adf_params = adf->params;
  evoasm_kernel_t *kernel, *next_kernel, *branch_kernel;
  unsigned size = adf_params->size;
  uint32_t *branch_phis[EVOASM_ADF_MAX_SIZE] = {0};
  uint8_t *kernel_addrs[EVOASM_ADF_MAX_SIZE];

  evoasm_buf_reset(buf);

  assert(size > 0);

  for(i = 0; i < size; i++) {
    kernel = &adf->kernels[i];

    kernel_addrs[i] = buf->data + buf->pos;
    kernel->buf_start = (uint16_t) buf->pos;

    EVOASM_TRY(error, evoasm_adf_x64_emit_kernel, adf, kernel, buf);

    if(i < size - 1) {
      next_kernel = &adf->kernels[i + 1];
    } else {
      next_kernel = NULL;
    }

    assert(kernel->params->alt_succ_idx < adf->params->size);
    branch_kernel = &adf->kernels[kernel->params->alt_succ_idx];

    EVOASM_TRY(error, evoasm_adf_x64_emit_kernel_transitions, adf, kernel,
               next_kernel, branch_kernel, buf, &branch_phis[i], set_io_mapping);

    kernel->buf_end = (uint16_t) buf->pos;
  }

  for(i = 0; i < size; i++) {
    uint32_t *branch_phi = branch_phis[i];
    if(branch_phi != NULL) {
      kernel = &adf->kernels[i];
      uint8_t *branch_kernel_addr = kernel_addrs[kernel->params->alt_succ_idx];
      assert(*branch_phi == 0xdeadbeef);
      _EVOASM_BUF_PHI_SET(branch_phi, branch_kernel_addr);
    }
  }

  return true;
error:
  return false;
}

static evoasm_success_t
evoasm_adf_x64_emit_io_load_store(evoasm_adf_t *adf,
                                  evoasm_adf_input_t *input,
                                  bool io_mapping) {
  unsigned i;
  unsigned n_examples = EVOASM_ADF_INPUT_N_EXAMPLES(input);
  evoasm_kernel_t *kernel = &adf->kernels[0];

  evoasm_buf_reset(adf->buf);
  EVOASM_TRY(error, evoasm_x64_func_prolog, adf->buf, EVOASM_X64_ABI_SYSV);

  for(i = 0; i < n_examples; i++) {
    evoasm_example_val_t *input_vals = input->vals + i * input->arity;
    EVOASM_TRY(error, evoasm_adf_x64_emit_input_load, adf, kernel, input_vals, input->types, input->arity, io_mapping);
    {
      size_t r = evoasm_buf_append(adf->buf, adf->body_buf);
      assert(r == 0);
    }
    EVOASM_TRY(error, evoasm_adf_x64_emit_output_store, adf, i);
  }

  EVOASM_TRY(error, evoasm_x64_func_epilog, adf->buf, EVOASM_X64_ABI_SYSV);
  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_adf_x64_emit(evoasm_adf_t *adf,
                    evoasm_adf_input_t *input,
                    bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping) {

  if(prepare) {
    evoasm_adf_x64_prepare(adf);
  }

  if(emit_kernels) {
    EVOASM_TRY(error, evoasm_adf_x64_emit_adf_kernels, adf, set_io_mapping);
  }

  if(emit_io_load_store) {
    EVOASM_TRY(error, evoasm_adf_x64_emit_io_load_store, adf, input, set_io_mapping);
  }

  evoasm_buf_log(adf->buf, EVOASM_LOG_LEVEL_DEBUG);


  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_adf_emit(evoasm_adf_t *adf,
                evoasm_adf_input_t *input,
                bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping) {
  switch(adf->arch_info->id) {
    case EVOASM_ARCH_X64: {
      return evoasm_adf_x64_emit(adf, input,
                                 prepare, emit_kernels, emit_io_load_store, set_io_mapping);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

typedef enum {
  EVOASM_METRIC_ABSDIFF,
  EVOASM_N_METRICS
} evoasm_metric;

static inline void
evoasm_adf_update_dist_mat(evoasm_adf_t *adf,
                           evoasm_kernel_t *kernel,
                           evoasm_adf_output_t *output,
                           unsigned height,
                           unsigned example_index,
                           double *dist_mat,
                           evoasm_metric metric) {
  unsigned i, j;
  unsigned width = kernel->n_output_regs;
  evoasm_example_val_t *example_vals = output->vals + example_index * output->arity;

  for(i = 0; i < height; i++) {
    evoasm_example_val_t example_val = example_vals[i];
    evoasm_example_type_t example_type = output->types[i];
    double example_val_dbl = evoasm_example_val_to_dbl(example_val, example_type);

    for(j = 0; j < width; j++) {
      evoasm_example_val_t output_val = adf->output_vals[example_index * width + j];
      //uint8_t output_size = adf->output_sizes[j];
      //switch(output_size) {
      //
      //}
      // FIXME: output is essentially just a bitstring and could be anything
      // an integer (both, signed or unsigned) a float or double.
      // Moreover, a portion of the output value could
      // hold the correct answer (e.g. lower 8 or 16 bits etc.).
      // For now we use the example output type and assume signedness.
      // This needs to be fixed.
      double output_val_dbl = evoasm_example_val_to_dbl(output_val, example_type);

      switch(metric) {
        default:
        case EVOASM_METRIC_ABSDIFF: {
          double dist = fabs(output_val_dbl - example_val_dbl);
          dist_mat[i * width + j] += dist;
          break;
        }
      }
    }
  }
}

static void
evoasm_adf_log_adf_output(evoasm_adf_t *adf,
                          evoasm_kernel_t *kernel,
                          evoasm_adf_output_t *output,
                          uint_fast8_t *const matching,
                          evoasm_log_level_t log_level) {

  unsigned n_examples = EVOASM_ADF_OUTPUT_N_EXAMPLES(output);
  unsigned height = output->arity;
  unsigned width = kernel->n_output_regs;
  unsigned i, j, k;

  evoasm_log(log_level, EVOASM_LOG_TAG, "OUTPUT MATRICES:\n");

  for(i = 0; i < width; i++) {
    evoasm_log(log_level, EVOASM_LOG_TAG, " %d  ", adf->output_regs[i]);
  }

  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");

  for(i = 0; i < n_examples; i++) {
    for(j = 0; j < height; j++) {
      for(k = 0; k < width; k++) {
        bool matched = matching[j] == k;
        evoasm_example_val_t val = adf->output_vals[i * width + k];

        if(matched) {
          evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[1m ");
        }
        evoasm_log(log_level, EVOASM_LOG_TAG, " %ld (%f)\t ", val.i64, val.f64);
        if(matched) {
          evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[0m ");
        }
      }
      evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
    }
    evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");
  }
}

static void
evoasm_adf_log_dist_dist_mat(evoasm_adf_t *adf,
                             evoasm_kernel_t *kernel,
                             unsigned height,
                             double *dist_mat,
                             uint_fast8_t *matching,
                             evoasm_log_level_t log_level) {

  unsigned width = kernel->n_output_regs;
  unsigned i, j;

  evoasm_log(log_level, EVOASM_LOG_TAG, "DIST MATRIX: (%d, %d)\n", height, width);
  for(i = 0; i < height; i++) {
    for(j = 0; j < width; j++) {
      if(matching[i] == j) {
        evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[1m ");
      }
      evoasm_log(log_level, EVOASM_LOG_TAG, " %.2g\t ", dist_mat[i * width + j]);
      if(matching[i] == j) {
        evoasm_log(log_level, EVOASM_LOG_TAG, " \x1b[0m ");
      }
    }
    evoasm_log(log_level, EVOASM_LOG_TAG, " \n ");
  }
  evoasm_log(log_level, EVOASM_LOG_TAG, " \n\n ");
}


static inline bool
evoasm_adf_match(evoasm_adf_t *adf,
                 unsigned width,
                 double *dist_mat,
                 uint_fast8_t *matching) {

  uint_fast8_t best_index = UINT_FAST8_MAX;
  double best_dist = INFINITY;
  uint_fast8_t i;

  for(i = 0; i < width; i++) {
    double v = dist_mat[i];
    if(v < best_dist) {
      best_dist = v;
      best_index = i;
    }
  }

  if(EVOASM_LIKELY(best_index != UINT_FAST8_MAX)) {
    *matching = best_index;
    return true;
  } else {
    /*evoasm_adf_log_dist_dist_mat(adf,
                                  1,
                                  dist_mat,
                                  matching,
                                  EVOASM_LOG_LEVEL_WARN);
    evoasm_assert_not_reached();*/
    /*
     * Might happen if all elements are inf or nan
     */
    return false;
  }
}

static inline void
evoasm_adf_calc_stable_matching(evoasm_adf_t *adf,
                                evoasm_kernel_t *kernel,
                                unsigned height,
                                double *dist_mat,
                                uint_fast8_t *matching) {

  uint_fast8_t width = (uint_fast8_t) kernel->n_output_regs;
  uint_fast8_t *inv_matching = evoasm_alloca(width * sizeof(uint_fast8_t));
  uint_fast8_t i;

  // calculates a stable matching
  for(i = 0; i < height; i++) {
    matching[i] = UINT_FAST8_MAX;
  }

  for(i = 0; i < width; i++) {
    inv_matching[i] = UINT_FAST8_MAX;
  }

  while(true) {
    uint_fast8_t unmatched_index = UINT_FAST8_MAX;
    uint_fast8_t best_index = UINT_FAST8_MAX;
    double best_dist = INFINITY;

    for(i = 0; i < height; i++) {
      if(matching[i] == UINT_FAST8_MAX) {
        unmatched_index = i;
        break;
      }
    }

    if(unmatched_index == UINT_FAST8_MAX) {
      break;
    }

    for(i = 0; i < width; i++) {
      double v = dist_mat[unmatched_index * width + i];
      if(v < best_dist) {
        best_dist = v;
        best_index = i;
      }
    }

    if(EVOASM_LIKELY(best_index != UINT_FAST8_MAX)) {
      if(inv_matching[best_index] == UINT_FAST8_MAX) {
        inv_matching[best_index] = unmatched_index;
        matching[unmatched_index] = best_index;
      } else {
        if(dist_mat[inv_matching[best_index] * width + best_index] > best_dist) {
          matching[inv_matching[best_index]] = UINT_FAST8_MAX;
          inv_matching[best_index] = unmatched_index;
          matching[unmatched_index] = best_index;
        } else {
          //dist_mat[unmatched_index * width + i] = copysign(best_dist, -1.0);
          dist_mat[unmatched_index * width + i] = INFINITY;
        }
      }
    } else {
      evoasm_adf_log_dist_dist_mat(adf,
                                   kernel,
                                   height,
                                   dist_mat,
                                   matching,
                                   EVOASM_LOG_LEVEL_DEBUG);
      evoasm_assert_not_reached();
    }
  }
}


static inline evoasm_loss_t
evoasm_adf_calc_loss(evoasm_adf_t *adf,
                     evoasm_kernel_t *kernel,
                     unsigned height,
                     double *dist_mat,
                     uint_fast8_t *matching) {
  unsigned i;
  unsigned width = kernel->n_output_regs;
  double scale = 1.0 / width;
  evoasm_loss_t loss = 0.0;

  for(i = 0; i < height; i++) {
    loss += scale * dist_mat[i * width + matching[i]];
  }

  return loss;
}

static evoasm_loss_t
evoasm_adf_assess(evoasm_adf_t *adf,
                  evoasm_adf_output_t *output) {

  unsigned i;
  unsigned n_examples = EVOASM_ADF_OUTPUT_N_EXAMPLES(output);
  unsigned height = output->arity;
  evoasm_kernel_t *kernel = &adf->kernels[adf->params->size - 1];
  unsigned width = kernel->n_output_regs;
  size_t dist_mat_len = (size_t) (width * height);
  double *dist_mat = evoasm_alloca(dist_mat_len * sizeof(double));
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));
  evoasm_loss_t loss;

  for(i = 0; i < dist_mat_len; i++) {
    dist_mat[i] = 0.0;
  }

  if(height == 1) {
    /* COMMON FAST-PATH */
    for(i = 0; i < n_examples; i++) {
      evoasm_adf_update_dist_mat(adf, kernel, output, 1, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    if(evoasm_adf_match(adf, width, dist_mat, matching)) {
      loss = evoasm_adf_calc_loss(adf, kernel, 1, dist_mat, matching);
    } else {
      loss = INFINITY;
    }
  } else {
    for(i = 0; i < n_examples; i++) {
      evoasm_adf_update_dist_mat(adf, kernel, output, height, i, dist_mat, EVOASM_METRIC_ABSDIFF);
    }

    evoasm_adf_calc_stable_matching(adf, kernel, height, dist_mat, matching);
    loss = evoasm_adf_calc_loss(adf, kernel, height, dist_mat, matching);
  }


  for(i = 0; i < height; i++) {
    switch(adf->arch_info->id) {
      case EVOASM_ARCH_X64: {
        adf->output_regs[i] = kernel->output_regs.x64[matching[i]];
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }

#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_DEBUG
  if(loss == 0.0) {
    evoasm_adf_log_adf_output(adf,
                              kernel,
                              output,
                              matching,
                              EVOASM_LOG_LEVEL_DEBUG);
  }
#endif

  return loss;
}

static evoasm_adf_output_t *
evoasm_adf_load_output(evoasm_adf_t *adf,
                       evoasm_kernel_t *kernel,
                       evoasm_adf_input_t *input) {

  unsigned i, j;
  unsigned width = kernel->n_output_regs;
  evoasm_adf_output_t *output = &adf->_output;
  unsigned height = output->arity;
  unsigned n_examples = EVOASM_ADF_INPUT_N_EXAMPLES(input);
  uint_fast8_t *matching = evoasm_alloca(height * sizeof(uint_fast8_t));

  evoasm_adf_output_t *load_output = evoasm_adf_io_alloc((uint16_t) (EVOASM_ADF_INPUT_N_EXAMPLES(input) * height));

  for(i = 0; i < height; i++) {
    for(j = 0; j < kernel->n_output_regs; j++) {
      if(adf->output_regs[i] == kernel->output_regs.x64[j]) {
        matching[i] = (uint_fast8_t) j;
        goto next;
      }
    }
    evoasm_fatal("adf output reg %d not found in kernel output regs", adf->output_regs[i]);
    evoasm_assert_not_reached();
next:;
  }

  for(i = 0; i < n_examples; i++) {
    for(j = 0; j < height; j++) {
      load_output->vals[i * height + j] = adf->output_vals[i * width + matching[j]];
    }
  }

  load_output->arity = output->arity;
  memcpy(load_output->types, output->types, EVOASM_ARY_LEN(output->types));

//#if EVOASM_MIN_LOG_LEVEL <= EVOASM_LOG_LEVEL_INFO

  evoasm_adf_log_adf_output(adf,
                            kernel,
                            load_output,
                            matching,
                            EVOASM_LOG_LEVEL_WARN);
//#endif
  return load_output;
}

evoasm_adf_output_t *
evoasm_adf_run(evoasm_adf_t *adf,
               evoasm_adf_input_t *input) {
  struct evoasm_signal_context signal_ctx = {0};
  unsigned i;
  evoasm_kernel_t *kernel = &adf->kernels[adf->params->size - 1];
  evoasm_adf_output_t *output;

  if(input->arity != adf->_input.arity) {
    evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                     "example arity mismatch (%d for %d)", input->arity, adf->_input.arity);
    return NULL;
  }

  for(i = 0; i < input->arity; i++) {
    if(input->types[i] != adf->_input.types[i]) {
      evoasm_set_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES, NULL,
                       "example type mismatch (%d != %d)", input->types[i], adf->_input.types[i]);
      return NULL;
    }
  }

  adf->output_vals = evoasm_alloca(EVOASM_ADF_OUTPUT_VALS_SIZE(input));
  signal_ctx.exception_mask = adf->exception_mask;
  adf->_signal_ctx = &signal_ctx;

  if(!evoasm_adf_emit(adf, input, false, adf->need_emit, true, false)) {
    return NULL;
  }

  adf->need_emit = false;

  if(kernel->n_output_regs == 0) {
    return NULL;
  }

  evoasm_buf_log(adf->buf, EVOASM_LOG_LEVEL_DEBUG);
  evoasm_signal_context_install(&signal_ctx, (evoasm_arch_id_t) adf->arch_info->id);

  if(!evoasm_buf_protect(adf->buf, EVOASM_MPROT_RX)) {
    evoasm_assert_not_reached();
  }

  if(_EVOASM_SIGNAL_CONTEXT_TRY(&signal_ctx)) {
    evoasm_buf_exec(adf->buf);
    output = evoasm_adf_load_output(adf,
                                    kernel,
                                    input);
  } else {
    evoasm_debug("signaled\n");
    output = NULL;
  }

  if(!evoasm_buf_protect(adf->buf, EVOASM_MPROT_RW)) {
    evoasm_assert_not_reached();
  }

  evoasm_signal_context_uninstall(&signal_ctx);

  adf->_signal_ctx = NULL;
  adf->output_vals = NULL;

  return output;
}

static evoasm_success_t
evoasm_deme_eval_adf(evoasm_deme_t *deme,
                     evoasm_adf_t *adf,
                     evoasm_loss_t *loss) {

  evoasm_kernel_t *kernel = &adf->kernels[adf->params->size - 1];

  if(!evoasm_adf_emit(adf, deme->params->adf_input, true, true, true, true)) {
    *loss = INFINITY;
    return false;
  }

  if(EVOASM_UNLIKELY(kernel->n_output_regs == 0)) {
    *loss = INFINITY;
    return true;
  }

  //evoasm_buf_log(adf->buf, EVOASM_LOG_LEVEL_INFO);
  {
    struct evoasm_signal_context *signal_ctx = (struct evoasm_signal_context *) adf->_signal_ctx;
    signal_ctx->exception_mask = adf->exception_mask;

    if(_EVOASM_SIGNAL_CONTEXT_TRY((struct evoasm_signal_context *) adf->_signal_ctx)) {
      evoasm_buf_exec(adf->buf);
      *loss = evoasm_adf_assess(adf, deme->params->adf_output);
    } else {
      evoasm_debug("adf %d signaled", adf->index);
      *loss = INFINITY;
    }
  }
  return true;
}

static bool
evoasm_kernel_param_x64_writes_p(evoasm_kernel_param_t *param, evoasm_reg_id_t reg_id,
                                 evoasm_x64_reg_write_acc_t *reg_write_acc) {
  evoasm_x64_inst_t *x64_inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);
  unsigned i;

  for(i = 0; i < x64_inst->n_operands; i++) {
    evoasm_x64_operand_t *op = &x64_inst->operands[i];
    evoasm_x64_reg_id_t op_reg_id = evoasm_op_x64_reg_id(op, param);

    if(op->written && op_reg_id == reg_id && evoasm_x64_reg_write_acc_is_dirty_read(reg_write_acc, op, param)) {
      evoasm_x64_reg_write_acc_update(reg_write_acc, op, param);
      return true;
    }
  }
  return false;
}

static unsigned
evoasm_adf_x64_find_writers_(evoasm_adf_t *adf, evoasm_kernel_t *kernel, evoasm_reg_id_t reg_id,
                             unsigned index, unsigned *writers) {
  unsigned len = 0;
  unsigned i, j;

  for(i = 0; i <= index; i++) {
    j = index - i;

    evoasm_kernel_param_t *param = &kernel->params->params[j];
    evoasm_x64_reg_write_acc_t reg_write_acc;
    evoasm_x64_reg_write_acc_init(&reg_write_acc);

    if(evoasm_kernel_param_x64_writes_p(param, reg_id, &reg_write_acc)) {
      writers[len++] = j;
    }
  }
  return len;
}

static unsigned
evoasm_adf_x64_find_writers(evoasm_adf_t *adf, evoasm_kernel_t *kernel,
                            evoasm_reg_id_t reg_id, unsigned index, unsigned *writers) {

  return evoasm_adf_x64_find_writers_(adf, kernel, reg_id, index, writers);
}


typedef evoasm_bitmap1024_t evoasm_mark_bitmap;

typedef struct {
  bool change;
  evoasm_bitmap512_t inst_bitmaps[EVOASM_ADF_MAX_SIZE];
  evoasm_bitmap256_t output_reg_bitmaps[EVOASM_ADF_MAX_SIZE];
} _evoasm_adf_intron_elimination_ctx;

static void
evoasm_adf_x64_mark_writers(evoasm_adf_t *adf, evoasm_kernel_t *kernel,
                            evoasm_reg_id_t reg_id, unsigned index, _evoasm_adf_intron_elimination_ctx *ctx) {
  unsigned i, j, k, l;
  unsigned writers[16];

  unsigned writers_len = evoasm_adf_x64_find_writers(adf, kernel, reg_id, index, writers);

  if(writers_len > 0) {
    for(i = 0; i < writers_len; i++) {
      unsigned writer_idx = writers[i];
      evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx->inst_bitmaps[kernel->idx];
      if(evoasm_bitmap_get(inst_bitmap, writer_idx)) continue;

      evoasm_kernel_param_t *param = &kernel->params->params[writer_idx];
      evoasm_x64_inst_t *x64_inst = _evoasm_x64_inst((evoasm_x64_inst_id_t) param->x64.inst);
      evoasm_bitmap_set(inst_bitmap, writer_idx);
      ctx->change = true;

      for(j = 0; j < x64_inst->n_operands; j++) {
        evoasm_x64_operand_t *op = &x64_inst->operands[j];
        evoasm_x64_reg_id_t op_reg_id = evoasm_op_x64_reg_id(op, param);

        if(op->read) {
          if(writer_idx > 0) {
            evoasm_adf_x64_mark_writers(adf, kernel, op_reg_id, writer_idx - 1, ctx);
          }

          if(kernel->reg_info.x64[op_reg_id].input) {
            unsigned trans_kernels_idcs[] = {(unsigned) (kernel->idx + 1),
                                             kernel->params->alt_succ_idx};
            for(k = 0; k < EVOASM_ARY_LEN(trans_kernels_idcs); k++) {
              //evoasm_kernel_t *trans_kernel = &adf->kernels[trans_kernels_idcs[k]];
              for(l = 0; l < EVOASM_X64_N_REGS; l++) {
                if(kernel->reg_info.x64[l].trans_regs[k] == op_reg_id) {
                  evoasm_bitmap_set((evoasm_bitmap_t *) &ctx->output_reg_bitmaps[trans_kernels_idcs[k]], l);
                }
              }
            }
          } else {
          }
        }
      }
    }
  }
}

static void
evoasm_adf_mark_writers(evoasm_adf_t *adf, evoasm_kernel_t *kernel,
                        evoasm_reg_id_t reg_id, unsigned index, _evoasm_adf_intron_elimination_ctx *ctx) {
  switch(adf->arch_info->id) {
    case EVOASM_ARCH_X64: {
      evoasm_adf_x64_mark_writers(adf, kernel, reg_id, index, ctx);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static evoasm_success_t
evoasm_adf_mark_kernel(evoasm_adf_t *adf, evoasm_kernel_t *kernel, _evoasm_adf_intron_elimination_ctx *ctx) {
  unsigned i;

  for(i = 0; i < EVOASM_X64_N_REGS; i++) {
    evoasm_bitmap_t *bitmap = (evoasm_bitmap_t *) &ctx->output_reg_bitmaps[kernel->idx];
    if(evoasm_bitmap_get(bitmap, i)) {
      evoasm_adf_mark_writers(adf, kernel, (evoasm_reg_id_t) i, (unsigned) (kernel->params->size - 1), ctx);
    }
  }

  return true;
}

evoasm_success_t
evoasm_adf_eliminate_introns(evoasm_adf_t *adf) {
  unsigned i, j;
  unsigned last_kernel_idx = (unsigned) (adf->params->size - 1);
  //evoasm_kernel_t *last_kernel = &adf->kernels[last_kernel_idx];

  _evoasm_adf_intron_elimination_ctx ctx = {0};

  {
    evoasm_bitmap_t *output_bitmap = (evoasm_bitmap_t *) &ctx.output_reg_bitmaps[last_kernel_idx];
    for(i = 0; i < adf->_output.arity; i++) {
      evoasm_bitmap_set(output_bitmap, adf->output_regs[i]);
    }
  }

  do {
    i = last_kernel_idx;
    ctx.change = false;
    for(i = 0; i <= last_kernel_idx; i++) {
      j = last_kernel_idx - i;
      EVOASM_TRY(error, evoasm_adf_mark_kernel, adf,
                 &adf->kernels[j], &ctx);
    }
  } while(ctx.change);

  /* sweep */
  for(i = 0; i <= last_kernel_idx; i++) {
    evoasm_kernel_t *kernel = &adf->kernels[i];
    unsigned k;
    evoasm_bitmap_t *inst_bitmap = (evoasm_bitmap_t *) &ctx.inst_bitmaps[i];

    for(k = 0, j = 0; j < kernel->params->size; j++) {
      if(evoasm_bitmap_get(inst_bitmap, j)) {
        kernel->params->params[k++] = kernel->params->params[j];
      }
    }
    kernel->params->size = (evoasm_adf_size_t) k;
  }

  /* adf is already prepared, must be reset before doing it again */
  evoasm_adf_unprepare(adf);

  /* reemit, but keep previous mappings */
  if(!evoasm_adf_emit(adf, NULL, true, true, false, false)) {
    return false;
  }

  return true;
error:
  return false;
}

evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme,
                 evoasm_adf_t *found_adf,
                 evoasm_loss_t *found_loss) {
  unsigned i, j;
  struct evoasm_signal_context signal_ctx = {0};
  bool retval;
  unsigned n_examples = EVOASM_ADF_INPUT_N_EXAMPLES(deme->params->adf_input);
  evoasm_loss_t max_loss = deme->params->max_loss;
  *found_loss = NAN;

  evoasm_signal_context_install(&signal_ctx, (evoasm_arch_id_t) deme->arch_info->id);

  for(i = 0; i < deme->params->size; i++) {
    evoasm_loss_t loss;
    evoasm_adf_params_t *adf_params = _EVOASM_DEME_ADF_PARAMS(deme, i);

    /* encode solution */
    evoasm_adf_t adf = {
        .params = adf_params,
        .index = i,
        .deme_params = deme->params,
        .buf = &deme->buf,
        .body_buf = &deme->body_buf,
        .arch_info = deme->arch_info,
        ._signal_ctx = &signal_ctx
    };

    adf.output_vals = deme->output_vals;

    for(j = 0; j < adf_params->size; j++) {
      evoasm_kernel_t *kernel = &adf.kernels[j];
      kernel->params = _EVOASM_ADF_PARAMS_KERNEL_PARAMS(adf_params, deme->params->max_kernel_size, j);
      kernel->idx = (evoasm_adf_size_t) j;
    }

    if(!evoasm_deme_eval_adf(deme, &adf, &loss)) {
      retval = false;
      goto done;
    }

    deme->losses[i] = loss;

    evoasm_debug("adf %d has loss %lf", i, loss);

    if(loss <= deme->best_loss) {
      deme->best_loss = loss;
      evoasm_debug("adf %d has best loss %lf", i, loss);
    }

    if(EVOASM_UNLIKELY(loss / n_examples <= max_loss)) {
      evoasm_info("adf %d has best loss %lf", i, loss);

      evoasm_adf_clone(&adf, found_adf);
      found_adf->_output = *deme->params->adf_output;
      found_adf->_input = *deme->params->adf_input;
      *found_loss = loss;

      retval = true;
      goto done;
    }
  }

  retval = true;
done:
  evoasm_signal_context_uninstall(&signal_ctx);
  return retval;
}

static void
evoasm_deme_select_parents(evoasm_deme_t *deme, uint32_t *parents) {
  uint32_t n = 0;
  unsigned i, j, k;

  j = 0;
  while(true) {
    for(i = 0; i < deme->params->size; i++) {
      uint32_t r = _evoasm_prng_rand32(deme->params->prng);
      if(n >= deme->params->size) goto done;
      if(r < UINT32_MAX * ((deme->best_loss + 1.0) / (deme->losses[i] + 1.0))) {
        parents[n++] = i;
        //evoasm_info("selecting loss %f", search->deme.losses[i]);
      }
      else {
        //evoasm_info("discarding loss %f", search->deme.losses[i]);
      }
    }
  }
done:;
}

static void
evoasm_deme_mutate_kernel(evoasm_deme_t *deme, evoasm_kernel_params_t *child) {
  uint32_t r = _evoasm_prng_rand32(deme->params->prng);
  evoasm_debug("mutating child: %u < %u", r, deme->params->mut_rate);
  if(r < deme->params->mut_rate) {

    r = _evoasm_prng_rand32(deme->params->prng);
    if(child->size > deme->params->min_kernel_size && r < UINT32_MAX / 16) {
      uint32_t index = r % child->size;

      if(index < (uint32_t) (child->size - 1)) {
        memmove(child->params + index, child->params + index + 1,
                (child->size - index - 1) * sizeof(evoasm_kernel_param_t));
      }
      child->size--;
    }

    r = _evoasm_prng_rand32(deme->params->prng);
    {
      evoasm_kernel_param_t *param = child->params + (r % child->size);
      evoasm_deme_seed_kernel_param(deme, param);
    }
  }
}

static void
evoasm_deme_crossover_kernel(evoasm_deme_t *deme,
                             evoasm_kernel_params_t *parent_a,
                             evoasm_kernel_params_t *parent_b,
                             evoasm_kernel_params_t *child) {

  /* NOTE: parent_a must be the longer parent, i.e. parent_size_a >= parent_size_b */
  evoasm_kernel_size_t child_size;
  unsigned crossover_point, crossover_len, i;

  assert(parent_a->size >= parent_b->size);

  child_size = (evoasm_kernel_size_t)
      _evoasm_prng_rand_between(deme->params->prng,
                                parent_b->size, parent_a->size);

  assert(child_size > 0);
  assert(child_size >= parent_b->size);

  /* offset for shorter parent */
  crossover_point = (unsigned) _evoasm_prng_rand_between(deme->params->prng,
                                                         0, child_size - parent_b->size);
  crossover_len = (unsigned) _evoasm_prng_rand_between(deme->params->prng,
                                                       0, parent_b->size);


  for(i = 0; i < child_size; i++) {
    unsigned index;
    evoasm_kernel_params_t *parent;

    if(i < crossover_point || i >= crossover_point + crossover_len) {
      parent = parent_a;
      index = i;
    } else {
      parent = parent_b;
      index = i - crossover_point;
    }
    child->params[i] = parent->params[index];
  }
  child->size = child_size;

  evoasm_deme_mutate_kernel(deme, child);
}


static void
evoasm_deme_crossover_adf(evoasm_deme_t *deme, evoasm_adf_params_t *parent_a, evoasm_adf_params_t *parent_b,
                          evoasm_adf_params_t *child) {

  /* NOTE: parent_a must be the longer parent, i.e. parent_size_a >= parent_size_b */
  evoasm_adf_size_t child_size;
  unsigned i, max_kernel_size;


  assert(parent_a->size >= parent_b->size);
  assert(parent_a->size > 0);
  assert(parent_b->size > 0);

  child_size = (evoasm_adf_size_t)
      _evoasm_prng_rand_between(deme->params->prng,
                                parent_b->size, parent_a->size);

  assert(child_size > 0);
  assert(child_size >= parent_b->size);

  max_kernel_size = deme->params->max_kernel_size;

  for(i = 0; i < child_size; i++) {
    evoasm_kernel_params_t *kernel_child = _EVOASM_ADF_PARAMS_KERNEL_PARAMS(child, max_kernel_size, i);

    if(i < parent_b->size) {
      evoasm_kernel_params_t *kernel_parent_a = _EVOASM_ADF_PARAMS_KERNEL_PARAMS(parent_a, max_kernel_size, i);
      evoasm_kernel_params_t *kernel_parent_b = _EVOASM_ADF_PARAMS_KERNEL_PARAMS(parent_b, max_kernel_size, i);

      if(kernel_parent_a->size < kernel_parent_b->size) {
        evoasm_kernel_params_t *t = kernel_parent_a;
        kernel_parent_a = kernel_parent_b;
        kernel_parent_b = t;
      }

      evoasm_deme_crossover_kernel(deme, kernel_parent_a, kernel_parent_b, kernel_child);
    } else {
      memcpy(kernel_child, parent_a, EVOASM_KERNEL_SIZE(max_kernel_size));
      evoasm_deme_mutate_kernel(deme, kernel_child);
    }
  }
  child->size = child_size;
}

static void
evoasm_deme_crossover(evoasm_deme_t *deme, evoasm_adf_params_t *parent_a, evoasm_adf_params_t *parent_b,
                      evoasm_adf_params_t *child_a, evoasm_adf_params_t *child_b) {

  if(parent_a->size < parent_b->size) {
    evoasm_adf_params_t *t = parent_a;
    parent_a = parent_b;
    parent_b = t;
  }

  //memcpy(_EVOASM_SEARCH_ADF_PARAMS(search, adfs, index), parent_a, EVOASM_ADF_SIZE(search));
  //memcpy(_EVOASM_SEARCH_ADF_PARAMS(search, adfs, index + 1), parent_a, EVOASM_ADF_SIZE(search));

  evoasm_deme_crossover_adf(deme, parent_a, parent_b, child_a);
  if(child_b != NULL) {
    evoasm_deme_crossover_adf(deme, parent_a, parent_b, child_b);
  }
}

static void
evoasm_deme_combine_parents(evoasm_deme_t *deme, uint32_t *parents) {
  unsigned i;

  size_t adf_size = EVOASM_ADF_SIZE(deme->params->max_adf_size, deme->params->max_kernel_size);

  for(i = 0; i < deme->params->size; i += 2) {
    evoasm_adf_params_t *parent_a_ = _EVOASM_DEME_ADF_PARAMS(deme, parents[i]);
    evoasm_adf_params_t *parent_a = _EVOASM_DEME_ADF_PARAMS_FULL(deme, 0, swap_adfs);
    evoasm_adf_params_t *parent_b_ = _EVOASM_DEME_ADF_PARAMS(deme, parents[i + 1]);
    evoasm_adf_params_t *parent_b = _EVOASM_DEME_ADF_PARAMS_FULL(deme, 1, swap_adfs);

    assert(parent_a->size > 0);

    // save parents into swap space
    memcpy(parent_a, parent_a_, adf_size);
    memcpy(parent_b, parent_b_, adf_size);

    evoasm_adf_params_t *child_a = parent_a_;
    evoasm_adf_params_t *child_b = parent_b_;
    evoasm_deme_crossover(deme, parent_a, parent_b, child_a, child_b);

    assert(child_a->size > 0);
    assert(child_b->size > 0);
  }
}

static evoasm_loss_t
evoasm_deme_loss(evoasm_deme_t *deme, unsigned *n_inf) {
  unsigned i;
  double scale = 1.0 / deme->params->size;
  double pop_loss = 0.0;
  *n_inf = 0;
  for(i = 0; i < deme->params->size; i++) {
    double loss = deme->losses[i];
    if(loss != INFINITY) {
      pop_loss += scale * loss;
    } else {
      (*n_inf)++;
    }
  }

  return pop_loss;
}

void
evoasm_deme_new_gen(evoasm_deme_t *deme) {
  uint32_t *parents = alloca(deme->params->size * sizeof(uint32_t));
  evoasm_deme_select_parents(deme, parents);

#if 0
  {
    double scale = 1.0 / deme->params->size;
    double deme_loss = 0.0;
    unsigned n_inf = 0;
    for(i = 0; i < deme->params->size; i++) {
      double loss = deme->deme.losses[parents[i]];
      if(loss != INFINITY) {
        deme_loss += scale * loss;
      }
      else {
        n_inf++;
      }
    }

    evoasm_info("deme selected loss: %g/%u", deme_loss, n_inf);
  }

  unsigned i;
  for(i = 0; i < deme->params->size; i++) {
    evoasm_adf_params_t *adf_params = _EVOASM_SEARCH_ADF_PARAMS(deme, deme->deme.adfs, parents[i]);
    assert(adf_params->size > 0);
  }
#endif

  evoasm_deme_combine_parents(deme, parents);
}

