//
// Created by jap on 9/16/16.
//


#include "evoasm-signal.h"
#include "evoasm-program-pop.h"
#include "evoasm-pop-params.h"

EVOASM_DEF_LOG_TAG("program_pop")

#define _EVOASM_PROGRAM_PARAMS_KERNEL_PARAMS(program_params, max_kernel_size, kernel_index) \
  ((evoasm_kernel_params_t *)((unsigned char *)(program_params) + sizeof(evoasm_program_params_t) + (kernel_index) * EVOASM_KERNEL_PARAMS_SIZE(max_kernel_size)))



static bool
evoasm_program_pop_destroy_(evoasm_program_pop_t *pop, bool free_buf, bool free_body_buf) {
  bool retval = true;

  evoasm_pop_destroy(&pop->pop);

  if(free_buf) EVOASM_TRY(buf_free_failed, evoasm_buf_destroy, &pop->buf);

cleanup:
  if(free_body_buf) EVOASM_TRY(body_buf_failed, evoasm_buf_destroy, &pop->body_buf);
  return retval;

buf_free_failed:
  retval = false;
  goto cleanup;

body_buf_failed:
  return false;
}

evoasm_program_pop_params_t *
evoasm_program_pop_params(evoasm_program_pop_t *program_pop) {
  return (evoasm_program_pop_params_t *) program_pop->pop.params;
}



evoasm_success_t
evoasm_program_pop_destroy(evoasm_program_pop_t *pop) {
  return evoasm_program_pop_destroy_(pop, true, true);
}




static evoasm_success_t
evoasm_program_pop_seed_indiv(evoasm_pop_t *pop, evoasm_indiv_t *indiv) {
  evoasm_program_pop_seed_program((evoasm_program_pop_t *) pop, (evoasm_program_params_t *) indiv);
  return true;
}

static evoasm_success_t
evoasm_program_pop_eval_program(evoasm_program_pop_t *program_pop,
                         evoasm_program_t *program,
                         evoasm_loss_t *loss) {

  evoasm_kernel_t *kernel = &program->kernels[program->params->kernel_count - 1];
  evoasm_program_pop_params_t *params = evoasm_program_pop_params(program_pop);

  if(!evoasm_program_emit(program, params->program_input, true, true, true, true)) {
    *loss = INFINITY;
    return false;
  }

  if(EVOASM_UNLIKELY(kernel->n_output_regs == 0)) {
    *loss = INFINITY;
    return true;
  }

  //evoasm_buf_log(program->buf, EVOASM_LOG_LEVEL_INFO);
  {
    evoasm_signal_set_exception_mask(program->exception_mask);

    if(EVOASM_SIGNAL_TRY()) {
      evoasm_buf_exec(program->buf);
      *loss = evoasm_program_assess(program, params->program_output);
    } else {
      evoasm_log_debug("program %p signaled", (void *) program);
      *loss = INFINITY;
    }
  }
  return true;
}


static evoasm_success_t
evoasm_program_pop_eval_setup(evoasm_pop_t *pop) {
  evoasm_program_pop_t *program_pop = (evoasm_program_pop_t *) pop;
  evoasm_signal_install((evoasm_arch_id_t) program_pop->arch_info->id, 0);
  return true;
}

static evoasm_success_t
evoasm_program_pop_eval_teardown(evoasm_pop_t *pop) {
  evoasm_program_pop_t *program_pop = (evoasm_program_pop_t *) pop;
  evoasm_signal_install((evoasm_arch_id_t) program_pop->arch_info->id, 0);
  return true;
}

static inline void
evoasm_program_pop_init_program(evoasm_program_pop_t *program_pop, evoasm_program_t *program,
                                evoasm_program_params_t *program_params) {

  evoasm_program_pop_params_t *params = evoasm_program_pop_params(program_pop);

  /* encode solution */
  evoasm_program_t program_ = {
      .params = program_params,
      .recur_limit = params->recur_limit,
      .buf = &program_pop->buf,
      .body_buf = &program_pop->body_buf,
      .arch_info = program_pop->arch_info,
  };

  unsigned i;
  for(i = 0; i < program_params->kernel_count; i++) {
    evoasm_kernel_t *kernel = &program_.kernels[i];
    kernel->params = _EVOASM_PROGRAM_PARAMS_KERNEL_PARAMS(program_params, params->max_kernel_size, i);
    kernel->idx = (evoasm_program_size_t) i;
  }

  *program = program_;
}

evoasm_success_t
evoasm_program_pop_get_program(evoasm_program_pop_t *program_pop, evoasm_program_params_t *program_params,
                               evoasm_program_t *program) {

  evoasm_program_pop_params_t *params = evoasm_program_pop_params(program_pop);

  evoasm_program_t program_;
  evoasm_program_pop_init_program(program_pop, &program_, program_params);
  program_._output = *params->program_output;
  program_._input = *params->program_input;

  return evoasm_program_clone(&program_, program);
}

static evoasm_success_t
evoasm_program_pop_eval_program_params(evoasm_program_pop_t *program_pop, evoasm_program_params_t *program_params, evoasm_loss_t *loss) {

  evoasm_program_t program;
  evoasm_program_pop_init_program(program_pop, &program, program_params);
  program.output_vals = program_pop->output_vals;

  return evoasm_program_pop_eval_program(program_pop, &program, loss);
}

static evoasm_success_t
evoasm_program_pop_eval_indiv(evoasm_pop_t *pop, evoasm_indiv_t *indiv, evoasm_loss_t *loss) {
  return evoasm_program_pop_eval_program_params((evoasm_program_pop_t *) pop, (evoasm_program_params_t *) indiv, loss);
}


static void
evoasm_program_pop_mutate_kernel(evoasm_program_pop_t *program_pop, evoasm_kernel_params_t *child) {

  evoasm_prng_t *prng = &program_pop->pop.prng;
  evoasm_program_pop_params_t *params = evoasm_program_pop_params(program_pop);
  uint32_t mut_rate = program_pop->pop.params->mut_rate;

  uint32_t r = _evoasm_prng_rand32(prng);
  evoasm_log_debug("mutating child: %u < %u", r, mut_rate);
  if(r < mut_rate) {

    r = _evoasm_prng_rand32(prng);
    if(child->size > params->min_kernel_size && r < UINT32_MAX / 16) {
      uint32_t index = r % child->size;

      if(index < (uint32_t) (child->size - 1)) {
        memmove(child->params + index, child->params + index + 1,
                (child->size - index - 1) * sizeof(evoasm_kernel_param_t));
      }
      child->size--;
    }

    r = _evoasm_prng_rand32(prng);
    {
      evoasm_kernel_param_t *param = child->params + (r % child->size);
      evoasm_program_pop_seed_kernel_param(program_pop, param);
    }
  }
}

static void
evoasm_program_pop_crossover_kernel(evoasm_program_pop_t *program_pop,
                                 evoasm_kernel_params_t *parent_a,
                                 evoasm_kernel_params_t *parent_b,
                                 evoasm_kernel_params_t *child) {

  /* NOTE: parent_a must be the longer parent, i.e. parent_size_a >= parent_size_b */
  evoasm_kernel_size_t child_size;
  unsigned crossover_point, crossover_len, i;
  evoasm_prng_t *prng = &program_pop->pop.prng;

  assert(parent_a->size >= parent_b->size);

  child_size = (evoasm_kernel_size_t)
      _evoasm_prng_rand_between(prng,
                                parent_b->size, parent_a->size);

  assert(child_size > 0);
  assert(child_size >= parent_b->size);

  /* offset for shorter parent */
  crossover_point = (unsigned) _evoasm_prng_rand_between(prng,
                                                         0, child_size - parent_b->size);
  crossover_len = (unsigned) _evoasm_prng_rand_between(prng,
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

  evoasm_program_pop_mutate_kernel(program_pop, child);
}


static void
evoasm_program_pop_crossover_program_param(evoasm_program_pop_t *program_pop, evoasm_program_params_t *parent_a,
                                    evoasm_program_params_t *parent_b,
                                    evoasm_program_params_t *child) {

  /* NOTE: parent_a must be the longer parent, i.e. parent_size_a >= parent_size_b */
  evoasm_program_size_t child_size;
  unsigned i;

  evoasm_prng_t *prng = &program_pop->pop.prng;
  evoasm_program_pop_params_t *params = evoasm_program_pop_params(program_pop);
  unsigned max_kernel_size = params->max_kernel_size;

  assert(parent_a->kernel_count >= parent_b->kernel_count);
  assert(parent_a->kernel_count > 0);
  assert(parent_b->kernel_count > 0);

  child_size = (evoasm_program_size_t)
      _evoasm_prng_rand_between(prng,
                                parent_b->kernel_count, parent_a->kernel_count);

  assert(child_size > 0);
  assert(child_size >= parent_b->kernel_count);


  for(i = 0; i < child_size; i++) {
    evoasm_kernel_params_t *kernel_child = _EVOASM_PROGRAM_PARAMS_KERNEL_PARAMS(child, max_kernel_size, i);

    if(i < parent_b->kernel_count) {
      evoasm_kernel_params_t *kernel_parent_a = _EVOASM_PROGRAM_PARAMS_KERNEL_PARAMS(parent_a, max_kernel_size, i);
      evoasm_kernel_params_t *kernel_parent_b = _EVOASM_PROGRAM_PARAMS_KERNEL_PARAMS(parent_b, max_kernel_size, i);

      if(kernel_parent_a->size < kernel_parent_b->size) {
        evoasm_kernel_params_t *t = kernel_parent_a;
        kernel_parent_a = kernel_parent_b;
        kernel_parent_b = t;
      }

      evoasm_program_pop_crossover_kernel(program_pop, kernel_parent_a, kernel_parent_b, kernel_child);
    } else {
      memcpy(kernel_child, parent_a, EVOASM_KERNEL_PARAMS_SIZE(max_kernel_size));
      evoasm_program_pop_mutate_kernel(program_pop, kernel_child);
    }
  }
  child->kernel_count = child_size;
}

static evoasm_success_t
evoasm_program_pop_crossover_program_params(evoasm_program_pop_t *pop, evoasm_program_params_t *parent_a, evoasm_program_params_t *parent_b,
                          evoasm_program_params_t *child_a, evoasm_program_params_t *child_b) {

  if(parent_a->kernel_count < parent_b->kernel_count) {
    evoasm_program_params_t *t = parent_a;
    parent_a = parent_b;
    parent_b = t;
  }

  //memcpy(_EVOASM_SEARCH_PROGRAM_PARAMS(search, indivs, index), parent_a, EVOASM_PROGRAM_PARAMS_SIZE(search));
  //memcpy(_EVOASM_SEARCH_PROGRAM_PARAMS(search, indivs, index + 1), parent_a, EVOASM_PROGRAM_PARAMS_SIZE(search));

  evoasm_program_pop_crossover_program_param(pop, parent_a, parent_b, child_a);
  evoasm_program_pop_crossover_program_param(pop, parent_a, parent_b, child_b);

  return true;
}

static evoasm_success_t
evoasm_program_pop_crossover(evoasm_pop_t *pop,
                          evoasm_indiv_t *parent_a,
                          evoasm_indiv_t *parent_b,
                          evoasm_indiv_t *child_a,
                          evoasm_indiv_t *child_b) {
  return evoasm_program_pop_crossover_program_params((evoasm_program_pop_t *) pop,
                                       (evoasm_program_params_t *) parent_a,
                                       (evoasm_program_params_t *) parent_b,
                                       (evoasm_program_params_t *) child_a,
                                       (evoasm_program_params_t *) child_b);
}

static const evoasm_pop_impl_t _evoasm_program_pop_cls = {
    .seed_indiv_func = evoasm_program_pop_seed_indiv,
    .eval_prepare_func = evoasm_program_pop_eval_setup,
    .eval_cleanup_func = evoasm_program_pop_eval_teardown,
    .eval_indiv_func = evoasm_program_pop_eval_indiv,
    .crossover_func = evoasm_program_pop_crossover,
    .type = EVOASM_POP_TYPE_PROGRAM
};

evoasm_success_t
evoasm_program_pop_init(evoasm_program_pop_t *program_pop, evoasm_arch_id_t arch_id, evoasm_program_pop_params_t *params) {

  if(!evoasm_program_pop_params_valid(params)) {
    return false;
  }

  unsigned n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(params->program_input);
  size_t indiv_size = EVOASM_PROGRAM_PARAMS_SIZE(params->max_kernel_count, params->max_kernel_size);

  if(!evoasm_pop_init(&program_pop->pop, (evoasm_pop_params_t *) params, &_evoasm_program_pop_cls, indiv_size,
                       n_examples)) {
    return false;
  }

  program_pop->arch_info = evoasm_get_arch_info(arch_id);
  program_pop->output_vals = evoasm_malloc(EVOASM_PROGRAM_OUTPUT_VALS_SIZE(params->program_input));
  if(!program_pop->output_vals) goto alloc_failed;

  /* FIXME: find a way to calculate tighter bound */

  EVOASM_TRY(domains_init_failed, evoasm_program_pop_init_domains, program_pop);

  EVOASM_TRY(buf_alloc_failed, evoasm_buf_init, &program_pop->buf, EVOASM_BUF_TYPE_MMAP, buf_size);
  EVOASM_TRY(body_buf_alloc_failed, evoasm_buf_init, &program_pop->body_buf, EVOASM_BUF_TYPE_MALLOC, body_buf_size);

  EVOASM_TRY(prot_failed, evoasm_buf_protect, &program_pop->buf,
             EVOASM_MPROT_RWX);


  return true;

alloc_failed:
  return false;

domains_init_failed:
buf_alloc_failed:
  evoasm_program_pop_destroy_(program_pop, false, false);
  return false;

body_buf_alloc_failed:
  evoasm_program_pop_destroy_(program_pop, true, false);
  return false;

prot_failed:
  evoasm_program_pop_destroy_(program_pop, true, true);
  return false;
}

_EVOASM_DEF_ALLOC_FREE_FUNCS(program_pop)