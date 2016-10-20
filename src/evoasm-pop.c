//
// Created by jap on 9/16/16.
//

#include "evoasm-pop.h"
#include "evoasm-pop-params.h"
#include "evoasm-rand.h"
#include "evoasm-signal.h"
#include "evoasm-program.h"
#include "evoasm.h"

//#ifdef _OPENMP
#  include <omp.h>
//#endif

EVOASM_DEF_LOG_TAG("pop")

#define EVOASM_POP_N_SAMPLES_PER_KERNEL 7
#define EVOASM_POP_N_SAMPLES_PER_PROGRAM 7

static evoasm_success_t
evoasm_pop_indiv_data_init(evoasm_pop_indiv_data_t *indiv_data, size_t n_demes, size_t deme_size,
                           size_t n_samples_per_indiv) {

  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->sizes, EVOASM_CACHE_LINE_SIZE,
                   n_demes * deme_size,
                   sizeof(uint16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->losses, EVOASM_CACHE_LINE_SIZE,
                   n_demes * deme_size * n_samples_per_indiv,
                   sizeof(evoasm_loss_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->sample_counters, EVOASM_CACHE_LINE_SIZE,
                   n_demes * deme_size,
                   sizeof(uint8_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->best_losses, EVOASM_CACHE_LINE_SIZE,
                   n_demes,
                   sizeof(evoasm_loss_t));

  for(size_t i = 0; i < n_demes; i++) {
    indiv_data->best_losses[i] = INFINITY;
  }

  return true;
error:
  return false;
}

static void
evoasm_pop_indiv_data_destroy(evoasm_pop_indiv_data_t *indiv_data) {
  evoasm_free(indiv_data->losses);
  evoasm_free(indiv_data->best_losses);
  evoasm_free(indiv_data->sizes);
  evoasm_free(indiv_data->sample_counters);
}

static evoasm_success_t
evoasm_pop_program_pos_data_init(evoasm_pop_program_pos_data_t *program_pos_data, size_t n) {

  EVOASM_TRY_ALLOC(error, aligned_calloc, program_pos_data->kernel_idxs, EVOASM_CACHE_LINE_SIZE,
                   n,
                   sizeof(uint16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, program_pos_data->kernel_deme_idxs, EVOASM_CACHE_LINE_SIZE,
                   n,
                   sizeof(uint16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, program_pos_data->jmp_offs, EVOASM_CACHE_LINE_SIZE,
                   n,
                   sizeof(uint16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, program_pos_data->jmp_selectors, EVOASM_CACHE_LINE_SIZE,
                   n,
                   sizeof(uint8_t));

  return true;

error:
  return false;
}

static void
evoasm_pop_program_pos_data_destroy(evoasm_pop_program_pos_data_t *program_pos_data) {
  evoasm_free(program_pos_data->kernel_idxs);
  evoasm_free(program_pos_data->kernel_deme_idxs);
  evoasm_free(program_pos_data->jmp_offs);
  evoasm_free(program_pos_data->jmp_selectors);
}

static evoasm_success_t bool
evoasm_pop_kernel_inst_data_init(evoasm_pop_kernel_inst_data_t *kernel_inst_data, evoasm_arch_id_t arch_id,
                                 size_t n_kernels,
                                 uint16_t kernel_size) {

  size_t n_insts = n_kernels * kernel_size;

  EVOASM_TRY_ALLOC(error, aligned_calloc, kernel_inst_data->insts, EVOASM_CACHE_LINE_SIZE,
                   n_insts,
                   sizeof(evoasm_inst_id_t));

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      EVOASM_TRY_ALLOC(error, aligned_calloc, kernel_inst_data->params.x64, EVOASM_CACHE_LINE_SIZE,
                       n_insts,
                       sizeof(evoasm_x64_basic_params_t));
      break;
    default:
      evoasm_assert_not_reached();
  }
  return true;

error:
  return false;
}

static evoasm_success_t bool
evoasm_pop_kernel_data_init(evoasm_pop_kernel_data_t *kernel_inst_data, evoasm_arch_id_t arch_id,
                            uint16_t program_size, uint16_t n_demes, uint16_t deme_size, uint16_t kernel_size) {

  size_t total_n_demes = program_size * n_demes;
  size_t total_n_kernels = total_n_demes * deme_size;

  EVOASM_TRY(error, evoasm_pop_kernel_inst_data_init, &kernel_inst_data->kernel_inst_data,
             arch_id, total_n_kernels, kernel_size);

  EVOASM_TRY(error, evoasm_pop_indiv_data_init, &kernel_inst_data->indiv_data,
             total_n_demes, deme_size, EVOASM_POP_N_SAMPLES_PER_KERNEL);

  return true;
error:
  return false;
}

static void
evoasm_pop_kernel_inst_data_destroy(evoasm_pop_kernel_inst_data_t *kernel_inst_data) {
  evoasm_free(kernel_inst_data->insts);
  evoasm_free(kernel_inst_data->params.data);
}

static void
evoasm_pop_kernel_data_destroy(evoasm_pop_kernel_data_t *kernel_data) {
  evoasm_pop_kernel_inst_data_destroy(&kernel_data->kernel_inst_data);
  evoasm_pop_indiv_data_destroy(&kernel_data->indiv_data);
}

static evoasm_success_t
evoasm_pop_program_data_init(evoasm_pop_program_data_t *program_data, size_t n_demes, size_t deme_size) {
  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &program_data->program_pos_data, n_demes * deme_size);
  EVOASM_TRY(error, evoasm_pop_indiv_data_init, &program_data->indiv_data, n_demes, deme_size,
             EVOASM_POP_N_SAMPLES_PER_PROGRAM);

  return true;
error:
  return false;
}

static void
evoasm_pop_program_data_destroy(evoasm_pop_program_data_t *program_data) {
  evoasm_pop_program_pos_data_destroy(&program_data->program_pos_data);
  evoasm_pop_indiv_data_destroy(&program_data->indiv_data);
}

static evoasm_success_t
evoasm_pop_module_data_init(evoasm_pop_module_data_t *module_data, size_t n) {
  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &module_data->program_pos_data, n);

  EVOASM_TRY_ALLOC(error, aligned_calloc, module_data->sizes, EVOASM_CACHE_LINE_SIZE,
                   n,
                   sizeof(uint16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, module_data->pheromones, EVOASM_CACHE_LINE_SIZE,
                   n,
                   sizeof(float));
  return true;
error:
  return false;
}

static void
evoasm_pop_module_data_destroy(evoasm_pop_module_data_t *module_data) {
  evoasm_pop_program_pos_data_destroy(&module_data->program_pos_data);
  evoasm_free(module_data->pheromones);
  evoasm_free(module_data->sizes);
}

static evoasm_success_t
evoasm_pop_thread_data_destroy(evoasm_pop_thread_data_t *thread_data) {
  bool retval = true;

  if(!evoasm_program_destroy(&thread_data->program)) retval = false;
  evoasm_prng_destroy(&thread_data->prng);
  evoasm_free(thread_data->parent_idxs);
  evoasm_free(thread_data->kernel_offs);

  evoasm_pop_program_pos_data_destroy(&thread_data->parent_program_pos_data);
  evoasm_pop_kernel_data_destroy(&thread_data->parent_kernel_inst_data);

  return retval;
}

evoasm_success_t
evoasm_pop_destroy(evoasm_pop_t *pop) {
  bool retval = true;

  evoasm_free(pop->error_counters);
  evoasm_free(pop->domains);

  for(int i = 0; i < pop->max_threads; i++) {
    retval &= evoasm_pop_thread_data_destroy(&pop->thread_data[i]);
  }
  evoasm_free(pop->thread_data);
  evoasm_free(pop->deme_losses);

  evoasm_pop_program_data_destroy(&pop->program_data);
  evoasm_pop_kernel_data_destroy(&pop->kernel_data);
  evoasm_pop_module_data_destroy(&pop->module_data);
  evoasm_pop_kernel_inst_data_destroy(&pop->best_kernel_data);
  evoasm_pop_program_pos_data_destroy(&pop->best_program_data);

  return retval;
}

static evoasm_success_t bool
evoasm_pop_thread_data_init(evoasm_pop_thread_data_t *thread_data,
                            evoasm_pop_params_t *params,
                            evoasm_prng_state_t *seed,
                            evoasm_arch_id_t arch_id) {

  evoasm_prng_init(&thread_data->prng, seed);
  EVOASM_TRY(error, evoasm_program_init, &thread_data->program,
             arch_id,
             params->program_input,
             params->max_program_size,
             params->max_kernel_size,
             params->recur_limit);

  size_t max_deme_size = EVOASM_MAX(params->kernel_deme_size, params->program_deme_size);
  EVOASM_TRY_ALLOC(error, calloc, thread_data->parent_idxs, max_deme_size, sizeof(uint16_t));

  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &thread_data->parent_program_pos_data,
             2u * params->max_program_size);
  EVOASM_TRY(error, evoasm_pop_kernel_inst_data_init, &thread_data->parent_kernel_inst_data, arch_id, 2,
             params->max_kernel_size);

  EVOASM_TRY_ALLOC(error, calloc, thread_data->kernel_offs, params->max_program_size, sizeof(size_t));

  return true;

error:
  return false;
}

evoasm_success_t
evoasm_pop_init_domains(evoasm_pop_t *pop) {
  size_t i, j, k;
  evoasm_domain_t cloned_domain;

  evoasm_pop_params_t *params = pop->params;

  size_t domains_len = (size_t) (params->n_insts * params->n_params);
  pop->domains = evoasm_calloc(domains_len,
                               sizeof(evoasm_domain_t));

  if(!pop->domains) goto fail;

  for(i = 0; i < params->n_insts; i++) {
    evoasm_x64_inst_t *inst = _evoasm_x64_inst(params->inst_ids[i]);
    for(j = 0; j < params->n_params; j++) {
      evoasm_domain_t *inst_domain = &pop->domains[i * params->n_params + j];
      evoasm_param_id_t param_id = params->param_ids[j];
      for(k = 0; k < inst->n_params; k++) {
        evoasm_param_t *param = &inst->params[k];
        if(param->id == param_id) {
          evoasm_domain_t *user_domain = params->domains[param_id];
          if(user_domain != NULL) {
            if(evoasm_domain_is_empty(user_domain)) goto empty_domain;

            evoasm_domain_clone(user_domain, &cloned_domain);
            evoasm_domain_intersect(&cloned_domain, param->domain, inst_domain);
            if(evoasm_domain_is_empty(inst_domain)) goto empty_domain;
          } else {
            evoasm_domain_clone(param->domain, inst_domain);
          }
          goto found;
        }
      }
      /* not found */
      inst_domain->type = EVOASM_DOMAIN_TYPE_NONE;
found:;
    }
  }

  /*
  for(i = 0; i < domains_len; i++) {
    evoasm_domain_log(&pop->domains[i], EVOASM_LOG_LEVEL_WARN);
  }*/

  return true;

fail:
  return false;

empty_domain:
  evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_ERROR_CODE_NONE,
               NULL, "Empty domain");
  return false;
}

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                evoasm_pop_params_t *params) {
  int max_threads;
  static evoasm_pop_t zero_pop = {0};
  evoasm_prng_t seed_prng;
  uint16_t n_examples = EVOASM_PROGRAM_INPUT_EXAMPLE_COUNT(params->program_input);

#ifdef _OPENMP
  max_threads = omp_get_max_threads();
#else
  max_threads = 1;
#endif

  *pop = zero_pop;
  pop->params = params;
  pop->n_examples = n_examples;
  pop->arch_id = arch_id;
  pop->max_threads = max_threads;

  evoasm_prng_init(&seed_prng, &params->seed);

  EVOASM_TRY(error, evoasm_pop_init_domains, pop);
  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &pop->kernel_data, arch_id, params->max_program_size,
             params->n_kernel_demes,
             params->kernel_deme_size, params->max_kernel_size);

  EVOASM_TRY(error, evoasm_pop_program_data_init, &pop->program_data, params->n_program_demes,
             params->program_deme_size);

  EVOASM_TRY(error, evoasm_pop_module_data_init, &pop->module_data, params->library_size);

  EVOASM_TRY(error, evoasm_pop_kernel_inst_data_init, &pop->best_kernel_data, arch_id, params->max_program_size,
             params->max_kernel_size);
  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &pop->best_program_data, params->max_program_size);

  EVOASM_TRY_ALLOC(error, aligned_calloc, pop->thread_data, EVOASM_CACHE_LINE_SIZE, (size_t) max_threads,
                   sizeof(evoasm_pop_thread_data_t));

  EVOASM_TRY_ALLOC(error, calloc, pop->deme_losses,
                   EVOASM_MAX(pop->params->program_deme_size, pop->params->kernel_deme_size),
                   sizeof(evoasm_pop_thread_data_t));

  for(int i = 0; i < max_threads; i++) {
    evoasm_prng_state_t seed;

    for(int j = 0; j < EVOASM_PRNG_SEED_LEN; j++) {
      seed.data[j] = _evoasm_prng_rand64(&seed_prng);
    }

    EVOASM_TRY(error, evoasm_pop_thread_data_init,
               &pop->thread_data[i],
               params,
               &seed,
               arch_id);
  }

  EVOASM_TRY_ALLOC(error, calloc, pop->error_counters, params->n_program_demes * n_examples, sizeof(uint64_t));
  pop->error_counter = 0;

  return true;

error:
  evoasm_pop_destroy(pop);
  return false;
}

#if 0
static evoasm_indiv_t *
evoasm_pop_indiv_(evoasm_pop_t *pop, uint32_t idx, size_t char *ptr) {
  return (evoasm_indiv_t *) (ptr + idx * pop->kernel_size);
}

evoasm_indiv_t *
evoasm_pop_get_indiv(evoasm_pop_t *pop, uint32_t idx) {
  return evoasm_pop_indiv_(pop, idx, pop->main_indivs);
}

evoasm_loss_t
evoasm_pop_get_indiv_loss(evoasm_pop_t *pop, uint32_t idx) {
  return pop->losses[idx];
}

size_t
evoasm_pop_get_indiv_size(evoasm_pop_t *pop) {
  return pop->kernel_size;
}

void
evoasm_pop_inject(evoasm_pop_t *pop, evoasm_indiv_t *indiv, size_t indiv_size, evoasm_loss_t loss) {
  size_t i;

  while(true) {
    for(i = 0; i < pop->params->size; i++) {
      uint32_t r = _evoasm_prng_rand32(&pop->prng);
      if(r > UINT32_MAX * ((pop->best_program_loss + 1.0) / (pop->losses[i] + 1.0))) {
        goto done;
      }
    }
  }
done:;
  assert(indiv_size <= pop->kernel_size);
  memcpy(evoasm_pop_get_indiv(pop, i), indiv, indiv_size);
  pop->losses[i] = loss;
}
#endif

#define EVOASM_POP_PROGRAM_OFF(pop, deme_idx, program_idx) \
  ((deme_idx) * (pop)->params->program_deme_size + (program_idx));

#define EVOASM_POP_PROGRAM_SAMPLE_OFF(pop, program_off, sample_idx) \
  ((program_off) * EVOASM_POP_N_SAMPLES_PER_PROGRAM + (sample_idx))

#define EVOASM_POP_PROGRAM_POS_OFF(pop, program_off, pos) \
  ((program_off) * (pop)->params->max_program_size + (pos));

#define EVOASM_POP_KERNEL_OFF(pop, pos, deme_idx, kernel_idx) \
  ((pos) * ((pop)->params->n_kernel_demes * (pop)->params->kernel_deme_size) \
                        + (deme_idx) * (pop)->params->kernel_deme_size \
                        + (kernel_idx));

#define EVOASM_POP_KERNEL_LOSS_OFF(pop, pos, deme_idx, kernel_idx, loss_idx) \
  (EVOASM_POP_KERNEL_OFF(pop, pos, deme_idx, kernel_idx) * EVOASM_POP_N_SAMPLES_PER_KERNEL)

#define EVOASM_POP_KERNEL_INST_OFF(pop, kernel_off, inst_idx) \
  ((kernel_off) * (pop)->params->max_kernel_size + (inst_idx))

#define EVOASM_POP_KERNEL_DEME_OFF(pop, pos, deme_idx) \
  ((pos) * (pop)->params->n_kernel_demes + (deme_idx))

#define EVOASM_POP_PROGRAM_DEME_OFF(pop, deme_idx) (deme_idx)

#define EVOASM_POP_KERNEL_SAMPLE_OFF(pop, kernel_off, sample_idx) \
  ((kernel_off) * EVOASM_POP_N_SAMPLES_PER_KERNEL + (sample_idx))


static void
evoasm_pop_seed_kernel_param_x64(evoasm_pop_t *pop, evoasm_inst_id_t *inst_id_ptr,
                                 evoasm_x64_basic_params_t *params_ptr,
                                 evoasm_prng_t *prng) {
  unsigned i;
  evoasm_pop_params_t *params = pop->params;
  unsigned n_params = params->n_params;

  int64_t inst_idx = _evoasm_prng_rand_between(prng, 0, params->n_insts - 1);
  evoasm_inst_id_t inst_id = params->inst_ids[inst_idx];

  *inst_id_ptr = inst_id;

  /* set parameters */
  for(i = 0; i < n_params; i++) {
    evoasm_domain_t *domain = &pop->domains[inst_idx * n_params + i];
    if(domain->type < EVOASM_DOMAIN_TYPE_NONE) {
      evoasm_x64_param_id_t param_id = (evoasm_x64_param_id_t) pop->params->param_ids[i];
      evoasm_param_val_t param_val;

      param_val = (evoasm_param_val_t) evoasm_domain_rand(domain, prng);
      _evoasm_x64_basic_params_set(params_ptr, param_id, param_val);
    }
  }
}

static void
evoasm_pop_seed_kernel(evoasm_pop_t *pop, size_t pos, size_t deme_idx, size_t kernel_idx, int tid) {
  size_t i;

  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_pop_params_t *params = pop->params;
  evoasm_pop_kernel_data_t *kernel_data = &pop->kernel_data;

  size_t kernel_off = EVOASM_POP_KERNEL_OFF(pop, pos, deme_idx, kernel_idx);

  uint16_t kernel_size =
      (uint16_t) _evoasm_prng_rand_between(prng,
                                           params->min_kernel_size,
                                           params->max_kernel_size);

  pop->kernel_data.indiv_data.sizes[kernel_off] = kernel_size;

  for(i = 0; i < kernel_size; i++) {
    size_t kernel_inst_off = EVOASM_POP_KERNEL_INST_OFF(pop, kernel_off, i);
    evoasm_inst_id_t *insts_ptr = &kernel_data->kernel_inst_data.insts[kernel_inst_off];

    switch(pop->arch_id) {
      case EVOASM_ARCH_X64: {
        evoasm_x64_basic_params_t *params_ptr = &kernel_data->kernel_inst_data.params.x64[kernel_inst_off];
        evoasm_pop_seed_kernel_param_x64(pop, insts_ptr, params_ptr, prng);
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }

#if 0
  kernel_params->jmp_selector = (uint8_t) _evoasm_prng_rand8(prng);
  kernel_params->alt_succ_idx = (uint16_t)
      _evoasm_prng_rand_between(prng, 0, program_size - 1);
#endif

}

static void
evoasm_pop_seed_program_pos(evoasm_pop_t *pop,
                            size_t program_pos_off,
                            uint16_t program_size,
                            evoasm_prng_t *prng) {

  evoasm_pop_program_pos_data_t *program_pos_data = &pop->program_data.program_pos_data;

  program_pos_data->jmp_selectors[program_pos_off] =
      (uint8_t) _evoasm_prng_rand8(prng);

  program_pos_data->jmp_offs[program_pos_off] =
      (uint16_t) _evoasm_prng_rand_between(prng, 0, program_size - 1);

  program_pos_data->kernel_idxs[program_pos_off] =
      (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->kernel_deme_size);

  program_pos_data->kernel_deme_idxs[program_pos_off] =
      (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->n_kernel_demes);

}

static void
evoasm_pop_seed_program(evoasm_pop_t *pop,
                        size_t deme_idx,
                        size_t program_idx,
                        int tid) {
  unsigned i;
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_pop_params_t *params = pop->params;

  size_t program_off = EVOASM_POP_PROGRAM_OFF(pop, deme_idx, program_idx);

  uint16_t program_size =
      (uint16_t) _evoasm_prng_rand_between(prng,
                                           params->min_program_size,
                                           params->max_program_size);

  pop->program_data.indiv_data.sizes[program_off] = program_size;


  for(i = 0; i < program_size; i++) {
    size_t program_pos_off = EVOASM_POP_PROGRAM_POS_OFF(pop, program_off, i);
    evoasm_pop_seed_program_pos(pop, program_pos_off, program_size, prng);
  }
}


evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop) {

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->max_program_size; i++) {
    for(unsigned j = 0; j < pop->params->n_kernel_demes; j++) {
      int tid;
#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif
      for(unsigned k = 0; k < pop->params->kernel_deme_size; k++) {
        evoasm_pop_seed_kernel(pop, i, j, k, tid);
      }
    }
  }

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->n_program_demes; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif

    for(unsigned j = 0; j < pop->params->program_deme_size; j++) {
      evoasm_pop_seed_program(pop, i, j, tid);
    }
  }

  pop->seeded = true;
  return true;
}

static evoasm_success_t
evoasm_pop_eval_prepare(evoasm_pop_t *pop) {
  evoasm_signal_install((evoasm_arch_id_t) pop->arch_id, 0);
  return true;
}

static evoasm_success_t
evoasm_pop_eval_cleanup(evoasm_pop_t *pop) {
  evoasm_signal_uninstall();
  return true;
}

static void
evoasm_pop_load_program(evoasm_pop_t *pop, evoasm_program_t *program, uint16_t program_size, size_t program_off,
                        size_t *kernel_offs) {
  evoasm_pop_kernel_inst_data_t *kernel_inst_data = &pop->kernel_data.kernel_inst_data;
  evoasm_pop_program_pos_data_t *program_pos_data = &pop->program_data.program_pos_data;

  program->program_size = program_size;

  for(unsigned i = 0; i < program_size; i++) {
    size_t program_pos_off = EVOASM_POP_PROGRAM_POS_OFF(pop, program_off, i);
    size_t inst0_off = EVOASM_POP_KERNEL_INST_OFF(pop, kernel_offs[i], 0);

    program->kernels[i].insts = &kernel_inst_data->insts[inst0_off];

    switch(pop->arch_id) {
      case EVOASM_ARCH_X64:
        program->kernels[i].params.x64 = &pop->kernel_data.kernel_inst_data.params.x64[inst0_off];
        break;
      default:
        evoasm_assert_not_reached();
    }

    program->jmp_offs[i] = program_pos_data->jmp_offs[program_pos_off];
    program->jmp_selectors[i] = program_pos_data->jmp_selectors[program_pos_off];
  }
}

static evoasm_success_t
evoasm_pop_assess_program(evoasm_pop_t *pop, evoasm_program_t *program, evoasm_loss_t *loss) {
  evoasm_kernel_t *kernel = &program->kernels[program->program_size - 1];
  evoasm_pop_params_t *params = pop->params;

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

static void
evoasm_pop_indiv_data_register_sample(evoasm_pop_indiv_data_t *indiv_data, size_t indiv_off, size_t n_samples,
                                      evoasm_loss_t loss) {

#pragma omp atomic capture
  uint8_t sample_idx = indiv_data->sample_counters[indiv_off]++;
  if(sample_idx < n_samples) {
    evoasm_log_debug("program/kernel %zu/%d has loss %f", indiv_off, sample_idx, loss);
    indiv_data->losses[indiv_off * n_samples + sample_idx] = loss;
  }
}

static evoasm_success_t
evoasm_pop_eval_program(evoasm_pop_t *pop, evoasm_program_t *program, uint16_t program_size, size_t program_off,
                        size_t *kernel_offs, evoasm_loss_t *ret_loss) {

  evoasm_loss_t loss;
  evoasm_pop_load_program(pop, program, program_size, program_off, kernel_offs);
  EVOASM_TRY(error, evoasm_pop_assess_program, pop, program, &loss);

  evoasm_pop_indiv_data_register_sample(&pop->program_data.indiv_data, program_off, EVOASM_POP_N_SAMPLES_PER_PROGRAM,
                                        loss);

  for(unsigned i = 0; i < program_size; i++) {
    size_t kernel_off = kernel_offs[i];
    evoasm_pop_indiv_data_register_sample(&pop->kernel_data.indiv_data, kernel_off, EVOASM_POP_N_SAMPLES_PER_KERNEL,
                                          loss);
  }

  *ret_loss = loss;
  return true;
error:
  return false;
}


static void
evoasm_pop_program_pos_data_copy(evoasm_pop_program_pos_data_t *program_pos_data,
                                 size_t off,
                                 evoasm_pop_program_pos_data_t *dst,
                                 size_t dst_off,
                                 size_t len) {

  memcpy(dst->kernel_idxs + dst_off, program_pos_data->kernel_idxs + off,
         sizeof(uint16_t) * len);
  memcpy(dst->kernel_deme_idxs + dst_off, program_pos_data->kernel_deme_idxs + off,
         sizeof(uint16_t) * len);
  memcpy(dst->jmp_offs + dst_off, program_pos_data->jmp_offs + off,
         sizeof(uint16_t) * len);
  memcpy(dst->jmp_selectors + dst_off, program_pos_data->jmp_selectors + off,
         sizeof(uint8_t) * len);
}

static void
evoasm_pop_program_pos_data_move(evoasm_pop_program_pos_data_t *program_pos_data,
                                 size_t src_off,
                                 size_t dst_off,
                                 size_t len) {

  memmove(program_pos_data->kernel_idxs + dst_off, program_pos_data->kernel_idxs + src_off,
          sizeof(uint16_t) * len);
  memmove(program_pos_data->kernel_deme_idxs + dst_off, program_pos_data->kernel_deme_idxs + src_off,
          sizeof(uint16_t) * len);
  memmove(program_pos_data->jmp_offs + dst_off, program_pos_data->jmp_offs + src_off,
          sizeof(uint16_t) * len);
  memmove(program_pos_data->jmp_selectors + dst_off, program_pos_data->jmp_selectors + src_off,
          sizeof(uint8_t) * len);
}


static void
evoasm_pop_kernel_inst_data_copy(evoasm_pop_kernel_inst_data_t *kernel_inst_data,
                                 evoasm_arch_id_t arch_id,
                                 size_t off,
                                 evoasm_pop_kernel_inst_data_t *dst,
                                 size_t dst_off,
                                 size_t len) {

  memcpy(dst->insts + dst_off, kernel_inst_data->insts + off,
         sizeof(evoasm_inst_id_t) * len);

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      memcpy(dst->params.x64 + dst_off, kernel_inst_data->params.x64 + off,
             sizeof(evoasm_x64_basic_params_t) * len);
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_pop_kernel_inst_data_move(evoasm_pop_kernel_inst_data_t *kernel_inst_data,
                                 evoasm_arch_id_t arch_id,
                                 size_t src_off,
                                 size_t dst_off,
                                 size_t len) {

  memmove(kernel_inst_data->insts + dst_off, kernel_inst_data->insts + src_off,
          sizeof(evoasm_inst_id_t) * len);

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      memmove(kernel_inst_data->params.x64 + dst_off, kernel_inst_data->params.x64 + src_off,
              sizeof(evoasm_x64_basic_params_t) * len);
      break;
    default:
      evoasm_assert_not_reached();
  }
}


static evoasm_success_t
evoasm_pop_eval_programs(evoasm_pop_t *pop) {
#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->n_program_demes; i++) {
    for(unsigned j = 0; j < pop->params->program_deme_size; j++) {
      int tid;

#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif

      evoasm_prng_t *prng = &pop->thread_data[tid].prng;
      evoasm_program_t *program = &pop->thread_data[tid].program;
      size_t *kernel_offs = pop->thread_data[tid].kernel_offs;

      size_t program_off = EVOASM_POP_PROGRAM_OFF(pop, i, j);
      uint16_t program_size = pop->program_data.indiv_data.sizes[program_off];
      evoasm_loss_t loss;

      for(unsigned k = 0; k < EVOASM_POP_N_SAMPLES_PER_KERNEL; k++) {
        for(unsigned l = 0; l < program_size; l++) {
          uint16_t kernel_deme_idx = (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->n_kernel_demes);
          uint16_t kernel_idx = (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->kernel_deme_size);
          kernel_offs[l] = EVOASM_POP_KERNEL_OFF(pop, l, kernel_deme_idx, kernel_idx);
        }
        EVOASM_TRY(error, evoasm_pop_eval_program, pop, program, program_size, program_off, kernel_offs, &loss);

        if(loss < pop->best_program_loss) {
          evoasm_log_info("new best loss: %g", loss);
          pop->best_program_loss = loss;
          pop->best_program_size = program_size;
          evoasm_pop_program_pos_data_copy(&pop->program_data.program_pos_data, program_off,
                                           &pop->best_program_data, 0, program_size);

          for(unsigned l = 0; l < program_size; l++) {
            evoasm_pop_kernel_inst_data_copy(&pop->kernel_data.kernel_inst_data, pop->arch_id, kernel_offs[l],
                                             &pop->best_kernel_data, 0, 1);
          }
        }
      }
    }
  }

error:
  return false;
}

static evoasm_success_t
evoasm_pop_eval_kernels(evoasm_pop_t *pop) {

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->max_program_size; i++) {
    for(unsigned j = 0; j < pop->params->n_program_demes; j++) {
      for(unsigned k = 0; k < pop->params->program_deme_size; k++) {
        int tid;

#ifdef _OPENMP
        tid = omp_get_thread_num();
#else
        tid = 1;
#endif

        evoasm_prng_t *prng = &pop->thread_data[tid].prng;
        evoasm_program_t *program = &pop->thread_data[tid].program;
        size_t *kernel_offs = pop->thread_data[tid].kernel_offs;

        for(unsigned l = 0; l < EVOASM_POP_N_SAMPLES_PER_KERNEL; l++) {
          uint16_t program_deme_idx = (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->n_program_demes);
          uint16_t program_idx = (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->program_deme_size);
          size_t program_off = EVOASM_POP_PROGRAM_OFF(pop, program_deme_idx, program_idx);
          uint16_t program_size = pop->program_data.indiv_data.sizes[program_off];
          evoasm_loss_t loss;

          for(unsigned m = 0; m < program_size; m++) {
            uint16_t kernel_deme_idx;
            uint16_t kernel_idx;

            if(m == i) {
              kernel_deme_idx = (uint16_t) j;
              kernel_idx = (uint16_t) k;
            } else {
              kernel_deme_idx = (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->n_kernel_demes);
              kernel_idx = (uint16_t) _evoasm_prng_rand_between(prng, 0, pop->params->kernel_deme_size);
            }
            kernel_offs[i] = EVOASM_POP_KERNEL_OFF(pop, l, kernel_deme_idx, kernel_idx);
          }
          evoasm_pop_eval_program(pop, program, program_size, program_off, kernel_offs, &loss);
        }
      }
    }
  }
}

#define EVOASM_SORT_PAIR(t, a, b) \
do { \
  t x = EVOASM_MIN(a, b); \
  t y = EVOASM_MAX(a, b); \
  (a) = x;\
  (b) = y;\
} while(0);

typedef void (*evoasm_pop_loss_sort_func_t)(evoasm_loss_t *);

static inline void
evoasm_pop_sort_losses7(evoasm_loss_t *losses) {
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[1], losses[2]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[0], losses[2]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[0], losses[1]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[3], losses[4]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[5], losses[6]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[3], losses[5]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[4], losses[6]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[4], losses[5]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[0], losses[4]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[0], losses[3]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[1], losses[5]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[2], losses[6]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[2], losses[5]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[1], losses[3]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[2], losses[4]);
  EVOASM_SORT_PAIR(evoasm_loss_t, losses[2], losses[3]);
}

static_assert(EVOASM_POP_N_SAMPLES_PER_PROGRAM % 2 == 1, "sample count must be odd");
static_assert(EVOASM_POP_N_SAMPLES_PER_KERNEL % 2 == 1, "sample count must be odd");

static_assert(EVOASM_POP_N_SAMPLES_PER_PROGRAM == 7, "sort function and sample count must match");
#define evoasm_pop_sort_program_losses evoasm_pop_sort_losses7

static_assert(EVOASM_POP_N_SAMPLES_PER_KERNEL == 7, "sort function and sample count must match");
#define evoasm_pop_sort_kernel_losses evoasm_pop_sort_losses7

static void
evoasm_pop_update_losses(evoasm_pop_t *pop) {

  {
    evoasm_pop_kernel_data_t *kernel_data = &pop->kernel_data;
    size_t kernel_losses_len =
        pop->params->max_program_size * pop->params->n_kernel_demes * pop->params->kernel_deme_size *
        (size_t) EVOASM_POP_N_SAMPLES_PER_KERNEL;

    for(size_t i = 0; i < kernel_losses_len; i += EVOASM_POP_N_SAMPLES_PER_KERNEL) {
      evoasm_pop_sort_kernel_losses(&kernel_data->indiv_data.losses[i]);
    }

#pragma omp parallel for collapse(2)
    for(unsigned i = 0; i < pop->params->max_program_size; i++) {
      for(unsigned j = 0; j < pop->params->n_kernel_demes; j++) {

        size_t deme_off = EVOASM_POP_KERNEL_DEME_OFF(pop, i, j);
        evoasm_loss_t deme_loss = kernel_data->indiv_data.best_losses[deme_off];

        for(unsigned k = 0; k < pop->params->kernel_deme_size; k++) {
          size_t kernel_off = EVOASM_POP_KERNEL_OFF(pop, i, j, k);
          size_t sample_off = EVOASM_POP_KERNEL_SAMPLE_OFF(pop, kernel_off, EVOASM_POP_N_SAMPLES_PER_KERNEL / 2 + 1);
          evoasm_loss_t kernel_loss = kernel_data->indiv_data.losses[sample_off];

          if(kernel_loss < deme_loss) {
            kernel_data->indiv_data.best_losses[deme_off] = kernel_loss;
          }
        }
      }
    }
  }

  {
    evoasm_pop_program_data_t *program_data = &pop->program_data;
    size_t program_losses_len =
        pop->params->n_program_demes * pop->params->program_deme_size * (size_t) EVOASM_POP_N_SAMPLES_PER_PROGRAM;

    for(size_t i = 0; i < program_losses_len; i += EVOASM_POP_N_SAMPLES_PER_PROGRAM) {
      evoasm_pop_sort_program_losses(&pop->program_data.indiv_data.losses[i]);
    }

#pragma omp parallel for
    for(unsigned j = 0; j < pop->params->n_program_demes; j++) {
      size_t deme_off = EVOASM_POP_PROGRAM_DEME_OFF(pop, j);
      evoasm_loss_t deme_loss = program_data->indiv_data.best_losses[deme_off];

      for(unsigned k = 0; k < pop->params->program_deme_size; k++) {
        size_t program_off = EVOASM_POP_PROGRAM_OFF(pop, j, k);
        size_t sample_off = EVOASM_POP_PROGRAM_SAMPLE_OFF(pop, program_off, EVOASM_POP_N_SAMPLES_PER_PROGRAM / 2 + 1);
        evoasm_loss_t program_loss = program_data->indiv_data.losses[sample_off];

        if(program_loss < deme_loss) {
          program_data->indiv_data.best_losses[deme_off] = program_loss;
        }
      }
    }
  }

}

evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop) {
  bool retval;
  uint32_t n_examples = pop->n_examples;

  if(!pop->seeded) {
    retval = false;
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_ERROR_CODE_NONE,
                 NULL, "not seeded");
    goto done;
  }

  if(!evoasm_pop_eval_prepare(pop)) {
    retval = false;
    goto done;
  }

  if(!evoasm_pop_eval_programs(pop)) {
    retval = false;
    goto done;
  }

  if(!evoasm_pop_eval_kernels(pop)) {
    retval = false;
    goto done;
  }

  evoasm_pop_update_losses(pop);

  retval = true;

done:
  if(!evoasm_pop_eval_cleanup(pop)) {
    retval = false;
  }
  return retval;
}

static evoasm_force_inline inline void
evoasm_pop_select_deme(evoasm_pop_t *pop, size_t deme_off, size_t indiv0_off, bool kernel_deme,
                       int tid) {
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  uint16_t *parent_idxs = pop->thread_data[tid].parent_idxs;
  evoasm_pop_indiv_data_t *indiv_data;
  uint16_t deme_size;
  uint32_t n = 0;

  if(kernel_deme) {
    indiv_data = &pop->kernel_data.indiv_data;
    deme_size = pop->params->kernel_deme_size;
  } else {
    indiv_data = &pop->program_data.indiv_data;
    deme_size = pop->params->program_deme_size;
  }

  evoasm_loss_t best_loss = indiv_data->best_losses[deme_off];

  while(true) {
    for(uint16_t i = 0; i < deme_size; i++) {
      uint32_t r = _evoasm_prng_rand32(prng);
      if(n >= deme_size) goto done;
      if(r < UINT32_MAX * ((best_loss + 1.0) / (indiv_data->losses[indiv0_off + i] + 1.0))) {
        parent_idxs[n++] = i;
      }
    }
  }
done:;
}

static evoasm_force_inline inline void
evoasm_pop_combine_deme(evoasm_pop_t *pop, size_t indiv0_off, bool kernel_deme, int tid) {
  evoasm_pop_thread_data_t *thread_data = &pop->thread_data[tid];
  evoasm_pop_program_pos_data_t *program_pos_data = &pop->program_data.program_pos_data;
  evoasm_pop_kernel_inst_data_t *kernel_inst_data = &pop->kernel_data.kernel_inst_data;
  evoasm_prng_t *prng = &thread_data->prng;
  evoasm_pop_indiv_data_t *indiv_data;
  uint16_t deme_size;

  if(kernel_deme) {
    indiv_data = &pop->kernel_data.indiv_data;
    deme_size = pop->params->kernel_deme_size;
  } else {
    indiv_data = &pop->program_data.indiv_data;
    deme_size = pop->params->program_deme_size;
  }

  for(unsigned i = 0; i < deme_size; i += 2) {
    size_t parent_offs[2] = {(indiv0_off + i), (indiv0_off + i + 1)};
    uint16_t parent_sizes[2] = {indiv_data->sizes[parent_offs[0]], indiv_data->sizes[parent_offs[1]]};

    if(parent_sizes[0] < parent_sizes[1]) {
      EVOASM_SWAP(size_t, parent_offs[0], parent_offs[1]);
      EVOASM_SWAP(uint16_t, parent_sizes[0], parent_sizes[1]);
    }

    evoasm_loss_t parent_losses[2] = {indiv_data->losses[parent_offs[0]],
                                      indiv_data->losses[parent_offs[1]]};

    /* rough estimate */
    evoasm_loss_t child_loss = 0.5f * (parent_losses[0] + parent_losses[1]);

    /* save parents to local storage, we override originals with children */
    for(unsigned j = 0; j < 2; j++) {
      uint16_t parent_size = parent_sizes[j];
      size_t parent_off = parent_offs[j];

      if(kernel_deme) {
        size_t kernel_inst0_off = EVOASM_POP_KERNEL_INST_OFF(pop, parent_off, 0);
        evoasm_pop_kernel_inst_data_copy(kernel_inst_data, pop->arch_id, kernel_inst0_off,
                                         &thread_data->parent_kernel_inst_data,
                                         j * pop->params->max_kernel_size, parent_size);
      } else {
        size_t program_pos0_off = EVOASM_POP_PROGRAM_POS_OFF(pop, parent_off, 0);
        evoasm_pop_program_pos_data_copy(program_pos_data, program_pos0_off, &thread_data->parent_program_pos_data,
                                         j * pop->params->max_program_size, parent_size);
      }
    }

    for(unsigned j = 0; j < 2; j++) {
      uint16_t child_size = (uint16_t) _evoasm_prng_rand_between(prng, parent_sizes[0], parent_sizes[1]);

      /* children replace their parents */
      size_t child_off = parent_offs[j];

      indiv_data->sizes[child_off] = child_size;
      indiv_data->losses[child_off] = child_loss;

      assert(child_size > 0);

      /* offset for shorter parent */
      unsigned crossover_point = (unsigned) _evoasm_prng_rand_between(prng,
                                                                      0, child_size - parent_sizes[1]);
      unsigned crossover_len = (unsigned) _evoasm_prng_rand_between(prng,
                                                                    0, parent_sizes[1]);

      size_t parent_off;
      size_t child_elem0_off;

      if(kernel_deme) {
        parent_off = j * pop->params->max_kernel_size;
        child_elem0_off = EVOASM_POP_KERNEL_INST_OFF(pop, child_off, 0);
      } else {
        parent_off = j * pop->params->max_program_size;
        child_elem0_off = EVOASM_POP_PROGRAM_POS_OFF(pop, child_off, 0);
      }

      size_t len1 = crossover_point;
      size_t len2 = crossover_len;
      size_t len3 = child_size - crossover_point - crossover_len;

      size_t src_off1 = parent_off + 0;
      size_t src_off2 = parent_off + crossover_point;
      size_t src_off3 = parent_off + crossover_point + crossover_len;

      size_t dst_off1 = child_elem0_off + 0;
      size_t dst_off2 = child_elem0_off + crossover_point;
      size_t dst_off3 = child_elem0_off + crossover_point + crossover_len;

      if(kernel_deme) {
        evoasm_pop_kernel_inst_data_copy(&thread_data->parent_kernel_inst_data,
                                         pop->arch_id, src_off1, kernel_inst_data, dst_off1, len1);
        evoasm_pop_kernel_inst_data_copy(&thread_data->parent_kernel_inst_data,
                                         pop->arch_id, src_off2, kernel_inst_data, dst_off2, len2);
        evoasm_pop_kernel_inst_data_copy(&thread_data->parent_kernel_inst_data,
                                         pop->arch_id, src_off2, kernel_inst_data, dst_off2, len2);

      } else {
        evoasm_pop_program_pos_data_copy(&thread_data->parent_program_pos_data,
                                         src_off1, program_pos_data, dst_off1, len1);
        evoasm_pop_program_pos_data_copy(&thread_data->parent_program_pos_data,
                                         src_off2, program_pos_data, dst_off2, len2);
        evoasm_pop_program_pos_data_copy(&thread_data->parent_program_pos_data,
                                         src_off3, program_pos_data, dst_off3, len3);


      }
    }
  }
}


evoasm_success_t
evoasm_pop_combine(evoasm_pop_t *pop) {

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->max_program_size; i++) {
    for(unsigned j = 0; j < pop->params->n_kernel_demes; j++) {
      int tid;
#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif

      size_t kernel0_off = EVOASM_POP_KERNEL_OFF(pop, i, j, 0);
      evoasm_pop_combine_deme(pop, kernel0_off, true, tid);
    }
  }

#pragma omp parallel for
  for(unsigned i = 0; i < pop->params->n_program_demes; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif

    size_t program0_off = EVOASM_POP_PROGRAM_OFF(pop, i, 0);
    evoasm_pop_combine_deme(pop, program0_off, false, tid);
  }


  return true;
}

static int evoasm_pop_loss_cmp_func(const void *a, const void *b) {
  evoasm_loss_t loss_a = *(const evoasm_loss_t *) a;
  evoasm_loss_t loss_b = *(const evoasm_loss_t *) b;
  return (loss_a > loss_b) - (loss_a < loss_b);
}


static evoasm_force_inline inline void
evoasm_pop_get_deme_loss(evoasm_pop_t *pop, size_t indiv0_off, bool kernel_deme,
                         evoasm_loss_t *summary) {
  evoasm_pop_indiv_data_t *indiv_data;
  uint16_t deme_size;

  if(kernel_deme) {
    indiv_data = &pop->kernel_data.indiv_data;
    deme_size = pop->params->kernel_deme_size;
  } else {
    indiv_data = &pop->program_data.indiv_data;
    deme_size = pop->params->program_deme_size;
  }

  memcpy(pop->deme_losses, &indiv_data->losses[indiv0_off], sizeof(evoasm_loss_t) * deme_size);
  qsort(pop->deme_losses, deme_size, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);

  summary[0] = pop->deme_losses[0 * deme_size / 4];
  summary[1] = pop->deme_losses[1 * deme_size / 4];
  summary[1] = pop->deme_losses[2 * deme_size / 4];
  summary[2] = pop->deme_losses[3 * deme_size / 4];
  summary[3] = pop->deme_losses[4 * deme_size / 4];
}

void
evoasm_pop_get_kernel_deme_loss(evoasm_pop_t *pop, size_t pos, size_t deme_idx,
                                evoasm_loss_t *summary) {
  evoasm_pop_get_deme_loss(pop, EVOASM_POP_KERNEL_OFF(pop, pos, deme_idx, 0), true, summary);
}

void
evoasm_pop_get_program_deme_loss(evoasm_pop_t *pop, size_t deme_idx,
                                 evoasm_loss_t *summary) {
  evoasm_pop_get_deme_loss(pop, EVOASM_POP_PROGRAM_OFF(pop, deme_idx, 0), false, summary);
}

#if 0
unsigned i;
double scale = 1.0 / pop->params->size;
double pop_loss = 0.0;
*n_invalid = 0;
for(i = 0; i < pop->params->size; i++) {
  double loss = pop->losses[i];
  if(loss != INFINITY) {
    pop_loss += scale * loss;
  } else {
    (*n_invalid)++;
  }
}

if(per_example) pop_loss /= pop->n_examples;
#endif


static void
evoasm_pop_mutate_program(evoasm_pop_t *pop, size_t program_off, int tid) {
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  uint32_t mut_rate = (uint32_t) (pop->params->mut_rate * UINT32_MAX);
  uint32_t r = _evoasm_prng_rand32(prng);
  evoasm_pop_program_pos_data_t *program_pos_data = &pop->program_data.program_pos_data;

  uint16_t program_size = pop->program_data.indiv_data.sizes[program_off];

  if(r < mut_rate) {
    r = _evoasm_prng_rand32(prng);
    if(program_size > pop->params->min_program_size && r < UINT32_MAX / 16) {
      uint32_t index = r % program_size;

      if(index < (uint32_t) (program_size - 1)) {
        evoasm_pop_program_pos_data_move(program_pos_data, index + 1, index, program_size - index - 1);
      }
      pop->program_data.indiv_data.sizes[program_off]--;
    }

    r = _evoasm_prng_rand32(prng);
    {
      //evoasm_pop_seed_program(
      evoasm_kernel_param_t *param = child->params + (r % child->program_size);
      evoasm_program_pop_seed_kernel_param(program_pop, param);
    }
  }
}

static void
evoasm_pop_mutate_kernel(evoasm_pop_t *pop, size_t kernel_off, int tid) {

  evoasm_prng_t *prng = &thread_data->prng;
  uint32_t mut_rate = (uint32_t) (pop->params->mut_rate * UINT32_MAX);
  uint32_t r = _evoasm_prng_rand32(prng);

  evoasm_log_debug("mutating child: %u < %u", r, mut_rate);

  if(r < mut_rate) {
    r = _evoasm_prng_rand32(prng);
    if(child->program_size > pop->params->min_kernel_size && r < UINT32_MAX / 16) {
      uint32_t index = r % child->program_size;

      if(index < (uint32_t) (child->program_size - 1)) {
        memmove(child->params + index, child->params + index + 1,
                (child->program_size - index - 1) * sizeof(evoasm_kernel_param_t));
      }
      child->program_size--;
    }

    r = _evoasm_prng_rand32(prng);
    {
      evoasm_kernel_param_t *param = child->params + (r % child->program_size);
      evoasm_program_pop_seed_kernel_param(program_pop, param);
    }
  }
}


static void
evoasm_pop_mutate_deme(evoasm_pop_t *pop, size_t depth, size_t deme_idx, int tid) {
}

void
evoasm_pop_next_gen(evoasm_pop_t *pop) {

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->max_program_size; i++) {
    for(unsigned j = 0; j < pop->params->n_kernel_demes; j++) {
      int tid;
#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif
      size_t kernel0_off = EVOASM_POP_KERNEL_OFF(pop, i, j, 0);
      size_t deme_off = EVOASM_POP_KERNEL_DEME_OFF(pop, i, j);

      evoasm_pop_select_deme(pop, deme_off, kernel0_off, true, tid);
      evoasm_pop_combine_deme(pop, kernel0_off, true, tid);
      evoasm_pop_mutate_deme(pop, kernel0_off, true, tid);
    }
  }

#pragma omp parallel for
  for(unsigned i = 0; i < pop->params->n_program_demes; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif
    size_t program0_off = EVOASM_POP_PROGRAM_OFF(pop, i, 0);
    size_t deme_off = EVOASM_POP_PROGRAM_DEME_OFF(pop, i);

    evoasm_pop_select_deme(pop, deme_off, program0_off, true, tid);
    evoasm_pop_combine_deme(pop, program0_off, true, tid);
    evoasm_pop_mutate_deme(pop, program0_off, true, tid);
  }
}


#if 0

evoasm_pop_select(pop, parent_idxs, pop->params->size);
  {
    double scale = 1.0 / pop->params->program_size;
    double pop_loss = 0.0;
    unsigned n_inf = 0;
    for(i = 0; i < pop->params->program_size; i++) {
      double loss = pop->pop.losses[parent_idxs[i]];
      if(loss != INFINITY) {
        pop_loss += scale * loss;
      }
      else {
        n_inf++;
      }
    }

    evoasm_log_info("pop selected loss: %g/%u", pop_loss, n_inf);
  }

  unsigned i;
  for(i = 0; i < pop->params->program_size; i++) {
    evoasm_program_params_t *program_params = _EVOASM_SEARCH_PROGRAM_PARAMS(pop, pop->pop.indivs, parent_idxs[i]);
    assert(program_params->program_size > 0);
  }

  return evoasm_pop_combine_parents(pop, parent_idxs);
}
#endif


