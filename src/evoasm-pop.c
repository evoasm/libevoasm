//
// Created by jap on 9/16/16.
//

#include "evoasm-pop.h"
#include "evoasm-pop-params.h"
#include "evoasm-rand.h"
#include "evoasm-signal.h"
#include "evoasm-program.h"
#include "evoasm.h"

#ifdef _OPENMP

#  include <omp.h>

#endif

EVOASM_DEF_LOG_TAG("pop")

#define EVOASM_DEME_MIN_LOSS_SAMPLES 8
#define EVOASM_DEME_MAX_LOSS_SAMPLES 16

#define EVOASM_DEME_PROGRAM_OFF(deme, program_idx) (program_idx)

#define EVOASM_DEME_PROGRAM_POS_OFF(deme, program_off, pos) \
  (((program_off) * (size_t)(deme)->params->max_program_size) + (pos))

#define EVOASM_DEME_KERNEL_OFF(deme, pos, kernel_idx) \
  ((size_t)((pos) * (size_t)(deme)->params->n_kernels_per_deme + (kernel_idx)))

#define EVOASM_DEME_KERNEL_INST_OFF(deme, kernel_off, inst_idx) \
  ((kernel_off) * (uint_fast16_t)(deme)->params->max_kernel_size + (inst_idx))

#define EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(deme, indiv_off, sample_idx) \
  ((indiv_off) * EVOASM_DEME_MAX_LOSS_SAMPLES + (sample_idx))

static evoasm_success_t
evoasm_pop_indiv_data_init(evoasm_pop_indiv_data_t *indiv_data, size_t n_indivs) {

  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->sizes, EVOASM_CACHE_LINE_SIZE,
                   n_indivs,
                   sizeof(uint16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->loss_samples, EVOASM_CACHE_LINE_SIZE,
                   n_indivs * EVOASM_DEME_MAX_LOSS_SAMPLES,
                   sizeof(evoasm_loss_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->loss_sample_counters, EVOASM_CACHE_LINE_SIZE,
                   n_indivs,
                   sizeof(uint8_t));

  return true;
error:
  return false;
}

static void
evoasm_pop_indiv_data_destroy(evoasm_pop_indiv_data_t *indiv_data) {
  evoasm_free(indiv_data->loss_samples);
  evoasm_free(indiv_data->sizes);
  evoasm_free(indiv_data->loss_sample_counters);
}

static evoasm_success_t
evoasm_pop_program_pos_data_init(evoasm_pop_program_pos_data_t *program_pos_data, size_t n_pos) {

  EVOASM_TRY_ALLOC(error, aligned_calloc, program_pos_data->jmp_offs, EVOASM_CACHE_LINE_SIZE,
                   n_pos,
                   sizeof(int16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, program_pos_data->jmp_cond, EVOASM_CACHE_LINE_SIZE,
                   n_pos,
                   sizeof(uint8_t));

  return true;

error:
  return false;
}

static void
evoasm_pop_program_pos_data_destroy(evoasm_pop_program_pos_data_t *program_pos_data) {
  evoasm_free(program_pos_data->jmp_offs);
  evoasm_free(program_pos_data->jmp_cond);
}

static evoasm_success_t
evoasm_pop_kernel_inst_data_init(evoasm_pop_kernel_inst_data_t *kernel_inst_data,
                                 evoasm_arch_id_t arch_id,
                                 size_t n_insts) {


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

static evoasm_success_t
evoasm_pop_kernel_data_init(evoasm_pop_kernel_data_t *kernel_inst_data, evoasm_arch_id_t arch_id,
                            size_t n_kernels, size_t max_kernel_size) {

  size_t n_insts = n_kernels * max_kernel_size;

  EVOASM_TRY(error, evoasm_pop_kernel_inst_data_init, &kernel_inst_data->kernel_inst_data,
             arch_id, n_insts);

  EVOASM_TRY(error, evoasm_pop_indiv_data_init, &kernel_inst_data->indiv_data, n_kernels);

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
evoasm_pop_program_data_init(evoasm_pop_program_data_t *program_data, size_t deme_size) {
  size_t n_programs = deme_size;

  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &program_data->program_pos_data, n_programs);
  EVOASM_TRY(error, evoasm_pop_indiv_data_init, &program_data->indiv_data, n_programs);

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

static void
evoasm_deme_destroy(evoasm_deme_t *deme) {
  EVOASM_TRY_WARN(evoasm_program_destroy, &deme->program);
  evoasm_prng_destroy(&deme->prng);
  evoasm_free(deme->selected_parent_idxs);
  evoasm_free(deme->error_counters);
  evoasm_free(deme->top_kernel_losses);

  evoasm_pop_program_data_destroy(&deme->program_data);
  evoasm_pop_kernel_data_destroy(&deme->kernel_data);
  evoasm_pop_kernel_inst_data_destroy(&deme->best_kernel_data);
  evoasm_pop_program_pos_data_destroy(&deme->best_program_data);

  evoasm_pop_program_pos_data_destroy(&deme->parent_program_pos_data);
  evoasm_pop_kernel_inst_data_destroy(&deme->parent_kernel_inst_data);
}

void
evoasm_pop_destroy(evoasm_pop_t *pop) {
  evoasm_free(pop->domains);

  for(int i = 0; i < pop->max_threads; i++) {
    evoasm_deme_destroy(&pop->demes[i]);
  }
  evoasm_free(pop->demes);
  evoasm_free(pop->summary_losses);

  evoasm_pop_module_data_destroy(&pop->module_data);
}

static evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme,
                 evoasm_arch_id_t arch_id,
                 evoasm_pop_params_t *params,
                 evoasm_prng_state_t *seed,
                 evoasm_domain_t *domains) {

  uint16_t n_examples = EVOASM_PROGRAM_INPUT_EXAMPLE_COUNT(params->program_input);
  static evoasm_deme_t zero_deme = {0};

  *deme = zero_deme;
  deme->n_examples = n_examples;
  deme->arch_id = arch_id;
  deme->params = params;
  deme->domains = domains;

  evoasm_prng_init(&deme->prng, seed);
  EVOASM_TRY(error, evoasm_program_init, &deme->program,
             arch_id,
             params->program_input,
             params->max_program_size,
             params->max_kernel_size,
             params->recur_limit);

  size_t max_deme_size = EVOASM_MAX(params->n_kernels_per_deme, params->n_programs_per_deme);
  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->selected_parent_idxs, EVOASM_CACHE_LINE_SIZE, max_deme_size,
                   sizeof(uint16_t));

  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &deme->parent_program_pos_data,
             2u * params->max_program_size);
  EVOASM_TRY(error, evoasm_pop_kernel_inst_data_init, &deme->parent_kernel_inst_data, arch_id,
             2u * params->max_kernel_size);

  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->kernel_data, arch_id,
             (size_t) (params->max_program_size * params->n_kernels_per_deme), params->max_kernel_size);

  EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->program_data,
             params->n_programs_per_deme);

  EVOASM_TRY(error, evoasm_pop_kernel_inst_data_init, &deme->best_kernel_data, arch_id,
             (size_t) (params->max_program_size * params->max_kernel_size));

  EVOASM_TRY(error, evoasm_pop_program_pos_data_init, &deme->best_program_data, params->max_program_size);

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->top_kernel_losses, EVOASM_CACHE_LINE_SIZE,
                   params->max_program_size,
                   sizeof(evoasm_loss_t));

  for(size_t i = 0; i < params->max_program_size; i++) {
    deme->top_kernel_losses[i] = INFINITY;
  }
  deme->top_program_loss = INFINITY;

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->error_counters, (size_t) n_examples, EVOASM_CACHE_LINE_SIZE,
                   sizeof(uint64_t));
  deme->error_counter = 0;

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
    evoasm_x64_inst_t *inst = evoasm_x64_inst_((evoasm_x64_inst_id_t) params->inst_ids[i]);
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
#ifdef _OPENMP
  max_threads = omp_get_max_threads();
#else
  max_threads = 1;
#endif

  if(params->n_demes == 0) {
    params->n_demes = (uint16_t) max_threads;
  }

  *pop = zero_pop;
  pop->params = params;
  pop->max_threads = max_threads;

  evoasm_prng_init(&seed_prng, &params->seed);

  EVOASM_TRY(error, evoasm_pop_init_domains, pop);
  EVOASM_TRY(error, evoasm_pop_module_data_init, &pop->module_data, params->library_size);

  EVOASM_TRY_ALLOC(error, aligned_calloc, pop->demes, EVOASM_CACHE_LINE_SIZE, (size_t) max_threads,
                   sizeof(evoasm_deme_t));

  for(int i = 0; i < max_threads; i++) {
    evoasm_prng_state_t seed;

    for(int j = 0; j < EVOASM_PRNG_SEED_LEN; j++) {
      seed.data[j] = evoasm_prng_rand64_(&seed_prng);
    }

    EVOASM_TRY(error, evoasm_deme_init,
               &pop->demes[i],
               arch_id,
               params,
               &seed,
               pop->domains);
  }

  return true;

error:
  evoasm_pop_destroy(pop);
  return false;
}

static void
evoasm_deme_seed_kernel_param_x64(evoasm_deme_t *deme, evoasm_inst_id_t *inst_id_ptr,
                                  evoasm_x64_basic_params_t *params_ptr) {
  evoasm_pop_params_t *params = deme->params;
  size_t n_params = params->n_params;
  evoasm_prng_t *prng = &deme->prng;

  size_t inst_idx = (size_t) evoasm_prng_rand_between_(prng, 0, params->n_insts - 1);
  evoasm_inst_id_t inst_id = params->inst_ids[inst_idx];

  *inst_id_ptr = inst_id;

  /* set parameters */
  for(size_t i = 0; i < n_params; i++) {
    evoasm_domain_t *domain = &deme->domains[inst_idx * n_params + i];
    if(domain->type < EVOASM_DOMAIN_TYPE_NONE) {
      evoasm_x64_param_id_t param_id = (evoasm_x64_param_id_t) deme->params->param_ids[i];
      evoasm_param_val_t param_val;

      param_val = (int64_t) evoasm_domain_rand(domain, prng);
      evoasm_x64_basic_params_set_(params_ptr, param_id, param_val);
    }
  }
}

static void
evoasm_deme_seed_kernel_inst(evoasm_deme_t *deme, size_t kernel_inst_off) {
  evoasm_pop_kernel_data_t *kernel_data = &deme->kernel_data;
  evoasm_inst_id_t *insts_ptr = &kernel_data->kernel_inst_data.insts[kernel_inst_off];

  switch(deme->arch_id) {
    case EVOASM_ARCH_X64: {
      evoasm_x64_basic_params_t *params_ptr = &kernel_data->kernel_inst_data.params.x64[kernel_inst_off];
      evoasm_deme_seed_kernel_param_x64(deme, insts_ptr, params_ptr);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_deme_seed_kernel(evoasm_deme_t *deme, size_t pos, size_t kernel_idx) {
  size_t i;

  evoasm_prng_t *prng = &deme->prng;
  evoasm_pop_params_t *params = deme->params;

  size_t kernel_off = EVOASM_DEME_KERNEL_OFF(deme, pos, kernel_idx);

  size_t kernel_size =
      (size_t) evoasm_prng_rand_between_(prng,
                                         params->min_kernel_size,
                                         params->max_kernel_size);

  deme->kernel_data.indiv_data.sizes[kernel_off] = (uint16_t) kernel_size;

  for(i = 0; i < kernel_size; i++) {
    size_t kernel_inst_off = EVOASM_DEME_KERNEL_INST_OFF(deme, kernel_off, i);
    evoasm_deme_seed_kernel_inst(deme, kernel_inst_off);
  }

#if 0
  kernel_params->jmp_selector = (uint8_t) evoasm_prng_rand8_(prng);
  kernel_params->alt_succ_idx = (uint16_t)
      evoasm_prng_rand_between_(prng, 0, size - 1);
#endif

}

static void
evoasm_deme_seed_program_pos(evoasm_deme_t *deme,
                             size_t program_pos_off,
                             size_t program_size) {

  evoasm_pop_program_pos_data_t *program_pos_data = &deme->program_data.program_pos_data;
  evoasm_prng_t *prng = &deme->prng;

  program_pos_data->jmp_cond[program_pos_off] =
      (uint8_t) evoasm_prng_rand8_(prng);

  program_pos_data->jmp_offs[program_pos_off] =
      (int16_t) (evoasm_prng_rand_between_(prng, 0, (int64_t) (program_size - 1)) - (int64_t) (program_size / 2));
}

static void
evoasm_deme_seed_program(evoasm_deme_t *deme,
                         size_t program_idx) {
  evoasm_prng_t *prng = &deme->prng;
  evoasm_pop_params_t *params = deme->params;

  size_t program_off = EVOASM_DEME_PROGRAM_OFF(pop, program_idx);

  size_t program_size =
      (size_t) evoasm_prng_rand_between_(prng,
                                           params->min_program_size,
                                           params->max_program_size);

  deme->program_data.indiv_data.sizes[program_off] = (uint16_t) program_size;
  deme->max_program_size =  EVOASM_MAX(deme->max_program_size, (uint16_t) program_size);

  for(size_t i = 0; i < program_size; i++) {
    size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, program_off, i);
    evoasm_deme_seed_program_pos(deme, program_pos_off, program_size);
  }
}

static void
evoasm_deme_seed(evoasm_deme_t *deme) {
  for(size_t i = 0; i < deme->params->n_programs_per_deme; i++) {
    evoasm_deme_seed_program(deme, i);
  }

  for(size_t i = 0; i < deme->max_program_size; i++) {
    for(size_t j = 0; j < deme->params->n_kernels_per_deme; j++) {
      evoasm_deme_seed_kernel(deme, i, j);
    }
  }
}

evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop) {

#pragma omp parallel for
  for(size_t i = 0; i < pop->params->n_demes; i++) {
    evoasm_deme_seed(&pop->demes[i]);
  }
  pop->seeded = true;
  return true;
}

static evoasm_success_t
evoasm_deme_eval_prepare(evoasm_deme_t *deme) {
  evoasm_signal_install((evoasm_arch_id_t) deme->arch_id, 0);
  return true;
}

static evoasm_success_t
evoasm_deme_eval_cleanup(evoasm_deme_t *deme) {
  evoasm_signal_uninstall();
  return true;
}

static void
evoasm_deme_load_program(evoasm_deme_t *deme,
                         evoasm_program_t *program,
                         evoasm_pop_program_pos_data_t *program_pos_data,
                         evoasm_pop_kernel_inst_data_t *kernel_inst_data,
                         size_t program_size,
                         size_t program_off,
                         size_t *kernel_offs) {

  program->size = (uint16_t) program_size;

  for(size_t i = 0; i < program_size; i++) {
    size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, program_off, i);
    size_t inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, kernel_offs[i], 0);

    program->kernels[i].insts = &kernel_inst_data->insts[inst0_off];

    switch(deme->arch_id) {
      case EVOASM_ARCH_X64:
        program->kernels[i].params.x64 = &deme->kernel_data.kernel_inst_data.params.x64[inst0_off];
        break;
      default:
        evoasm_assert_not_reached();
    }

    program->jmp_offs[i] = program_pos_data->jmp_offs[program_pos_off];
    program->jmp_conds[i] = program_pos_data->jmp_cond[program_pos_off];
  }
}

static evoasm_success_t
evoasm_deme_assess_program(evoasm_deme_t *deme, evoasm_program_t *program, evoasm_loss_t *loss) {
  evoasm_kernel_t *kernel = &program->kernels[program->size - 1];
  evoasm_pop_params_t *params = deme->params;

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
evoasm_pop_indiv_data_register_sample(evoasm_pop_indiv_data_t *indiv_data, size_t indiv_off, evoasm_loss_t loss) {
  size_t sample_idx = indiv_data->loss_sample_counters[indiv_off];
  if(sample_idx < EVOASM_DEME_MAX_LOSS_SAMPLES) {
    size_t sample_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(deme, indiv_off, sample_idx);
    indiv_data->loss_samples[sample_off] = loss;
    indiv_data->loss_sample_counters[indiv_off]++;
  }
}

evoasm_success_t
evoasm_pop_load_best_program(evoasm_pop_t *pop, evoasm_program_t *program) {
  evoasm_pop_params_t *params = pop->params;
  evoasm_loss_t best_loss = INFINITY;
  evoasm_deme_t *best_deme = NULL;

  for(size_t i = 0; i < params->n_demes; i++) {
    evoasm_deme_t *deme = &pop->demes[i];
    if(deme->best_loss < best_loss) {
      best_loss = deme->best_loss;
      best_deme = deme;
    }
  }

  EVOASM_TRY(error, evoasm_program_init, program,
             best_deme->arch_id,
             params->program_input,
             params->max_program_size,
             params->max_kernel_size,
             params->recur_limit);

  size_t kernel_offs[EVOASM_PROGRAM_MAX_SIZE];
  for(size_t i = 0; i < best_deme->best_program_size; i++) {
    kernel_offs[i] = i;
  }

  evoasm_deme_load_program(best_deme,
                           program,
                           &best_deme->best_program_data,
                           &best_deme->best_kernel_data,
                           best_deme->best_program_size,
                           0, kernel_offs);


error:
  return false;
}

static evoasm_success_t
evoasm_deme_eval_program(evoasm_deme_t *deme, size_t program_size, size_t program_off,
                         size_t *kernel_offs, evoasm_loss_t *ret_loss) {

  evoasm_loss_t loss;
  evoasm_program_t *program = &deme->program;
  evoasm_pop_kernel_inst_data_t *kernel_inst_data = &deme->kernel_data.kernel_inst_data;
  evoasm_pop_program_pos_data_t *program_pos_data = &deme->program_data.program_pos_data;

  evoasm_deme_load_program(deme, program, program_pos_data, kernel_inst_data, program_size, program_off, kernel_offs);
  EVOASM_TRY(error, evoasm_deme_assess_program, deme, program, &loss);

  evoasm_pop_indiv_data_register_sample(&deme->program_data.indiv_data, program_off, loss);

  for(size_t i = 0; i < program_size; i++) {
    size_t kernel_off = kernel_offs[i];
    evoasm_pop_indiv_data_register_sample(&deme->kernel_data.indiv_data, kernel_off, loss);
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

  memcpy(dst->jmp_offs + dst_off, program_pos_data->jmp_offs + off,
         sizeof(int16_t) * len);
  memcpy(dst->jmp_cond + dst_off, program_pos_data->jmp_cond + off,
         sizeof(uint8_t) * len);
}

static void
evoasm_pop_program_pos_data_move(evoasm_pop_program_pos_data_t *program_pos_data,
                                 size_t src_off,
                                 size_t dst_off,
                                 size_t len) {

  memmove(program_pos_data->jmp_offs + dst_off, program_pos_data->jmp_offs + src_off,
          sizeof(int16_t) * len);
  memmove(program_pos_data->jmp_cond + dst_off, program_pos_data->jmp_cond + src_off,
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
evoasm_deme_eval_programs(evoasm_deme_t *deme) {
  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_offs[EVOASM_PROGRAM_MAX_SIZE];

  for(size_t i = 0; i < deme->params->n_programs_per_deme; i++) {

    size_t program_off = EVOASM_DEME_PROGRAM_OFF(deme, i);
    uint16_t program_size = deme->program_data.indiv_data.sizes[program_off];
    evoasm_loss_t loss;

    for(size_t j = 0; j < EVOASM_DEME_MIN_LOSS_SAMPLES; j++) {
      for(size_t k = 0; k < program_size; k++) {
        size_t kernel_idx = (size_t) evoasm_prng_rand_between_(prng, 0,
                                                               deme->params->n_kernels_per_deme - 1);
        kernel_offs[k] = EVOASM_DEME_KERNEL_OFF(deme, k, kernel_idx);
      }

      EVOASM_TRY(error, evoasm_deme_eval_program, deme, program_size, program_off, kernel_offs, &loss);

      if(loss < deme->best_program_loss) {
        evoasm_log_info("new best program loss: %g", loss);
        deme->best_program_loss = loss;
        deme->best_program_size = program_size;
        evoasm_pop_program_pos_data_copy(&deme->program_data.program_pos_data, program_off,
                                         &deme->best_program_data, 0, program_size);

        for(size_t k = 0; k < program_size; k++) {
          evoasm_pop_kernel_inst_data_copy(&deme->kernel_data.kernel_inst_data, deme->arch_id, kernel_offs[k],
                                           &deme->best_kernel_data, k, 1);
        }
      }
    }
  }

error:
  return false;
}

static evoasm_success_t
evoasm_deme_eval_kernels(evoasm_deme_t *deme) {

  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_offs[EVOASM_PROGRAM_MAX_SIZE];

  for(size_t i = 0; i < deme->max_program_size; i++) {
    for(size_t j = 0; j < deme->params->n_kernels_per_deme; j++) {
      size_t kernel_off = EVOASM_DEME_KERNEL_OFF(deme, i, j);
      size_t n_samples = deme->kernel_data.indiv_data.loss_sample_counters[kernel_off];

      for(size_t k = n_samples; k < EVOASM_DEME_MIN_LOSS_SAMPLES; k++) {
        size_t program_idx;
        size_t program_off;
        size_t program_size = 0;
        evoasm_loss_t loss;

#ifndef NDEBUG
        size_t loop_guard = 0;
#endif
        do {
          program_idx = (size_t) evoasm_prng_rand_between_(prng, 0, deme->params->n_programs_per_deme - 1);
          program_off = EVOASM_DEME_PROGRAM_OFF(deme, program_idx);
          program_size = deme->program_data.indiv_data.sizes[program_off];

          assert(loop_guard++ < deme->params->n_programs_per_deme);
        } while(i >= program_size);

        for(size_t l = 0; l < program_size; l++) {
          size_t kernel_idx;

          if(l == i) {
            /* the current kernel */
            kernel_idx = j;
          } else {
            /* some random other kernel */
            kernel_idx = (size_t) evoasm_prng_rand_between_(prng, 0, deme->params->n_kernels_per_deme - 1);
          }
          kernel_offs[i] = EVOASM_DEME_KERNEL_OFF(deme, l, kernel_idx);
        }
        EVOASM_TRY(error, evoasm_deme_eval_program, deme, program_size, program_off, kernel_offs, &loss);
      }
    }
  }

  return true;
error:
  return false;
}

#define EVOASM_SORT_PAIR(t, a, b) \
do { \
  t x = EVOASM_MIN(a, b); \
  t y = EVOASM_MAX(a, b); \
  (a) = x;\
  (b) = y;\
} while(0);

typedef void (*evoasm_pop_loss_sort_func_t)(evoasm_loss_t *);

#define EVOASM_POP_FIND_MEDIAN_RUN_LEN 8u

static inline evoasm_loss_t
evoasm_pop_find_median_loss_(evoasm_loss_t *losses, size_t len) {
  size_t trunc_len = EVOASM_ALIGN_DOWN(len, EVOASM_POP_FIND_MEDIAN_RUN_LEN);
  size_t n_runs = trunc_len / EVOASM_POP_FIND_MEDIAN_RUN_LEN;
  size_t front_idxs[EVOASM_DEME_MAX_LOSS_SAMPLES / EVOASM_POP_FIND_MEDIAN_RUN_LEN] = {0};
  evoasm_loss_t scratch[EVOASM_DEME_MAX_LOSS_SAMPLES / 2];

  for(size_t i = 0; i < trunc_len; i += EVOASM_POP_FIND_MEDIAN_RUN_LEN) {
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 0], losses[i + 1]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 2], losses[i + 3]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 0], losses[i + 2]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 1], losses[i + 3]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 1], losses[i + 2]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 4], losses[i + 5]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 6], losses[i + 7]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 4], losses[i + 6]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 5], losses[i + 7]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 5], losses[i + 6]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 0], losses[i + 4]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 1], losses[i + 5]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 1], losses[i + 4]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 2], losses[i + 6]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 3], losses[i + 7]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 3], losses[i + 6]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 2], losses[i + 4]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 3], losses[i + 5]);
    EVOASM_SORT_PAIR(evoasm_loss_t, losses[i + 3], losses[i + 4]);
  }

  if(n_runs == 1) {
    return losses[EVOASM_POP_FIND_MEDIAN_RUN_LEN / 2];
  } else {
    size_t merge_len = trunc_len / 2;
    for(size_t i = 0; i < merge_len; i++) {
      evoasm_loss_t min_loss = INFINITY;
      size_t min_run_idx = SIZE_MAX;
      for(size_t j = 0; j < n_runs; j++) {
        evoasm_loss_t front_loss = losses[j * EVOASM_POP_FIND_MEDIAN_RUN_LEN + front_idxs[j]];
        if(front_loss < min_loss) {
          min_loss = front_loss;
          min_run_idx = j;
        }
      }
      front_idxs[min_run_idx]++;
      scratch[i] = min_loss;
    }
    return scratch[merge_len - 1];
  }
}

evoasm_loss_t
evoasm_pop_find_median_loss(evoasm_loss_t *losses, size_t len) {
  return evoasm_pop_find_median_loss_(losses, len);
}

static void
evoasm_deme_eval_update(evoasm_deme_t *deme) {

  {
    evoasm_pop_program_data_t *program_data = &deme->program_data;
    evoasm_pop_indiv_data_t *indiv_data = &program_data->indiv_data;

    for(size_t i = 0; i < deme->params->n_programs_per_deme; i++) {
      size_t program_off = EVOASM_DEME_PROGRAM_OFF(pop, i);
      size_t sample0_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(pop, program_off, 0);

      evoasm_loss_t program_loss = evoasm_pop_find_median_loss_(&indiv_data->loss_samples[sample0_off],
                                                                indiv_data->loss_sample_counters[program_off]);
      indiv_data->loss_samples[sample0_off] = program_loss;

      if(deme->top_program_loss > program_loss) {
        deme->top_program_loss = program_loss;
      }
    }
  }

  {
    evoasm_pop_kernel_data_t *kernel_data = &deme->kernel_data;
    evoasm_pop_indiv_data_t *indiv_data = &kernel_data->indiv_data;

    for(size_t i = 0; i < deme->max_program_size; i++) {
      for(size_t j = 0; j < deme->params->n_kernels_per_deme; j++) {
        size_t kernel_off = EVOASM_DEME_KERNEL_OFF(deme, i, j);
        size_t sample0_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(pop, kernel_off, 0);

        evoasm_loss_t kernel_loss =
            evoasm_pop_find_median_loss_(&indiv_data->loss_samples[sample0_off],
                                         indiv_data->loss_sample_counters[kernel_off]);
        indiv_data->loss_samples[sample0_off] = kernel_loss;

        if(deme->top_kernel_losses[i] > kernel_loss) {
          deme->top_kernel_losses[i] = kernel_loss;
        }
      }
    }
  }
}

static evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme) {
  bool retval = true;

  if(!evoasm_deme_eval_prepare(deme)) {
    retval = false;
    goto done;
  }

  if(!evoasm_deme_eval_programs(deme)) {
    retval = false;
    goto done;
  }

  if(!evoasm_deme_eval_kernels(deme)) {
    retval = false;
    goto done;
  }

  evoasm_deme_eval_update(deme);

done:
  if(!evoasm_deme_eval_cleanup(deme)) {
    retval = false;
  }
  return retval;
}

evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop) {
  bool retval = true;
  size_t n_demes = pop->params->n_demes;

  if(!pop->seeded) {
    retval = false;
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_ERROR_CODE_NONE,
                 NULL, "not seeded");
    goto done;
  }

  bool *retvals = evoasm_alloca(sizeof(bool) * n_demes);
  evoasm_error_t *errors = evoasm_alloca(sizeof(evoasm_error_t) * n_demes);

#pragma omp parallel for
  for(size_t i = 0; i < n_demes; i++) {
    retvals[i] = evoasm_deme_eval(&pop->demes[i]);
    if(!retvals[i]) {
      errors[i] = *evoasm_get_last_error();
    }
  }

  for(size_t i = 0; i < n_demes; i++) {
    if(!retvals[i]) {
      evoasm_set_last_error(&errors[i]);
      retval = false;
      break;
    }
  }

done:
  return retval;
}


static evoasm_force_inline inline void
evoasm_deme_select_indivs(evoasm_deme_t *deme, evoasm_pop_indiv_data_t *indiv_data,
                          size_t indiv0_off, size_t deme_size, evoasm_loss_t top_loss) {
  evoasm_prng_t *prng = &deme->prng;
  uint16_t *parent_idxs = deme->selected_parent_idxs;
  uint32_t n = 0;

  while(true) {
    for(size_t i = 0; i < deme_size; i++) {
      float r = evoasm_prng_randf_(prng);
      size_t sample0_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(deme, indiv0_off + i, 0);
      if(r < (top_loss + 1.0) / (indiv_data->loss_samples[sample0_off] + 1.0)) {
        parent_idxs[n++] = (uint16_t) i;
        if(n >= deme_size) goto done;
      }
    }
  }
done:;
}

static evoasm_force_inline inline void
evoasm_deme_combine(evoasm_deme_t *deme, evoasm_pop_indiv_data_t *indiv_data, size_t indiv0_off, size_t deme_size,
                    bool kernels) {
  evoasm_pop_program_pos_data_t *program_pos_data = &deme->program_data.program_pos_data;
  evoasm_pop_kernel_inst_data_t *kernel_inst_data = &deme->kernel_data.kernel_inst_data;
  evoasm_prng_t *prng = &deme->prng;

  for(size_t i = 0; i < deme_size; i += 2) {
    size_t parent_offs[2] = {(indiv0_off + i), (indiv0_off + i + 1)};
    uint16_t parent_sizes[2] = {indiv_data->sizes[parent_offs[0]], indiv_data->sizes[parent_offs[1]]};
    evoasm_loss_t parent_losses[2] = {indiv_data->loss_samples[parent_offs[0]],
                                      indiv_data->loss_samples[parent_offs[1]]};

    /* rough estimate */
    evoasm_loss_t child_loss = 0.5f * parent_losses[0] + 0.5f * parent_losses[1];

    /* save parents to local storage, we override originals with children */
    for(size_t j = 0; j < 2; j++) {
      size_t parent_off = parent_offs[j];
      uint16_t parent_size = parent_sizes[j];

      if(kernels) {
        size_t kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, parent_off, 0);
        evoasm_pop_kernel_inst_data_copy(kernel_inst_data, deme->arch_id, kernel_inst0_off,
                                         &deme->parent_kernel_inst_data,
                                         j * deme->params->max_kernel_size, parent_size);
      } else {
        size_t program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, parent_off, 0);
        evoasm_pop_program_pos_data_copy(program_pos_data, program_pos0_off, &deme->parent_program_pos_data,
                                         j * deme->params->max_program_size, parent_size);
      }
    }

    for(size_t j = 0; j < 2; j++) {
      /* children replace their parents */
      size_t child_off = parent_offs[j];
      size_t sample0_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(deme, child_off, 0);
      size_t max_parent_size;
      size_t child_elem0_off;

      if(kernels) {
        max_parent_size = deme->params->max_kernel_size;
        child_elem0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, child_off, 0);
      } else {
        max_parent_size = deme->params->max_program_size;
        child_elem0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, child_off, 0);
      }

      float crossover_point = evoasm_prng_randf_(prng);

      size_t len1 = (size_t) (crossover_point * parent_sizes[0]);
      size_t len2 = (size_t) ((1.0f - crossover_point) * parent_sizes[1]);
      size_t child_size = len1 + len2;

      indiv_data->sizes[child_off] = (uint16_t) child_size;
      indiv_data->loss_samples[sample0_off] = child_loss;

      size_t src_off1 = 0;
      size_t src_off2 = max_parent_size;

      size_t dst_off1 = child_elem0_off + 0;
      size_t dst_off2 = child_elem0_off + len1;

      if(kernels) {
        evoasm_pop_kernel_inst_data_copy(&deme->parent_kernel_inst_data,
                                         deme->arch_id, src_off1, kernel_inst_data, dst_off1, len1);
        evoasm_pop_kernel_inst_data_copy(&deme->parent_kernel_inst_data,
                                         deme->arch_id, src_off2, kernel_inst_data, dst_off2, len2);

      } else {
        evoasm_pop_program_pos_data_copy(&deme->parent_program_pos_data,
                                         src_off1, program_pos_data, dst_off1, len1);
        evoasm_pop_program_pos_data_copy(&deme->parent_program_pos_data,
                                         src_off2, program_pos_data, dst_off2, len2);
      }
    }
  }
}


static int evoasm_pop_loss_cmp_func(const void *a, const void *b) {
  evoasm_loss_t loss_a = *(const evoasm_loss_t *) a;
  evoasm_loss_t loss_b = *(const evoasm_loss_t *) b;
  return (loss_a > loss_b) - (loss_a < loss_b);
}

static evoasm_force_inline inline void
evoasm_deme_calc_summary(evoasm_deme_t *deme, evoasm_loss_t *summary_losses, evoasm_loss_t *summary) {

  {
    evoasm_pop_indiv_data_t *indiv_data;
    uint16_t deme_size = deme->params->n_programs_per_deme;
    indiv_data = &deme->program_data.indiv_data;

    for(size_t i = 0; i < deme_size; i++) {
      size_t program_off = EVOASM_DEME_PROGRAM_OFF(deme, i);
      size_t sample0_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(deme, program_off, 0);
      summary_losses[i] = indiv_data->loss_samples[sample0_off];
    }
    qsort(summary_losses, deme_size, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);

    summary[0] = summary_losses[0 * deme_size / 4];
    summary[1] = summary_losses[1 * deme_size / 4];
    summary[2] = summary_losses[2 * deme_size / 4];
    summary[3] = summary_losses[3 * deme_size / 4];
    summary[4] = summary_losses[4 * deme_size / 4];
  }

  {
    evoasm_pop_indiv_data_t *indiv_data;
    uint16_t deme_size = deme->params->n_kernels_per_deme;
    indiv_data = &deme->kernel_data.indiv_data;

    for(size_t i = 0; i < deme->params->max_program_size; i++) {
      for(size_t j = 0; j < deme_size; j++) {
        size_t kernel_off = EVOASM_DEME_KERNEL_OFF(deme, i, j);
        size_t sample0_off = EVOASM_DEME_INDIV_LOSS_SAMPLE_OFF(pop, kernel_off, 0);
        summary_losses[i] = indiv_data->loss_samples[sample0_off];
      }
      size_t summary_off = (i + 1) * 5;
      qsort(summary_losses, deme_size, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);

      summary[summary_off + 0] = summary_losses[0 * deme_size / 4];
      summary[summary_off + 1] = summary_losses[1 * deme_size / 4];
      summary[summary_off + 2] = summary_losses[2 * deme_size / 4];
      summary[summary_off + 3] = summary_losses[3 * deme_size / 4];
      summary[summary_off + 4] = summary_losses[4 * deme_size / 4];
    }
  }
}

#define EVOASM_POP_DEME_SUMMARY_LEN(pop) (5 * (1u + pop->params->max_program_size))

size_t
evoasm_pop_summary_len(evoasm_pop_t *pop) {
  return pop->params->n_demes * EVOASM_POP_DEME_SUMMARY_LEN(pop);
}

evoasm_success_t
evoasm_pop_calc_summary(evoasm_pop_t *pop, evoasm_loss_t *summary) {

  const size_t deme_summary_len = EVOASM_POP_DEME_SUMMARY_LEN(pop);

  if(pop->summary_losses == NULL) {
    pop->summary_losses = evoasm_calloc(EVOASM_MAX(pop->params->n_programs_per_deme,
                                                   pop->params->n_kernels_per_deme),
                                        sizeof(evoasm_loss_t));
    if(!pop->summary_losses) {
      return false;
    }
  }

  for(size_t i = 0; i < pop->params->n_demes; i++) {
    evoasm_deme_calc_summary(&pop->demes[i], pop->summary_losses, &summary[i * deme_summary_len]);
  }

  return true;
}


#if 0
size_t i;
double scale = 1.0 / pop->params->size;
double pop_loss = 0.0;
*n_invalid = 0;
for(i = 0; i < pop->params->size; i++) {
  double loss = pop->top_kernel_losses[i];
  if(loss != INFINITY) {
    pop_loss += scale * loss;
  } else {
    (*n_invalid)++;
  }
}

if(per_example) pop_loss /= pop->n_examples;
#endif

static evoasm_force_inline inline void
evoasm_deme_mutate_indiv(evoasm_deme_t *deme, evoasm_pop_indiv_data_t *indiv_data, size_t indiv_off,
                         size_t min_indiv_size, bool kernel_indiv) {
  evoasm_prng_t *prng = &deme->prng;
  uint64_t mut_rate = (uint64_t) (deme->params->mut_rate * UINT64_MAX);
  uint64_t r = evoasm_prng_rand64_(prng);
  size_t indiv_size = indiv_data->sizes[indiv_off];

  if(r < mut_rate) {
    r = evoasm_prng_rand64_(prng);
    if(indiv_size > min_indiv_size && r < UINT64_MAX / 16) {
      size_t index = (size_t) (r % indiv_size);

      if(index < indiv_size - 1) {

        size_t len = indiv_size - index - 1u;

        if(kernel_indiv) {
          evoasm_pop_kernel_inst_data_move(&deme->kernel_data.kernel_inst_data,
                                           deme->arch_id,
                                           EVOASM_DEME_KERNEL_INST_OFF(deme, indiv_off, index + 1),
                                           EVOASM_DEME_KERNEL_INST_OFF(deme, indiv_off, index),
                                           len);
        } else {
          evoasm_pop_program_pos_data_move(&deme->program_data.program_pos_data,
                                           EVOASM_DEME_PROGRAM_POS_OFF(deme, indiv_off, index + 1),
                                           EVOASM_DEME_PROGRAM_POS_OFF(deme, indiv_off, index),
                                           len);
        }
      }
      indiv_data->sizes[indiv_off]--;
    }

    r = evoasm_prng_rand64_(prng);
    {
      size_t indiv_elem_idx = (r % indiv_size);

      if(kernel_indiv) {
        size_t kernel_inst_off = EVOASM_DEME_KERNEL_INST_OFF(deme, indiv_off, indiv_elem_idx);
        evoasm_deme_seed_kernel_inst(deme, kernel_inst_off);
      } else {
        size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, indiv_off, indiv_elem_idx);
        evoasm_deme_seed_program_pos(deme, program_pos_off, indiv_size);
      }
    }
  }
}

static evoasm_force_inline inline void
evoasm_deme_mutate(evoasm_deme_t *deme, evoasm_pop_indiv_data_t *indiv_data, size_t indiv0_off, size_t deme_size,
                   bool kernels) {
  size_t min_indiv_size;

  if(kernels) {
    min_indiv_size = deme->params->min_kernel_size;
  } else {
    min_indiv_size = deme->params->min_program_size;
  }

  for(size_t i = 0; i < deme_size; i++) {
    evoasm_deme_mutate_indiv(deme, indiv_data, indiv0_off + i, min_indiv_size, kernels);
  }
}

static void
evoasm_deme_next_gen(evoasm_deme_t *deme) {

  {
    evoasm_pop_indiv_data_t *indiv_data = &deme->program_data.indiv_data;
    size_t deme_size = deme->params->n_programs_per_deme;

    evoasm_loss_t top_loss = deme->top_program_loss;
    size_t program0_off = EVOASM_DEME_PROGRAM_OFF(deme, 0);

    evoasm_deme_select_indivs(deme, indiv_data, program0_off, deme_size, top_loss);
    evoasm_deme_combine(deme, indiv_data, program0_off, deme_size, false);
    evoasm_deme_mutate(deme, indiv_data, program0_off, deme_size, false);
  }

  {
    evoasm_pop_indiv_data_t *indiv_data = &deme->kernel_data.indiv_data;
    size_t deme_size = deme->params->n_kernels_per_deme;

    for(size_t i = 0; i < deme->params->max_program_size; i++) {
      evoasm_loss_t top_loss = deme->top_kernel_losses[i];
      size_t kernel0_off = EVOASM_DEME_KERNEL_OFF(deme, i, 0);

      evoasm_deme_select_indivs(deme, indiv_data, kernel0_off, deme_size, top_loss);
      evoasm_deme_combine(deme, indiv_data, kernel0_off, deme_size, true);
      evoasm_deme_mutate(deme, indiv_data, kernel0_off, deme_size, true);
    }
  }
}

void
evoasm_pop_next_gen(evoasm_pop_t *pop) {
#pragma omp parallel for
  for(size_t i = 0; i < pop->params->n_demes; i++) {
    evoasm_deme_next_gen(&pop->demes[i]);
  }
}

#if 0

evoasm_pop_select(pop, selected_parent_idxs, pop->params->size);
  {
    double scale = 1.0 / pop->params->size;
    double pop_loss = 0.0;
    size_t n_inf = 0;
    for(i = 0; i < pop->params->size; i++) {
      double loss = pop->pop.top_kernel_losses[selected_parent_idxs[i]];
      if(loss != INFINITY) {
        pop_loss += scale * loss;
      }
      else {
        n_inf++;
      }
    }

    evoasm_log_info("pop selected loss: %g/%u", pop_loss, n_inf);
  }

  size_t i;
  for(i = 0; i < pop->params->size; i++) {
    evoasm_program_params_t *program_params = EVOASM_SEARCH_PROGRAM_PARAMS(pop, pop->pop.indivs, selected_parent_idxs[i]);
    assert(program_params->size > 0);
  }

  return evoasm_pop_combine_parents(pop, selected_parent_idxs);
}
#endif


