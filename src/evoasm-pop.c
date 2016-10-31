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

#define EVOASM_DEME_INDIV_OFF_(deme_size, row, indiv_idx) \
  ((size_t)((row) * (size_t)(deme_size) + (indiv_idx)))

#define EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx) \
  EVOASM_DEME_INDIV_OFF_((deme)->params->deme_size, row, indiv_idx)

#define EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, indiv_idx, sample_idx) \
  (EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx) * EVOASM_DEME_MAX_LOSS_SAMPLES + (sample_idx))

/* first sample is replaced with median loss after update */
#define EVOASM_DEME_LOSS_OFF(deme, row, indiv_idx) \
  EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, indiv_idx, 0)

#define EVOASM_DEME_PROGRAM_ROW(deme) ((deme)->params->max_program_size)
#define EVOASM_DEME_KERNEL_ROW(deme, pos) (pos)

#define EVOASM_DEME_PROGRAM_OFF_(deme_size, max_program_size, program_idx) \
  EVOASM_DEME_INDIV_OFF_(deme_size, max_program_size, program_idx)

#define EVOASM_DEME_PROGRAM_OFF(deme, program_idx) \
  EVOASM_DEME_PROGRAM_OFF_((deme)->params->deme_size, (deme)->params->max_program_size, program_idx)

#define EVOASM_DEME_KERNEL_OFF_(deme_size, pos, kernel_idx) \
  EVOASM_DEME_INDIV_OFF_(deme_size, pos, kernel_idx)

#define EVOASM_DEME_KERNEL_OFF(deme, pos, kernel_idx) \
  EVOASM_DEME_KERNEL_OFF_((deme)->params->deme_size, pos, kernel_idx)

#define EVOASM_DEME_PROGRAM_POS_OFF_(max_program_size, program_idx, pos) \
  (((program_idx) * (size_t)(max_program_size) + (pos)))

#define EVOASM_DEME_PROGRAM_POS_OFF(deme, program_idx, pos) \
  EVOASM_DEME_PROGRAM_POS_OFF_((deme)->params->max_program_size, program_idx, pos)

#define EVOASM_DEME_KERNEL_INST_OFF_(deme_size, max_kernel_size, pos, kernel_idx, inst_idx) \
  ((((pos) * (deme_size) + (kernel_idx)) * (max_kernel_size) + (inst_idx)))

#define EVOASM_DEME_KERNEL_INST_OFF(deme, pos, kernel_idx, inst_idx) \
  EVOASM_DEME_KERNEL_INST_OFF_((deme)->params->deme_size, (deme)->params->max_kernel_size, pos, kernel_idx, inst_idx)


static evoasm_success_t
evoasm_pop_loss_data_init(evoasm_pop_loss_data_t *loss_data, size_t n_indivs) {
  EVOASM_TRY_ALLOC(error, aligned_calloc, loss_data->samples, EVOASM_CACHE_LINE_SIZE,
                   n_indivs * EVOASM_DEME_MAX_LOSS_SAMPLES,
                   sizeof(evoasm_loss_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, loss_data->counters, EVOASM_CACHE_LINE_SIZE,
                   n_indivs,
                   sizeof(uint8_t));

  memset(loss_data->counters, 0, n_indivs * sizeof(uint8_t));

  return true;
error:
  return false;
}

static evoasm_success_t
evoasm_pop_indiv_data_init(evoasm_pop_indiv_data_t *indiv_data, size_t n_indivs) {
  EVOASM_TRY_ALLOC(error, aligned_calloc, indiv_data->sizes, EVOASM_CACHE_LINE_SIZE,
                   n_indivs,
                   sizeof(uint16_t));


  return true;
error:
  return false;
}


static void
evoasm_pop_indiv_data_destroy(evoasm_pop_indiv_data_t *indiv_data) {
  evoasm_free(indiv_data->sizes);
}

static void
evoasm_pop_loss_data_destroy(evoasm_pop_loss_data_t *loss_data) {
  evoasm_free(loss_data->samples);
  evoasm_free(loss_data->counters);
}

static evoasm_success_t
evoasm_pop_program_data_init(evoasm_pop_program_data_t *program_data, size_t n_pos) {

  EVOASM_TRY_ALLOC(error, aligned_calloc, program_data->jmp_offs, EVOASM_CACHE_LINE_SIZE,
                   n_pos,
                   sizeof(int16_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, program_data->jmp_cond, EVOASM_CACHE_LINE_SIZE,
                   n_pos,
                   sizeof(uint8_t));

  return true;

error:
  return false;
}

static void
evoasm_pop_program_data_destroy(evoasm_pop_program_data_t *program_data) {
  evoasm_free(program_data->jmp_offs);
  evoasm_free(program_data->jmp_cond);
}

static evoasm_success_t
evoasm_pop_kernel_data_init(evoasm_pop_kernel_data_t *kernel_data,
                            evoasm_arch_id_t arch_id,
                            size_t n_insts) {


  EVOASM_TRY_ALLOC(error, aligned_calloc, kernel_data->insts, EVOASM_CACHE_LINE_SIZE,
                   n_insts,
                   sizeof(evoasm_inst_id_t));

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      EVOASM_TRY_ALLOC(error, aligned_calloc, kernel_data->params.x64, EVOASM_CACHE_LINE_SIZE,
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

static void
evoasm_pop_kernel_data_destroy(evoasm_pop_kernel_data_t *kernel_data) {
  evoasm_free(kernel_data->insts);
  evoasm_free(kernel_data->params.data);
}

static evoasm_success_t
evoasm_pop_module_data_init(evoasm_pop_module_data_t *module_data, size_t n) {
  EVOASM_TRY(error, evoasm_pop_program_data_init, &module_data->program_data, n);

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
  evoasm_pop_program_data_destroy(&module_data->program_data);
  evoasm_free(module_data->pheromones);
  evoasm_free(module_data->sizes);
}

static void
evoasm_deme_destroy(evoasm_deme_t *deme) {
  EVOASM_TRY_WARN(evoasm_program_destroy, &deme->program);
  evoasm_prng_destroy(&deme->prng);
  evoasm_free(deme->selected_parent_idxs);
  evoasm_free(deme->error_counters);
  evoasm_free(deme->top_losses);

  evoasm_pop_program_data_destroy(&deme->program_data);
  evoasm_pop_kernel_data_destroy(&deme->kernel_data);
  evoasm_pop_indiv_data_destroy(&deme->indiv_data);
  evoasm_pop_loss_data_destroy(&deme->loss_data);

  evoasm_pop_indiv_data_destroy(&deme->best_indiv_data);
  evoasm_pop_kernel_data_destroy(&deme->best_kernel_data);
  evoasm_pop_program_data_destroy(&deme->best_program_data);

  evoasm_pop_program_data_destroy(&deme->parent_program_data);
  evoasm_pop_kernel_data_destroy(&deme->parent_kernel_data);
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
             params->recur_limit, NULL, NULL);

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->selected_parent_idxs, EVOASM_CACHE_LINE_SIZE, params->deme_size,
                   sizeof(uint16_t));

  EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->parent_program_data,
             2u * params->max_program_size);
  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->parent_kernel_data, arch_id,
             2u * params->max_kernel_size);

  size_t n_indivs = (1u + params->max_program_size) * params->deme_size;

  EVOASM_TRY(error, evoasm_pop_indiv_data_init, &deme->indiv_data, n_indivs);
  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->kernel_data, arch_id,
             (size_t) params->max_program_size * params->deme_size * params->max_kernel_size);
  EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->program_data,
             params->deme_size);
  EVOASM_TRY(error, evoasm_pop_loss_data_init, &deme->loss_data, n_indivs);

  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->best_kernel_data, arch_id,
             (size_t) (params->max_program_size * params->max_kernel_size));

  EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->best_program_data, params->max_program_size);

  EVOASM_TRY(error, evoasm_pop_indiv_data_init, &deme->best_indiv_data, params->max_program_size + 1u);

  deme->best_loss = INFINITY;

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->top_losses, EVOASM_CACHE_LINE_SIZE,
                   params->max_program_size + 1u,
                   sizeof(evoasm_loss_t));

  for(size_t i = 0; i <= params->max_program_size; i++) {
    deme->top_losses[i] = INFINITY;
  }

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

  *pop = zero_pop;

  if(!evoasm_pop_params_validate(params)) goto error;
  if(params->n_demes == 0) {
    params->n_demes = (uint16_t) max_threads;
  }

  pop->params = params;
  pop->max_threads = max_threads;


  evoasm_prng_init(&seed_prng, &params->seed);

  EVOASM_TRY(error, evoasm_pop_init_domains, pop);
  EVOASM_TRY(error, evoasm_pop_module_data_init, &pop->module_data, params->library_size);

  EVOASM_TRY_ALLOC(error, aligned_calloc, pop->demes, EVOASM_CACHE_LINE_SIZE, (size_t) max_threads,
                   sizeof(evoasm_deme_t));

  for(int i = 0; i < params->n_demes; i++) {
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
  evoasm_inst_id_t *insts_ptr = &kernel_data->insts[kernel_inst_off];

  switch(deme->arch_id) {
    case EVOASM_ARCH_X64: {
      evoasm_x64_basic_params_t *params_ptr = &kernel_data->params.x64[kernel_inst_off];
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

  deme->indiv_data.sizes[kernel_off] = (uint16_t) kernel_size;

  for(i = 0; i < kernel_size; i++) {
    size_t kernel_inst_off = EVOASM_DEME_KERNEL_INST_OFF(deme, pos, kernel_idx, i);
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

  evoasm_pop_program_data_t *program_data = &deme->program_data;
  evoasm_prng_t *prng = &deme->prng;

  program_data->jmp_cond[program_pos_off] =
      (uint8_t) evoasm_prng_rand8_(prng);

  program_data->jmp_offs[program_pos_off] =
      (int16_t) (evoasm_prng_rand_between_(prng, 0, (int64_t) (program_size - 1)) - (int64_t) (program_size / 2));
}

static void
evoasm_deme_seed_program(evoasm_deme_t *deme,
                         size_t program_idx) {
  evoasm_prng_t *prng = &deme->prng;
  evoasm_pop_params_t *params = deme->params;

  size_t program_off = EVOASM_DEME_PROGRAM_OFF(deme, program_idx);

  size_t program_size =
      (size_t) evoasm_prng_rand_between_(prng,
                                         params->min_program_size,
                                         params->max_program_size);

  deme->indiv_data.sizes[program_off] = (uint16_t) program_size;
  deme->max_program_size = EVOASM_MAX(deme->max_program_size, (uint16_t) program_size);

  for(size_t i = 0; i < program_size; i++) {
    size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, program_idx, i);
    evoasm_deme_seed_program_pos(deme, program_pos_off, program_size);
  }
}

static void
evoasm_deme_seed(evoasm_deme_t *deme) {
  for(size_t i = 0; i < deme->params->deme_size; i++) {
    evoasm_deme_seed_program(deme, i);
  }

  for(size_t i = 0; i < deme->max_program_size; i++) {
    for(size_t j = 0; j < deme->params->deme_size; j++) {
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

static void
evoasm_deme_eval_prepare(evoasm_deme_t *deme) {
  evoasm_signal_install((evoasm_arch_id_t) deme->arch_id, 0);
}

static void
evoasm_deme_eval_cleanup(evoasm_deme_t *deme) {
  evoasm_signal_uninstall();
}

static void
evoasm_deme_load_program_(evoasm_deme_t *deme,
                          evoasm_program_t *program,
                          evoasm_pop_indiv_data_t *indiv_data,
                          evoasm_pop_program_data_t *program_data,
                          evoasm_pop_kernel_data_t *kernel_data,
                          size_t program_idx,
                          size_t *kernel_idxs,
                          size_t deme_size,
                          size_t max_program_size,
                          size_t max_kernel_size) {

  size_t program_off = EVOASM_DEME_PROGRAM_OFF_(deme_size, max_program_size, program_idx);
  size_t program_size = indiv_data->sizes[program_off];
  program->size = (uint16_t) program_size;

  for(size_t i = 0; i < program_size; i++) {
    size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF_(max_program_size, program_idx, i);
    size_t kernel_idx = kernel_idxs[i];
    size_t inst0_off = EVOASM_DEME_KERNEL_INST_OFF_(deme_size, max_kernel_size, i, kernel_idx, 0);
    size_t kernel_off = EVOASM_DEME_KERNEL_OFF_(deme_size, i, kernel_idx);
    size_t kernel_size = indiv_data->sizes[kernel_off];

    program->kernels[i].insts = &kernel_data->insts[inst0_off];
    program->kernels[i].size = (uint16_t) kernel_size;

    switch(deme->arch_id) {
      case EVOASM_ARCH_X64:
        program->kernels[i].params.x64 = &deme->kernel_data.params.x64[inst0_off];
        break;
      default:
        evoasm_assert_not_reached();
    }

    program->jmp_offs[i] = program_data->jmp_offs[program_pos_off];
    program->jmp_conds[i] = program_data->jmp_cond[program_pos_off];
  }
}

static inline void
evoasm_deme_load_program(evoasm_deme_t *deme,
                         evoasm_program_t *program,
                         evoasm_pop_indiv_data_t *indiv_data,
                         evoasm_pop_program_data_t *program_data,
                         evoasm_pop_kernel_data_t *kernel_data,
                         size_t program_idx,
                         size_t *kernel_idxs) {

  evoasm_deme_load_program_(deme, program, indiv_data, program_data,
                            kernel_data, program_idx, kernel_idxs,
                            deme->params->deme_size, deme->params->max_program_size,
                            deme->params->max_kernel_size);
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
evoasm_deme_register_sample_loss(evoasm_deme_t *deme, size_t row, size_t indiv_idx, evoasm_loss_t loss) {
  size_t indiv_off = EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx);
  size_t sample_counter = deme->loss_data.counters[indiv_off];

  if(sample_counter <= EVOASM_DEME_MAX_LOSS_SAMPLES) {
    size_t sample_off = EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, indiv_idx, sample_counter);
    deme->loss_data.samples[sample_off] = loss;
    deme->loss_data.counters[indiv_off]++;
  }
}


static evoasm_deme_t *
evoasm_pop_find_best_deme(evoasm_pop_t *pop) {
  evoasm_loss_t best_loss = INFINITY;
  evoasm_deme_t *best_deme = NULL;

  for(size_t i = 0; i < pop->params->n_demes; i++) {
    evoasm_deme_t *deme = &pop->demes[i];
    if(deme->best_loss < best_loss) {
      best_loss = deme->best_loss;
      best_deme = deme;
    }
  }
  return best_deme;
}

evoasm_success_t
evoasm_pop_load_best_program(evoasm_pop_t *pop, evoasm_program_t *program) {

  evoasm_deme_t *best_deme = evoasm_pop_find_best_deme(pop);
  evoasm_pop_params_t *params = best_deme->params;

  EVOASM_TRY(error, evoasm_program_init, program,
             best_deme->arch_id,
             params->program_input,
             params->max_program_size,
             params->max_kernel_size,
             params->recur_limit,
             params->program_input,
             params->program_output);

  size_t program_idx = 0;
  size_t kernel_idxs[EVOASM_PROGRAM_MAX_SIZE];
  size_t best_program_size = best_deme->best_indiv_data.sizes[EVOASM_DEME_PROGRAM_ROW(best_deme)];

  for(size_t i = 0; i < best_program_size; i++) {
    kernel_idxs[i] = i;
  }

  evoasm_deme_load_program_(best_deme,
                           program,
                           &best_deme->best_indiv_data,
                           &best_deme->best_program_data,
                           &best_deme->best_kernel_data,
                           program_idx,
                           kernel_idxs,
                           1,
                           params->max_program_size,
                           params->max_kernel_size);

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_eval_program(evoasm_deme_t *deme, size_t program_idx, size_t *kernel_idxs, evoasm_loss_t *ret_loss) {

  evoasm_loss_t loss;
  evoasm_program_t *program = &deme->program;
  evoasm_pop_kernel_data_t *kernel_data = &deme->kernel_data;
  evoasm_pop_program_data_t *program_data = &deme->program_data;
  evoasm_pop_indiv_data_t *indiv_data = &deme->indiv_data;

  evoasm_deme_load_program(deme, program, indiv_data, program_data, kernel_data, program_idx, kernel_idxs);

  EVOASM_TRY(error, evoasm_deme_assess_program, deme, program, &loss);

  size_t program_off = EVOASM_DEME_PROGRAM_OFF(deme, program_idx);
  size_t program_size = indiv_data->sizes[program_off];
  evoasm_deme_register_sample_loss(deme, EVOASM_DEME_PROGRAM_ROW(deme),
                                   program_idx, loss);

  for(size_t i = 0; i < program_size; i++) {
    evoasm_deme_register_sample_loss(deme, EVOASM_DEME_KERNEL_ROW(deme, i), kernel_idxs[i], loss);
  }

  *ret_loss = loss;
  return true;
error:
  return false;
}


static void
evoasm_pop_program_data_copy(evoasm_pop_program_data_t *program_data,
                             size_t off,
                             evoasm_pop_program_data_t *dst,
                             size_t dst_off,
                             size_t len) {

  memcpy(dst->jmp_offs + dst_off, program_data->jmp_offs + off,
         sizeof(int16_t) * len);
  memcpy(dst->jmp_cond + dst_off, program_data->jmp_cond + off,
         sizeof(uint8_t) * len);
}

static void
evoasm_pop_indiv_data_copy(evoasm_pop_indiv_data_t *indiv_data,
                           size_t off,
                           evoasm_pop_indiv_data_t *dst,
                           size_t dst_off,
                           size_t len) {

  memcpy(dst->sizes + dst_off, indiv_data->sizes + off,
         sizeof(uint16_t) * len);
}

static void
evoasm_pop_program_data_move(evoasm_pop_program_data_t *program_data,
                             size_t src_off,
                             size_t dst_off,
                             size_t len) {

  memmove(program_data->jmp_offs + dst_off, program_data->jmp_offs + src_off,
          sizeof(int16_t) * len);
  memmove(program_data->jmp_cond + dst_off, program_data->jmp_cond + src_off,
          sizeof(uint8_t) * len);
}


static void
evoasm_pop_kernel_data_copy(evoasm_pop_kernel_data_t *kernel_data,
                            evoasm_arch_id_t arch_id,
                            size_t off,
                            evoasm_pop_kernel_data_t *dst,
                            size_t dst_off,
                            size_t len) {

  memcpy(dst->insts + dst_off, kernel_data->insts + off,
         sizeof(evoasm_inst_id_t) * len);

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      memcpy(dst->params.x64 + dst_off, kernel_data->params.x64 + off,
             sizeof(evoasm_x64_basic_params_t) * len);
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_pop_kernel_data_move(evoasm_pop_kernel_data_t *kernel_data,
                            evoasm_arch_id_t arch_id,
                            size_t src_off,
                            size_t dst_off,
                            size_t len) {

  memmove(kernel_data->insts + dst_off, kernel_data->insts + src_off,
          sizeof(evoasm_inst_id_t) * len);

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      memmove(kernel_data->params.x64 + dst_off, kernel_data->params.x64 + src_off,
              sizeof(evoasm_x64_basic_params_t) * len);
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static inline void
evoasm_deme_update_best(evoasm_deme_t *deme, evoasm_loss_t loss, size_t program_idx, size_t *kernel_idxs) {

  size_t program_off = EVOASM_DEME_PROGRAM_OFF(deme, program_idx);
  size_t program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, program_idx, 0);
  size_t program_size = deme->indiv_data.sizes[program_off];

  if(loss < deme->best_loss) {
    evoasm_log_info("new best program loss: %g", loss);
    deme->best_loss = loss;

    evoasm_pop_program_data_copy(&deme->program_data, program_pos0_off,
                                 &deme->best_program_data, 0, program_size);

    evoasm_pop_indiv_data_copy(&deme->indiv_data, program_off, &deme->best_indiv_data, EVOASM_DEME_PROGRAM_ROW(deme),
                               1);

    for(size_t k = 0; k < program_size; k++) {
      size_t kernel_off = EVOASM_DEME_KERNEL_OFF(deme, k, kernel_idxs[k]);
      size_t kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, k, kernel_idxs[k], 0);

      evoasm_pop_kernel_data_copy(&deme->kernel_data, deme->arch_id, kernel_inst0_off,
                                  &deme->best_kernel_data, k, 1);

      evoasm_pop_indiv_data_copy(&deme->indiv_data, kernel_off,
                                 &deme->best_indiv_data, k, 1);
    }
  }
}

static evoasm_success_t
evoasm_deme_eval_programs(evoasm_deme_t *deme) {
  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_idxs[EVOASM_PROGRAM_MAX_SIZE];

  for(size_t i = 0; i < deme->params->deme_size; i++) {
    size_t program_off = EVOASM_DEME_PROGRAM_OFF(deme, i);
    size_t program_size = deme->indiv_data.sizes[program_off];
    evoasm_loss_t loss;

    for(size_t j = 0; j < EVOASM_DEME_MIN_LOSS_SAMPLES; j++) {
      for(size_t k = 0; k < program_size; k++) {
        size_t kernel_idx = (size_t) evoasm_prng_rand_between_(prng, 0,
                                                               deme->params->deme_size - 1);
        kernel_idxs[k] = kernel_idx;
      }

      EVOASM_TRY(error, evoasm_deme_eval_program, deme, i, kernel_idxs, &loss);
      evoasm_deme_update_best(deme, loss, i, kernel_idxs);
    }
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_eval_kernels(evoasm_deme_t *deme) {

  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_idxs[EVOASM_PROGRAM_MAX_SIZE];

  for(size_t i = 0; i < deme->max_program_size; i++) {
    for(size_t j = 0; j < deme->params->deme_size; j++) {
      size_t kernel_off = EVOASM_DEME_KERNEL_OFF(deme, i, j);
      size_t n_samples = deme->loss_data.counters[kernel_off];

      for(size_t k = n_samples; k < EVOASM_DEME_MIN_LOSS_SAMPLES; k++) {
        size_t program_idx;
        size_t program_off;
        size_t program_size = 0;
        evoasm_loss_t loss;

#ifndef NDEBUG
        size_t loop_guard = 0;
#endif
        do {
          program_idx = (size_t) evoasm_prng_rand_between_(prng, 0, deme->params->deme_size - 1);
          program_off = EVOASM_DEME_PROGRAM_OFF(deme, program_idx);
          program_size = deme->indiv_data.sizes[program_off];

          assert(loop_guard++ < deme->params->deme_size);
        } while(i >= program_size);

        for(size_t l = 0; l < program_size; l++) {
          size_t load_kernel_idx;

          if(l == i) {
            /* the current kernel */
            load_kernel_idx = j;
          } else {
            /* some random other kernel */
            load_kernel_idx = (size_t) evoasm_prng_rand_between_(prng, 0, deme->params->deme_size - 1);
          }
          kernel_idxs[i] = load_kernel_idx;
        }
        EVOASM_TRY(error, evoasm_deme_eval_program, deme, program_idx, kernel_idxs, &loss);
        evoasm_deme_update_best(deme, loss, program_idx, kernel_idxs);
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

evoasm_loss_t
evoasm_pop_get_best_loss(evoasm_pop_t *pop) {
  evoasm_deme_t *best_deme = evoasm_pop_find_best_deme(pop);
  return best_deme->best_loss;
}


static void
evoasm_deme_eval_update(evoasm_deme_t *deme) {

  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;

  for(size_t i = 0; i <= deme->max_program_size; i++) {
    for(size_t j = 0; j < deme->params->deme_size; j++) {
      size_t indiv_off = EVOASM_DEME_INDIV_OFF(deme, i, j);
      size_t sample0_off = EVOASM_DEME_LOSS_SAMPLE_OFF(deme, i, j, 0);

      evoasm_loss_t indiv_loss =
          evoasm_pop_find_median_loss_(&loss_data->samples[sample0_off],
                                       loss_data->counters[indiv_off]);

      loss_data->samples[sample0_off] = indiv_loss;

      if(deme->top_losses[i] > indiv_loss) {
        deme->top_losses[i] = indiv_loss;
      }
    }
  }
}

static evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme) {
  bool retval = true;

  evoasm_deme_eval_prepare(deme);

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
  evoasm_deme_eval_cleanup(deme);
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


static inline void
evoasm_deme_select_indivs(evoasm_deme_t *deme, size_t row) {
  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;
  evoasm_prng_t *prng = &deme->prng;
  uint16_t *parent_idxs = deme->selected_parent_idxs;
  uint32_t n = 0;
  size_t deme_size = deme->params->deme_size;
  evoasm_loss_t top_loss = deme->top_losses[row];

  while(true) {
    for(size_t i = 0; i < deme_size; i++) {
      float r = evoasm_prng_randf_(prng);
      size_t sample0_off = EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, i, 0);
      if(r < (top_loss + 1.0) / (loss_data->samples[sample0_off] + 1.0)) {
        parent_idxs[n++] = (uint16_t) i;
        if(n >= deme_size) goto done;
      }
    }
  }
done:;
}

static evoasm_force_inline inline void
evoasm_deme_combine(evoasm_deme_t *deme, size_t row) {

  evoasm_pop_indiv_data_t *indiv_data = &deme->indiv_data;
  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;
  evoasm_pop_program_data_t *program_data = &deme->program_data;
  evoasm_pop_kernel_data_t *kernel_data = &deme->kernel_data;
  evoasm_prng_t *prng = &deme->prng;
  size_t deme_size = deme->params->deme_size;
  bool program_row = row == EVOASM_DEME_PROGRAM_ROW(deme);
  size_t max_indiv_size;

  if(program_row) {
    max_indiv_size = deme->params->max_program_size;
  } else {
    max_indiv_size = deme->params->max_kernel_size;
  }

  for(size_t i = 0; i < deme_size; i += 2) {
    size_t parent_indiv_offs[2] = {
        EVOASM_DEME_INDIV_OFF(deme, row, i),
        EVOASM_DEME_INDIV_OFF(deme, row, i + 1)
    };

    size_t parent_indiv_loss_offs[2] = {
        EVOASM_DEME_LOSS_OFF(deme, row, i),
        EVOASM_DEME_LOSS_OFF(deme, row, i + 1),
    };

    uint16_t parent_sizes[2] = {
        indiv_data->sizes[parent_indiv_offs[0]],
        indiv_data->sizes[parent_indiv_offs[1]]
    };

    evoasm_loss_t parent_losses[2] = {
        loss_data->samples[parent_indiv_loss_offs[0]],
        loss_data->samples[parent_indiv_loss_offs[0]]
    };

    /* rough estimate */
    evoasm_loss_t child_loss = 0.5f * parent_losses[0] + 0.5f * parent_losses[1];

    /* save parents to local storage, we override originals with children */
    for(size_t j = 0; j < 2; j++) {
      uint16_t parent_size = parent_sizes[j];

      if(program_row) {
        size_t program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, i + j, 0);
        evoasm_pop_program_data_copy(program_data, program_pos0_off, &deme->parent_program_data,
                                     j * deme->params->max_program_size, parent_size);
      } else {
        size_t kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, row, i + j, 0);
        evoasm_pop_kernel_data_copy(kernel_data, deme->arch_id, kernel_inst0_off,
                                    &deme->parent_kernel_data,
                                    j * deme->params->max_kernel_size, parent_size);
      }
    }

    float crossover_point = evoasm_prng_randf_(prng);

    for(size_t j = 0; j < 2; j++) {
      size_t seg1_src_off = j * max_indiv_size;
      size_t seg2_src_off = (1 - j) * max_indiv_size;
      size_t seg1_len = EVOASM_MAX(1u, (size_t) (crossover_point * parent_sizes[j]));
      size_t seg2_len = (size_t) ((1.0f - crossover_point) * parent_sizes[j]);
      size_t child_size = seg1_len + seg2_len;

      assert(child_size > 0 && (child_size <= parent_sizes[0] || child_size <= parent_sizes[1]));

      /* children replace their parents */
      indiv_data->sizes[parent_indiv_offs[j]] = (uint16_t) child_size;
      loss_data->samples[parent_indiv_loss_offs[j]] = child_loss;

      if(program_row) {
        size_t program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, i + j, 0);

        evoasm_pop_program_data_copy(&deme->parent_program_data,
                                     seg1_src_off, program_data, program_pos0_off, seg1_len);
        evoasm_pop_program_data_copy(&deme->parent_program_data,
                                     seg2_src_off, program_data, program_pos0_off + seg1_len, seg2_len);

      } else {
        size_t kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, row, i + j, 0);
        evoasm_pop_kernel_data_copy(&deme->parent_kernel_data, deme->arch_id,
                                    seg1_src_off, kernel_data, kernel_inst0_off, seg1_len);
        evoasm_pop_kernel_data_copy(&deme->parent_kernel_data, deme->arch_id,
                                    seg2_src_off, kernel_data, kernel_inst0_off + seg1_len, seg2_len);
      }
    }
  }
}


static int evoasm_pop_loss_cmp_func(const void *a, const void *b) {
  evoasm_loss_t loss_a = *(const evoasm_loss_t *) a;
  evoasm_loss_t loss_b = *(const evoasm_loss_t *) b;
  return (loss_a > loss_b) - (loss_a < loss_b);
}

static inline void
evoasm_deme_calc_summary(evoasm_deme_t *deme, evoasm_loss_t *summary_losses, evoasm_loss_t *summary) {
  size_t deme_size = deme->params->deme_size;
  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;

  for(size_t i = 0; i <= deme->params->max_program_size; i++) {
    size_t summary_off = i * 5;

    for(size_t j = 0; j < deme_size; j++) {
      size_t loss_off = EVOASM_DEME_LOSS_OFF(deme, i, j);
      summary_losses[i] = loss_data->samples[loss_off];
    }

    qsort(summary_losses, deme_size, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);

    summary[summary_off + 0] = summary_losses[0 * deme_size / 4];
    summary[summary_off + 1] = summary_losses[1 * deme_size / 4];
    summary[summary_off + 2] = summary_losses[2 * deme_size / 4];
    summary[summary_off + 3] = summary_losses[3 * deme_size / 4];
    summary[summary_off + 4] = summary_losses[4 * deme_size / 4];
  }
}

#define EVOASM_DEME_SUMMARY_LEN(pop) (5 * (1u + pop->params->max_program_size))

size_t
evoasm_pop_summary_len(evoasm_pop_t *pop) {
  return pop->params->n_demes * EVOASM_DEME_SUMMARY_LEN(pop);
}

evoasm_success_t
evoasm_pop_calc_summary(evoasm_pop_t *pop, evoasm_loss_t *summary) {

  const size_t deme_summary_len = EVOASM_DEME_SUMMARY_LEN(pop);

  if(pop->summary_losses == NULL) {
    pop->summary_losses = evoasm_calloc(pop->params->deme_size, sizeof(evoasm_loss_t));
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
  double loss = pop->top_losses[i];
  if(loss != INFINITY) {
    pop_loss += scale * loss;
  } else {
    (*n_invalid)++;
  }
}

if(per_example) pop_loss /= pop->n_examples;
#endif

static inline void
evoasm_deme_mutate_indiv(evoasm_deme_t *deme, size_t row, size_t indiv_idx) {
  evoasm_prng_t *prng = &deme->prng;
  evoasm_pop_indiv_data_t *indiv_data = &deme->indiv_data;
  size_t indiv_off = EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx);
  size_t indiv_size = indiv_data->sizes[indiv_off];
  bool program_row = row == EVOASM_DEME_PROGRAM_ROW(deme);
  size_t min_indiv_size;

  if(program_row) {
    min_indiv_size = deme->params->min_program_size;
  } else {
    min_indiv_size = deme->params->min_kernel_size;
  }

  if(evoasm_prng_randf_(prng) < deme->params->mut_rate) {
    uint64_t r = evoasm_prng_rand64_(prng);
    if(indiv_size > min_indiv_size && r < UINT64_MAX / 16) {
      size_t elem_idx = (size_t) (r % indiv_size);

      if(elem_idx < indiv_size - 1) {

        size_t len = indiv_size - elem_idx - 1u;

        if(program_row) {
          evoasm_pop_program_data_move(&deme->program_data,
                                       EVOASM_DEME_PROGRAM_POS_OFF(deme, indiv_idx, elem_idx + 1),
                                       EVOASM_DEME_PROGRAM_POS_OFF(deme, indiv_idx, elem_idx),
                                       len);
        } else {
          evoasm_pop_kernel_data_move(&deme->kernel_data,
                                      deme->arch_id,
                                      EVOASM_DEME_KERNEL_INST_OFF(deme, row, indiv_idx, elem_idx + 1),
                                      EVOASM_DEME_KERNEL_INST_OFF(deme, row, indiv_idx, elem_idx),
                                      len);
        }
      }
      indiv_data->sizes[indiv_off]--;
    }

    r = evoasm_prng_rand64_(prng);
    {
      size_t elem_idx = (r % indiv_size);

      if(program_row) {
        size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, indiv_idx, elem_idx);
        evoasm_deme_seed_program_pos(deme, program_pos_off, indiv_size);
      } else {
        size_t kernel_inst_off = EVOASM_DEME_KERNEL_INST_OFF(deme, row, indiv_idx, elem_idx);
        evoasm_deme_seed_kernel_inst(deme, kernel_inst_off);
      }
    }
  }
}

static void
evoasm_deme_mutate(evoasm_deme_t *deme, size_t row) {
  for(size_t i = 0; i < deme->params->deme_size; i++) {
    evoasm_deme_mutate_indiv(deme, row, i);
  }
}

static void
evoasm_deme_next_gen(evoasm_deme_t *deme) {
  for(size_t i = 0; i <= deme->params->max_program_size; i++) {
    evoasm_deme_select_indivs(deme, i);
    evoasm_deme_combine(deme, i);
    evoasm_deme_mutate(deme, i);
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
      double loss = pop->pop.top_losses[selected_parent_idxs[i]];
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

EVOASM_DEF_ALLOC_FREE_FUNCS(pop)
