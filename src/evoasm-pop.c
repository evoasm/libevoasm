/*
 * Copyright (C) 2016 Julian Aron Prenner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "evoasm-pop.h"
#include "evoasm-signal.h"
#include "evoasm-util.h"
#include "evoasm-program.h"
#include "evoasm-error.h"

#ifdef _OPENMP

#  include <omp.h>
#include <gen/evoasm-x64-params.h>

#endif

EVOASM_DEF_LOG_TAG("pop")

#define EVOASM_DEME_MIN_LOSS_SAMPLES 8
#define EVOASM_DEME_MAX_LOSS_SAMPLES 16
#define EVOASM_DEME_EXAMPLE_WIN_SIZE 64

#define EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx) \
  ((size_t)((row) * (size_t)(deme)->params->deme_size + (indiv_idx)))

#define EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, indiv_idx, sample_idx) \
  (EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx) * EVOASM_DEME_MAX_LOSS_SAMPLES + (sample_idx))

/* first sample is replaced with median loss after update */
#define EVOASM_DEME_LOSS_OFF(deme, row, indiv_idx) \
  EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, indiv_idx, 0)

#define EVOASM_DEME_PROGRAMS_ROW(deme) ((deme)->params->program_size)

#define EVOASM_DEME_PROGRAM_POS_OFF_(program_size, program_idx, pos) \
  (((program_idx) * (size_t)(program_size) + (pos)))

#define EVOASM_DEME_PROGRAM_POS_OFF(deme, program_idx, pos) \
  EVOASM_DEME_PROGRAM_POS_OFF_((deme)->params->program_size, program_idx, pos)

#define EVOASM_DEME_KERNEL_INST_OFF_(deme_size, kernel_size, pos, kernel_idx, inst_idx) \
  ((((pos) * (deme_size) + (kernel_idx)) * (kernel_size) + (inst_idx)))

#define EVOASM_DEME_KERNEL_INST_OFF(deme, pos, kernel_idx, inst_idx) \
  EVOASM_DEME_KERNEL_INST_OFF_((deme)->params->deme_size, (deme)->params->kernel_size, pos, kernel_idx, inst_idx)

#define EVOASM_DEME_N_INDIVS(deme) ((evoasm_pop_params_get_deme_height((deme)->params)) * (deme)->params->deme_size)

static evoasm_success_t
evoasm_pop_loss_data_init(evoasm_pop_loss_data_t *loss_data, size_t n_indivs) {
  EVOASM_TRY_ALLOC(error, aligned_calloc, loss_data->samples, EVOASM_CACHE_LINE_SIZE,
                   n_indivs * EVOASM_DEME_MAX_LOSS_SAMPLES,
                   sizeof(evoasm_loss_t));

  EVOASM_TRY_ALLOC(error, aligned_calloc, loss_data->counters, EVOASM_CACHE_LINE_SIZE,
                   n_indivs,
                   sizeof(uint8_t));

  return true;
error:
  return false;
}

static void
evoasm_pop_loss_data_destroy(evoasm_pop_loss_data_t *loss_data) {
  evoasm_free(loss_data->samples);
  evoasm_free(loss_data->counters);
}

static evoasm_success_t
evoasm_pop_program_data_init(evoasm_pop_program_data_t *program_data, size_t n_pos) {

  assert(sizeof(*program_data->jmp_offs) == sizeof(uint16_t));

  EVOASM_TRY_ALLOC(error, aligned_calloc, program_data->jmp_offs, EVOASM_CACHE_LINE_SIZE,
                   n_pos,
                   sizeof(*program_data->jmp_offs));
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

static inline size_t
evoasm_pop_params_get_deme_height_(evoasm_pop_params_t *params) {
  size_t height = params->program_size;
  if(params->program_size > 1) return height + 1;
  return height;
}

size_t
evoasm_pop_params_get_deme_height(evoasm_pop_params_t *params) {
  return evoasm_pop_params_get_deme_height_(params);
}

static void
evoasm_deme_destroy(evoasm_deme_t *deme) {
  EVOASM_TRY_WARN(evoasm_program_destroy, &deme->program);
  evoasm_prng_destroy(&deme->prng);
  evoasm_free(deme->blessed_indiv_idxs);
  evoasm_free(deme->doomed_indiv_idxs);
  evoasm_free(deme->error_counters);
  evoasm_free(deme->top_losses);
  evoasm_free(deme->avg_losses);

  evoasm_pop_kernel_data_destroy(&deme->kernel_data);
  evoasm_pop_loss_data_destroy(&deme->loss_data);

  evoasm_pop_kernel_data_destroy(&deme->best_kernel_data);

  if(deme->params->program_size > 1) {
    evoasm_pop_program_data_destroy(&deme->best_program_data);
    evoasm_pop_program_data_destroy(&deme->parent_program_data);
    evoasm_pop_program_data_destroy(&deme->program_data);
  }

  evoasm_pop_kernel_data_destroy(&deme->parent_kernel_data);
}

void
evoasm_pop_destroy(evoasm_pop_t *pop) {
  evoasm_free(pop->domains);

  for(size_t i = 0; i < pop->params->n_demes; i++) {
    evoasm_deme_destroy(&pop->demes[i]);
  }
  evoasm_free(pop->demes);
  evoasm_free(pop->summary_losses);

  evoasm_pop_module_data_destroy(&pop->module_data);
}

#define EVOASM_DEME_MIN_MUT_RATE 0.008f
#define EVOASM_DEME_MAX_MUT_RATE 0.15f

static evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme,
                 size_t deme_idx,
                 evoasm_arch_id_t arch_id,
                 evoasm_pop_params_t *params,
                 evoasm_prng_state_t *seed,
                 evoasm_domain_t *domains) {

  size_t n_examples = EVOASM_PROGRAM_INPUT_N_TUPLES(params->program_input);
  static evoasm_deme_t zero_deme = {0};

  *deme = zero_deme;

  if(n_examples > EVOASM_DEME_EXAMPLE_WIN_SIZE) {
    deme->input_win_off = (uint16_t) (n_examples / params->n_demes * deme_idx);
  }
  deme->arch_id = arch_id;
  deme->params = params;
  deme->domains = domains;
  deme->mut_rate = EVOASM_DEME_MIN_MUT_RATE;

  evoasm_prng_init(&deme->prng, seed);

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->blessed_indiv_idxs, EVOASM_CACHE_LINE_SIZE, params->deme_size,
                   sizeof(uint16_t));

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->doomed_indiv_idxs, EVOASM_CACHE_LINE_SIZE, params->deme_size,
                   sizeof(uint16_t));

  EVOASM_TRY(error, evoasm_program_init, &deme->program,
             evoasm_get_arch_info(arch_id),
             params->program_size,
             params->kernel_size,
             n_examples,
             params->recur_limit,
             true);

  if(params->program_size > 1) {
    EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->program_data,
               (size_t) params->deme_size * params->kernel_size);

    EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->parent_program_data,
               2u * params->program_size);

    EVOASM_TRY(error, evoasm_pop_program_data_init, &deme->best_program_data, params->program_size);
  }

  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->parent_kernel_data, arch_id,
             2u * params->kernel_size);

  size_t n_indivs = EVOASM_DEME_N_INDIVS(deme);
  size_t height = evoasm_pop_params_get_deme_height_(deme->params);

  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->kernel_data, arch_id,
             (size_t) params->program_size * params->deme_size * params->kernel_size);
  EVOASM_TRY(error, evoasm_pop_loss_data_init, &deme->loss_data, n_indivs);

  EVOASM_TRY(error, evoasm_pop_kernel_data_init, &deme->best_kernel_data, arch_id,
             (size_t) (params->program_size * params->kernel_size));


  deme->best_loss = INFINITY;

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->top_losses, EVOASM_CACHE_LINE_SIZE,
                   height,
                   sizeof(evoasm_loss_t));

  EVOASM_TRY_ALLOC(error, aligned_calloc, deme->avg_losses, EVOASM_CACHE_LINE_SIZE,
                   height,
                   sizeof(evoasm_loss_t));

  for(size_t i = 0; i < height; i++) {
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
  evoasm_error(EVOASM_ERROR_TYPE_POP, EVOASM_ERROR_CODE_NONE,
               "Empty domain");
  return false;
}

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                evoasm_pop_params_t *params) {
  static evoasm_pop_t zero_pop = {0};
  evoasm_prng_t seed_prng;

  *pop = zero_pop;

  pop->params = params;

  if(!evoasm_pop_params_validate(params)) goto error;

#ifdef _OPENMP
  {
    int max_threads;
    max_threads = omp_get_max_threads();
    omp_set_dynamic(0);
    int n_threads = EVOASM_MIN(max_threads, params->n_demes);
    omp_set_num_threads(n_threads);
    evoasm_log_info("Using OpenMP with %d threads", n_threads);
  }
#endif

  evoasm_prng_init(&seed_prng, &params->seed);

  EVOASM_TRY(error, evoasm_pop_init_domains, pop);
  EVOASM_TRY(error, evoasm_pop_module_data_init, &pop->module_data, params->library_size);

  EVOASM_TRY_ALLOC(error, aligned_calloc, pop->demes, EVOASM_CACHE_LINE_SIZE, (size_t) params->n_demes,
                   sizeof(evoasm_deme_t));

  for(size_t i = 0; i < params->n_demes; i++) {
    evoasm_prng_state_t seed;

    for(size_t j = 0; j < EVOASM_PRNG_SEED_LEN; j++) {
      seed.data[j] = evoasm_prng_rand64_(&seed_prng);
    }

    EVOASM_TRY(error, evoasm_deme_init,
               &pop->demes[i],
               i,
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

      param_val = (int64_t) evoasm_domain_rand_(domain, prng);
      evoasm_x64_basic_params_set_(params_ptr, param_id, param_val);
    }
  }
}

static void
evoasm_deme_seed_kernel_inst(evoasm_deme_t *deme,
                             size_t pos,
                             size_t kernel_idx,
                             size_t inst_idx) {

  size_t kernel_inst_off = EVOASM_DEME_KERNEL_INST_OFF(deme, pos, kernel_idx, inst_idx);

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
  for(size_t i = 0; i < deme->params->kernel_size; i++) {
    evoasm_deme_seed_kernel_inst(deme, pos, kernel_idx, i);
  }
}

static void
evoasm_deme_seed_program_pos(evoasm_deme_t *deme,
                             size_t program_idx,
                             size_t pos) {

  size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, program_idx, pos);
  evoasm_pop_program_data_t *program_data = &deme->program_data;
  evoasm_prng_t *prng = &deme->prng;

  program_data->jmp_cond[program_pos_off] =
      (uint8_t) evoasm_prng_rand8_(prng);

  program_data->jmp_offs[program_pos_off] = evoasm_prng_rand16_(prng);
}

static void
evoasm_deme_seed_program(evoasm_deme_t *deme,
                         size_t program_idx) {
  for(size_t i = 0; i < deme->params->program_size; i++) {
    evoasm_deme_seed_program_pos(deme, program_idx, i);
  }
}

static void
evoasm_deme_seed(evoasm_deme_t *deme) {
  if(deme->params->program_size > 1) {
    for(size_t i = 0; i < deme->params->deme_size; i++) {
      evoasm_deme_seed_program(deme, i);
    }
  }

  for(size_t i = 0; i < deme->params->program_size; i++) {
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
evoasm_deme_load_program_(evoasm_deme_t *deme,
                          evoasm_program_t *program,
                          evoasm_pop_program_data_t *program_data,
                          evoasm_pop_kernel_data_t *kernel_data,
                          size_t program_idx,
                          size_t *kernel_idxs,
                          size_t deme_size) {

  size_t program_size = deme->params->program_size;
  size_t kernel_size = deme->params->kernel_size;

  for(size_t i = 0; i < program_size; i++) {
    size_t kernel_idx = kernel_idxs[i];
    size_t inst0_off = EVOASM_DEME_KERNEL_INST_OFF_(deme_size, kernel_size, i, kernel_idx, 0);
    evoasm_kernel_t *kernel = &program->kernels[i];

    if(program->shallow) {
      kernel->insts = &kernel_data->insts[inst0_off];
    } else {
      EVOASM_MEMCPY_N(kernel->insts,
                      &kernel_data->insts[inst0_off], kernel->size);
    }

    switch(deme->arch_id) {
      case EVOASM_ARCH_X64:
        if(program->shallow) {
          kernel->x64.params = &kernel_data->params.x64[inst0_off];
        } else {
          EVOASM_MEMCPY_N(kernel->x64.params,
                          &kernel_data->params.x64[inst0_off], kernel->size);
        }
        break;
      default:
        evoasm_assert_not_reached();
    }
  }

  if(program_size > 1) {
    for(size_t i = 0; i < program_size; i++) {
      size_t program_pos_off = EVOASM_DEME_PROGRAM_POS_OFF_(program_size, program_idx, i);
      program->jmp_offs[i] = program_data->jmp_offs[program_pos_off];
      program->jmp_conds[i] = program_data->jmp_cond[program_pos_off];
    }
  }
}

static inline void
evoasm_deme_load_program(evoasm_deme_t *deme,
                         evoasm_program_t *program,
                         evoasm_pop_program_data_t *program_data,
                         evoasm_pop_kernel_data_t *kernel_data,
                         size_t program_idx,
                         size_t *kernel_idxs) {

  evoasm_deme_load_program_(deme, program, program_data,
                            kernel_data, program_idx, kernel_idxs,
                            deme->params->deme_size);
}


static evoasm_success_t
evoasm_deme_eval_program(evoasm_deme_t *deme, evoasm_program_t *program, evoasm_loss_t *ret_loss) {
  evoasm_pop_params_t *params = deme->params;

  //bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping
  evoasm_program_emit_flags_t emit_flags =
      EVOASM_PROGRAM_EMIT_FLAG_PREPARE |
      EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS |
      EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE |
      EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;

  if(!evoasm_program_emit(program, params->program_input, deme->input_win_off, EVOASM_DEME_EXAMPLE_WIN_SIZE, emit_flags)) {
    *ret_loss = INFINITY;

    if(evoasm_last_error.code == EVOASM_PROGRAM_ERROR_CODE_NO_OUTPUT) {
      /* do not abort on this error, instead just let loss be infinity */
      return true;
    }
    return false;
  }

  *ret_loss = evoasm_program_eval(program, params->program_output);

  return true;
}

static void
evoasm_deme_register_loss_sample(evoasm_deme_t *deme, size_t row, size_t indiv_idx, evoasm_loss_t loss) {
  size_t indiv_off = EVOASM_DEME_INDIV_OFF(deme, row, indiv_idx);
  size_t sample_counter = deme->loss_data.counters[indiv_off];

  if(sample_counter < EVOASM_DEME_MAX_LOSS_SAMPLES) {
    size_t sample_off = EVOASM_DEME_LOSS_SAMPLE_OFF(deme, row, indiv_idx, sample_counter);
    deme->loss_data.samples[sample_off] = loss;
    deme->loss_data.counters[indiv_off]++;
  }
}


static evoasm_deme_t *
evoasm_pop_find_best_deme(evoasm_pop_t *pop) {
  evoasm_deme_t *best_deme = &pop->demes[0];
  evoasm_loss_t best_loss = best_deme->best_loss;

  for(size_t i = 1; i < pop->params->n_demes; i++) {
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
             evoasm_get_arch_info(best_deme->arch_id),
             params->program_size,
             params->kernel_size,
             EVOASM_DEME_EXAMPLE_WIN_SIZE,
             params->recur_limit,
             false);

  size_t program_idx = 0;
  size_t kernel_idxs[EVOASM_PROGRAM_MAX_SIZE] = {0};

  evoasm_deme_load_program_(best_deme,
                            program,
                            &best_deme->best_program_data,
                            &best_deme->best_kernel_data,
                            program_idx,
                            kernel_idxs,
                            1);


  program->_input = *params->program_input;
  program->_output = *params->program_output;
  program->_input.len = 0;
  program->_output.len = 0;

  evoasm_program_emit_flags_t emit_flags =
      EVOASM_PROGRAM_EMIT_FLAG_PREPARE |
      EVOASM_PROGRAM_EMIT_FLAG_EMIT_KERNELS |
      EVOASM_PROGRAM_EMIT_FLAG_EMIT_IO_LOAD_STORE |
      EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;

  EVOASM_TRY(error, evoasm_program_emit, program, params->program_input, best_deme->input_win_off, EVOASM_DEME_EXAMPLE_WIN_SIZE, emit_flags);

  evoasm_signal_set_exception_mask(program->exception_mask);
  evoasm_loss_t loss = evoasm_program_eval(program, params->program_output);
  (void) loss;
  assert(loss == best_deme->best_loss);
  evoasm_signal_clear_exception_mask();

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_test_program(evoasm_deme_t *deme, size_t program_idx, size_t *kernel_idxs, evoasm_loss_t *ret_loss) {

  evoasm_loss_t loss;
  evoasm_program_t *program = &deme->program;
  evoasm_pop_kernel_data_t *kernel_data = &deme->kernel_data;
  evoasm_pop_program_data_t *program_data = &deme->program_data;

  evoasm_deme_load_program(deme, program, program_data, kernel_data, program_idx, kernel_idxs);

  EVOASM_TRY(error, evoasm_deme_eval_program, deme, program, &loss);

  size_t program_size = deme->params->program_size;

  for(size_t i = 0; i < program_size; i++) {
    evoasm_deme_register_loss_sample(deme, i, kernel_idxs[i], loss);
  }

  if(program_size > 1) {
    evoasm_deme_register_loss_sample(deme, EVOASM_DEME_PROGRAMS_ROW(deme),
                                     program_idx, loss);
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

  assert(sizeof(*dst->jmp_offs) == sizeof(uint16_t));
  assert(sizeof(*dst->jmp_cond) == sizeof(uint8_t));

  memcpy(dst->jmp_offs + dst_off, program_data->jmp_offs + off,
         sizeof(*dst->jmp_offs) * len);
  memcpy(dst->jmp_cond + dst_off, program_data->jmp_cond + off,
         sizeof(*dst->jmp_cond) * len);
}

static evoasm_used void
evoasm_pop_program_data_move(evoasm_pop_program_data_t *program_data,
                             size_t src_off,
                             size_t dst_off,
                             size_t len) {

  memmove(program_data->jmp_offs + dst_off, program_data->jmp_offs + src_off,
          sizeof(*program_data->jmp_offs) * len);
  memmove(program_data->jmp_cond + dst_off, program_data->jmp_cond + src_off,
          sizeof(*program_data->jmp_cond) * len);
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

static evoasm_used void
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

static inline bool
evoasm_deme_update_best(evoasm_deme_t *deme, evoasm_loss_t loss, size_t program_idx, size_t *kernel_idxs) {

  if(loss < deme->best_loss) {
    size_t src_program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, program_idx, 0);
    size_t dst_program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF_(deme->params->program_size, 0, 0);

    size_t program_size = deme->params->program_size;
    size_t kernel_size = deme->params->kernel_size;

    evoasm_log_info("new best program loss: %g", loss);
    evoasm_program_log(&deme->program, EVOASM_LOG_LEVEL_INFO);

    deme->best_loss = loss;

    if(program_size > 1) {
      evoasm_pop_program_data_copy(&deme->program_data, src_program_pos0_off,
                                   &deme->best_program_data, dst_program_pos0_off, program_size);
    }

    for(size_t k = 0; k < program_size; k++) {
      size_t src_kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, k, kernel_idxs[k], 0);
      size_t dst_kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF_(1, deme->params->kernel_size, k, 0, 0);

      evoasm_pop_kernel_data_copy(&deme->kernel_data, deme->arch_id, src_kernel_inst0_off,
                                  &deme->best_kernel_data, dst_kernel_inst0_off, kernel_size);

    }
    return true;
  }

  return false;
}

static evoasm_success_t
evoasm_deme_test_programs(evoasm_deme_t *deme, bool *new_best) {
  evoasm_prng_t *prng = &deme->prng;
  size_t program_size = deme->params->program_size;

  for(size_t i = 0; i < deme->params->deme_size; i++) {
    for(size_t j = 0; j < EVOASM_DEME_MIN_LOSS_SAMPLES; j++) {
      size_t kernel_idxs[EVOASM_PROGRAM_MAX_SIZE];
      evoasm_loss_t loss;

      for(size_t k = 0; k < program_size; k++) {
        size_t kernel_idx = (size_t) evoasm_prng_rand_between_(prng, 0,
                                                               deme->params->deme_size - 1);
        kernel_idxs[k] = kernel_idx;
      }

      EVOASM_TRY(error, evoasm_deme_test_program, deme, i, kernel_idxs, &loss);
      if(evoasm_deme_update_best(deme, loss, i, kernel_idxs)) {
        *new_best = true;
      }
    }

    assert(deme->loss_data.counters[EVOASM_DEME_INDIV_OFF(deme, EVOASM_DEME_PROGRAMS_ROW(deme), i)] ==
           EVOASM_DEME_MIN_LOSS_SAMPLES);
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_test_kernels(evoasm_deme_t *deme, bool *new_best) {

  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_idxs[EVOASM_PROGRAM_MAX_SIZE];
  size_t program_size = deme->params->program_size;

  for(size_t i = 0; i < deme->params->program_size; i++) {
    for(size_t j = 0; j < deme->params->deme_size; j++) {
      size_t kernel_off = EVOASM_DEME_INDIV_OFF(deme, i, j);
      size_t n_samples = deme->loss_data.counters[kernel_off];

      for(size_t k = n_samples; k < EVOASM_DEME_MIN_LOSS_SAMPLES; k++) {
        size_t program_idx;
        evoasm_loss_t loss;

        program_idx = (size_t) evoasm_prng_rand_between_(prng, 0, deme->params->deme_size - 1);

        for(size_t l = 0; l < program_size; l++) {
          size_t load_kernel_idx;

          if(l == i) {
            /* the current kernel */
            load_kernel_idx = j;
          } else {
            /* some random other kernel */
            load_kernel_idx = (size_t) evoasm_prng_rand_between_(prng, 0, deme->params->deme_size - 1);
          }
          kernel_idxs[l] = load_kernel_idx;
        }
        EVOASM_TRY(error, evoasm_deme_test_program, deme, program_idx, kernel_idxs, &loss);
        if(evoasm_deme_update_best(deme, loss, program_idx, kernel_idxs)) {
          *new_best = true;
        }
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

static int evoasm_pop_loss_cmp_func(const void *a, const void *b) {
  evoasm_loss_t loss_a = *(const evoasm_loss_t *) a;
  evoasm_loss_t loss_b = *(const evoasm_loss_t *) b;
  return (loss_a > loss_b) - (loss_a < loss_b);
}

#define EVOASM_POP_FIND_MEDIAN_RUN_LEN 8u

static inline evoasm_loss_t
evoasm_pop_find_median_loss_(evoasm_loss_t *losses, size_t len) {

  evoasm_loss_t median;
  assert(len >= EVOASM_DEME_MIN_LOSS_SAMPLES && len <= EVOASM_DEME_MAX_LOSS_SAMPLES);

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

  switch(n_runs) {
    case 1:
      return losses[EVOASM_POP_FIND_MEDIAN_RUN_LEN / 2 - 1];
    case 2: {
      const size_t merge_len = 8;
      for(size_t i = 0; i < merge_len; i++) {
        size_t loss_off0 = 0 * EVOASM_POP_FIND_MEDIAN_RUN_LEN + front_idxs[0];
        size_t loss_off1 = 1 * EVOASM_POP_FIND_MEDIAN_RUN_LEN + front_idxs[1];
        evoasm_loss_t loss0 = losses[loss_off0];
        evoasm_loss_t loss1 = losses[loss_off1];
        evoasm_loss_t min_loss;
        size_t min_run_idx;

        if(loss0 < loss1) {
          min_run_idx = 0;
          min_loss = loss0;
        } else {
          min_run_idx = 1;
          min_loss = loss1;
        }
        front_idxs[min_run_idx]++;
        scratch[i] = min_loss;
      }
      median = scratch[merge_len - 1];
      break;
    }
    default:
      evoasm_assert_not_reached();
  }

#ifdef EVOASM_ENABLE_PARANOID_MODE
  evoasm_loss_t median_;
  qsort(losses, len, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);
  median_ = losses[(len - 1) / 2];
  assert(median == median_);
#endif

  return median;
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

size_t
evoasm_pop_get_gen_counter(evoasm_pop_t *pop) {
  return pop->gen_counter;
}

static void
evoasm_deme_eval_update(evoasm_deme_t *deme, bool new_best) {

  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;

  size_t height = evoasm_pop_params_get_deme_height_(deme->params);

  evoasm_loss_t prev_avg_losses[EVOASM_PROGRAM_MAX_SIZE + 1];

  for(size_t i = 0; i < height; i++) {
    prev_avg_losses[i] = deme->avg_losses[i];
    deme->top_losses[i] = INFINITY;
    deme->avg_losses[i] = 0;
  }


  for(size_t i = 0; i < height; i++) {
    size_t indiv_loss_n = 1;

    for(size_t j = 0; j < deme->params->deme_size; j++) {
      size_t indiv_off = EVOASM_DEME_INDIV_OFF(deme, i, j);
      size_t sample0_off = EVOASM_DEME_LOSS_SAMPLE_OFF(deme, i, j, 0);

      evoasm_loss_t indiv_loss =
          evoasm_pop_find_median_loss_(&loss_data->samples[sample0_off],
                                       loss_data->counters[indiv_off]);

      loss_data->samples[sample0_off] = indiv_loss;

      if(!isinf(indiv_loss)) {
        deme->avg_losses[i] += (indiv_loss - deme->avg_losses[i]) / (evoasm_loss_t) (indiv_loss_n);
        indiv_loss_n++;
      }

      if(indiv_loss < deme->top_losses[i]) {
        evoasm_log_info("new top loss %zu: %f -> %f", i, deme->top_losses[i], indiv_loss);
        deme->top_losses[i] = indiv_loss;
      }
    }
  }

  double avg_losses_diff = 0.0;
  for(size_t i = 0; i < height; i++) {
    avg_losses_diff += fabs(prev_avg_losses[i] - deme->avg_losses[i]);
  }

  fprintf(stderr, "MUT RATE: %f| LOSS DIFF %f\n", deme->mut_rate, avg_losses_diff);

  if(avg_losses_diff < 0.05) {
    deme->mut_rate = EVOASM_MIN(EVOASM_DEME_MAX_MUT_RATE, deme->mut_rate * 1.01f);
    deme->stagn_counter++;
  } else {
    deme->mut_rate = EVOASM_MAX(EVOASM_DEME_MIN_MUT_RATE, deme->mut_rate / 1.02f);
    deme->stagn_counter = 0;
  }
}

size_t
evoasm_pop_get_loss_samples(evoasm_pop_t *pop, size_t deme_idx, const evoasm_loss_t **losses) {
  evoasm_deme_t *deme = &pop->demes[deme_idx];
  size_t len = EVOASM_DEME_N_INDIVS(deme) * EVOASM_DEME_MAX_LOSS_SAMPLES;
  *losses = deme->loss_data.samples;

  return len;
}

static evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme) {
  bool retval = true;
  bool new_best = false;

  EVOASM_MEMSET_N(deme->loss_data.counters, 0, EVOASM_DEME_N_INDIVS(deme));
  //EVOASM_MEMSET_N(deme->loss_data.samples, 0, EVOASM_DEME_N_INDIVS(deme) * EVOASM_DEME_MAX_LOSS_SAMPLES);

  if(deme->params->program_size > 1) {
    if(!evoasm_deme_test_programs(deme, &new_best)) {
      retval = false;
      goto done;
    }
  }

  if(!evoasm_deme_test_kernels(deme, &new_best)) {
    retval = false;
    goto done;
  }

  evoasm_deme_eval_update(deme, new_best);

done:
  return retval;
}

evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop) {
  bool retval = true;
  size_t n_demes = pop->params->n_demes;

  if(!pop->seeded) {
    retval = false;
    evoasm_error(EVOASM_ERROR_TYPE_POP, EVOASM_ERROR_CODE_NONE,
                 "not seeded");
    goto done;
  }

  bool *retvals = evoasm_alloca(sizeof(bool) * n_demes);
  evoasm_error_t *errors = evoasm_alloca(sizeof(evoasm_error_t) * n_demes);

  if(pop->gen_counter > 0 && EVOASM_PROGRAM_INPUT_N_TUPLES(pop->params->program_input) > EVOASM_DEME_EXAMPLE_WIN_SIZE) {
    for(size_t i = 0; i < n_demes; i++) {
      pop->demes[i].input_win_off++;
    }
  }

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
evoasm_deme_select_indivs(evoasm_deme_t *deme, size_t row, bool programs) {
  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;
  size_t n_doomed_indivs = 0;
  size_t n_blessed_indivs = 0;
  size_t deme_size = deme->params->deme_size;


//  size_t n = 1;
//  evoasm_loss_t avg_loss = 0.0;
//  for(size_t i = 0; i < deme_size; i++) {
//    evoasm_loss_t loss = loss_data->samples[EVOASM_DEME_LOSS_OFF(deme, row, i)];
//    if(!isinf(loss)) {
//      avg_loss += (loss - avg_loss) / (evoasm_loss_t) n;
//      n++;
//    }
//  }

  /* floating-point inaccuracy */
  evoasm_loss_t avg_loss = deme->avg_losses[row] + 0.0001f;

  for(size_t i = 0; i < deme_size; i++) {
    evoasm_loss_t loss = loss_data->samples[EVOASM_DEME_LOSS_OFF(deme, row, i)];

    if(loss > avg_loss) {
      deme->doomed_indiv_idxs[n_doomed_indivs++] = (uint16_t) i;
    } else {
      deme->blessed_indiv_idxs[n_blessed_indivs++] = (uint16_t) i;
    }
  }

  //assert(n_blessed_indivs > 0);
  //assert(n_doomed_indivs > 0);

  deme->n_blessed_indivs = (uint16_t) n_blessed_indivs;
  deme->n_doomed_indivs = (uint16_t) n_doomed_indivs;
}

static size_t
evoasm_deme_get_indiv_size(evoasm_deme_t *deme, bool programs) {
  return programs ? deme->params->program_size : deme->params->kernel_size;
}

static evoasm_force_inline inline void
evoasm_deme_combine_indivs(evoasm_deme_t *deme, size_t row, size_t idx, bool programs) {
  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;
  evoasm_pop_program_data_t *program_data = &deme->program_data;
  evoasm_pop_kernel_data_t *kernel_data = &deme->kernel_data;
  evoasm_prng_t *prng = &deme->prng;

  size_t indiv_size = evoasm_deme_get_indiv_size(deme, programs);

  size_t parent_idxs[2] = {
      deme->blessed_indiv_idxs[idx % deme->n_blessed_indivs],
      deme->blessed_indiv_idxs[(idx + 1) % deme->n_blessed_indivs]
  };

  size_t child_idxs[2] = {
      deme->doomed_indiv_idxs[idx],
      deme->doomed_indiv_idxs[idx + 1]
  };

  /* rough estimate */
  evoasm_loss_t child_loss = 0.5f * loss_data->samples[EVOASM_DEME_LOSS_OFF(deme, row, parent_idxs[0])]
                             + 0.5f * loss_data->samples[EVOASM_DEME_LOSS_OFF(deme, row, parent_idxs[1])];

  assert(isfinite(child_loss));

  float crossover_point = evoasm_prng_randf_(prng);
  size_t seg1_len = EVOASM_MAX(1u, (size_t) (crossover_point * (float) indiv_size));
  size_t seg2_len = indiv_size - seg1_len;

  for(size_t j = 0; j < 2; j++) {
    loss_data->samples[EVOASM_DEME_LOSS_OFF(deme, row, child_idxs[j])] = child_loss;

    if(programs) {
      size_t parent_pos0_offs[] = {
          EVOASM_DEME_PROGRAM_POS_OFF(deme, parent_idxs[j], 0),
          EVOASM_DEME_PROGRAM_POS_OFF(deme, parent_idxs[1 - j], 0)
      };

      size_t child_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, child_idxs[j], 0);

      evoasm_pop_program_data_copy(program_data, parent_pos0_offs[0],
                                   program_data, child_pos0_off, seg1_len);
      evoasm_pop_program_data_copy(program_data, parent_pos0_offs[1] + seg1_len,
                                   program_data, child_pos0_off + seg1_len, seg2_len);

    } else {
      size_t parent_inst0_offs[] = {
          EVOASM_DEME_KERNEL_INST_OFF(deme, row, parent_idxs[j], 0),
          EVOASM_DEME_KERNEL_INST_OFF(deme, row, parent_idxs[1 - j], 0)
      };
      size_t child_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, row, child_idxs[j], 0);

      evoasm_pop_kernel_data_copy(kernel_data, deme->arch_id, parent_inst0_offs[0],
                                  kernel_data, child_inst0_off, seg1_len);
      evoasm_pop_kernel_data_copy(kernel_data, deme->arch_id, parent_inst0_offs[1] + seg1_len,
                                  kernel_data, child_inst0_off + seg1_len, seg2_len);
    }
  }
}

static evoasm_force_inline inline void
evoasm_deme_combine(evoasm_deme_t *deme, size_t row, bool programs) {
  size_t n_doomed = EVOASM_ALIGN_DOWN(deme->n_doomed_indivs, 2u);
  for(size_t i = 0; i < n_doomed; i += 2) {
    evoasm_deme_combine_indivs(deme, row, i, programs);
  }
}

static inline void
evoasm_deme_calc_summary(evoasm_deme_t *deme, evoasm_loss_t *summary_losses, evoasm_loss_t *summary) {
  size_t deme_size = deme->params->deme_size;
  evoasm_pop_loss_data_t *loss_data = &deme->loss_data;

  size_t height = evoasm_pop_params_get_deme_height_(deme->params);

  for(size_t i = 0; i < height; i++) {
    size_t summary_off = i * 5;

    for(size_t j = 0; j < deme_size; j++) {
      size_t loss_off = EVOASM_DEME_LOSS_OFF(deme, i, j);
      evoasm_loss_t loss = loss_data->samples[loss_off];
      summary_losses[j] = loss;
    }

    qsort(summary_losses, deme_size, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);

    for(size_t j = 0; j < 5; j++) {
      summary[summary_off + j] = summary_losses[j * (deme_size - 1) / 4];
    }
  }
}

#define EVOASM_DEME_SUMMARY_LEN(pop) (5 * (evoasm_pop_params_get_deme_height_(pop->params)))

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

static evoasm_force_inline inline void
evoasm_deme_mutate_indiv(evoasm_deme_t *deme, size_t row, size_t indiv_idx, bool program) {
  evoasm_prng_t *prng = &deme->prng;
  size_t indiv_size = evoasm_deme_get_indiv_size(deme, program);

  float r1 = evoasm_prng_randf_(prng);
  float mut_rate = (float) indiv_size * deme->mut_rate;

  if(r1 < mut_rate) {
    for(size_t i = 0; i < indiv_size; i++) {
      float r2 = evoasm_prng_randf_(prng);

      if(r2 < deme->mut_rate) {
        if(program) {
          evoasm_deme_seed_program_pos(deme, indiv_idx, i);
        } else {
          evoasm_deme_seed_kernel_inst(deme, row, indiv_idx, i);
        }
      }
    }
  }
}

static evoasm_force_inline inline void
evoasm_deme_mutate(evoasm_deme_t *deme, size_t row, bool programs) {
  for(size_t i = 0; i < deme->params->deme_size; i++) {
    evoasm_deme_mutate_indiv(deme, row, i, programs);
  }
}

static evoasm_force_inline inline void
evoasm_deme_inject_best(evoasm_deme_t *deme, evoasm_deme_t *src_deme, size_t row, bool program) {
  assert(deme->n_doomed_indivs > 0);

  if(program) {
    size_t src_program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF_(deme->params->program_size, 0, 0);
    size_t dst_program_pos0_off = EVOASM_DEME_PROGRAM_POS_OFF(deme, deme->doomed_indiv_idxs[deme->n_doomed_indivs - 1],
                                                              0);
    evoasm_pop_program_data_copy(&src_deme->best_program_data, src_program_pos0_off, &deme->program_data,
                                 dst_program_pos0_off, deme->params->program_size);
  } else {
    size_t src_kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF_(1, deme->params->kernel_size, row, 0, 0);
    size_t dst_kernel_inst0_off = EVOASM_DEME_KERNEL_INST_OFF(deme, row,
                                                              deme->doomed_indiv_idxs[deme->n_doomed_indivs - 1], 0);
    evoasm_pop_kernel_data_copy(&src_deme->best_kernel_data, deme->arch_id, src_kernel_inst0_off, &deme->kernel_data,
                                dst_kernel_inst0_off, deme->params->program_size);
  }
  deme->n_doomed_indivs--;
}

static evoasm_force_inline inline void
evoasm_deme_save_elite(evoasm_deme_t *deme, size_t row, bool program) {
  if(deme->n_doomed_indivs > 0) {
    evoasm_deme_inject_best(deme, deme, row, program);
  }
}

static evoasm_force_inline inline void
evoasm_deme_immigrate_elite(evoasm_deme_t *deme, evoasm_deme_t *demes, size_t row, bool program) {
  if(deme->stagn_counter > 0 && deme->stagn_counter % 4) {
    for(size_t i = 0; i < demes->params->n_demes; i++) {
      evoasm_deme_t *immigration_deme = &demes[i];

      if(deme->n_doomed_indivs == 0) {
        break;
      }

      if(deme != immigration_deme) {
        evoasm_deme_inject_best(deme, immigration_deme, row, program);
      }

    }
  }
}

static void
evoasm_deme_next_gen(evoasm_deme_t *deme, evoasm_deme_t *demes) {
  for(size_t i = 0; i < deme->params->program_size; i++) {
    evoasm_deme_select_indivs(deme, i, false);
    evoasm_deme_save_elite(deme, i, false);
    evoasm_deme_immigrate_elite(deme, demes, i, false);

    evoasm_deme_combine(deme, i, false);
    evoasm_deme_mutate(deme, i, false);
  }

  if(deme->params->program_size > 1) {
    evoasm_deme_select_indivs(deme, EVOASM_DEME_PROGRAMS_ROW(deme), true);

    evoasm_deme_save_elite(deme, EVOASM_DEME_PROGRAMS_ROW(deme), true);
    evoasm_deme_immigrate_elite(deme, demes, EVOASM_DEME_PROGRAMS_ROW(deme), true);

    evoasm_deme_combine(deme, EVOASM_DEME_PROGRAMS_ROW(deme), true);

    evoasm_deme_mutate(deme, EVOASM_DEME_PROGRAMS_ROW(deme), true);
  }
}

void
evoasm_pop_next_gen(evoasm_pop_t *pop) {
#pragma omp parallel for
  for(size_t i = 0; i < pop->params->n_demes; i++) {
    evoasm_deme_next_gen(&pop->demes[i], pop->demes);
  }

  pop->gen_counter++;

}

#if 0

evoasm_pop_select(pop, blessed_indiv_idxs, pop->params->size);
  {
    double scale = 1.0 / pop->params->size;
    double pop_loss = 0.0;
    size_t n_inf = 0;
    for(i = 0; i < pop->params->size; i++) {
      double loss = pop->pop.top_losses[blessed_indiv_idxs[i]];
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
    evoasm_program_params_t *program_params = EVOASM_SEARCH_PROGRAM_PARAMS(pop, pop->pop.indivs, blessed_indiv_idxs[i]);
    assert(program_params->size > 0);
  }

  return evoasm_pop_combine_parents(pop, blessed_indiv_idxs);
}
#endif

EVOASM_DEF_ALLOC_FREE_FUNCS(pop)
