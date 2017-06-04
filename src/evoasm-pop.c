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
#include "evoasm-kernel.h"
#include "evoasm-error.h"
#include "evoasm-kernel-io.h"
#include "evoasm-x64.h"
#include "evoasm-param.h"

#ifdef _OPENMP

#  include <omp.h>

#endif

#include <gen/evoasm-x64-params.h>
#include <gen/evoasm-x64-misc.h>

EVOASM_DEF_LOG_TAG("pop")

static evoasm_success_t
evoasm_deme_losses_init(evoasm_deme_losses_t *losses, evoasm_deme_t *deme) {
  size_t n_indivs = deme->params->deme_size;

  EVOASM_TRY_ALLOC(error, aligned_calloc, losses->losses, EVOASM_CACHE_LINE_SIZE,
                   n_indivs,
                   sizeof(evoasm_loss_t));

  return true;
error:
  return false;
}

static void
evoasm_deme_losses_destroy(evoasm_deme_losses_t *losses) {
  evoasm_free(losses->losses);
}

EVOASM_DEF_ALLOC_FREE_FUNCS(deme_kernels)

evoasm_success_t
evoasm_deme_kernels_init(evoasm_deme_kernels_t *kernels,
                         const evoasm_pop_params_t *pop_params,
                         evoasm_arch_id_t arch_id,
                         size_t n_kernels) {

  kernels->pop_params = pop_params;
  size_t kernel_size = kernels->pop_params->max_kernel_size;
  size_t n_insts = n_kernels * kernel_size;

  kernels->arch_id = arch_id;
  kernels->n_kernels = (uint16_t) n_kernels;

  EVOASM_TRY_ALLOC_N(error, aligned_calloc, kernels->sizes, EVOASM_CACHE_LINE_SIZE,
                     n_kernels);

  EVOASM_TRY_ALLOC_N(error, aligned_calloc, kernels->insts, EVOASM_CACHE_LINE_SIZE,
                     n_insts);

  switch(arch_id) {
    case EVOASM_ARCH_X64:
      EVOASM_TRY_ALLOC_N(error, aligned_calloc, kernels->params.x64, EVOASM_CACHE_LINE_SIZE,
                         n_insts);
      break;
    default:
      evoasm_assert_not_reached();
  }
  return true;

error:
  return false;
}

void
evoasm_deme_kernels_destroy(evoasm_deme_kernels_t *kernels) {
  evoasm_free(kernels->sizes);
  evoasm_free(kernels->insts);
  evoasm_free(kernels->params.data);
}


void evoasm_deme_kernels_set_size(evoasm_deme_kernels_t *kernels, size_t kernel_idx, size_t size) {
  kernels->sizes[kernel_idx] = (uint16_t) size;
}

static inline size_t
evoasm_deme_kernels_get_inst_off(evoasm_deme_kernels_t *kernels, size_t kernel_idx, size_t inst_idx) {
  return (size_t) ((kernel_idx) * (kernels->pop_params->max_kernel_size) + (inst_idx));
}

void
evoasm_deme_kernels_set_inst(evoasm_deme_kernels_t *kernels, size_t kernel_idx, size_t inst_idx,
                             evoasm_inst_id_t inst_id, void *params) {

  size_t inst_off = evoasm_deme_kernels_get_inst_off(kernels, kernel_idx, inst_idx);

  kernels->insts[inst_off] = inst_id;

  switch(kernels->arch_id) {
    case EVOASM_ARCH_X64:
      kernels->params.x64[inst_off] = *((evoasm_x64_basic_params_t *) params);
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static void
evoasm_deme_destroy(evoasm_deme_t *deme) {
  EVOASM_TRY_WARN(evoasm_kernel_destroy, &deme->kernel);
  evoasm_prng_destroy(&deme->prng);
  evoasm_free(deme->won_tourns_counters);
  evoasm_free(deme->immig_idxs);

  evoasm_deme_kernels_destroy(&deme->kernels);
  evoasm_deme_losses_destroy(&deme->losses);

  evoasm_deme_kernels_destroy(&deme->best_kernels);
}

void
evoasm_pop_destroy(evoasm_pop_t *pop) {
  evoasm_free(pop->domains);

  for(size_t i = 0; i < pop->n_demes; i++) {
    evoasm_deme_destroy(&pop->demes[i]);
  }

  evoasm_free(pop->inst_idx_mapping);
  evoasm_free(pop->imm_insts_bitmap);
  evoasm_free(pop->insts_bitmap);
  evoasm_free(pop->demes);
  evoasm_free(pop->summary_losses);

  evoasm_free(pop->similar_insts);
  evoasm_free(pop->similar_inst_idxs);
}

#define EVOASM_DEME_MIN_MUT_RATE 0.008f
#define EVOASM_DEME_MAX_MUT_RATE 0.15f

static evoasm_success_t
evoasm_deme_init(evoasm_deme_t *deme,
                 evoasm_pop_t *pop,
                 size_t deme_idx,
                 evoasm_arch_id_t arch_id,
                 const evoasm_prng_state_t *seed) {

  static evoasm_deme_t zero_deme = {0};
  const evoasm_pop_params_t *params = pop->params;
  size_t n_examples = evoasm_kernel_io_get_n_tuples_(params->kernel_input);

  *deme = zero_deme;
  deme->idx = (uint16_t) deme_idx;

  deme->pop = pop;
  deme->params = pop->params;
  deme->domains = pop->domains;
  deme->inst_idx_mapping = pop->inst_idx_mapping;
  deme->imm_insts_bitmap = pop->imm_insts_bitmap;
  deme->similar_insts = pop->similar_insts;
  deme->similar_inst_idxs = pop->similar_inst_idxs;
  deme->arch_id = arch_id;
  deme->mut_rate = EVOASM_DEME_MIN_MUT_RATE;

  if(n_examples > deme->params->example_win_size) {
    deme->example_win_off = (uint16_t) (n_examples / params->n_demes * deme_idx);
  }

  deme->imm_param_idx = UINT16_MAX;
  for(size_t i = 0; i < params->n_params; i++) {
    if(params->param_ids[i] == EVOASM_X64_PARAM_IMM0) {
      deme->imm_param_idx = (uint16_t) i;
      break;
    }
  }

  evoasm_prng_init(&deme->prng, seed);

  EVOASM_TRY_ALLOC_N(error, aligned_calloc, deme->won_tourns_counters, EVOASM_CACHE_LINE_SIZE, params->deme_size);
  EVOASM_TRY_ALLOC_N(error, aligned_calloc, deme->immig_idxs, EVOASM_CACHE_LINE_SIZE, params->deme_size);

  EVOASM_TRY(error, evoasm_kernel_init, &deme->kernel,
             evoasm_get_arch_info(arch_id),
             params->max_kernel_size,
             n_examples,
             true);

  EVOASM_TRY(error, evoasm_deme_kernels_init, &deme->kernels, deme->params, deme->arch_id, params->deme_size);
  EVOASM_TRY(error, evoasm_deme_kernels_init, &deme->best_kernels, deme->params, deme->arch_id, 1u);
  EVOASM_TRY(error, evoasm_deme_losses_init, &deme->losses, deme);

  deme->best_loss = INFINITY;
  deme->top_loss = INFINITY;

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_pop_init_domains(evoasm_pop_t *pop) {
  evoasm_domain_t cloned_domain;

  const evoasm_pop_params_t *params = pop->params;

  size_t domains_len = (size_t) (params->n_insts * params->n_params);
  evoasm_x64_param_id_t empty_domain_param_id;

  EVOASM_TRY_ALLOC_N(error, calloc, pop->domains, domains_len);

//  pop->domains = evoasm_calloc(domains_len,
//                               sizeof(evoasm_domain_t));

//  if(!pop->domains) goto error;

  EVOASM_TRY_ALLOC(error, calloc, pop->imm_insts_bitmap, EVOASM_BITMAP_BYTESIZE(params->n_insts), 1);
  EVOASM_TRY_ALLOC(error, calloc, pop->insts_bitmap, EVOASM_BITMAP_BYTESIZE(EVOASM_X64_INST_NONE), 1);

  for(size_t i = 0; i < params->n_insts; i++) {
    evoasm_x64_inst_id_t inst_id = (evoasm_x64_inst_id_t) params->inst_ids[i];
    evoasm_x64_inst_t *inst = evoasm_x64_get_inst_(inst_id);
    evoasm_bitmap_set_(pop->insts_bitmap, inst_id);

    for(size_t j = 0; j < params->n_params; j++) {
      evoasm_domain_t *inst_domain = &pop->domains[i * params->n_params + j];
      evoasm_param_id_t param_id = params->param_ids[j];
      for(size_t k = 0; k < inst->n_params; k++) {
        evoasm_param_t *param = &inst->params[k];
        if(param->id == param_id) {
          evoasm_domain_t *user_domain = params->domains[param_id];
          if(user_domain != NULL) {
            if(evoasm_domain_is_empty(user_domain)) {
              empty_domain_param_id = (evoasm_x64_param_id_t) param_id;
              goto empty_domain;
            }

            evoasm_domain_clone(user_domain, &cloned_domain);
            evoasm_domain_intersect(&cloned_domain, param->domain, inst_domain);
            if(evoasm_domain_is_empty(inst_domain)) {
              empty_domain_param_id = (evoasm_x64_param_id_t) param_id;
              goto empty_domain;
            }
          } else {
            evoasm_domain_clone(param->domain, inst_domain);
          }

          if(param_id == EVOASM_X64_PARAM_IMM0 && inst_domain->type == EVOASM_DOMAIN_TYPE_RANGE) {
            evoasm_bitmap_set_(pop->imm_insts_bitmap, i);
          }

          goto found;
        }
      }
      /* not found */
      inst_domain->type = EVOASM_DOMAIN_TYPE_NONE;
found:;
    }
  }

  EVOASM_TRY_ALLOC_N(error, calloc, pop->similar_insts,
                     (size_t) (EVOASM_X64_MAX_SIMILAR_INSTS_PER_INST * params->n_insts));
  EVOASM_TRY_ALLOC_N(error, calloc, pop->similar_inst_idxs, 2u * params->n_insts);

  {
    const uint16_t *similar_inst_idxs;
    const evoasm_x64_similar_inst_entry_t *similar_insts;

    switch(params->dist_metric) {
      case EVOASM_METRIC_ABSDIFF:
        similar_inst_idxs = evoasm_x64_similar_inst_idxs_absdiff;
        similar_insts = evoasm_x64_similar_insts_absdiff;
        break;
      case EVOASM_METRIC_HAMMING:
        similar_inst_idxs = evoasm_x64_similar_inst_idxs_hamming;
        similar_insts = evoasm_x64_similar_insts_hamming;
        break;
      default:
        evoasm_assert_not_reached();
    };

    size_t entry_counter = 0;
    size_t inst_counter = 0;

    for(size_t i = 0; i < EVOASM_X64_INST_NONE; i++) {
      if(evoasm_bitmap_get_(pop->insts_bitmap, i)) {
        size_t idx_from = similar_inst_idxs[2 * i];
        size_t idx_to = similar_inst_idxs[2 * i + 1];

        pop->similar_inst_idxs[2 * inst_counter] = (uint16_t) entry_counter;

        for(size_t j = idx_from; j < idx_to; j++) {
          evoasm_x64_similar_inst_entry_t entry = similar_insts[j];
          if(evoasm_bitmap_get_(pop->insts_bitmap, entry.inst_id)) {
            pop->similar_insts[entry_counter++] = entry;
          }
        }

        pop->similar_inst_idxs[2 * inst_counter + 1] = (uint16_t) entry_counter;
        inst_counter++;
      }
    }
  }

  /*
  for(i = 0; i < domains_len; i++) {
    evoasm_domain_log(&pop->domains[i], EVOASM_LOG_LEVEL_WARN);
  }*/

  return true;

error:
  return false;

empty_domain:
  evoasm_error(EVOASM_ERROR_TYPE_POP, EVOASM_ERROR_CODE_NONE,
               "Empty domain (%s)", evoasm_x64_param_get_name_(empty_domain_param_id));
  return false;
}

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                const evoasm_pop_params_t *params) {
  static evoasm_pop_t zero_pop = {0};
  evoasm_prng_t seed_prng;

  *pop = zero_pop;

  if(!evoasm_pop_params_validate((evoasm_pop_params_t *) params)) goto error;

  pop->params = params;
  size_t n_demes = params->n_demes;
#ifdef _OPENMP
  {
    int max_threads;
    max_threads = omp_get_max_threads();
    omp_set_dynamic(0);
    int n_threads = EVOASM_MIN(max_threads, (int) n_demes);
    omp_set_num_threads(n_threads);
    evoasm_log_info("Using OpenMP with %d threads", n_threads);
  }
#endif

  evoasm_prng_init(&seed_prng, &params->seed);

  EVOASM_TRY(error, evoasm_pop_init_domains, pop);

  size_t n_insts;
  switch(arch_id) {
    case EVOASM_ARCH_X64:
      n_insts = EVOASM_X64_INST_NONE;
      break;
    default:
      evoasm_assert_not_reached();
  }

  EVOASM_TRY_ALLOC_N(error, calloc, pop->inst_idx_mapping, n_insts);
  EVOASM_MEMSET_N(pop->inst_idx_mapping, -1, n_insts);
  for(size_t i = 0; i < params->n_insts; i++) {
    pop->inst_idx_mapping[params->inst_ids[i]] = (uint16_t) i;
  }

  EVOASM_TRY_ALLOC(error, aligned_calloc, pop->demes, EVOASM_CACHE_LINE_SIZE, n_demes,
                   sizeof(evoasm_deme_t));


  for(size_t i = 0; i < n_demes; i++) {
    evoasm_prng_state_t seed;

    for(size_t j = 0; j < EVOASM_PRNG_SEED_LEN; j++) {
      seed.data[j] = evoasm_prng_rand64_(&seed_prng);
    }

    EVOASM_TRY(error, evoasm_deme_init,
               &pop->demes[i],
               pop,
               i,
               arch_id,
               &seed);
  }

  pop->n_demes = (uint16_t) n_demes;

  return true;

error:
  evoasm_pop_destroy(pop);
  return false;
}

static void
evoasm_deme_seed_kernel_param_x64(evoasm_deme_t *deme, size_t kernel_idx, evoasm_inst_id_t *inst_id_ptr,
                                  evoasm_x64_basic_params_t *params_ptr) {
  const evoasm_pop_params_t *params = deme->params;
  size_t n_params = params->n_params;
  evoasm_prng_t *prng = &deme->prng;
  size_t inst_idx;

  if(deme->params->max_kernel_size > 1) {
    inst_idx = (size_t) evoasm_prng_rand_between_(prng, 0, params->n_insts);
  } else {
    inst_idx = ((size_t) deme->idx * deme->params->deme_size + kernel_idx) % params->n_insts;
  }

  evoasm_inst_id_t inst_id = params->inst_ids[inst_idx];
  *inst_id_ptr = inst_id;


  /* set parameters */
  for(size_t i = 0; i < n_params; i++) {
    evoasm_domain_t *domain = &deme->domains[inst_idx * n_params + i];
    if(domain->type < EVOASM_DOMAIN_TYPE_NONE) {
      evoasm_x64_basic_param_id_t param_id = (evoasm_x64_basic_param_id_t) deme->params->param_ids[i];
      evoasm_param_val_t param_val;

      param_val = (int64_t) evoasm_domain_rand_(domain, prng);
      evoasm_x64_basic_params_set_(params_ptr, param_id, param_val);
    }
  }
}


static void
evoasm_deme_seed_kernel_inst(evoasm_deme_t *deme,
                             size_t kernel_idx,
                             size_t inst_idx) {


  evoasm_deme_kernels_t *kernels = &deme->kernels;
  size_t kernel_inst_off = evoasm_deme_kernels_get_inst_off(kernels, kernel_idx, inst_idx);
  evoasm_inst_id_t *insts_ptr = &kernels->insts[kernel_inst_off];

  switch(deme->arch_id) {
    case EVOASM_ARCH_X64: {
      evoasm_x64_basic_params_t *params_ptr = &kernels->params.x64[kernel_inst_off];
      evoasm_deme_seed_kernel_param_x64(deme, kernel_idx, insts_ptr, params_ptr);
      break;
    }
    default:
      evoasm_assert_not_reached();
  }
}


static void
evoasm_deme_mutate_kernel_inst(evoasm_deme_t *deme,
                               size_t kernel_idx,
                               size_t inst_idx) {
  evoasm_deme_seed_kernel_inst(deme, kernel_idx, inst_idx);
}

static void
evoasm_deme_seed_kernel(evoasm_deme_t *deme, size_t kernel_idx) {

  uint16_t kernel_size = (uint16_t) evoasm_prng_rand_between_(&deme->prng,
                                                              deme->params->min_kernel_size,
                                                              deme->params->max_kernel_size + 1);

  assert(kernel_size > 0);
  deme->kernels.sizes[kernel_idx] = kernel_size;

  for(size_t i = 0; i < kernel_size; i++) {
    evoasm_deme_seed_kernel_inst(deme, kernel_idx, i);
  }
}

static void
evoasm_deme_kernels_copy(evoasm_deme_kernels_t *kernels,
                         size_t kernel_idx,
                         evoasm_deme_kernels_t *dst_kernels,
                         size_t dst_kernel_idx,
                         size_t n_kernels) {

//  size_t n_kernels = kernels->n_kernels;
  size_t n_insts = n_kernels * kernels->pop_params->max_kernel_size;
  size_t inst_off = evoasm_deme_kernels_get_inst_off(kernels, kernel_idx, 0);
  size_t dst_inst_off = evoasm_deme_kernels_get_inst_off(dst_kernels, dst_kernel_idx, 0);

  EVOASM_MEMCPY_N(dst_kernels->insts + dst_inst_off, kernels->insts + inst_off, n_insts);

  switch(kernels->arch_id) {
    case EVOASM_ARCH_X64:
      EVOASM_MEMCPY_N(dst_kernels->params.x64 + dst_inst_off, kernels->params.x64 + inst_off, n_insts);
      break;
    default:
      evoasm_assert_not_reached();
  }

  EVOASM_MEMCPY_N(dst_kernels->sizes + dst_kernel_idx, kernels->sizes + kernel_idx, n_kernels);

}

static void
evoasm_deme_seed(evoasm_deme_t *deme, evoasm_deme_kernels_t *kernels) {
  size_t n_total_kernels = deme->params->deme_size;

  size_t n_seed_kernels = 0;

  {
    if(kernels != NULL) {
      n_seed_kernels = kernels->n_kernels;
      evoasm_deme_kernels_copy(kernels, 0, &deme->kernels, 0, kernels->n_kernels);
    }
  }

  for(size_t i = n_seed_kernels; i < n_total_kernels; i++) {
    evoasm_deme_seed_kernel(deme, i);
  }
}

evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop, evoasm_deme_kernels_t *kernels) {

  if(kernels != NULL && kernels->n_kernels > pop->params->deme_size) {
    evoasm_error(EVOASM_ERROR_TYPE_POP, EVOASM_ERROR_CODE_NONE,
                 "number of kernels exceeds deme size (%d > %d)", kernels->n_kernels, pop->params->deme_size);
    return false;
  }

#pragma omp parallel for
  for(size_t i = 0; i < pop->n_demes; i++) {
    evoasm_deme_seed(&pop->demes[i], kernels);
  }
  pop->seeded = true;
  return true;

error:
  return false;

}

static void
evoasm_deme_load_kernel_(evoasm_deme_t *deme,
                         evoasm_kernel_t *kernel,
                         evoasm_deme_kernels_t *kernels,
                         size_t kernel_idx) {

  size_t inst0_off = evoasm_deme_kernels_get_inst_off(kernels, kernel_idx, 0);
  size_t kernel_size = kernels->sizes[kernel_idx];

  assert(kernel_size > 0);

  kernel->size = (uint16_t) kernel_size;

  if(kernel->shallow) {
    kernel->insts = &kernels->insts[inst0_off];
  } else {
    EVOASM_MEMCPY_N(kernel->insts,
                    &kernels->insts[inst0_off], kernel_size);
  }

  switch(deme->arch_id) {
    case EVOASM_ARCH_X64:
      if(kernel->shallow) {
        kernel->x64.params = &kernels->params.x64[inst0_off];
      } else {
        EVOASM_MEMCPY_N(kernel->x64.params,
                        &kernels->params.x64[inst0_off], kernel_size);
      }
      break;
    default:
      evoasm_assert_not_reached();
  }
}

static inline void
evoasm_deme_load_kernel(evoasm_deme_t *deme,
                        size_t kernel_idx) {

  evoasm_kernel_t *kernel = &deme->kernel;
  evoasm_deme_kernels_t *kernels = &deme->kernels;

  evoasm_deme_load_kernel_(deme, kernel, kernels, kernel_idx);
}

static evoasm_success_t
evoasm_deme_eval_kernel(evoasm_deme_t *deme, evoasm_loss_t *ret_loss) {
  const evoasm_pop_params_t *params = deme->params;
  evoasm_kernel_t *kernel = &deme->kernel;

  //bool prepare, bool emit_kernels, bool emit_io_load_store, bool set_io_mapping
  evoasm_kernel_emit_flags_t emit_flags = EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;

  size_t win_off = 0;
  size_t win_size = SIZE_MAX;

  if(!deme->major) {
    win_off = deme->example_win_off;
    win_size = deme->params->example_win_size;
  }

  if(!evoasm_kernel_emit(kernel, params->kernel_input, win_off, win_size,
                         emit_flags)) {
    *ret_loss = INFINITY;

    if(evoasm_last_error.type == EVOASM_ERROR_TYPE_KERNEL &&
       evoasm_last_error.code == EVOASM_KERNEL_ERROR_CODE_NO_OUTPUT) {
      /* do not abort on this error, instead just let loss be infinity */
      return true;
    }
    return false;
  }

  *ret_loss = evoasm_kernel_eval(kernel, params->kernel_output, (evoasm_metric_t) params->dist_metric, win_off,
                                 win_size);

  return true;
}

static evoasm_deme_t *
evoasm_pop_find_best_deme(evoasm_pop_t *pop) {
  evoasm_deme_t *best_deme = &pop->demes[0];
  evoasm_loss_t best_loss = best_deme->best_loss;

  for(size_t i = 1; i < pop->n_demes; i++) {
    evoasm_deme_t *deme = &pop->demes[i];
    if(deme->best_loss < best_loss) {
      best_loss = deme->best_loss;
      best_deme = deme;
    }
  }
  return best_deme;
}

evoasm_success_t
evoasm_pop_load_best_kernel(evoasm_pop_t *pop, evoasm_kernel_t *kernel) {

  evoasm_deme_t *best_deme = evoasm_pop_find_best_deme(pop);
  const evoasm_pop_params_t *params = best_deme->params;
  size_t n_examples = evoasm_kernel_io_get_n_tuples_(params->kernel_input);

  EVOASM_TRY(error, evoasm_kernel_init, kernel,
             evoasm_get_arch_info(best_deme->arch_id),
             params->max_kernel_size,
             n_examples,
             false);

  size_t kernel_idx = 0;
  evoasm_deme_load_kernel_(best_deme,
                           kernel,
                           &best_deme->best_kernels,
                           kernel_idx);


  kernel->_input = *params->kernel_input;
  kernel->_output = *params->kernel_output;
  kernel->_input.n_tuples = 0;
  kernel->_output.n_tuples = 0;

  evoasm_kernel_emit_flags_t emit_flags = EVOASM_PROGRAM_EMIT_FLAG_SET_IO_MAPPING;

  EVOASM_TRY(error, evoasm_kernel_emit, kernel, params->kernel_input, 0, SIZE_MAX, emit_flags);

//  evoasm_kernel_topo_log(&kernel->topo, EVOASM_LOG_LEVEL_FATAL);

  evoasm_signal_set_exception_mask(kernel->exception_mask);
  evoasm_loss_t loss = evoasm_kernel_eval(kernel, params->kernel_output, (evoasm_metric_t) params->dist_metric, 0,
                                          SIZE_MAX);
  (void) loss;
  assert(loss == best_deme->best_loss);
  evoasm_signal_clear_exception_mask();

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_test_kernel(evoasm_deme_t *deme, size_t kernel_idx) {
  evoasm_loss_t loss;
  evoasm_deme_losses_t *losses = &deme->losses;

  evoasm_deme_load_kernel(deme, kernel_idx);

  EVOASM_TRY(error, evoasm_deme_eval_kernel, deme, &loss);

  evoasm_log_debug("kernel %zu has loss: %g", kernel_idx, loss);
  losses->losses[kernel_idx] = loss;

  return true;
error:
  return false;
}

static inline void
evoasm_deme_update_best(evoasm_deme_t *deme, evoasm_loss_t loss, size_t kernel_idx) {

  if(loss < deme->best_loss) {
    evoasm_log_info("new best kernel loss: %g", loss);
  }

  evoasm_buf_log(deme->kernel.buf, EVOASM_LOG_LEVEL_DEBUG);

//    for(size_t i = 0; i < deme->kernel.output_reg_mapping)

  deme->best_loss = loss;

  evoasm_deme_kernels_copy(&deme->kernels, kernel_idx, &deme->best_kernels, 0u, deme->best_kernels.n_kernels);
}

static evoasm_success_t
evoasm_deme_test(evoasm_deme_t *deme) {

  for(size_t i = 0; i < deme->params->deme_size; i++) {
    EVOASM_TRY(error, evoasm_deme_test_kernel, deme, i);
  }

  return true;

error:
  return false;
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
evoasm_deme_eval_update(evoasm_deme_t *deme) {

  if(deme->major) {
    evoasm_deme_losses_t *losses = &deme->losses;

    evoasm_loss_t top_loss = INFINITY;
//  evoasm_loss_t avg_loss = 0.0;
    size_t top_kernel_idx = SIZE_MAX;

    {
//    size_t n = 1;


      for(size_t i = 0; i < deme->params->deme_size; i++) {
        evoasm_loss_t kernel_loss = losses->losses[i];

        if(kernel_loss <= top_loss) {
          top_loss = kernel_loss;
          top_kernel_idx = i;
        }

//      if(!isinf(kernel_loss)) {
//        avg_loss += (kernel_loss - avg_loss) / (evoasm_loss_t) n;
//        n++;
//      }
      }

    }

//    fprintf(stderr, "top loss: %f\n", top_loss);

    if(top_loss <= deme->best_loss) {
      evoasm_deme_update_best(deme, top_loss, top_kernel_idx);
    }

    double top_loss_diff = fabs(deme->top_loss - top_loss);

    if(top_loss_diff < 0.05) {
      deme->mut_rate = EVOASM_MIN(EVOASM_DEME_MAX_MUT_RATE, deme->mut_rate * 1.04f);
      deme->stagn_counter++;
    } else {
      deme->mut_rate = EVOASM_MAX(EVOASM_DEME_MIN_MUT_RATE, deme->mut_rate / 1.02f);
      deme->stagn_counter = 0;
    }

    deme->top_loss = top_loss;
  }

}

static evoasm_success_t
evoasm_deme_eval(evoasm_deme_t *deme, bool major) {
  bool retval = true;

  if(!major && evoasm_kernel_input_get_n_tuples(deme->params->kernel_input) > deme->params->example_win_size) {
    deme->example_win_off++;
  }

  deme->major = major;

  if(!evoasm_deme_test(deme)) {
    retval = false;
    goto done;
  }

  evoasm_deme_eval_update(deme);

done:
  return retval;
}

static evoasm_success_t
evoasm_pop_run_major_gen(evoasm_pop_t *pop) {
  bool retval = true;
  size_t n_demes = pop->n_demes;

  bool *retvals = evoasm_alloca(sizeof(bool) * n_demes);
  evoasm_error_t *errors = evoasm_alloca(sizeof(evoasm_error_t) * n_demes);

  for(size_t i = 0; i < n_demes; i++) {
    pop->demes[i].major = true;
  }

#pragma omp parallel for
  for(size_t i = 0; i < n_demes; i++) {
    retvals[i] = evoasm_deme_eval(&pop->demes[i], true);
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

static inline bool
evoasm_deme_select(evoasm_deme_t *deme) {
  evoasm_deme_losses_t *losses = &deme->losses;
  size_t deme_size = deme->params->deme_size;

  EVOASM_MEMSET_N(deme->won_tourns_counters, 0, deme_size);

  size_t n_selected = 0;
  size_t n_to_select = deme_size - deme->params->n_demes;
  size_t n_iters = 0;

  while(n_selected < n_to_select) {
    size_t min_idx = SIZE_MAX;
    evoasm_loss_t min_loss = INFINITY;

    for(size_t i = 0; i < deme->params->tourn_size; i++) {
      size_t idx = (size_t) evoasm_prng_rand_between_(&deme->prng, 0, (int64_t) deme_size);
      evoasm_loss_t loss = losses->losses[idx];

      if(loss <= min_loss) {
        min_loss = loss;
        min_idx = idx;
      }
    }

    if(!isinf(min_loss)) {
      deme->won_tourns_counters[min_idx]++;
      n_selected++;
    }

    n_iters++;
    if(n_iters > deme_size && n_selected == 0) return false;
  }

  return true;
}

static void
evoasm_deme_copy_kernel(evoasm_deme_t *deme, size_t parent_idx, size_t child_idx) {
  evoasm_deme_kernels_t *kernels = &deme->kernels;
  evoasm_deme_kernels_copy(kernels, parent_idx, kernels, child_idx, 1);
}

static inline void
evoasm_deme_mutate_kernel(evoasm_deme_t *deme, size_t kernel_idx) {
  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_size = deme->kernels.sizes[kernel_idx];
  float r1 = evoasm_prng_randf_(prng);
  float kernel_mut_rate = (float) kernel_size * deme->mut_rate;
  if(r1 < kernel_mut_rate) {
    for(size_t i = 0; i < kernel_size; i++) {
      float r2 = evoasm_prng_randf_(prng);
      if(r2 < deme->mut_rate) {
        evoasm_deme_mutate_kernel_inst(deme, kernel_idx, i);
      }
    }
  }
}

static inline void
evoasm_deme_soft_mutate_kernel(evoasm_deme_t *deme, size_t kernel_idx) {
  evoasm_prng_t *prng = &deme->prng;
  size_t kernel_size = deme->kernels.sizes[kernel_idx];
  float r1 = evoasm_prng_randf_(prng);
  float kernel_mut_rate = (float) kernel_size * deme->mut_rate;
  if(r1 < kernel_mut_rate) {
    for(size_t i = 0; i < kernel_size; i++) {
      float r2 = evoasm_prng_randf_(prng);
      if(r2 < deme->mut_rate) {
        evoasm_deme_mutate_kernel_inst(deme, kernel_idx, i);
      }
    }
  }
}

static inline evoasm_success_t
evoasm_deme_local_search_run_and_eval(evoasm_deme_t *deme,
                                      size_t kernel_idx,
                                      bool *undo) {


  evoasm_loss_t old_loss = deme->losses.losses[kernel_idx];
  evoasm_loss_t new_loss;

  evoasm_deme_load_kernel(deme, kernel_idx);
  EVOASM_TRY(error, evoasm_deme_eval_kernel, deme, &new_loss);

  if(new_loss < old_loss) {
    evoasm_log_debug("local search improved %g -> %g\n", old_loss, new_loss);
    deme->losses.losses[kernel_idx] = new_loss;
    if(evoasm_unlikely(new_loss <= deme->best_loss)) {
      evoasm_deme_update_best(deme, new_loss, kernel_idx);
    }
    *undo = false;
  } else {
    *undo = true;
  }

  return true;

error:
  return false;

}

static inline evoasm_success_t
evoasm_deme_local_search_imm_operand_x64(evoasm_deme_t *deme,
                                         size_t kernel_idx,
                                         evoasm_x64_basic_params_t *params_ptr,
                                         size_t inst_idx) {

  evoasm_domain_t *domain = &deme->domains[inst_idx * deme->params->n_params + deme->imm_param_idx];
  evoasm_range_domain_t *range_domain = (evoasm_range_domain_t *) domain;
  evoasm_prng_t *prng = &deme->prng;

  int32_t old_param_val = params_ptr->imm0;
  int32_t new_param_val;

  switch((evoasm_metric_t) deme->params->dist_metric) {
    case EVOASM_METRIC_ABSDIFF: {
      uint64_t size = evoasm_range_domain_get_size(range_domain);
      float r1 = (evoasm_prng_randf_(prng) - 0.5f) * 0.1f;
      float r2 = (evoasm_prng_randf_(prng) - 0.5f) * 0.1f;
      new_param_val = (int32_t) round((double) size * r1 * r2);
      break;
    }
    case EVOASM_METRIC_HAMMING: {
      size_t bit_pos = (size_t) evoasm_prng_rand_between_(prng, 0,
                                                          (int64_t) evoasm_range_domain_get_bitsize(range_domain));
      new_param_val = old_param_val ^ (1 << bit_pos);
      break;
    }
    default:
      evoasm_assert_not_reached();
      break;
  }

#ifdef EVOASM_ENABLE_PARANOID_MODE
  {
    evoasm_loss_t old_loss = deme->losses.losses[kernel_idx];
    evoasm_loss_t new_loss;
    evoasm_deme_load_kernel(deme, kernel_idx);
    EVOASM_TRY(error, evoasm_deme_eval_kernel, deme, &new_loss);
    assert(old_loss == new_loss);
  }
#endif

  bool undo;

  assert(new_param_val != old_param_val);
  params_ptr->imm0 = new_param_val;

  EVOASM_TRY(error, evoasm_deme_local_search_run_and_eval, deme, kernel_idx, &undo);

  if(undo) {
    params_ptr->imm0 = old_param_val;
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_local_search_inst_x64(evoasm_deme_t *deme, size_t kernel_idx, evoasm_inst_id_t *inst_id_ptr,
                                  evoasm_x64_basic_params_t *params_ptr, size_t inst_idx) {
  evoasm_x64_inst_id_t old_inst_id = (evoasm_x64_inst_id_t) *inst_id_ptr;
  evoasm_prng_t *prng = &deme->prng;

  size_t idx_from = deme->similar_inst_idxs[2 * inst_idx];
  size_t idx_to = deme->similar_inst_idxs[2 * inst_idx + 1];

  if(idx_from < idx_to) {
    size_t idx_r = (size_t) evoasm_prng_rand_between_(prng, (int64_t) idx_from, (int64_t) idx_to);
    evoasm_x64_similar_inst_entry_t entry = deme->similar_insts[idx_r];
    evoasm_x64_inst_id_t new_inst_id = (evoasm_x64_inst_id_t) entry.inst_id;
    int32_t old_imm = params_ptr->imm0;
    int32_t new_imm = entry.imm;


#ifdef EVOASM_ENABLE_PARANOID_MODE
    {
      evoasm_loss_t old_loss = deme->losses.losses[kernel_idx];
      evoasm_loss_t new_loss;
      evoasm_deme_load_kernel(deme, kernel_idx);
      EVOASM_TRY(error, evoasm_deme_eval_kernel, deme, &new_loss);
      assert(old_loss == new_loss);
    }
#endif

    bool undo;

    params_ptr->imm0 = new_imm;
    *inst_id_ptr = new_inst_id;

#define EVOASM_DEME_LOCAL_SEARCH_INST_X64_SET_REG_PARAM(reg_idx) \
    if(entry.reg ## reg_idx ##_domain_idx != UINT8_MAX) { \
      evoasm_domain_t *domain = (evoasm_domain_t *) evoasm_domains[entry.reg ## reg_idx ##_domain_idx]; \
      evoasm_param_val_t param_val = evoasm_domain_rand_(domain, prng); \
      evoasm_x64_basic_params_set_(params_ptr, EVOASM_X64_BASIC_PARAM_REG ## reg_idx, param_val); \
    }

//    assert(new_inst_id != EVOASM_X64_INST_VTESTPD_XMM_XMMM128);


    EVOASM_DEME_LOCAL_SEARCH_INST_X64_SET_REG_PARAM(0)
    EVOASM_DEME_LOCAL_SEARCH_INST_X64_SET_REG_PARAM(1)
    EVOASM_DEME_LOCAL_SEARCH_INST_X64_SET_REG_PARAM(2)
    EVOASM_DEME_LOCAL_SEARCH_INST_X64_SET_REG_PARAM(3)

#undef EVOASM_DEME_LOCAL_SEARCH_INST_X64_SET_REG_PARAM

    EVOASM_TRY(error, evoasm_deme_local_search_run_and_eval, deme, kernel_idx, &undo);

    if(undo) {
      params_ptr->imm0 = old_imm;
      *inst_id_ptr = old_inst_id;
    }
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_local_search_kernel_param_x64(evoasm_deme_t *deme, size_t kernel_idx, evoasm_inst_id_t *inst_id_ptr,
                                          evoasm_x64_basic_params_t *params_ptr) {

  evoasm_prng_t *prng = &deme->prng;
  evoasm_x64_inst_id_t inst_id = (evoasm_x64_inst_id_t) *inst_id_ptr;
  size_t inst_idx = deme->inst_idx_mapping[inst_id];

  assert(deme->params->inst_ids[inst_idx] == inst_id);

  if(evoasm_bitmap_get_(deme->imm_insts_bitmap, inst_idx)) {
    float r = evoasm_prng_randf_(prng);
    if(r < 0.6) {
      EVOASM_TRY(error, evoasm_deme_local_search_imm_operand_x64, deme, kernel_idx, params_ptr, inst_idx);
    } else {
      goto change_inst;
    }
  } else {
change_inst:
    EVOASM_TRY(error, evoasm_deme_local_search_inst_x64, deme, kernel_idx, inst_id_ptr, params_ptr, inst_idx);
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_deme_local_search_kernel(evoasm_deme_t *deme, size_t kernel_idx) {
  evoasm_deme_kernels_t *kernels = &deme->kernels;
  size_t iters = deme->params->n_local_search_iters;
  size_t kernel_size = deme->kernels.sizes[kernel_idx];
  evoasm_prng_t *prng = &deme->prng;

  for(size_t i = 0; i < iters; i++) {
    size_t inst_idx = (size_t) evoasm_prng_rand_between_(prng, 0, (int64_t) kernel_size);
    size_t inst_off = evoasm_deme_kernels_get_inst_off(kernels, kernel_idx, inst_idx);
    evoasm_inst_id_t *insts_ptr = &kernels->insts[inst_off];

    switch(deme->arch_id) {
      case EVOASM_ARCH_X64: {
        evoasm_x64_basic_params_t *params_ptr = &kernels->params.x64[inst_off];
        EVOASM_TRY(error, evoasm_deme_local_search_kernel_param_x64, deme, kernel_idx, insts_ptr, params_ptr);
        break;
      }
      default:
        evoasm_assert_not_reached();
    }


  }

  return true;

error:
  return false;
}


static void
evoasm_deme_reproduce(evoasm_deme_t *deme) {
  size_t deme_size = deme->params->deme_size;
  size_t dead_idx = 0;
  size_t surviv_idx = 0;

  while(true) {
    while(surviv_idx < deme_size && deme->won_tourns_counters[surviv_idx] <= 1) surviv_idx++;
    if(surviv_idx >= deme_size) break;

    while(dead_idx < deme_size && deme->won_tourns_counters[dead_idx] != 0) dead_idx++;

    // This check should not be necessary, mathematically,
    // for each survivor there must be a corresponding dead
    // as we only let individuals survive if they won > 1 tournaments and there
    // are < deme_size tournaments in total
    // just to be sure let's add an assert
    //    if(dead_idx >= deme_size) break;
    assert(dead_idx < deme_size);

    evoasm_deme_copy_kernel(deme, surviv_idx, dead_idx);
    evoasm_deme_mutate_kernel(deme, dead_idx);

    deme->won_tourns_counters[surviv_idx]--;
    dead_idx++;
  }

  // store immigration target indexes
  {

    while(dead_idx < deme_size && deme->won_tourns_counters[dead_idx] != 0) dead_idx++;
    size_t j = 0;
    for(size_t i = dead_idx; i < deme_size; i++) {
      if(deme->won_tourns_counters[i] == 0) {
        deme->immig_idxs[j++] = (uint16_t) i;
      }
    }
    assert(j == deme->params->n_demes);
  }

}

//static void evoasm_used
//evoasm_deme_crossover(evoasm_deme_t *deme) {
//  size_t n_doomed = EVOASM_ALIGN_DOWN(deme->n_doomed_indivs, 2u);
//  for(size_t i = 0; i < n_doomed; i += 2) {
//    size_t parent_indiv1_idx = deme->blessed_indiv_idxs[i % deme->n_blessed_indivs];
//    size_t parent_indiv2_idx = deme->blessed_indiv_idxs[(i + 1) % deme->n_blessed_indivs];
//
//    size_t child_indiv1_idx = deme->doomed_indiv_idxs[i];
//    size_t child_indiv2_idx = deme->doomed_indiv_idxs[i + 1];
//
//    evoasm_deme_crossover_indivs(deme, parent_indiv1_idx, parent_indiv2_idx, child_indiv1_idx, child_indiv2_idx);
//  }
//}

static int evoasm_pop_loss_cmp_func(const void *a, const void *b) {
  evoasm_loss_t loss_a = *(const evoasm_loss_t *) a;
  evoasm_loss_t loss_b = *(const evoasm_loss_t *) b;
  return (loss_a > loss_b) - (loss_a < loss_b);
}

#define EVOASM_POP_SUMMARY_LEN 5u

static inline void
evoasm_deme_calc_summary(evoasm_deme_t *deme, evoasm_loss_t *summary_losses, evoasm_loss_t *summary) {
  size_t deme_size = deme->params->deme_size;
  evoasm_deme_losses_t *losses = &deme->losses;

  for(size_t j = 0; j < deme_size; j++) {
    evoasm_loss_t loss = losses->losses[j];
    summary_losses[j] = loss;
  }

  qsort(summary_losses, deme_size, sizeof(evoasm_loss_t), evoasm_pop_loss_cmp_func);

  for(size_t j = 0; j < EVOASM_POP_SUMMARY_LEN; j++) {
    summary[j] = summary_losses[j * (deme_size - 1) / 4];
  }
}

size_t
evoasm_pop_summary_len(evoasm_pop_t *pop) {
  return pop->n_demes * EVOASM_POP_SUMMARY_LEN;
}

evoasm_success_t
evoasm_pop_calc_summary(evoasm_pop_t *pop, evoasm_loss_t *summary) {
  if(pop->summary_losses == NULL) {
    pop->summary_losses = evoasm_calloc(pop->params->deme_size, sizeof(evoasm_loss_t));
    if(!pop->summary_losses) {
      return false;
    }
  }

  for(size_t i = 0; i < pop->n_demes; i++) {
    evoasm_deme_calc_summary(&pop->demes[i], pop->summary_losses, &summary[i * EVOASM_POP_SUMMARY_LEN]);
  }

  return true;
}

static bool
evoasm_deme_local_search(evoasm_deme_t *deme) {
  if(deme->params->n_local_search_iters == 0 || deme->pop->gen_counter < 2 * deme->params->n_minor_gens) {
    return true;
  }

  for(size_t i = 0; i < deme->params->deme_size; i++) {
    EVOASM_TRY(error, evoasm_deme_local_search_kernel, deme, i);
  }

  return true;

error:
  return false;
}

static void
evoasm_deme_inject_best(evoasm_deme_t *deme, evoasm_deme_t *src_deme) {
  size_t dead_kernel_idx = deme->immig_idxs[src_deme->idx];
  evoasm_deme_kernels_copy(&src_deme->best_kernels, 0, &deme->kernels, dead_kernel_idx,
                           src_deme->best_kernels.n_kernels);
}

static void
evoasm_deme_save_elite(evoasm_deme_t *deme) {
  evoasm_deme_inject_best(deme, deme);
}

static void
evoasm_deme_immigrate_elite(evoasm_deme_t *deme) {
  evoasm_deme_t *demes = deme->pop->demes;
  size_t demes_len = deme->params->n_demes;

  for(size_t i = 0; i < demes_len; i++) {
    evoasm_deme_t *immigration_deme = &demes[i];

    if(deme != immigration_deme) {
      evoasm_deme_inject_best(deme, immigration_deme);
    }

  }
}

static evoasm_success_t
evoasm_deme_next_gen(evoasm_deme_t *deme, bool major) {
  if(evoasm_deme_select(deme)) {

    if(major) {
      evoasm_deme_save_elite(deme);
      evoasm_deme_immigrate_elite(deme);
    }

    evoasm_deme_reproduce(deme);
    EVOASM_TRY(error, evoasm_deme_local_search, deme);
  } else {
    evoasm_log_info("reseeding deme %d", deme->idx);
    evoasm_deme_seed(deme, NULL);
  }

  return true;

error:
  return false;
}

static evoasm_success_t
evoasm_pop_next_gen_major(evoasm_pop_t *pop) {
  bool retval = true;
  size_t n_demes = pop->params->n_demes;
  bool *retvals = evoasm_alloca(sizeof(bool) * n_demes);
  evoasm_error_t *errors = evoasm_alloca(sizeof(evoasm_error_t) * n_demes);

#pragma omp parallel for
  for(size_t i = 0; i < pop->n_demes; i++) {
    retvals[i] = evoasm_deme_next_gen(&pop->demes[i], true);
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

  pop->gen_counter++;

  return retval;
}

evoasm_success_t
evoasm_pop_next_gen(evoasm_pop_t *pop) {
  return evoasm_pop_next_gen_major(pop);
}

static evoasm_success_t
evoasm_pop_run_minor_gens(evoasm_pop_t *pop) {

  bool retval = true;
  size_t n_demes = pop->params->n_demes;
  bool *retvals = evoasm_alloca(sizeof(bool) * n_demes);
  evoasm_error_t *errors = evoasm_alloca(sizeof(evoasm_error_t) * n_demes);
  size_t n_minor_gens = pop->params->n_minor_gens;

#pragma omp parallel for
  for(size_t i = 0; i < pop->n_demes; i++) {
    evoasm_deme_t *deme = &pop->demes[i];

    for(size_t j = 0; j < n_minor_gens; j++) {
      retvals[i] = evoasm_deme_eval(deme, false);
      if(!retvals[i]) {
        errors[i] = *evoasm_get_last_error();
        break;
      }
      retvals[i] = evoasm_deme_next_gen(&pop->demes[i], false);
      if(!retvals[i]) {
        errors[i] = *evoasm_get_last_error();
        break;
      }
    }
  }

  for(size_t i = 0; i < n_demes; i++) {
    if(!retvals[i]) {
      evoasm_set_last_error(&errors[i]);
      retval = false;
      break;
    }
  }

  pop->gen_counter = (uint16_t) (pop->gen_counter + n_minor_gens);

  return retval;
}

evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop) {

  if(!pop->seeded) {
    evoasm_error(EVOASM_ERROR_TYPE_POP, EVOASM_ERROR_CODE_NONE,
                 "not seeded");
    goto error;
  }

  if(pop->gen_counter > 0) {
    EVOASM_TRY(error, evoasm_pop_run_minor_gens, pop);
  }

  EVOASM_TRY(error, evoasm_pop_run_major_gen, pop);
  return true;

error:
  return false;
}

EVOASM_DEF_ALLOC_FREE_FUNCS(pop)
