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

//team_data->team_pos_count
static evoasm_success_t
evoasm_pop_team_pos_data_init(evoasm_pop_team_pos_data_t *team_pos_data, size_t count) {
  EVOASM_TRY_ALLOC(error, aligned_calloc, team_pos_data->member_idxs, EVOASM_CACHE_LINE_SIZE,
                   count,
                   sizeof(evoasm_deme_size_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, team_pos_data->member_deme_idxs, EVOASM_CACHE_LINE_SIZE,
                   count,
                   sizeof(evoasm_deme_count_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, team_pos_data->alt_succ_idxs, EVOASM_CACHE_LINE_SIZE,
                   count,
                   sizeof(evoasm_team_size_t));
  EVOASM_TRY_ALLOC(error, aligned_calloc, team_pos_data->jmp_selectors, EVOASM_CACHE_LINE_SIZE,
                   count,
                   sizeof(uint8_t));
}

static void
evoasm_pop_team_pos_data_destroy(evoasm_pop_team_pos_data_t *team_pos_data) {
  evoasm_free(team_pos_data->member_idxs);
  evoasm_free(team_pos_data->member_deme_idxs);
  evoasm_free(team_pos_data->alt_succ_idxs);
  evoasm_free(team_pos_data->jmp_selectors);
}

static evoasm_success_t
evoasm_pop_thread_data_destroy(evoasm_pop_thread_data_t *thread_data) {
  bool retval = true;

  if(!evoasm_program_destroy(&thread_data->program)) retval = false;
  evoasm_prng_destroy(&thread_data->prng);
  evoasm_free(thread_data->parent_idxs);

  evoasm_pop_team_pos_data_destroy(&thread_data->parent_team_pos_data);

  return retval;
}

evoasm_success_t
evoasm_pop_destroy(evoasm_pop_t *pop) {
  bool retval = true;

  evoasm_free(pop->indivs);
  evoasm_free(pop->error_counters);
  evoasm_free(pop->domains);

  for(int i = 0; i < pop->max_threads; i++) {
    retval &= evoasm_pop_thread_data_destroy(&pop->thread_data[i]);
  }
  evoasm_free(pop->thread_data);

  evoasm_pop_team_pos_data_destroy(&pop->team_pos_data);

  evoasm_free(pop->team_data.losses);
  evoasm_free(pop->team_data.sizes);

  evoasm_free(pop->kernel_data.losses);
  evoasm_free(pop->kernel_data.sizes);
  evoasm_free(pop->kernel_data.insts);
  evoasm_free(&pop->kernel_data.params);

  return retval;
}


static evoasm_success_t bool
evoasm_pop_thread_data_init(evoasm_pop_thread_data_t *thread_data,
                            evoasm_pop_t *pop,
                            evoasm_prng_state_t *seed,
                            evoasm_team_size_t program_size,
                            evoasm_kernel_size_t kernel_size,
                            uint32_t recur_limit) {

  evoasm_prng_init(&thread_data->prng, seed);

  EVOASM_TRY(error, evoasm_program_init, &thread_data->program,
             pop->arch_info,
             pop->params->program_input,
             program_size,
             kernel_size,
             recur_limit);

  unsigned max_deme_size = 0;
  unsigned max_team_size = 0;
  for(unsigned i = 0; i < pop->params->depth; i++) {
    max_deme_size = EVOASM_MAX(max_deme_size, pop->params->team_deme_sizes[i]);
    max_team_size = EVOASM_MAX(max_team_size, pop->params->max_team_sizes[i]);
  }
  max_deme_size = EVOASM_MAX(max_deme_size, pop->params->kernel_deme_size);

  EVOASM_TRY_ALLOC(error, calloc, thread_data->parent_idxs, max_deme_size, sizeof(evoasm_deme_size_t));
  EVOASM_TRY(error, evoasm_pop_team_pos_data_init, &thread_data->parent_team_pos_data, 2 * max_team_size);

  return true;

error:
  return false;
}

evoasm_success_t
evoasm_pop_init_domains(evoasm_pop_t *pop) {
  unsigned i, j, k;
  evoasm_domain_t cloned_domain;

  evoasm_pop_params_t *params = pop->params;

  size_t domains_len = (size_t) (params->inst_count * params->param_count);
  pop->domains = evoasm_calloc(domains_len,
                               sizeof(evoasm_domain_t));

  if(!pop->domains) goto fail;

  for(i = 0; i < params->inst_count; i++) {
    evoasm_x64_inst_t *inst = _evoasm_x64_inst(params->inst_ids[i]);
    for(j = 0; j < params->param_count; j++) {
      evoasm_domain_t *inst_domain = &pop->domains[i * params->param_count + j];
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
  evoasm_kernel_count_t program_kernel_count;
  evoasm_prng_t seed_prng;
  evoasm_pop_team_data_t *team_data = &pop->team_data;
  evoasm_pop_kernel_data_t *kernel_data = &pop->kernel_data;
  unsigned example_count = EVOASM_PROGRAM_INPUT_EXAMPLE_COUNT(params->program_input);

#ifdef _OPENMP
  max_threads = omp_get_max_threads();
#else
  max_threads = 1;
#endif

  *pop = zero_pop;
  pop->params = params;
  pop->example_count = example_count;
  pop->arch_info = evoasm_get_arch_info(arch_id);
  pop->max_threads = max_threads;

  evoasm_prng_init(&seed_prng, &params->seed);

  team_data->team_count = 0;
  team_data->team_pos_count = 0;
  program_kernel_count = 1;

  for(unsigned i = 0; i < params->depth; i++) {
    team_data->team_offs[i] = team_data->team_count;
    team_data->team_pos_offs[i] = team_data->team_pos_count;

    team_data->team_count += params->team_deme_counts[i] * params->team_deme_sizes[i];
    team_data->team_pos_count += params->team_deme_counts[i] * params->team_deme_sizes[i] * params->max_team_sizes[i];

    program_kernel_count *= params->max_team_sizes[i];
  }

  kernel_data->kernel_count = params->kernel_deme_count * params->kernel_deme_size;
  kernel_data->inst_count = kernel_data->kernel_count * params->max_kernel_size;

  EVOASM_TRY(error, evoasm_pop_init_domains, pop);

  {
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernel_data.insts, EVOASM_CACHE_LINE_SIZE, kernel_data->inst_count,
                     sizeof(evoasm_inst_id_t));

    switch(arch_id) {
      case EVOASM_ARCH_X64:
        EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernel_data.params.x64, EVOASM_CACHE_LINE_SIZE,
                         kernel_data->inst_count,
                         sizeof(evoasm_x64_basic_params_t));
        break;
      default:
        evoasm_assert_not_reached();
    }

    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernel_data.sizes, EVOASM_CACHE_LINE_SIZE, kernel_data->kernel_count,
                     sizeof(evoasm_kernel_size_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernel_data.losses, EVOASM_CACHE_LINE_SIZE,
                     kernel_data->kernel_count,
                     sizeof(evoasm_loss_t));
  }

  {
    EVOASM_TRY(error, evoasm_pop_team_pos_data_init, &pop->team_pos_data, team_data->team_pos_count);
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->team_data.losses, EVOASM_CACHE_LINE_SIZE, team_data->team_count,
                     sizeof(evoasm_loss_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->team_data.sizes, EVOASM_CACHE_LINE_SIZE, team_data->team_count,
                     sizeof(evoasm_kernel_count_t));
  }

  EVOASM_TRY_ALLOC(error, aligned_calloc, pop->thread_data, EVOASM_CACHE_LINE_SIZE, (size_t) max_threads,
                   sizeof(evoasm_pop_thread_data_t));

  for(int i = 0; i < max_threads; i++) {
    evoasm_prng_state_t seed;

    for(int j = 0; j < EVOASM_PRNG_SEED_LEN; j++) {
      seed.data[j] = _evoasm_prng_rand64(&seed_prng);
    }

    EVOASM_TRY(error, evoasm_pop_thread_data_init,
               &pop->thread_data[i],
               pop,
               &seed,
               program_kernel_count,
               params->max_kernel_size,
               params->recur_limit);
  }

  pop->best_loss = INFINITY;
  pop->best_indiv_idx = UINT32_MAX;

  EVOASM_TRY_ALLOC(error, calloc, pop->error_counters, example_count, sizeof(uint64_t));
  pop->error_counter = 0;

  return true;

error:
  evoasm_pop_destroy(pop);
  return false;
}

#if 0
static evoasm_indiv_t *
evoasm_pop_indiv_(evoasm_pop_t *pop, uint32_t idx, unsigned char *ptr) {
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
  unsigned i;

  while(true) {
    for(i = 0; i < pop->params->size; i++) {
      uint32_t r = _evoasm_prng_rand32(&pop->prng);
      if(r > UINT32_MAX * ((pop->best_loss + 1.0) / (pop->losses[i] + 1.0))) {
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

#define EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, team_idx) \
  ((pop)->team_data.team_offs[(depth)]\
        + (deme_idx) * (pop)->params->team_deme_sizes[depth]\
        + (team_idx))

#define EVOASM_POP_TEAM_POS_OFF(pop, depth, deme_idx, team_idx, team_pos_idx)\
  ((pop)->team_data.team_pos_offs[(depth)]\
         + (deme_idx) * (pop)->params->team_deme_sizes[depth]\
         + (team_idx) * (pop)->params->max_team_sizes[depth]\
         + team_pos_idx)

#define EVOASM_POP_KERNEL_OFF(pop, deme_idx, kernel_idx) \
  ((deme_idx) * (pop)->params->kernel_deme_size + (kernel_idx))

#define EVOASM_POP_INST_OFF(pop, deme_idx, kernel_idx, inst_idx) \
  ((deme_idx) * (pop)->params->kernel_deme_size\
        + (kernel_idx) * (pop)->params->max_kernel_size\
        + (inst_idx))

static void
evoasm_pop_seed_kernel_param_x64(evoasm_pop_t *pop, evoasm_inst_id_t *inst_id_ptr,
                                 evoasm_x64_basic_params_t *params_ptr,
                                 evoasm_prng_t *prng) {
  unsigned i;
  evoasm_pop_params_t *params = pop->params;
  unsigned param_count = params->param_count;

  int64_t inst_idx = _evoasm_prng_rand_between(prng, 0, params->inst_count - 1);
  evoasm_inst_id_t inst_id = params->inst_ids[inst_idx];

  *inst_id_ptr = inst_id;

  /* set parameters */
  for(i = 0; i < param_count; i++) {
    evoasm_domain_t *domain = &pop->domains[inst_idx * param_count + i];
    if(domain->type < EVOASM_DOMAIN_TYPE_NONE) {
      evoasm_x64_param_id_t param_id = (evoasm_x64_param_id_t) pop->params->param_ids[i];
      evoasm_param_val_t param_val;

      param_val = (evoasm_param_val_t) evoasm_domain_rand(domain, prng);
      _evoasm_x64_basic_params_set(params_ptr, param_id, param_val);
    }
  }
}

static void
evoasm_pop_seed_kernel(evoasm_pop_t *pop, unsigned deme_idx, unsigned kernel_idx, int tid) {
  unsigned i;

  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_pop_params_t *params = pop->params;
  evoasm_pop_kernel_data_t *kernel_data = &pop->kernel_data;

  evoasm_kernel_size_t kernel_size =
      (evoasm_kernel_size_t) _evoasm_prng_rand_between(prng,
                                                       params->min_kernel_size,
                                                       params->max_kernel_size);

  assert(kernel_size > 0);

  kernel_data->sizes[EVOASM_POP_KERNEL_OFF(pop, deme_idx, kernel_idx)] = kernel_size;

  for(i = 0; i < kernel_size; i++) {
    unsigned inst_off = EVOASM_POP_INST_OFF(pop, deme_idx, kernel_idx, i);

    evoasm_inst_id_t *insts_ptr = &kernel_data->insts[inst_off];

    switch(pop->arch_info->id) {
      case EVOASM_ARCH_X64: {
        evoasm_x64_basic_params_t *params_ptr = &kernel_data->params.x64[inst_off];
        evoasm_pop_seed_kernel_param_x64(pop, insts_ptr, params_ptr, prng);
        break;
      }
      default:
        evoasm_assert_not_reached();
    }
  }

#if 0
  kernel_params->jmp_selector = (uint8_t) _evoasm_prng_rand8(prng);
  kernel_params->alt_succ_idx = (evoasm_kernel_size_t)
      _evoasm_prng_rand_between(prng, 0, kernel_count - 1);
#endif

}

static void
evoasm_pop_seed_team(evoasm_pop_t *pop,
                     unsigned depth,
                     unsigned deme_idx,
                     unsigned team_idx,
                     int tid) {
  unsigned i;
  evoasm_pop_team_data_t *team_data = &pop->team_data;
  evoasm_pop_team_pos_data_t *team_pos_data = &pop->team_pos_data;
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_pop_params_t *params = pop->params;
  evoasm_team_size_t min_team_size = params->min_team_sizes[depth];
  evoasm_team_size_t max_team_size = params->max_team_sizes[depth];
  evoasm_team_size_t team_size = (evoasm_team_size_t) _evoasm_prng_rand_between(prng,
                                                                                min_team_size,
                                                                                max_team_size);

  unsigned deme_size = params->team_deme_sizes[depth];
  unsigned deme_count = params->team_deme_counts[depth];

  team_data->sizes[EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, team_idx)] = team_size;

  for(i = 0; i < team_size; i++) {
    unsigned team_pos_off = EVOASM_POP_TEAM_POS_OFF(pop, depth, deme_idx, team_idx, i);

    team_pos_data->jmp_selectors[team_pos_off] =
        (uint8_t) _evoasm_prng_rand8(prng);

    team_pos_data->alt_succ_idxs[team_pos_off] =
        (evoasm_team_size_t) _evoasm_prng_rand_between(prng, 0, team_size - 1);

    team_pos_data->member_idxs[team_pos_off] =
        (evoasm_deme_size_t) _evoasm_prng_rand_between(prng, 0, deme_size);

    team_pos_data->member_deme_idxs[team_pos_off] =
        (evoasm_deme_size_t) _evoasm_prng_rand_between(prng, 0, deme_count);
  }
}

evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop) {

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->depth; i++) {
    for(unsigned j = 0; j < pop->params->team_deme_counts[i]; j++) {
      int tid;
#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif

      for(unsigned k = 0; k < pop->params->team_deme_sizes[i]; k++) {
        evoasm_pop_seed_team(pop, i, j, k, tid);
      }
    }
  }

#pragma omp parallel for
  for(unsigned i = 0; i < pop->params->kernel_deme_count; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif

    for(unsigned j = 0; j < pop->params->kernel_deme_size; j++) {
      evoasm_pop_seed_kernel(pop, i, j, tid);
    }
  }

  pop->seeded = true;
  return true;
}

static evoasm_success_t
evoasm_pop_eval_prepare(evoasm_pop_t *pop) {
  evoasm_signal_install((evoasm_arch_id_t) pop->arch_info->id, 0);
  return true;
}

static evoasm_success_t
evoasm_pop_eval_cleanup(evoasm_pop_t *pop) {
  evoasm_signal_uninstall();
  return true;
}

static void
evoasm_pop_load_program(evoasm_pop_t *pop, evoasm_program_t *program,
                        unsigned depth, unsigned deme_idx, unsigned team_idx, int tid) {

  evoasm_pop_team_data_t *team_data = &pop->team_data;
  evoasm_pop_team_pos_data_t *team_pos_data = &pop->team_pos_data;
  evoasm_pop_kernel_data_t *kernel_data = &pop->kernel_data;

  unsigned team_off = EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, team_idx);

  evoasm_team_size_t team_size = team_data->sizes[team_off];

  for(unsigned i = 0; i < team_size; i++) {
    unsigned team_pos_off = EVOASM_POP_TEAM_POS_OFF(pop, depth, deme_idx, team_idx, i);

    evoasm_deme_count_t member_deme_idx = team_pos_data->member_deme_idxs[team_pos_off];
    evoasm_deme_size_t member_idx = team_pos_data->member_idxs[team_pos_off];

    if(depth < pop->params->depth) {
      evoasm_pop_load_program(pop, program, depth + 1, member_deme_idx, member_idx, tid);
    } else {
      unsigned inst_off = EVOASM_POP_INST_OFF(pop, member_deme_idx, member_deme_idx, 0u);

      program->kernels[pop->thread_data[tid].kernel_counter].insts = &kernel_data->insts[inst_off];

      switch(pop->arch_info->id) {
        case EVOASM_ARCH_X64:
          program->kernels[pop->thread_data[tid].kernel_counter].params.x64 = &kernel_data->params.x64[inst_off];
          break;
        default:
          evoasm_assert_not_reached();
      }

      pop->thread_data[tid].kernel_counter++;
    }

    program->alt_succ_idxs[pop->thread_data[tid].kernel_counter - 1] = team_pos_data->alt_succ_idxs[team_pos_off];
    program->jmp_selectors[pop->thread_data[tid].kernel_counter - 1] = team_pos_data->jmp_selectors[team_pos_off];
  }
}

static evoasm_success_t
evoasm_pop_eval_program(evoasm_pop_t *pop, evoasm_program_t *program, evoasm_loss_t *loss) {
  evoasm_kernel_t *kernel = &program->kernels[program->kernel_count - 1];
  evoasm_pop_params_t *params = pop->params;

  if(!evoasm_program_emit(program, params->program_input, true, true, true, true)) {
    *loss = INFINITY;
    return false;
  }

  if(EVOASM_UNLIKELY(kernel->output_reg_count == 0)) {
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
evoasm_pop_update_loss(evoasm_pop_t *pop, evoasm_loss_t loss, unsigned depth, unsigned deme_idx, unsigned team_idx) {

  evoasm_pop_team_data_t *team_data = &pop->team_data;
  evoasm_pop_team_pos_data_t *team_pos_data = &pop->team_pos_data;
  unsigned team_off = EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, team_idx);

  evoasm_team_size_t team_size = team_data->sizes[team_off];
  team_data->losses[team_off] = loss;
  evoasm_loss_t member_loss = loss / team_size;

  for(unsigned i = 0; i < team_size; i++) {
    unsigned team_pos_off = EVOASM_POP_TEAM_POS_OFF(pop, depth, deme_idx, team_idx, i);
    evoasm_deme_count_t member_deme_idx = team_pos_data->member_deme_idxs[team_pos_off];
    evoasm_deme_size_t member_idx = team_pos_data->member_idxs[team_pos_off];

    evoasm_pop_update_loss(pop, member_loss, depth + 1, member_deme_idx, member_idx);
  }
}

static evoasm_success_t
evoasm_pop_eval_team(evoasm_pop_t *pop, unsigned depth, unsigned deme_idx, unsigned team_idx, int tid) {

  evoasm_program_t *program = &pop->thread_data[tid].program;
  evoasm_loss_t loss;

  evoasm_pop_load_program(pop, program, depth, deme_idx, team_idx, tid);

  assert(pop->thread_data->kernel_counter == program->kernel_count);
  EVOASM_TRY(error, evoasm_pop_eval_program, pop, program, &loss);
  evoasm_log_debug("team %d has loss %lf", team_idx, loss);

  evoasm_pop_update_loss(pop, loss, depth, deme_idx, team_idx);

  return true;
error:
  return false;
}

static evoasm_success_t
evoasm_pop_eval_(evoasm_pop_t *pop) {
#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->team_deme_counts[0]; i++) {
    for(unsigned j = 0; j < pop->params->team_deme_sizes[0]; j++) {
      int tid;
#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif

      evoasm_pop_eval_team(pop, 0, i, j, tid);
    }
  }
}

static void
evoasm_pop_update_best_losses(evoasm_pop_t *pop) {

  {
    evoasm_pop_team_data_t *team_data = &pop->team_data;
#pragma omp parallel for
    for(unsigned i = 0; i < pop->params->depth; i++) {
      for(unsigned j = 0; j < pop->params->team_deme_counts[i]; j++) {
        int tid;
#ifdef _OPENMP
        tid = omp_get_thread_num();
#else
        tid = 1;
#endif

        for(unsigned k = 0; k < pop->params->team_deme_sizes[i]; k++) {
          evoasm_loss_t loss = team_data->losses[EVOASM_POP_TEAM_OFF(pop, i, j, k)];
          if(loss > team_data->best_losses[i]) {
            team_data->best_losses[i] = loss;
          }
        }
      }
    }
  }

  {
    evoasm_pop_kernel_data_t *kernel_data = &pop->kernel_data;

    for(unsigned i = 0; i < pop->params->kernel_deme_count; i++) {
      for(unsigned j = 0; j < pop->params->kernel_deme_size; j++) {
        evoasm_loss_t loss = kernel_data->losses[EVOASM_POP_KERNEL_OFF(pop, i, j)];

        if(loss > kernel_data->best_loss) {
          kernel_data->best_loss = loss;
        }
      }
    }
  }
}


evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop) {
  bool retval;
  uint32_t example_count = pop->example_count;

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

  if(!evoasm_pop_eval_(pop)) {
    retval = false;
    goto done;
  }

  evoasm_pop_update_best_losses(pop);

  retval = true;

done:
  if(!evoasm_pop_eval_cleanup(pop)) {
    retval = false;
  }
  return retval;
}


static void
evoasm_pop_select_(evoasm_pop_t *pop, evoasm_deme_size_t deme_size, evoasm_loss_t best_loss, evoasm_loss_t *losses,
                   int tid) {
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_deme_size_t *parent_idxs = pop->thread_data[tid].parent_idxs;
  uint32_t n = 0;

  while(true) {
    for(evoasm_deme_size_t i = 0; i < deme_size; i++) {
      uint32_t r = _evoasm_prng_rand32(prng);
      if(n >= deme_size) goto done;
      if(r < UINT32_MAX * ((best_loss + 1.0) / (losses[i] + 1.0))) {
        parent_idxs[n++] = i;
      }
    }
  }
done:;
}

static void
evoasm_pop_team_deme_select(evoasm_pop_t *pop, unsigned depth, unsigned deme_idx, int tid) {
  evoasm_pop_select_(pop, pop->params->team_deme_sizes[depth], pop->team_data.best_losses[depth],
                     &pop->team_data.losses[EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, 0)], tid);
}

static void
evoasm_pop_kernel_deme_select(evoasm_pop_t *pop, unsigned deme_idx, int tid) {
  evoasm_pop_select_(pop, pop->params->kernel_deme_size, pop->kernel_data.best_loss,
                     &pop->kernel_data.losses[EVOASM_POP_KERNEL_OFF(pop, deme_idx, 0)], tid);
}

static void
evoasm_pop_team_pos_data_copy(evoasm_pop_team_pos_data_t *team_pos_data_dst,
                              size_t off_dst,
                              evoasm_pop_team_pos_data_t *team_pos_data_src,
                              size_t off_src,
                              size_t len) {

  memcpy(team_pos_data_dst->member_idxs + off_dst, team_pos_data_src->member_idxs + off_src,
         sizeof(evoasm_deme_size_t) * len);
  memcpy(team_pos_data_dst->member_deme_idxs + off_dst, team_pos_data_src->member_deme_idxs + off_src,
         sizeof(evoasm_deme_count_t) * len);
  memcpy(team_pos_data_dst->alt_succ_idxs + off_dst, team_pos_data_src->alt_succ_idxs + off_src,
         sizeof(evoasm_team_size_t) * len);
  memcpy(team_pos_data_dst->jmp_selectors + off_dst, team_pos_data_src->jmp_selectors + off_src,
         sizeof(uint8_t) * len);
}

static void
evoasm_pop_combine_kernel_deme(evoasm_pop_t *pop, unsigned deme_idx, int tid) {

}

static void
evoasm_pop_combine_team_deme(evoasm_pop_t *pop, unsigned depth, unsigned deme_idx, int tid) {
  evoasm_pop_team_data_t *team_data = &pop->team_data;
  evoasm_pop_team_pos_data_t *team_pos_data = &pop->team_pos_data;
  evoasm_pop_thread_data_t *thread_data = &pop->thread_data[tid];
  evoasm_prng_t *prng = &thread_data->prng;

  for(unsigned i = 0; i < pop->params->team_deme_sizes[depth]; i += 2) {
    unsigned parent_team_idxs[2] = {thread_data->parent_idxs[i], thread_data->parent_idxs[i + 1]};
    unsigned parent_team_offs[2] = {EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, parent_team_idxs[0]),
                                    EVOASM_POP_TEAM_OFF(pop, depth, deme_idx, parent_team_idxs[1])};

    evoasm_team_size_t parent_team_sizes[2] = {team_data->sizes[parent_team_offs[0]],
                                               team_data->sizes[parent_team_offs[1]]};

    if(parent_team_sizes[0] < parent_team_sizes[1]) {
      EVOASM_SWAP(unsigned, parent_team_idxs[0], parent_team_idxs[1]);
      EVOASM_SWAP(unsigned, parent_team_offs[0], parent_team_offs[1]);
      EVOASM_SWAP(evoasm_team_size_t, parent_team_sizes[0], parent_team_sizes[1]);
    }

    evoasm_loss_t parent_team_losses[2] = {team_data->losses[parent_team_offs[0]],
                                           team_data->losses[parent_team_offs[1]]};

    /* save parents to local storage, we override originals with children */
    for(unsigned j = 0; j < 2; j++) {
      unsigned team_pos_off = EVOASM_POP_TEAM_POS_OFF(pop, depth, deme_idx, parent_team_idxs[j], 0);
      unsigned parent_off = j * parent_team_sizes[0];
      evoasm_team_size_t parent_team_size = parent_team_sizes[j];

      evoasm_pop_team_pos_data_copy(&thread_data->parent_team_pos_data, parent_off, team_pos_data, team_pos_off,
                                    parent_team_size);
    }

    /* rough estimate */
    evoasm_loss_t child_team_loss = 0.5 * (parent_team_losses[0] + parent_team_losses[1]);

    for(unsigned child_idx = 0; child_idx < 2; child_idx++) {
      evoasm_team_size_t child_team_size = (evoasm_kernel_size_t)
          _evoasm_prng_rand_between(prng, parent_team_sizes[0], parent_team_sizes[1]);

      assert(child_team_size > 0);

      /* offset for shorter parent */
      unsigned crossover_point = (unsigned) _evoasm_prng_rand_between(prng,
                                                                      0, child_team_size - parent_team_sizes[1]);
      unsigned crossover_len = (unsigned) _evoasm_prng_rand_between(prng,
                                                                    0, parent_team_sizes[1]);

      unsigned child_team_pos0_off = EVOASM_POP_TEAM_POS_OFF(pop, depth, deme_idx, parent_team_idxs[child_idx],
                                                             0);

      evoasm_pop_team_pos_data_copy(team_pos_data, child_team_pos0_off, &thread_data->parent_team_pos_data, 0,
                                    crossover_point);
      evoasm_pop_team_pos_data_copy(team_pos_data, child_team_pos0_off + crossover_point,
                                    &thread_data->parent_team_pos_data, parent_team_sizes[0] + crossover_point,
                                    crossover_len);
      evoasm_pop_team_pos_data_copy(team_pos_data, child_team_pos0_off + crossover_point + crossover_len,
                                    &thread_data->parent_team_pos_data, crossover_point + crossover_len,
                                    child_team_size - crossover_point - crossover_len);

      team_data->sizes[parent_team_offs[child_idx]] = child_team_size;
      team_data->losses[parent_team_offs[child_idx]] = child_team_loss;
    }

  }
}

static evoasm_success_t
evoasm_pop_combine_(evoasm_pop_t *pop) {
  unsigned i;

  for(i = 0; i < pop->params->size; i += 2) {
    evoasm_indiv_t *parent_a_ = evoasm_pop_get_indiv(pop, parents[i]);
    evoasm_indiv_t *parent_a = evoasm_pop_indiv_(pop, 0, pop->swap_indivs);
    evoasm_indiv_t *parent_b_ = evoasm_pop_get_indiv(pop, parents[i + 1]);
    evoasm_indiv_t *parent_b = evoasm_pop_indiv_(pop, 1, pop->swap_indivs);

    // save parent_idxs into swap space
    memcpy(parent_a, parent_a_, pop->kernel_size);
    memcpy(parent_b, parent_b_, pop->kernel_size);

    evoasm_indiv_t *child_a = parent_a_;
    evoasm_indiv_t *child_b = parent_b_;

    if(!pop->impl->crossover_func(pop, parent_a, parent_b, child_a, child_b)) {
      return false;
    }
  }

  return true;
}

evoasm_loss_t
evoasm_pop_get_loss(evoasm_pop_t *pop, unsigned *inf_count, bool per_example) {
  unsigned i;
  double scale = 1.0 / pop->params->size;
  double pop_loss = 0.0;
  *inf_count = 0;
  for(i = 0; i < pop->params->size; i++) {
    double loss = pop->losses[i];
    if(loss != INFINITY) {
      pop_loss += scale * loss;
    } else {
      (*inf_count)++;
    }
  }

  if(per_example) pop_loss /= pop->example_count;

  return pop_loss;
}

static void
evoasm_pop_team_deme_next_gen(evoasm_pop_t *pop, unsigned depth, unsigned deme_idx, int tid) {
  evoasm_pop_team_deme_select(pop, depth, deme_idx, tid);

}

static void
evoasm_pop_kernel_deme_next_gen(evoasm_pop_t *pop, unsigned deme_idx, int tid) {
  evoasm_pop_kernel_deme_select(pop, deme_idx, tid);
}

evoasm_success_t
evoasm_pop_next_gen(evoasm_pop_t *pop) {

#pragma omp parallel for collapse(2)
  for(unsigned i = 0; i < pop->params->depth; i++) {
    for(unsigned j = 0; j < pop->params->team_deme_counts[i]; j++) {
      int tid;
#ifdef _OPENMP
      tid = omp_get_thread_num();
#else
      tid = 1;
#endif

      evoasm_pop_team_deme_next_gen(pop, i, j, tid);
    }
  }

#pragma omp parallel for
  for(unsigned i = 0; i < pop->params->kernel_deme_count; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif
    evoasm_pop_kernel_deme_next_gen(pop, i, tid);
  }

  return true;
}


#if 0

evoasm_pop_select(pop, parent_idxs, pop->params->size);
  {
    double scale = 1.0 / pop->params->kernel_count;
    double pop_loss = 0.0;
    unsigned inf_count = 0;
    for(i = 0; i < pop->params->kernel_count; i++) {
      double loss = pop->pop.losses[parent_idxs[i]];
      if(loss != INFINITY) {
        pop_loss += scale * loss;
      }
      else {
        inf_count++;
      }
    }

    evoasm_log_info("pop selected loss: %g/%u", pop_loss, inf_count);
  }

  unsigned i;
  for(i = 0; i < pop->params->kernel_count; i++) {
    evoasm_program_params_t *program_params = _EVOASM_SEARCH_PROGRAM_PARAMS(pop, pop->pop.indivs, parent_idxs[i]);
    assert(program_params->kernel_count > 0);
  }

  return evoasm_pop_combine_parents(pop, parent_idxs);
}
#endif


