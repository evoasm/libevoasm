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


static evoasm_success_t
evoasm_pop_thread_data_destroy(evoasm_pop_thread_data_t *thread_data) {
  bool retval = true;

  if(!evoasm_program_destroy(&thread_data->program)) retval = false;
  evoasm_prng_destroy(&thread_data->prng);

  return retval;
}

evoasm_success_t
evoasm_pop_destroy(evoasm_pop_t *pop) {
  bool retval = true;

  evoasm_free(pop->indivs);
  evoasm_free(pop->losses);
  evoasm_free(pop->error_counters);
  evoasm_free(pop->domains);
  for(int i = 0; i < pop->max_threads; i++) {
    retval &= evoasm_pop_thread_data_destroy(&pop->thread_data[i]);
  }
  evoasm_free(pop->thread_data);

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

  return true;

error:
  return false;
}

evoasm_success_t
evoasm_pop_init_domains(evoasm_pop_t *pop) {
  unsigned i, j, k;
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
      inst_domain->type = EVOASM_N_DOMAIN_TYPES;
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
  evoasm_error(EVOASM_ERROR_TYPE_ARG, EVOASM_N_ERROR_CODES,
               NULL, "Empty domain");
  return false;
}

evoasm_success_t
evoasm_pop_init(evoasm_pop_t *pop,
                evoasm_arch_id_t arch_id,
                evoasm_pop_params_t *params) {
  int max_threads;
  static evoasm_pop_t zero_pop = {0};
  unsigned n_kernels_total;
  unsigned n_teams_total;
  unsigned n_members_total;
  evoasm_kernel_count_t kernel_count;
  evoasm_prng_t seed_prng;
  evoasm_pop_teams_data_t *team_data = &pop->teams_data;
  unsigned n_examples = EVOASM_PROGRAM_INPUT_N_EXAMPLES(params->program_input);

  *pop = zero_pop;
  pop->params = params;
  pop->n_examples = n_examples;

  evoasm_prng_init(&seed_prng, &params->seed);

#ifdef _OPENMP
  max_threads = omp_get_max_threads();
#else
  max_threads = 1;
#endif

  n_kernels_total = 1;
  kernel_count = 1;

  {
    unsigned team_len = 1;
    unsigned team_off = 0;
    unsigned member_off = 0;
    for(unsigned i = 0; i < params->depth; i++) {
      team_data->kernels_per_member[params->depth - 1 - i] = kernel_count;
      kernel_count *= params->max_team_sizes[params->depth - 1 - i];

      team_data->team_offs[i] = team_off;
      team_data->members_offs[i] = member_off;

      n_kernels_total *= params->deme_sizes[i] * params->max_team_sizes[i];
      team_len *= params->deme_sizes[i];
      team_data->team_lens[i] = team_len;
      team_off += team_len;
      team_len *= params->max_team_sizes[i];
      member_off += team_len;
    }
    n_teams_total = team_off;
    n_members_total = member_off;
  }
  n_kernels_total *= params->deme_sizes[params->depth];


  EVOASM_TRY(error, evoasm_pop_init_domains, pop);

  pop->arch_info = evoasm_get_arch_info(arch_id);
  pop->max_threads = max_threads;

  {
    unsigned n_insts = n_kernels_total * params->max_kernel_size;
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernels_data.insts, EVOASM_CACHE_LINE_SIZE, n_insts,
                     sizeof(evoasm_inst_id_t));

    switch(arch_id) {
      case EVOASM_ARCH_X64:
        EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernels_data.params.x64, EVOASM_CACHE_LINE_SIZE, n_insts,
                         sizeof(evoasm_x64_basic_params_t));
        break;
      default:
        evoasm_assert_not_reached();
    }

    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernels_data.sizes, EVOASM_CACHE_LINE_SIZE, n_kernels_total,
                     sizeof(evoasm_kernel_size_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->kernels_data.losses, EVOASM_CACHE_LINE_SIZE, n_kernels_total,
                     sizeof(evoasm_loss_t));
    pop->kernels_data.len = n_kernels_total;
  }

  {
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->teams_data.member_idxs, EVOASM_CACHE_LINE_SIZE, n_members_total,
                     sizeof(evoasm_deme_size_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->teams_data.alt_succ_idxs, EVOASM_CACHE_LINE_SIZE, n_members_total,
                     sizeof(evoasm_team_size_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->teams_data.jmp_selectors, EVOASM_CACHE_LINE_SIZE, n_members_total,
                     sizeof(uint8_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->teams_data.losses, EVOASM_CACHE_LINE_SIZE, n_teams_total,
                     sizeof(evoasm_loss_t));
    EVOASM_TRY_ALLOC(error, aligned_calloc, pop->teams_data.sizes, EVOASM_CACHE_LINE_SIZE, n_teams_total,
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
               kernel_count,
               params->max_kernel_size,
               params->recur_limit);
  }

  pop->best_loss = INFINITY;
  pop->best_indiv_idx = UINT32_MAX;

  EVOASM_TRY_ALLOC(error, calloc, pop->error_counters, n_examples, sizeof(uint64_t));
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
    if(domain->type < EVOASM_N_DOMAIN_TYPES) {
      evoasm_x64_param_id_t param_id = (evoasm_x64_param_id_t) pop->params->param_ids[i];
      evoasm_param_val_t param_val;

      param_val = (evoasm_param_val_t) evoasm_domain_rand(domain, prng);
      _evoasm_x64_basic_params_set(params_ptr, param_id, param_val);
    }
  }
}

static void
evoasm_pop_seed_kernel(evoasm_pop_t *pop,
                       unsigned idx,
                       int tid) {
  unsigned i;

  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_pop_params_t *params = pop->params;
  evoasm_pop_kernels_data_t *kernels_data = &pop->kernels_data;

  evoasm_kernel_size_t kernel_size =
      (evoasm_kernel_size_t) _evoasm_prng_rand_between(prng,
                                                       params->min_kernel_size,
                                                       params->max_kernel_size);

  assert(kernel_size > 0);

  unsigned base_inst_idx = idx * params->max_kernel_size
  kernels_data->sizes[idx] = kernel_size;

  for(i = 0; i < kernel_size; i++) {
    unsigned inst_idx = base_inst_idx + i;
    evoasm_inst_id_t *inst_id_ptr = &kernels_data->insts[inst_idx];

    switch(pop->arch_info->id) {
      case EVOASM_ARCH_X64: {
        evoasm_x64_basic_params_t *params_ptr = &kernels_data->params.x64[inst_idx];
        evoasm_pop_seed_kernel_param_x64(pop, inst_id_ptr, params_ptr, prng);
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
                     unsigned team_idx,
                     int tid) {
  unsigned i;
  evoasm_pop_teams_data_t *teams_data = &pop->teams_data;
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  evoasm_pop_params_t *params = pop->params;
  evoasm_team_size_t min_program_size = params->min_team_sizes[depth];
  evoasm_team_size_t max_program_size = params->max_team_sizes[depth];
  evoasm_team_size_t team_size = (evoasm_team_size_t) _evoasm_prng_rand_between(prng,
                                                                                   min_program_size,
                                                                                   max_program_size);

  unsigned deme_size = params->deme_sizes[depth + 1];
  teams_data->sizes[pop->teams_data.team_offs[depth] + team_idx] = team_size;

  unsigned base_team_pos_idx = teams_data->members_offs[depth] + team_idx * max_program_size;

  for(i = 0; i < team_size; i++) {
    unsigned team_pos_idx = base_team_pos_idx + i;

    teams_data->jmp_selectors[team_pos_idx] = (uint8_t) _evoasm_prng_rand8(prng);
    teams_data->alt_succ_idxs[team_pos_idx] = (evoasm_team_size_t) _evoasm_prng_rand_between(prng, 0, deme_size);
    teams_data->member_idxs[team_pos_idx] = (evoasm_deme_size_t) _evoasm_prng_rand_between(prng, 0, deme_size);
  }
}

static void
evoasm_pop_seed_kernels(evoasm_pop_t *pop) {
#pragma omp parallel for
  for(unsigned i = 0; i < pop->kernels_data.len; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif
    evoasm_pop_seed_kernel(pop, i, tid);
  }
}

static void
evoasm_pop_seed_teams(evoasm_pop_t *pop, unsigned depth) {

#pragma omp parallel for
  for(unsigned i = 0; i < pop->teams_data.team_lens[depth]; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif
    evoasm_pop_seed_team(pop, depth, i, tid);
  }
}

evoasm_success_t
evoasm_pop_seed(evoasm_pop_t *pop) {

  for(unsigned i = 0; i < pop->params->depth; i++) {
    evoasm_pop_seed_teams(pop, i);
  }

  evoasm_pop_seed_kernels(pop);

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
                        unsigned depth, unsigned team_idx) {

  evoasm_pop_teams_data_t *teams_data = &pop->teams_data;
  evoasm_pop_kernels_data_t *kernels_data = &pop->kernels_data;

  evoasm_team_size_t team_size = teams_data->sizes[pop->teams_data.team_offs[depth] + team_idx];

  unsigned team_pos_idx = team_idx * pop->params->max_team_sizes[depth];
  evoasm_deme_size_t *member_idxs = &teams_data->member_idxs[pop->teams_data.members_offs[depth] + team_pos_idx];
  evoasm_team_size_t *alt_succ_idxs = &team_layer->alt_succ_idxs[team_pos_idx];
  uint8_t *jmp_selectors = &team_layer->jmp_selectors[team_pos_idx];
  evoasm_deme_size_t deme_size = pop->params->deme_sizes[depth + 1];

  unsigned base_member_idx = team_pos_idx * deme_size;
  unsigned base_kernel_idx = team_pos_idx * team_layer->kernels_per_member;

  for(unsigned i = 0; i < team_size; i++) {
    /** NOTE: member_idxs[] contains deme indexes not layer indexes */
    unsigned member_idx = base_member_idx + i * deme_size + member_idxs[i];
    unsigned kernel_idx = base_kernel_idx + i * team_layer->kernels_per_member;

    assert(member_idx < team_layer->len);

    if(depth < pop->params->depth - 1) {
      evoasm_pop_load_program(pop, program, depth + 1, member_idx);
    } else {
      assert(kernel_idx < program->kernel_count);
      unsigned inst_idx = member_idx * pop->params->max_kernel_size;

      program->kernels[kernel_idx].insts = &kernel_layer->insts[inst_idx];

      switch(pop->arch_info->id) {
        case EVOASM_ARCH_X64:
          program->kernels[kernel_idx].params.x64 = &kernel_layer->params.x64[inst_idx];
          break;
        default:
          evoasm_assert_not_reached();
      }
    }

    program->alt_succ_idxs[kernel_idx] = alt_succ_idxs[i];
    program->jmp_selectors[kernel_idx] = jmp_selectors[i];
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
evoasm_pop_update_loss(evoasm_pop_t *pop, evoasm_loss_t loss, unsigned depth, unsigned team_idx) {

  evoasm_pop_teams_data_t *team_layer = &pop->teams_data[depth];
  evoasm_team_size_t team_size = team_layer->sizes[team_idx];
  evoasm_deme_size_t deme_size = pop->params->deme_sizes[depth + 1];
  unsigned team_pos_idx = team_idx * pop->params->max_team_sizes[depth];
  unsigned base_member_idx = team_pos_idx * deme_size;
  evoasm_deme_size_t *member_idxs = &team_layer->member_idxs[team_pos_idx];
  evoasm_loss_t member_loss = loss / team_size;

  team_layer->losses[team_idx] = loss;

  for(unsigned i = 0; i < team_size; i++) {
    unsigned member_idx = base_member_idx + i * deme_size + member_idxs[i];

    if(depth < pop->params->depth - 1) {
      evoasm_pop_update_loss(pop, member_loss, depth + 1, member_idx);
    } else {
      evoasm_pop_kernels_data_t *kernel_layer = &pop->kernels_data;
      kernel_layer->losses[member_idx] = member_loss;
    }
  }
}

static evoasm_success_t
evoasm_pop_eval_team(evoasm_pop_t *pop, unsigned depth, unsigned team_idx, int tid) {
  evoasm_program_t *program = &pop->thread_data[tid].program;
  evoasm_pop_teams_data_t *team_layer = &pop->teams_data[depth];
  evoasm_loss_t loss;

  evoasm_pop_load_program(pop, program, depth, team_idx);
  EVOASM_TRY(error, evoasm_pop_eval_program, pop, program, &loss);

  evoasm_log_debug("team %d has loss %lf", team_idx, loss);

  evoasm_pop_update_loss(pop, loss, depth, team_idx);

  return true;
error:
  return false;
}

static evoasm_success_t
evoasm_pop_eval_(evoasm_pop_t *pop) {
#pragma omp parallel for
  for(unsigned i = 0; i < pop->params->deme_sizes[0]; i++) {
    int tid;
#ifdef _OPENMP
    tid = omp_get_thread_num();
#else
    tid = 1;
#endif

    unsigned team_idx = i;

    evoasm_pop_eval_team(pop, 0, team_idx, tid);
  }
}

evoasm_success_t
evoasm_pop_eval(evoasm_pop_t *pop, evoasm_loss_t max_loss) {
  bool retval;
  uint32_t n_examples = pop->n_examples;

  if(!pop->seeded) {
    retval = false;
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_N_ERROR_CODES,
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

  retval = true;

done:
  if(!evoasm_pop_eval_cleanup(pop)) {
    retval = false;
  }
  return retval;
}

static void
evoasm_pop_select(evoasm_pop_t *pop, unsigned depth, uint32_t *idxs, unsigned n_idxs, unsigned tid) {
  evoasm_prng_t *prng = &pop->thread_data[tid].prng;
  uint32_t n = 0;
  unsigned i;

  while(true) {
    for(i = 0; i < pop->params->deme_sizes[depth]; i++) {
      uint32_t r = _evoasm_prng_rand32(prng);
      if(n >= n_idxs) goto done;
      if(r < UINT32_MAX * ((pop->best_loss + 1.0) / (pop->losses[i] + 1.0))) {
        idxs[n++] = i;
      }
    }
  }
done:;
}

static evoasm_success_t
evoasm_pop_combine_parents(evoasm_pop_t *pop, uint32_t *parents) {
  unsigned i;

  for(i = 0; i < pop->params->size; i += 2) {
    evoasm_indiv_t *parent_a_ = evoasm_pop_get_indiv(pop, parents[i]);
    evoasm_indiv_t *parent_a = evoasm_pop_indiv_(pop, 0, pop->swap_indivs);
    evoasm_indiv_t *parent_b_ = evoasm_pop_get_indiv(pop, parents[i + 1]);
    evoasm_indiv_t *parent_b = evoasm_pop_indiv_(pop, 1, pop->swap_indivs);

    // save parents into swap space
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
evoasm_pop_get_loss(evoasm_pop_t *pop, unsigned *n_inf, bool per_example) {
  unsigned i;
  double scale = 1.0 / pop->params->size;
  double pop_loss = 0.0;
  *n_inf = 0;
  for(i = 0; i < pop->params->size; i++) {
    double loss = pop->losses[i];
    if(loss != INFINITY) {
      pop_loss += scale * loss;
    } else {
      (*n_inf)++;
    }
  }

  if(per_example) pop_loss /= pop->n_examples;

  return pop_loss;
}

evoasm_success_t
evoasm_pop_next_gen(evoasm_pop_t *pop) {
  uint32_t *parents = alloca(pop->params->size * sizeof(uint32_t));
  evoasm_pop_select(pop, parents, pop->params->size);

#if 0
  {
    double scale = 1.0 / pop->params->kernel_count;
    double pop_loss = 0.0;
    unsigned n_inf = 0;
    for(i = 0; i < pop->params->kernel_count; i++) {
      double loss = pop->pop.losses[parents[i]];
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
  for(i = 0; i < pop->params->kernel_count; i++) {
    evoasm_program_params_t *program_params = _EVOASM_SEARCH_PROGRAM_PARAMS(pop, pop->pop.indivs, parents[i]);
    assert(program_params->kernel_count > 0);
  }
#endif

  return evoasm_pop_combine_parents(pop, parents);
}

