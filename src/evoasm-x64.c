#include "evoasm-x64.h"

static const char *_evoasm_log_tag = "x64";

uint8_t evoasm_x64_reg_type_sizes[EVOASM_X64_N_REG_TYPES] = {0};

static int64_t
evoasm_x64_disp_size(evoasm_x64_t *x64, evoasm_arch_param_val_t *param_vals, evoasm_bitmap_t *set_params) {
  evoasm_arch_param_val_t val = param_vals[EVOASM_X64_PARAM_DISP];
  if(!evoasm_bitmap_get(set_params, EVOASM_X64_PARAM_DISP)) return 0;
  if(val >= INT8_MIN && val <= INT8_MAX) return 8;
  if(val >= INT32_MIN && val <= INT32_MAX) return 32;
  return 0;
}

static evoasm_x64_reg_id_t evoasm_x64_sysv_callee_save_regs[] = {
    EVOASM_X64_REG_BP,
    EVOASM_X64_REG_B,
    EVOASM_X64_REG_12,
    EVOASM_X64_REG_13,
    EVOASM_X64_REG_14,
    EVOASM_X64_REG_15,
};

#include "gen/evoasm-x64.c"

static uint16_t
evoasm_x64_insts(evoasm_x64_t *x64, evoasm_x64_inst_id_t *insts) {
  uint16_t len = 0;
  unsigned i;

  for(i = 0; i < EVOASM_X64_N_INSTS; i++) {
    const evoasm_x64_inst_t *inst = &_EVOASM_X64_STATIC_INSTS_VAR_NAME[i];
    if((inst->features & ~x64->features) == 0) insts[len++] = i;
  }
  return len;
}

static evoasm_arch_cls_t evoasm_x64_cls = {
    EVOASM_ARCH_X64,
    EVOASM_X64_N_INSTS,
    EVOASM_X64_N_PARAMS,
    15,
    (evoasm_arch_insts_func_t) evoasm_x64_insts,
    (evoasm_arch_enc_func_t) evoasm_x64_enc,
};

static evoasm_success_t
evoasm_x64_func_prolog_or_epilog(evoasm_x64_t *x64, evoasm_buf_t *buf, evoasm_x64_abi_t abi, bool prolog) {
  evoasm_arch_t *arch = (evoasm_arch_t *) x64;
  unsigned i;
  size_t regs_len = EVOASM_ARY_LEN(evoasm_x64_sysv_callee_save_regs);
  evoasm_x64_params_t params = {0};

  /* touch RSP and RBX so we don't get a read access violation for PUSH */
  //evoasm_arch_write_access(arch, (evoasm_bitmap_t *) &arch->acc, EVOASM_X64_REG_SP);

  for(i = 0; i < regs_len; i++) {
    evoasm_x64_reg_id_t reg = evoasm_x64_sysv_callee_save_regs[prolog ? i : (regs_len - 1 - i)];
    evoasm_arch_write_access(arch, (evoasm_bitmap_t *) &arch->acc, reg);
    EVOASM_X64_SET(EVOASM_X64_PARAM_REG0, reg);

    if(prolog) {
      EVOASM_X64_ENC(push_r64);
    }
    else {
      EVOASM_X64_ENC(pop_r64);
    }
    evoasm_arch_save(arch, buf);
  }

  if(!prolog) {
    EVOASM_X64_ENC(ret);
    evoasm_arch_save(arch, buf);
  }

  return true;

  enc_failed:
  return false;
}

evoasm_success_t
evoasm_x64_func_prolog(evoasm_x64_t *x64, evoasm_buf_t *buf, evoasm_x64_abi_t abi) {
  return evoasm_x64_func_prolog_or_epilog(x64, buf, abi, true);
}

evoasm_success_t
evoasm_x64_func_epilog(evoasm_x64_t *x64, evoasm_buf_t *buf, evoasm_x64_abi_t abi) {
  return evoasm_x64_func_prolog_or_epilog(x64, buf, abi, false);
}

evoasm_success_t
evoasm_x64_init(evoasm_x64_t *x64) {
  static evoasm_x64_t zero_x64 = {0};
  evoasm_arch_t *arch = (evoasm_arch_t *) x64;
  *x64 = zero_x64;

  evoasm_arch_init(arch, &evoasm_x64_cls);
  EVOASM_TRY(cpuid_failed, evoasm_x64_load_cpuid, x64);

  evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_GP] = 8;

#ifdef EVOASM_X64_ENABLE_AVX512
  uint64_t avx512 = EVOASM_X64_FEATURE_AVX512F |
                    EVOASM_X64_FEATURE_AVX512DQ |
                    EVOASM_X64_FEATURE_AVX512IFMA |
                    EVOASM_X64_FEATURE_AVX512PF |
                    EVOASM_X64_FEATURE_AVX512ER |
                    EVOASM_X64_FEATURE_AVX512CD |
                    EVOASM_X64_FEATURE_AVX512BW |
                    EVOASM_X64_FEATURE_AVX512VL;

  if(x64->features & avx512) {
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] = 64;
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_ZMM] = 64;
  }
  else
#endif
  if(x64->features & EVOASM_X64_FEATURE_AVX2) {
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] = 32;
  } else {
    evoasm_x64_reg_type_sizes[EVOASM_X64_REG_TYPE_XMM] = 16;
  }
  return true;

  cpuid_failed:
  evoasm_arch_destroy(arch);
  return false;
}

void
evoasm_x64_destroy(evoasm_x64_t *x64) {
  evoasm_arch_t *arch = (evoasm_arch_t *) x64;
  evoasm_arch_destroy(arch);
}
