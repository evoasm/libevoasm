#include "evoasm-arch.h"
#include "evoasm-util.h"
#include <string.h>
#include <inttypes.h>

EVOASM_DECL_LOG_TAG("arch")

uint16_t
evoasm_arch_insts(evoasm_arch_t *arch, evoasm_inst_id_t *insts) {
  return arch->cls->insts_func(arch, insts);
}

evoasm_success_t
evoasm_arch_enc(evoasm_arch_t *arch, evoasm_inst_id_t inst, evoasm_arch_param_val_t *param_vals, evoasm_bitmap_t *set_params) {
  return arch->cls->enc_func(arch, inst, param_vals, set_params);
}

void
evoasm_arch_reset(evoasm_arch_t *arch) {
  arch->buf_start = EVOASM_ARCH_BUF_CAPA / 2;
  arch->buf_end   = EVOASM_ARCH_BUF_CAPA / 2;
}

void
evoasm_arch_init(evoasm_arch_t *arch, evoasm_arch_cls_t *cls) {
  static evoasm_arch_t zero_arch = {0};
  *arch = zero_arch;
  evoasm_arch_reset(arch);
  arch->cls = cls;
}

void
evoasm_arch_destroy(evoasm_arch_t *arch) {
}

void
evoasm_arch_save(evoasm_arch_t *arch, evoasm_buf_t *buf) {
  uint8_t len = (uint8_t)(arch->buf_end - arch->buf_start);

  memcpy(buf->data + buf->pos, arch->buf + arch->buf_start, len);
  buf->pos += len;

  evoasm_arch_reset(arch);
}
