/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-arch.h"
#include "evoasm-util.h"
#include <string.h>
#include <inttypes.h>

EVOASM_DECL_LOG_TAG("arch")

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

size_t
evoasm_arch_save(evoasm_arch_t *arch, evoasm_buf_t *buf) {
  size_t len = (size_t) (arch->buf_end - arch->buf_start);

  memcpy(buf->data + buf->pos, arch->buf + arch->buf_start, len);
  buf->pos += len;

  evoasm_arch_reset(arch);

  return len;
}

size_t
evoasm_arch_save2(evoasm_arch_t *arch, uint8_t *buf) {
  size_t len = (size_t) (arch->buf_end - arch->buf_start);

  memcpy(buf, arch->buf + arch->buf_start, len);

  evoasm_arch_reset(arch);

  return len;
}
