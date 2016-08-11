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
evoasm_arch_ctx_reset(evoasm_arch_ctx_t *arch_ctx) {
  arch_ctx->buf_start = EVOASM_ARCH_BUF_CAPA / 2;
  arch_ctx->buf_end   = EVOASM_ARCH_BUF_CAPA / 2;
}

void
evoasm_arch_ctx_init(evoasm_arch_ctx_t *arch_ctx, evoasm_arch_cls_t *cls) {
  static evoasm_arch_ctx_t zero_arch = {0};
  *arch_ctx = zero_arch;
  evoasm_arch_ctx_reset(arch_ctx);
  arch_ctx->cls = cls;
}

void
evoasm_arch_ctx_destroy(evoasm_arch_ctx_t *arch_ctx) {
}

size_t
evoasm_arch_ctx_save(evoasm_arch_ctx_t *arch_ctx, evoasm_buf_t *buf) {
  size_t len = (size_t) (arch_ctx->buf_end - arch_ctx->buf_start);

  memcpy(buf->data + buf->pos, arch_ctx->buf + arch_ctx->buf_start, len);
  buf->pos += len;

  evoasm_arch_ctx_reset(arch_ctx);

  return len;
}

size_t
evoasm_arch_ctx_save2(evoasm_arch_ctx_t *arch_ctx, uint8_t *buf) {
  size_t len = (size_t) (arch_ctx->buf_end - arch_ctx->buf_start);

  memcpy(buf, arch_ctx->buf + arch_ctx->buf_start, len);

  evoasm_arch_ctx_reset(arch_ctx);

  return len;
}
