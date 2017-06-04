#include "evoasm-bitmap.h"
#include "evoasm-util.h"
#include "evoasm-alloc.h"

EVOASM_DEF_FREE_FUNC(bitmap)

evoasm_bitmap_t *evoasm_bitmap_alloc(size_t n_bits) {
  return (evoasm_bitmap_t *) evoasm_malloc(EVOASM_BITMAP_BYTESIZE(n_bits));
}

void
evoasm_bitmap_init(evoasm_bitmap_t *bitmap, size_t size) {
  memset(bitmap, 0, EVOASM_BITMAP_BYTESIZE(size));
}

void
evoasm_bitmap_set(evoasm_bitmap_t *bitmap, size_t idx) {
  evoasm_bitmap_set_(bitmap, idx);
}

void
evoasm_bitmap_unset(evoasm_bitmap_t *bitmap, size_t idx) {
  evoasm_bitmap_unset_(bitmap, idx);
}

void
evoasm_bitmap_set_to(evoasm_bitmap_t *bitmap, size_t idx, bool value) {
  evoasm_bitmap_set_to_(bitmap, idx, value);
}

bool
evoasm_bitmap_get(evoasm_bitmap_t *bitmap, size_t idx) {
  return evoasm_bitmap_get_(bitmap, idx);
}
