#include "evoasm.h"
#include "evoasm-util.h"
#include "evoasm-misc.h"

//static const char *_evoasm_log_tag = "general";

void
evoasm_prng64_init(evoasm_prng64_t *prng, evoasm_prng64_seed_t *seed) {
  prng->s = *seed;
}

void
evoasm_prng64_destroy(evoasm_prng64_t *prng) {
}

void
evoasm_prng32_init(evoasm_prng32_t *prng, evoasm_prng32_seed_t *seed) {
  prng->s = *seed;
}

void
evoasm_prng32_destroy(evoasm_prng32_t *prng) {
}

