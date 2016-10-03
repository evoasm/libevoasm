/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#include "evoasm-alloc.h"
#include "evoasm.h"

#include <stdlib.h>
#include <errno.h>

EVOASM_DEF_LOG_TAG("alloc")

void *
evoasm_malloc(size_t size) {
  void *ptr = malloc(size);
  if(EVOASM_UNLIKELY(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
      NULL, "Allocationg %zu bytes via malloc failed: %s", size, strerror(errno));
    return NULL;
  }
  return ptr;
}

void *
evoasm_aligned_alloc(size_t align, size_t size) {
  void *ptr = aligned_alloc(align, size);
  if(EVOASM_UNLIKELY(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
                 NULL, "Allocationg %zu bytes via aligned_alloc failed: %s", size, strerror(errno));
    return NULL;
  }
  return ptr;
}

void *
evoasm_calloc(size_t n, size_t size) {
  void *ptr = calloc(n, size);

  if(EVOASM_UNLIKELY(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
      NULL, "Allocationg %zux%zu () bytes via calloc failed: %s", n, size, n * size, strerror(errno));
    return NULL;
  }
  return ptr;
}

void *
evoasm_aligned_calloc(size_t align, size_t n, size_t size) {
  return evoasm_aligned_alloc(align, n * size);
}

void *
evoasm_realloc(void *ptr, size_t size) {
  void *new_ptr = realloc(ptr, size);

  if(EVOASM_UNLIKELY(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
        NULL, "Allocating %zu bytes via realloc failed: %s", size, strerror(errno));
    return NULL;
  }
  return new_ptr;
}

void
evoasm_free(void *ptr) {
  free(ptr);
}

void *
evoasm_mmap(size_t size, void *p) {
  /* Note that mmap considers the pointer passed soley as a hint address
   * and returns a valid address (possibly at a different address) in any case.
   * VirtualAlloc, on the other hand, will return NULL if the address is
   * not available
   */
    void *mem;

#if defined(_WIN32)
retry:
    mem = VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);
    if(mem == NULL) {
      if(p != NULL) {
        goto retry;
      } else {
        goto error;
      }
    }
    return mem;
#elif defined(_POSIX_VERSION)
    mem = mmap(p, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(mem == MAP_FAILED) {
      goto error;
    }
#else
#error
#endif
  return mem;

error:
    evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
        NULL, "Allocationg %zu bytes via mmap failed: %s", size, strerror(errno));
    return NULL;
}

evoasm_success_t
evoasm_munmap(void *p, size_t size) {
  bool ret;
#if defined(_WIN32)
  ret = VirtualFree(p, size, MEM_DECOMMIT);
#elif defined(_POSIX_VERSION)
  ret = (munmap(p, size) == 0);
#else
#  error
#endif

  if(!ret) {
    evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
        NULL, "Unmapping %zu bytes via munmap failed: %s", size, strerror(errno));
  }

  return ret;
}

evoasm_success_t
evoasm_mprot(void *p, size_t size, int mode)
{

#if defined(_WIN32)
  if(VirtualProtect(p, size, mode, NULL) != 0) {
    goto error;
  }
#elif defined(_POSIX_VERSION)
  if(mprotect(p, size, mode) != 0) {
    goto error;
  }
#else
#error
#endif
  return true;

error:
  evoasm_error(EVOASM_ERROR_TYPE_MEMORY, EVOASM_N_ERROR_CODES,
      NULL, "Changing memory protection failed: %s", strerror(errno));
  return false;
}

static size_t _evoasm_page_size = 0;

static long
evoasm_query_page_size() {
#if defined(_WIN32)
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return si.dwPageSize;
#elif defined(_POSIX_VERSION)
  return sysconf(_SC_PAGESIZE);
#else
#error
#endif
}

size_t
evoasm_get_page_size() {
  if(_evoasm_page_size == 0) {
    long page_size = evoasm_query_page_size();
    if(page_size == -1) {
      page_size = 4096;
      evoasm_log_warn("requesting page size failed. This might cause problems.");
    }
    _evoasm_page_size = (size_t) page_size;
  }
  return (size_t) _evoasm_page_size;
}
