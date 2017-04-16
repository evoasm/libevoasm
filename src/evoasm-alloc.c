/*
 * Copyright (C) 2016 Julian Aron Prenner <jap@polyadic.com>
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

#include "evoasm-alloc.h"
#include "evoasm.h"

#include <stdlib.h>
#include <errno.h>

EVOASM_DEF_LOG_TAG("alloc")

void *
evoasm_malloc(size_t size) {
  void *ptr = malloc(size);
  if(evoasm_unlikely(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
                 "Allocating %zu bytes via malloc failed: %s", size, strerror(errno));
    return NULL;
  }
  return ptr;
}

void *
evoasm_aligned_alloc(size_t align, size_t size) {
#if __STDC_VERSION__ >= 201112L
  void *ptr = aligned_alloc(align, size);
  if(evoasm_unlikely(!ptr)) {
    int error_code = errno;
#elif _POSIX_C_SOURCE >= 200112L
  void *ptr;
  int error_code = posix_memalign(&ptr, align, size);
  if(evoasm_unlikely(error_code)) {
#else
#error No aligned memory allocation function found
#endif

    evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
                 "Allocating %zu bytes aligned to %zu via aligned_alloc failed: %s", size, align, strerror(error_code));
    return NULL;
  }
  return ptr;
}

void *
evoasm_calloc(size_t n, size_t size) {
  void *ptr = calloc(n, size);

  if(evoasm_unlikely(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
                 "Allocating %zux%zu (%zu) bytes via calloc failed: %s", n, size, n * size, strerror(errno));
    return NULL;
  }
  return ptr;
}


void *
evoasm_aligned_calloc_set(size_t align, size_t n, size_t size, int val) {
  if(evoasm_unlikely(size == 0 || n >= SIZE_MAX / size)) {
    evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
                 "Allocating %zux%zu bytes via aligned_calloc failed: integer overflow", n, size);
    return NULL;
  }

  size_t len = n * size;
  void *ptr = evoasm_aligned_alloc(align, len);

  if(evoasm_likely(ptr != NULL)) {
    memset(ptr, val, len);
  }
  return ptr;
}

void *
evoasm_aligned_calloc(size_t align, size_t n, size_t size) {
  return evoasm_aligned_calloc_set(align, n, size, 0);
}

void *
evoasm_realloc(void *ptr, size_t size) {
  void *new_ptr = realloc(ptr, size);

  if(evoasm_unlikely(!ptr)) {
    evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
                 "Allocating %zu bytes via realloc failed: %s", size, strerror(errno));
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
  evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
               "Allocating %zu bytes via mmap failed: %s", size, strerror(errno));
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
    evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
                 "Unmapping %zu bytes via munmap failed: %s", size, strerror(errno));
  }

  return ret;
}


#if defined(_WIN32)
#define EVOASM_MPROT_RW PAGE_READWRITE
#define EVOASM_MPROT_RX PAGE_EXECUTE_READ
#define EVOASM_MPROT_RWX PAGE_EXECUTE_READWRITE
#elif defined(_POSIX_VERSION)
#define EVOASM_MPROT_RW (PROT_READ|PROT_WRITE)
#define EVOASM_MPROT_RX (PROT_READ|PROT_EXEC)
#define EVOASM_MPROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)
#else
#error
#endif

evoasm_success_t
evoasm_mprot(void *p, size_t size, evoasm_mprot_mode_t mode) {
  int mode_;

  switch(mode) {
    case EVOASM_MPROT_MODE_RW:
      mode_ = EVOASM_MPROT_RW;
      break;
    case EVOASM_MPROT_MODE_RWX:
      mode_ = EVOASM_MPROT_RWX;
      break;
    case EVOASM_MPROT_MODE_RX:
      mode_ = EVOASM_MPROT_RX;
      break;
    default:
      evoasm_assert_not_reached();
  }


#if defined(_WIN32)
  if(VirtualProtect(p, size, mode_, NULL) != 0) {
    goto error;
  }
#elif defined(_POSIX_VERSION)
  if(mprotect(p, size, mode_) != 0) {
    goto error;
  }
#else
#error
#endif
  return true;

error:
  evoasm_error(EVOASM_ERROR_TYPE_ALLOC, EVOASM_ERROR_CODE_NONE,
               "Changing memory protection failed: %s", strerror(errno));
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
