/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include "evoasm-util.h"

#ifdef EVOASM_UNIX
#  include <unistd.h>
#  include <sys/mman.h>
#  if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#    define MAP_ANONYMOUS MAP_ANON
#  endif
#endif

#include <string.h>
#include <alloca.h>

#if defined(_WIN32)
#  include <malloc.h>
#endif

#include "evoasm-error.h"

#ifdef __GNUC__
#  define EVOASM_MALLOC_ATTRS  __attribute__((malloc))
#  define EVOASM_CALLOC_ATTRS  __attribute__((malloc))
#  define EVOASM_REALLOC_ATTRS __attribute__((malloc))
#else
#  define EVOASM_MALLOC_ATTRS
#  define EVOASM_CALLOC_ATTRS
#  define EVOASM_REALLOC_ATTRS
#endif

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

void *evoasm_malloc(size_t) EVOASM_MALLOC_ATTRS;
void *evoasm_calloc(size_t, size_t) EVOASM_CALLOC_ATTRS;
void *evoasm_realloc(void *, size_t) EVOASM_REALLOC_ATTRS;
void evoasm_free(void *);

void *evoasm_mmap(size_t size, void *p);
evoasm_success_t evoasm_munmap(void *p, size_t size);
evoasm_success_t evoasm_mprot(void *p, size_t size, int mode);
long evoasm_page_size();


#define EVOASM_CHECKED_CALLOC(f, n, s) \
do { \
  if(!(f = evoasm_calloc((n), (s)))) goto calloc_failed; \
} while(0);

#if defined(_WIN32)
  #define evoasm_alloca(s) _malloca(s);
#else
  #define evoasm_alloca(s) alloca(s);
#endif
