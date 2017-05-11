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
#  define EVOASM_ALIGNED_ALLOC_ATTRS __attribute__((malloc))
#  define EVOASM_ALIGNED_CALLOC_ATTRS __attribute__((malloc))
#else
#  define EVOASM_MALLOC_ATTRS
#  define EVOASM_CALLOC_ATTRS
#  define EVOASM_REALLOC_ATTRS
#  define EVOASM_ALIGNED_ALLOC_ATTRS
#  define EVOASM_ALIGNED_CALLOC_ATTRS
#endif

typedef enum {
  EVOASM_MPROT_MODE_RW,
  EVOASM_MPROT_MODE_RX,
  EVOASM_MPROT_MODE_RWX,
} evoasm_mprot_mode_t;

void *evoasm_malloc(size_t) EVOASM_MALLOC_ATTRS;
void *evoasm_calloc(size_t, size_t) EVOASM_CALLOC_ATTRS;
evoasm_success_t evoasm_realloc(void **ptr, size_t size);
void *evoasm_aligned_alloc(size_t, size_t) EVOASM_ALIGNED_ALLOC_ATTRS;
void *evoasm_aligned_calloc_set(size_t align, size_t n, size_t size, int val) EVOASM_ALIGNED_CALLOC_ATTRS ;
void *evoasm_aligned_calloc(size_t align, size_t n, size_t size) EVOASM_ALIGNED_CALLOC_ATTRS;
void evoasm_free(void *);

void *evoasm_mmap(size_t size, void *p);
evoasm_success_t evoasm_munmap(void *p, size_t size);
evoasm_success_t evoasm_mprot(void *p, size_t size, evoasm_mprot_mode_t mode);
size_t evoasm_get_page_size();

#define EVOASM_TRY_ALLOC(label, func, var, ...) \
do { \
  if(!(var = evoasm_##func(__VA_ARGS__))) goto label; \
} while(0);

#define EVOASM_TRY_ALLOC_N(label, func, var, ...) \
do { \
  if(!(var = evoasm_##func(__VA_ARGS__, sizeof((var)[0])))) goto label; \
} while(0);

#if defined(_WIN32)
  #define evoasm_alloca(s) _malloca(s);
#else
  #define evoasm_alloca(s) alloca(s);
#endif

#ifndef EVOASM_CACHE_LINE_SIZE
#define EVOASM_CACHE_LINE_SIZE 64
#endif
