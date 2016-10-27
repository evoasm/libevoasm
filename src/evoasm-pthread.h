/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Julian Aron Prenner <jap@polyadic.com>
 */

#pragma once

#include <pthread.h>
#include "evoasm-error.h"

typedef struct {
  pthread_mutex_t mutex;
} evoasm_mutex_t;

typedef struct {
  pthread_rwlock_t rwlock;
} evoasm_rwlock_t;

typedef struct {
  pthread_t thread;
} evoasm_thread_t;

typedef void *(*evoasm_thread_func_t)(void *);

#define EVOASM_PTHREAD_WRAPPER_FUNC_BODY(type, name, msg) \
  if(errno) { \
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_ERROR_CODE_NONE, \
                       NULL, msg ": %s", strerror(errno)); \
    return false; \
  } \
  return true;

#define EVOASM_PTHREAD_DEF_WRAPPER_INIT_FUNC(type, name, msg) \
  static inline evoasm_success_t \
  evoasm_##type##_##name(evoasm_##type##_t *ptr) { \
    int errno = pthread_##type##_##name(&ptr->type, NULL); \
    EVOASM_PTHREAD_WRAPPER_FUNC_BODY(type, name, msg) \
  }

#define EVOASM_PTHREAD_DEF_WRAPPER_FUNC(type, name, msg) \
  static inline evoasm_success_t \
  evoasm_##type##_##name(evoasm_##type##_t *ptr) { \
    int errno = pthread_##type##_##name(&ptr->type); \
    EVOASM_PTHREAD_WRAPPER_FUNC_BODY(type, name, msg) \
  }


EVOASM_PTHREAD_DEF_WRAPPER_INIT_FUNC(mutex, init, "rwlock initialization failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(mutex, destroy, "rwlock destruction failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(mutex, lock, "locking rwlock failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(mutex, unlock, "unlocking rwlock failed")

EVOASM_PTHREAD_DEF_WRAPPER_INIT_FUNC(rwlock, init, "rwlock initialization failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(rwlock, destroy, "rwlock destruction failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(rwlock, rdlock, "read-locking rwlock failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(rwlock, wrlock, "write-locking rwlock failed")

EVOASM_PTHREAD_DEF_WRAPPER_FUNC(rwlock, unlock, "unlocking rwlock failed")

static inline evoasm_success_t
evoasm_thread_create(evoasm_thread_t *thread, evoasm_thread_func_t thread_func, void *arg) {
  int errno = pthread_create(&thread->thread, NULL /* attrs */,
                             thread_func, arg);

  if(errno) {
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_ERROR_CODE_NONE,
                 NULL, "creating thread failed: %s", strerror(errno));
    return false;
  }
  return true;
}

static inline evoasm_success_t
evoasm_thread_join(evoasm_thread_t *thread, void **retval) {
  int errno = pthread_join(thread->thread, retval);

  if(errno) {
    evoasm_error(EVOASM_ERROR_TYPE_RUNTIME, EVOASM_ERROR_CODE_NONE,
                 NULL, "joining thread failed: %s", strerror(errno));
    return false;
  }
  return true;
}

#undef EVOASM_PTHREAD_DEF_WRAPPER_INIT_FUNC
#undef EVOASM_PTHREAD_DEF_WRAPPER_FUNC
#undef EVOASM_PTHREAD_WRAPPER_FUNC_BODY
