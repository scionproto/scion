/* Copyright 2016 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MUTEXSCION_H_
#define MUTEXSCION_H_

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include "Mutex.h"

// From Utils.h
extern int debugprint(FILE *stream, const char *format, ...);

// Basic wrapper around a pthread mutex
class CAPABILITY("mutex") Mutex {
public:
    enum LinkerInitialized { LINKER_INITIALIZED };

    // pthread_mutex_init() always returns 0, so no need to assert()
    inline Mutex() {pthread_mutex_init(&lock, nullptr);}
    inline Mutex(LinkerInitialized) {pthread_mutex_init(&lock, nullptr);}

    inline ~Mutex() {
        auto ret = pthread_mutex_destroy(&lock);
        if (ret) {
            debugprint(stderr, "%lx Held mutex: %p: %d\n", pthread_self(), &lock, ret);
        }
    }

    inline void Lock() ACQUIRE() {
        debugprint(stderr, "%lx  ML>: %p\n", pthread_self(), &lock);
        auto ret = pthread_mutex_lock(&lock);
        debugprint(stderr, "%lx  ML<: %p: %d\n", pthread_self(), &lock, ret);
    }

    inline void Unlock() RELEASE() {
        auto ret = pthread_mutex_unlock(&lock);
        debugprint(stderr, "%lx   MR: %p: %d\n", pthread_self(), &lock, ret);
    }

    inline int timedWait(pthread_cond_t *cond, struct timespec *ts) REQUIRES(this) {
        debugprint(stderr, "%lx MTw>: %p\n", pthread_self(), &lock);
        auto ret = pthread_cond_timedwait(cond, &lock, ts);
        debugprint(stderr, "%lx MTw<: %p: %d\n", pthread_self(), &lock, ret);
    return ret;
    }

    inline void condWait(pthread_cond_t *cond) REQUIRES(this) {
        // While pcw has an int return value, it's always 0.
        debugprint(stderr, "%lx MCw>: %p\n", pthread_self(), &lock);
        pthread_cond_wait(cond, &lock);
        debugprint(stderr, "%lx MCw<: %p\n", pthread_self(), &lock);
    }

private:
    pthread_mutex_t lock;
    DISALLOW_COPY_AND_ASSIGN(Mutex);
};

#endif  // MUTEXSCION_H_
