/* Copyright 2015 ETH Zurich
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

#ifndef UTILS_H
#define UTILS_H

#include <sys/time.h>

#include "DataStructures.h"
#include "SCIONDefines.h"
#include "Mutex.h"
#include "MutexScion.h"

// elapsed time in ms
inline long elapsedTime(struct timeval *old, struct timeval *current)
{
    return (current->tv_usec - old->tv_usec) + (current->tv_sec - old->tv_sec) * 1000000;
}

int compareOffset(void *p1, void *p2);
int compareOffsetNested(void *p1, void *p2);

void buildSSPHeader(SSPHeader *header, uint8_t *ptr);
void buildSSPAck(SSPAck *ack, uint8_t *ptr);

SCIONPacket * cloneSSPPacket(SCIONPacket *packet);

void destroySCIONPacket(void *p);
void destroySSPPacket(void *p);
void destroySSPPacketFull(void *p);
void destroySUDPPacket(void *p);

int reversePath(uint8_t *original, uint8_t *reverse, int len);
uint64_t createRandom(int bits);
int registerFlow(int proto, DispatcherEntry *e, int sock);
void destroyStats(SCIONStats *stats);

int timedWait(pthread_cond_t *cond, pthread_mutex_t *mutex, double timeout);
int timedWaitMutex(pthread_cond_t *cond, Mutex *mutex, double timeout);

// pthread_mutex_lock and pthread_mutex_unlock wrappers that use debugprint()
int p_m_lock(pthread_mutex_t *mutex, char const *filename, int lineno);
int p_m_unlock(pthread_mutex_t *mutex, char const *filename, int lineno);

// Print text to stream iff SCIONDEBUGPRINT is defined
int debugprint(FILE *stream, const char *format, ...);

#endif // UTILS_H
