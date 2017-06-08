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

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "ProtocolConfigs.h"
#include "Utils.h"
#include "Mutex.h"
#include "MutexScion.h"

int compareOffset(void *p1, void *p2)
{
    SSPPacket *sp1 = (SSPPacket *)p1;
    SSPPacket *sp2 = (SSPPacket *)p2;
    if (sp1->getOffset() < sp2->getOffset() &&
            sp2->getOffset() < sp1->getOffset() + sp1->len)
        return 0;
    return sp1->getOffset() - sp2->getOffset();
}

int compareOffsetNested(void *p1, void *p2)
{
    SCIONPacket *s1 = (SCIONPacket *)p1;
    SCIONPacket *s2 = (SCIONPacket *)p2;
    SSPPacket *sp1 = (SSPPacket *)(s1->payload);
    SSPPacket *sp2 = (SSPPacket *)(s2->payload);
    return sp1->getOffset() - sp2->getOffset();
}

SCIONPacket * cloneSSPPacket(SCIONPacket *packet)
{
    SCIONPacket *dup = (SCIONPacket *)malloc(sizeof(SCIONPacket));
    memcpy(dup, packet, sizeof(SCIONPacket));
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    SSPPacket *dupsp = new SSPPacket(*sp);
    dup->payload = dupsp;
    return dup;
}

void buildSSPHeader(SSPHeader *header, uint8_t *ptr)
{
    header->flowID = *(uint64_t *)ptr;
    ptr += 8;
    header->port = *(uint16_t *)ptr;
    ptr += 2;
    header->headerLen = *ptr;
    ptr++;
    header->offset = *(uint64_t *)ptr;
    ptr += 8;
    header->flags = *ptr;
}

void buildSSPAck(SSPAck *ack, uint8_t *ptr)
{
    ack->L = *(uint64_t *)ptr;
    ptr += 8;
    ack->I = *(int32_t *)ptr;
    ptr += 4;
    ack->H = *(int32_t *)ptr;
    ptr += 4;
    ack->O = *(int32_t *)ptr;
    ptr += 4;
    ack->V = *(uint32_t *)ptr;
}

void destroySCIONPacket(void *p)
{
    SCIONPacket *packet = (SCIONPacket *)p;
    if (packet->header.path)
        free(packet->header.path);
    SCIONExtension *se = packet->header.extensions;
    while (se) {
        SCIONExtension *next = se->nextExt;
        if (se->data)
            free(se->data);
        free(se);
        se = next;
    }
    free(packet);
}

void destroySSPPacket(void *p)
{
    SSPPacket *packet = (SSPPacket *)p;
    delete packet;
}

void destroySSPPacketFull(void *p)
{
    SCIONPacket *packet = (SCIONPacket *)p;
    SSPPacket *sp = (SSPPacket *)(packet->payload);
    delete sp;
    destroySCIONPacket(p);
}

void destroySUDPPacket(void *p)
{
    SUDPPacket *packet = (SUDPPacket *)p;
    if (packet->payload)
        free(packet->payload);
    free(packet);
}

uint64_t createRandom(int bits)
{
    // Eventually use better randomness
    int fd = open("/dev/urandom", O_RDONLY);
    uint64_t r;
    read(fd, &r, 8);
    close(fd);
    if (bits == 64)
        return r;
    return r & ((1 << bits) - 1);
}

int registerFlow(int proto, DispatcherEntry *e, int sock)
{
    DEBUG("register flow via socket %d: flow = %lu, port = %d\n",
            sock, e->flow_id, ntohs(e->port));

    int len;
    int addr_len = get_addr_len(e->addr_type);
    int common = 2 + ISD_AS_LEN + 2 + 1;
    switch (proto) {
        case L4_SSP:
            len = common + SSP_FID_LEN + addr_len;
            break;
        case L4_UDP:
            len = common + addr_len;
            break;
        default:
            len = 0;
            break;
    }
    uint8_t buf[128];
    write_dp_header(buf, NULL, len);
    uint8_t *ptr = buf + DP_HEADER_LEN;
    ptr[0] = 0x3; // SCMP | reg
    ptr[1] = proto;
    memcpy(ptr + 2, &e->isd_as, ISD_AS_LEN);
    *(uint16_t *)(ptr + 2 + ISD_AS_LEN) = e->port;
    ptr[2 + ISD_AS_LEN + 2] = e->addr_type;
    switch (proto) {
        case L4_SSP:
            memcpy(ptr + common, &e->flow_id, SSP_FID_LEN);
            memcpy(ptr + common + SSP_FID_LEN, e->addr, addr_len);
            break;
        case L4_UDP:
            memcpy(ptr + common, e->addr, addr_len);
            break;
        default:
            return -1;
    }

    struct sockaddr_un su;
    memset(&su, 0, sizeof(su));
    su.sun_family = AF_UNIX;
    char *env = getenv("DISPATCHER_ID");
    if (!env)
        env = (char *)DEFAULT_DISPATCHER_ID;
    snprintf(su.sun_path, sizeof(su.sun_path), "%s/%s.sock", DISPATCHER_DIR, env);
    int res = connect(sock, (struct sockaddr *)&su, sizeof(su));
    if (res < 0) {
        if (errno == EISCONN) {
            DEBUG("already connected\n");
            return 0;
        }
        fprintf(stderr, "CRITICAL: failed to connect to dispatcher: %s\n", strerror(errno));
        return -1;
    }

    res = send_all(sock, buf, len + DP_HEADER_LEN);
    if (res < 0) {
        fprintf(stderr, "CRITICAL: sendto failed: %s\n", strerror(errno));
        return -1;
    }
    res = recv_all(sock, buf, DP_HEADER_LEN + 2);
    len = 0;
    parse_dp_header(buf, NULL, &len);
    if (res < 0 || len == 0) {
        fprintf(stderr, "CRITICAL: recvfrom failed\n");
        return -1;
    }
    uint16_t port = *(uint16_t *)(buf + DP_HEADER_LEN);
    if (e->port > 0 && port != ntohs(e->port)) {
        fprintf(stderr, "CRITICAL: dispatcher registration failed: %d|%d\n", port, ntohs(e->port));
        return -1;
    }
    return port;
}

void destroyStats(SCIONStats *stats)
{
    for (int i = 0; i < MAX_TOTAL_PATHS; i++) {
        if (stats->ifCounts[i] > 0)
            free(stats->ifLists[i]);
    }
    free(stats);
}

int timedWait(pthread_cond_t *cond, pthread_mutex_t *mutex, double timeout)
{
    int secs = (int)timeout;
    uint64_t ns = (timeout - secs) * 1000000000;
    struct timespec ts;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts.tv_sec = tv.tv_sec + secs;
    ts.tv_nsec = tv.tv_usec * 1000 + ns;
    return pthread_cond_timedwait(cond, mutex, &ts);
}

int timedWaitMutex(pthread_cond_t *cond, Mutex *mutex, double timeout) REQUIRES(mutex)
{
    int secs = (int)timeout;
    uint64_t ns = (timeout - secs) * 1000000000;
    struct timespec ts;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts.tv_sec = tv.tv_sec + secs;
    ts.tv_nsec = tv.tv_usec * 1000 + ns;
    return mutex->timedWait(cond, &ts);
}


int p_m_lock(pthread_mutex_t *mutex, char const *filename, int lineno) {
    debugprint(stderr, "%lx:%s:%d: Acquiring mutex at %p\n",
               pthread_self(), filename, lineno, mutex);
    int ret = pthread_mutex_lock(mutex);
    debugprint(stderr, "%lx:%s:%d: Acquired mutex at %p (%d)\n",
               pthread_self(), filename, lineno, mutex, ret);
    return ret;
}

int p_m_unlock(pthread_mutex_t *mutex, char const *filename, int lineno) {
    debugprint(stderr, "%lx:%s:%d: Releasing mutex at %p\n",
               pthread_self(), filename, lineno, mutex);
    int ret = pthread_mutex_unlock(mutex);
    debugprint(stderr, "%lx:%s:%d: Released mutex at %p (%d)\n",
               pthread_self(), filename, lineno, mutex, ret);
    return ret;
}

int debugprint(FILE *stream, const char *format, ...) {
    int ret=0;
#ifdef SCIONDEBUGPRINT
    va_list args;
    va_start(args, format);
    ret = vfprintf(stream, format, args);
    va_end(args);
#endif
    return ret;
}
