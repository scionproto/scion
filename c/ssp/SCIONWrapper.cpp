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

#include <uthash.h>
#include "SCIONSocket.h"
#include "SCIONWrapper.h"
#include "Utils.h"

typedef struct SocketEntry {
    int fd;
    int selectRID;
    int selectWID;
    SCIONSocket *sock;
    UT_hash_handle hh;
} SocketEntry;

SocketEntry *sockets = NULL;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

extern "C" {

void updateTable(SocketEntry *e)
{
    SocketEntry *old;
    HASH_FIND(hh, sockets, &e->fd, sizeof(e->fd), old);
    if (old) {
        delete old->sock;
        HASH_DELETE(hh, sockets, old);
    }
    HASH_ADD(hh, sockets, fd, sizeof(e->fd), e);
}

SocketEntry * findSocket(int sock)
{
    SocketEntry *e = NULL;
    HASH_FIND(hh, sockets, &sock, sizeof(sock), e);
    if (!e)
        DEBUG("socket %d not found\n", sock);
    return e;
}

int newSCIONSocket(int protocol, const char *sciond)
{
    p_m_lock(&mutex, __FILE__, __LINE__);
    SCIONSocket *s = new SCIONSocket(protocol, sciond);
    SocketEntry *e;
    e = (SocketEntry *)malloc(sizeof(SocketEntry));
    e->fd = s->getReliableSocket();
    e->sock = s;
    updateTable(e);
    p_m_unlock(&mutex, __FILE__, __LINE__);
    return e->fd;
}

void deleteSCIONSocket(int sock)
{
    p_m_lock(&mutex, __FILE__, __LINE__);
    SocketEntry *e = findSocket(sock);
    if (e) {
        delete e->sock;
        HASH_DELETE(hh, sockets, e);
    }
    p_m_unlock(&mutex, __FILE__, __LINE__);
}

int SCIONAccept(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    SCIONSocket *s = e->sock->accept();
    e = (SocketEntry *)malloc(sizeof(SocketEntry));
    e->fd = s->getReliableSocket();
    e->sock = s;
    updateTable(e);
    return e->fd;
}

int SCIONBind(int sock, SCIONAddr addr)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->bind(addr);
}

int SCIONConnect(int sock, SCIONAddr addr)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->connect(addr);
}

int SCIONListen(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->listen();
}

int SCIONSend(int sock, uint8_t *buf, size_t len, SCIONAddr *dstAddr)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->send(buf, len, dstAddr);
}

int SCIONSendProfile(int sock, uint8_t *buf, size_t len, SCIONAddr *dstAddr)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->send(buf, len, dstAddr);
}

int SCIONRecv(int sock, uint8_t *buf, size_t len, SCIONAddr *srcAddr)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->recv(buf, len, srcAddr);
}

void * SCIONGetStats(int sock, void *buf, int len)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return NULL;
    return e->sock->getStats(buf, len);
}

void SCIONDestroyStats(void *stats)
{
    SCIONStats *s = (SCIONStats *)stats;
    destroyStats(s);
}

int SCIONSetOption(int fd, SCIONOption *option)
{
    SocketEntry *e = findSocket(fd);
    if (!e)
        return -EINVAL;
    return e->sock->setSocketOption(option);
}

int SCIONGetOption(int fd, SCIONOption *option)
{
    SocketEntry *e = findSocket(fd);
    if (!e)
        return -EINVAL;
    return e->sock->getSocketOption(option);
}

int checkReadWrite(fd_set *fdset, int mode, int fd, Notification *n)
{
    SocketEntry *e = findSocket(fd);
    int ready = 0;
    if ((mode == SCION_SELECT_READ && e->sock->readyToRead()) ||
        (mode == SCION_SELECT_WRITE && e->sock->readyToWrite())) {
        FD_SET(fd, fdset);
        ready = 1;
    } else {
        FD_CLR(fd, fdset);
    }
    return ready;
}

int SCIONSelect(int numfds, fd_set *readfds, fd_set *writefds,
                struct timeval *timeout)
{
    struct timespec t;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_condattr_t ca;
    Notification n;

    pthread_mutex_init(&mutex, NULL);

    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_REALTIME);
    pthread_cond_init(&cond, &ca);

    n.cond = &cond;
    n.mutex = &mutex;

    if (timeout) {
        t.tv_sec = timeout->tv_sec;
        t.tv_nsec = timeout->tv_usec * 1000;
    }

    fd_set rfds, wfds;

    /* Check if stuff is ready now */
    int total = 0;
    int err = 0;
    while (!total) {
        std::vector<SocketEntry *> regRead, regWrite;
        if (readfds)
            memcpy(&rfds, readfds, sizeof(rfds));
        if (writefds)
            memcpy(&wfds, writefds, sizeof(wfds));
        for (int i = 0; i < numfds; i++) {
            SocketEntry *e = findSocket(i);
            if (!e)
                continue;
            int ready = 0;
            if (readfds) {
                if (FD_ISSET(i, &rfds)) {
                    DEBUG("check if %d is ready to read\n", i);
                    ready = checkReadWrite(&rfds, SCION_SELECT_READ, i, &n);
                }
                if (!ready)
                    regRead.push_back(e);
            }
            if (writefds) {
                if (FD_ISSET(i, &wfds)) {
                    DEBUG("check if %d is ready to write\n", i);
                    ready |= checkReadWrite(&wfds, SCION_SELECT_WRITE, i, &n);
                }
                if (!ready)
                    regWrite.push_back(e);
            }
            total += ready;
        }
        if (!total) {
            DEBUG("nothing ready yet, will block\n");
            p_m_lock(&mutex, __FILE__, __LINE__);
            for (size_t j = 0; j < regRead.size(); j++) {
                SocketEntry *e = regRead[j];
                e->selectRID =
                    e->sock->registerSelect(&n, SCION_SELECT_READ);
            }
            for (size_t j = 0; j < regWrite.size(); j++) {
                SocketEntry *e = regWrite[j];
                e->selectWID =
                    e->sock->registerSelect(&n, SCION_SELECT_WRITE);
            }

            if (timeout)
                err = pthread_cond_timedwait(&cond, &mutex, &t);
            else
                err = pthread_cond_wait(&cond, &mutex);
            p_m_unlock(&mutex, __FILE__, __LINE__);

            for (size_t j = 0; j < regRead.size(); j++) {
                SocketEntry *e = regRead[j];
                e->sock->deregisterSelect(e->selectRID);
            }
            for (size_t j = 0; j < regWrite.size(); j++) {
                SocketEntry *e = regWrite[j];
                e->sock->deregisterSelect(e->selectWID);
            }
        }
        if (err) {
            DEBUG("error occurred: %d\n", err);
            if (err != ETIMEDOUT)
                total = err;
            break;
        }
    }

    if (readfds)
        memcpy(readfds, &rfds, sizeof(rfds));
    if (writefds)
        memcpy(writefds, &wfds, sizeof(wfds));
    DEBUG("%d fds ready\n", total);
    return total;
}

int SCIONShutdown(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->shutdown();
}

uint32_t SCIONGetLocalIA(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return 0;
    return e->sock->getLocalIA();
}

void SCIONSetTimeout(int sock, double timeout)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return;
    e->sock->setTimeout(timeout);
}

double SCIONGetTimeout(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return 0.0;
    return e->sock->getTimeout();
}

int SCIONGetPort(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return 0;
    return e->sock->getPort();
}

int SCIONMaxPayloadSize(int sock, double timeout)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->maxPayloadSize(timeout);
}

}
