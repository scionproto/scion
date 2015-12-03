#include "SCIONSocket.h"
#include "SCIONWrapper.h"
#include "uthash.h"
#include "Utils.h"

typedef struct SocketEntry {
    int fd;
    SCIONSocket *sock;
    UT_hash_handle hh;
} SocketEntry;

SocketEntry *sockets = NULL;

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
        fprintf(stderr, "socket %d not found\n", sock);
    return e;
}

int newSCIONSocket(int protocol,
                   SCIONAddr *dstAddrs, int numAddrs,
                   short srcPort, short dstPort)
{
    SCIONSocket *s =
        new SCIONSocket(protocol, dstAddrs, numAddrs, srcPort, dstPort);
    SocketEntry *e;
    e = (SocketEntry *)malloc(sizeof(SocketEntry));
    e->fd = s->getDispatcherSocket();
    e->sock = s;
    updateTable(e);
    return e->fd;
}

int SCIONAccept(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    SCIONSocket &s = e->sock->accept();
    e = (SocketEntry *)malloc(sizeof(SocketEntry));
    e->fd = s.getDispatcherSocket();
    e->sock = &s;
    updateTable(e);
    return e->fd;
}

int SCIONSend(int sock, uint8_t *buf, size_t len)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->send(buf, len);
}

int SCIONSendProfile(int sock, uint8_t *buf, size_t len,
                     int profile)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->send(buf, len, (DataProfile)profile);
}

int SCIONRecv(int sock, uint8_t *buf, size_t len,
              SCIONAddr *srcAddr)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return -1;
    return e->sock->recv(buf, len, srcAddr);
}

SCIONStats * SCIONGetStats(int sock)
{
    SocketEntry *e = findSocket(sock);
    if (!e)
        return NULL;
    return e->sock->getStats();
}

void SCIONDestroyStats(void *stats)
{
    SCIONStats *s = (SCIONStats *)stats;
    destroyStats(s);
}

}
