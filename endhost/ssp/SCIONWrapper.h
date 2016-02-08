#ifndef _SCION_WRAPPER_H
#define _SCION_WRAPPER_H

#include "SCIONDefines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SCIONSocket SCIONSocket;

int newSCIONSocket(int protocol,
                   SCIONAddr *dstAddrs, int numAddrs,
                   short srcPort, short dstPort);
void deleteSCIONSocket(int sock);
int SCIONAccept(int sock);
int SCIONSend(int sock, uint8_t *buf, size_t len);
int SCIONSendProfile(int sock, uint8_t *buf, size_t len,
                     int profile);
int SCIONRecv(int sock, uint8_t *buf, size_t len,
              SCIONAddr *srcAddr);
int SCIONSelect(int numfds, fd_set *readfds, fd_set *writefds,
                struct timeval *timeout);
int SCIONShutdown(int fd);

void * SCIONGetStats(int sock, void *buf, int len);
void SCIONDestroyStats(void *stats);

#ifdef __cplusplus
}
#endif

#endif
