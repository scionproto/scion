#ifndef _SCION_WRAPPER_H
#define _SCION_WRAPPER_H

#include "SCIONDefines.h"

#ifdef __cplusplus
extern "C" {
#endif

int newSCIONSocket(int protocol, const char *sciond);
void deleteSCIONSocket(int sock);
int SCIONAccept(int sock);
int SCIONBind(int sock, SCIONAddr addr);
int SCIONConnect(int sock, SCIONAddr addr);
int SCIONListen(int sock);
int SCIONSend(int sock, uint8_t *buf, size_t len, SCIONAddr *dstAddr);
int SCIONSendProfile(int sock, uint8_t *buf, size_t len,
                     SCIONAddr *dstAddr);
int SCIONRecv(int sock, uint8_t *buf, size_t len,
              SCIONAddr *srcAddr);
int SCIONSelect(int numfds, fd_set *readfds, fd_set *writefds,
                struct timeval *timeout);
int SCIONShutdown(int sock);

void * SCIONGetStats(int sock, void *buf, int len);
void SCIONDestroyStats(void *stats);

int SCIONSetOption(int sock, SCIONOption *option);
int SCIONGetOption(int sock, SCIONOption *option);

uint32_t SCIONGetLocalIA(int sock);

void SCIONSetTimeout(int sock, double timeout);

int SCIONGetPort(int sock);
int SCIONMaxPayloadSize(int sock, double timeout);

#ifdef __cplusplus
}
#endif

#endif
