#ifndef UTILS_H
#define UTILS_H

#include <sys/time.h>

#include "DataStructures.h"
#include "SCIONDefines.h"

inline int isd(SCIONAddr &addr)
{
    return addr.isd_ad >> 20;
}

inline int ad(SCIONAddr &addr)
{
    return addr.isd_ad & 0xfffff;
}

inline void buildCommonHeader(SCIONCommonHeader &header, int protocol)
{
    header.versionAddrs = 0x4100; // version = 0, src = 8, dst = 8
    header.currentIOF = 2 * SCION_ADDR_LEN + sizeof(header);
    header.currentOF = 2 * SCION_ADDR_LEN + 8 + sizeof(header);
    header.nextHeader = protocol;
}

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
int registerFlow(int proto, void *data, int sock, uint8_t reg);
void destroyStats(SCIONStats *stats);

int isL4(uint8_t type);
uint16_t checksum(SCIONPacket *packet);

#endif
