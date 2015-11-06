#ifndef UTILS_H
#define UTILS_H

#include <sys/time.h>

#include "DataStructures.h"
#include "SCIONDefines.h"

inline SCIONAddr ISD_AD(int isd, int ad)
{
    SCIONAddr addr;
    addr.isd_ad = (isd << 20) | (ad & 0xfffff);
    return addr;
}

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

inline void destroySCIONPacket(SCIONPacket *packet)
{
    if (packet->header.path)
        free(packet->header.path);
    free(packet);
}

// elapsed time in ms
inline long elapsedTime(struct timeval *old, struct timeval *current)
{
    return (current->tv_usec - old->tv_usec) + (current->tv_sec - old->tv_sec) * 1000000;
}

inline void destroySDAMPFrame(SDAMPFrame *frame)
{
    if (frame->data)
        free(frame->data);
    free(frame);
}

inline void destroySDAMPPacket(SDAMPPacket *packet)
{
    if (packet->interfaces)
        free(packet->interfaces);
    if (packet->frames)
        free(packet->frames);
    free(packet);
}

inline void destroySSPInPacket(SSPInPacket *packet)
{
    if (packet->data)
        free(packet->data);
    free(packet);
}

inline void destroySSPOutPacket(SSPOutPacket *packet)
{
    if (packet->data)
        free(packet->data);
    free(packet);
}

bool compareDeadline(void *p1, void *p2);
bool comparePacketNum(void *p1, void *p2);
bool compareOffset(void *p1, void *p2);

inline void destroySUDPPacket(SUDPPacket *packet)
{
    if (packet->payload)
        free(packet->payload);
    free(packet);
}

int reversePath(uint8_t *original, uint8_t *reverse, int len);
uint64_t createRandom(int bits);
int registerFlow(int proto, void *data, int sock);

#endif
