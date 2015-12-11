#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "Utils.h"

int compareDeadline(void *p1, void *p2)
{
    SCIONPacket *s1 = (SCIONPacket *)p1;
    SCIONPacket *s2 = (SCIONPacket *)p2;
    SDAMPPacket *sp1 = (SDAMPPacket *)(s1->payload);
    SDAMPPacket *sp2 = (SDAMPPacket *)(s2->payload);
    if (sp1->deadline == sp2->deadline)
        return be64toh(sp1->header.packetNum) -
                be64toh(sp2->header.packetNum);
    return sp1->deadline - sp2->deadline;
}

int comparePacketNum(void *p1, void *p2)
{
    L4Packet *sp1 = (L4Packet *)p1;
    L4Packet *sp2 = (L4Packet *)p2;
    return sp1->number() - sp2->number();
}

int comparePacketNumNested(void *p1, void *p2)
{
    SCIONPacket *s1 = (SCIONPacket *)p1;
    SCIONPacket *s2 = (SCIONPacket *)p2;
    SDAMPPacket *sp1 = (SDAMPPacket *)(s1->payload);
    SDAMPPacket *sp2 = (SDAMPPacket *)(s2->payload);
    return be64toh(sp1->header.packetNum) -
            be64toh(sp2->header.packetNum);
}

int compareOffset(void *p1, void *p2)
{
    SSPPacket *sp1 = (SSPPacket *)p1;
    SSPPacket *sp2 = (SSPPacket *)p2;
    if (sp1->header.offset < sp2->header.offset &&
            sp2->header.offset < sp1->header.offset + sp1->len)
        return 0;
    return sp1->header.offset - sp2->header.offset;
}

int compareOffsetNested(void *p1, void *p2)
{
    SCIONPacket *s1 = (SCIONPacket *)p1;
    SCIONPacket *s2 = (SCIONPacket *)p2;
    SSPPacket *sp1 = (SSPPacket *)(s1->payload);
    SSPPacket *sp2 = (SSPPacket *)(s2->payload);
    return be64toh(sp1->header.offset) - be64toh(sp2->header.offset);
}

void destroySCIONPacket(void *p)
{
    SCIONPacket *packet = (SCIONPacket *)p;
    if (packet->header.path)
        free(packet->header.path);
    free(packet);
}

void destroySDAMPPacket(void *p)
{
    SDAMPPacket *packet = (SDAMPPacket *)p;
    delete packet;
}

void destroySDAMPPacketFull(void *p)
{
    SCIONPacket *packet = (SCIONPacket *)p;
    SDAMPPacket *sp = (SDAMPPacket *)(packet->payload);
    delete sp;
    destroySCIONPacket(p);
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

int reversePath(uint8_t *original, uint8_t *reverse, int len)
{
    if (len == 0)
        return 0;

    if (IS_HOP_OF(*original)) {
        DEBUG("No leading Info OF in path\n");
        return -1;
    }

    DEBUG("reverse a path of length %d\n", len);

    int offset = 0;
    uint8_t *upIOF = NULL;
    uint8_t upHops = 0;
    uint8_t *coreIOF = NULL;
    uint8_t coreHops = 0;
    uint8_t *downIOF = NULL;
    uint8_t downHops = 0;

    upIOF = original;
    upHops = *(upIOF + 7);
    uint8_t type = *upIOF >> 1;
    if (type == TDC_XOVR) {
        coreIOF = upIOF + (upHops + 1) * 8;
        coreHops = *(coreIOF + 7);
        downIOF = coreIOF + (coreHops + 1) * 8;
        downHops = *(downIOF + 7);
        DEBUG("%d up hops, %d core hops, %d down hops\n", upHops, coreHops, downHops);

        // up segment = reversed down segment
        *(uint64_t *)reverse = *(uint64_t *)downIOF;
        *reverse ^= 1;
        offset = 8;
        for (int i = downHops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(downIOF + i * 8);
            offset += 8;
        }
        DEBUG("offset after up segment = %d\n", offset);

        // reverse core hops
        *(uint64_t *)(reverse + offset) = *(uint64_t *)coreIOF;
        *(reverse + offset) ^= 1;
        offset += 8;
        for (int i = coreHops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(coreIOF + i * 8);
            offset += 8;
        }
        DEBUG("offset after core segment = %d\n", offset);

        // down segment = reversed up segment
        *(uint64_t *)(reverse + offset) = *(uint64_t *)upIOF;
        *(reverse + offset) ^= 1;
        offset += 8;
        for (int i = upHops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(upIOF + i * 8);
            offset += 8;
        }
        DEBUG("offset after down segment = %d\n", offset);
    } else if (type == NON_TDC_XOVR || type == INPATH_XOVR) {
        downIOF = upIOF + (upHops + 2) * 8;
        downHops = *(downIOF + 7);

        // up segment = reversed down segment
        *(uint64_t *)reverse = *(uint64_t *)downIOF;
        *reverse ^= 1;
        offset = 8;
        for (int i = downHops + 1; i > 1; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(downIOF + i * 8);
            offset += 8;
        }
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(downIOF + 8);
        offset += 8;
        DEBUG("offset after up segment = %d\n", offset);

        // down segment = reversed up segment
        *(uint64_t *)(reverse + offset) = *(uint64_t *)upIOF;
        *(reverse + offset) ^= 1;
        offset += 8;
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(upIOF + (upHops + 1) * 8);
        offset += 8;
        for (int i = upHops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(upIOF + i * 8);
            offset += 8;
        }
        DEBUG("offset after down segment = %d\n", offset);
    } else {
        downIOF = upIOF + (upHops + 3) * 8;
        downHops = *(downIOF + 7);

        // up segment = reversed down segment
        *(uint64_t *)reverse = *(uint64_t *)downIOF;
        *reverse ^= 1;
        offset = 8;
        for (int i = downHops + 2; i > 2; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(downIOF + i * 8);
            offset += 8;
        }
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(downIOF + 16);
        offset += 8;
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(downIOF + 8);
        offset += 8;
        DEBUG("offset after up segment = %d\n", offset);

        // down segment = reversed up segment
        *(uint64_t *)(reverse + offset) = *(uint64_t *)upIOF;
        *(reverse + offset) ^= 1;
        offset += 8;
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(upIOF + (upHops + 2) * 8);
        offset += 8;
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(upIOF + (upHops + 1) * 8);
        offset += 8;
        for (int i = upHops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(upIOF + i * 8);
            offset += 8;
        }
        DEBUG("offset after down segment = %d\n", offset);
    }

    if (offset != len) {
        DEBUG("Size mismatch reversing core path\n");
        return -1;
    }

    return 0;
}

uint64_t createRandom(int bits)
{
    // Eventually use better randomness
    uint64_t r;
    srand(time(NULL));
    r = random();
    if (bits == 32)
        return r;
    r = r << 32;
    r |= random();
    if (bits == 64)
        return r;
    return r & ((1 << bits) - 1);
}

int registerFlow(int proto, void *data, int sock)
{
    DEBUG("register flow via socket %d\n", sock);

    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    memset(&addr, 0, addrLen);
    addr.sin_port = htons(SCIOND_DISPATCHER_PORT);
    addr.sin_addr.s_addr = inet_addr(SCIOND_API_HOST);

    int len;
    char buf[32];
    buf[0] = proto;
    switch (proto) {
        case SCION_PROTO_SDAMP: {
            SDAMPEntry *se = (SDAMPEntry *)data;
            memcpy(buf + 1, &se->flowID, sizeof(se->flowID));
            memcpy(buf + 9, &se->port, sizeof(se->port));
            len = 11;
            break;
        }
        case SCION_PROTO_SUDP: {
            SUDPEntry *se = (SUDPEntry *)data;
            memcpy(buf + 1, &se->port, sizeof(se->port));
            len = 3;
            break;
        }
        default:
            return -1;
    }
    int res = sendto(sock, buf, len, 0, (struct sockaddr *)&addr, addrLen);
    if (res < 0) {
        DEBUG("sendto failed\n");
        return res;
    }
    res = recvfrom(sock, buf, 1, 0, NULL, NULL);
    if (res < 0)
        DEBUG("recvfrom failed\n");
    return res;
}

void destroyStats(SCIONStats *stats)
{
    for (int i = 0; i < MAX_TOTAL_PATHS; i++) {
        if (stats->ifCounts[i] > 0)
            free(stats->ifLists[i]);
    }
    free(stats);
}
