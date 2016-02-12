#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include "Utils.h"

int comparePacketNum(void *p1, void *p2)
{
    L4Packet *sp1 = (L4Packet *)p1;
    L4Packet *sp2 = (L4Packet *)p2;
    return sp1->number() - sp2->number();
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
    header->flowID = be64toh(*(uint64_t *)ptr);
    ptr += 8;
    header->port = ntohs(*ptr);
    ptr += 2;
    header->headerLen = *ptr;
    ptr++;
    header->offset = be64toh(*(uint64_t *)ptr);
    ptr += 8;
    header->flags = *ptr;
    ptr++;
    header->mark = *ptr;
}

void buildSSPAck(SSPAck *ack, uint8_t *ptr)
{
    ack->L = be64toh(*(uint64_t *)ptr);
    ptr += 8;
    ack->I = ntohl(*(int32_t *)ptr);
    ptr += 4;
    ack->H = ntohl(*(int32_t *)ptr);
    ptr += 4;
    ack->O = ntohl(*(int32_t *)ptr);
    ptr += 4;
    ack->V = ntohl(*(uint32_t *)ptr);
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

int reverseCorePath(uint8_t *original, uint8_t *reverse, int len)
{
    int offset = 0;
    uint8_t *upIOF = original;
    uint8_t upHops = *(upIOF + 7);
    uint8_t *coreIOF = upIOF + (upHops + 1) * 8;
    uint8_t coreHops = *(coreIOF + 7);
    uint8_t *downIOF = coreIOF + (coreHops + 1) * 8;
    uint8_t downHops = *(downIOF + 7);

    if (downIOF >= original + len) {
        downIOF = coreIOF;
        downHops = coreHops;
        coreIOF = NULL;
        coreHops = 0;
    } else {
        downHops = *(downIOF + 7);
    }
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
    return offset;
}

int reverseCrossoverPath(uint8_t *original, uint8_t *reverse, int len)
{
    int offset = 0;
    uint8_t *upIOF = original;
    uint8_t upHops = *(upIOF + 7);
    uint8_t *downIOF = upIOF + (upHops + 2) * 8;
    uint8_t downHops = *(downIOF + 7);

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
    return offset;
}

int reversePeerPath(uint8_t *original, uint8_t *reverse, int len)
{
    int offset = 0;
    uint8_t *upIOF = original;
    uint8_t upHops = *(upIOF + 7);
    uint8_t *downIOF = upIOF + (upHops + 3) * 8;
    uint8_t downHops = *(downIOF + 7);

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
    return offset;
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
    uint8_t type = *original >> 1;
    if (type == TDC_XOVR)
        offset = reverseCorePath(original, reverse, len);
    else if (type == NON_TDC_XOVR || type == INPATH_XOVR)
        offset = reverseCrossoverPath(original, reverse, len);
    else
        offset = reversePeerPath(original, reverse, len);

    if (offset != len) {
        DEBUG("Size mismatch reversing core path\n");
        return -1;
    }

    return 0;
}

uint64_t createRandom(int bits)
{
    // Eventually use better randomness
    int fd = open("/dev/urandom", O_RDONLY);
    uint64_t r;
    read(fd, &r, 8);
    if (bits == 64)
        return r;
    return r & ((1 << bits) - 1);
}

int registerFlow(int proto, void *data, int sock, uint8_t reg)
{
    DEBUG("register flow via socket %d\n", sock);

    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    memset(&addr, 0, addrLen);
    addr.sin_port = htons(SCIOND_DISPATCHER_PORT);
    addr.sin_addr.s_addr = inet_addr(SCIOND_API_HOST);

    int len;
    char buf[32];
    buf[0] = reg;
    buf[1] = proto;
    switch (proto) {
        case SCION_PROTO_SSP: {
            SSPEntry *se = (SSPEntry *)data;
            memcpy(buf + 2, &se->flowID, sizeof(se->flowID));
            memcpy(buf + 10, &se->port, sizeof(se->port));
            len = 12;
            break;
        }
        case SCION_PROTO_UDP: {
            SUDPEntry *se = (SUDPEntry *)data;
            memcpy(buf + 2, &se->port, sizeof(se->port));
            len = 4;
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

int isL4(uint8_t headerType)
{
    switch (headerType) {
    case SCION_PROTO_ICMP:
    case SCION_PROTO_TCP:
    case SCION_PROTO_UDP:
    case SCION_PROTO_SSP:
    case SCION_PROTO_NONE:
    case SCION_PROTO_RES:
        return headerType;
    default:
        return 0;
    }
}

uint16_t checksum(SCIONPacket *packet)
{
    SCIONHeader *sh = &packet->header;
    SUDPPacket *sp = (SUDPPacket *)(packet->payload);
    SUDPHeader *uh = &sp->header;
    uint32_t sum = 0;
    int i;
    uint8_t buf[uh->len + 2 * SCION_ADDR_LEN + 1];
    uint8_t *ptr = buf;
    int total;

    memcpy(ptr, sh->srcAddr, SCION_ADDR_LEN);
    ptr += SCION_ADDR_LEN;
    memcpy(ptr, sh->dstAddr, SCION_ADDR_LEN);
    ptr += SCION_ADDR_LEN;
    *ptr++ = SCION_PROTO_UDP;
    *(uint16_t *)ptr = uh->srcPort;
    ptr += 2;
    *(uint16_t *)ptr = uh->dstPort;
    ptr += 2;
    *(uint16_t *)ptr = uh->len;
    ptr += 2;
    memcpy(ptr, sp->payload, sp->payloadLen);
    ptr += sp->payloadLen;

    total = ptr - buf;
    if (total % 2 != 0) {
        *ptr = 0;
        ptr++;
        total++;
    }

    for (i = 0; i < total; i += 2)
        sum += *(uint16_t *)(buf + i);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    sum = ~sum;

    if (htons(1) == 1) {
        /* Big endian */
        return sum & 0xffff;
    } else {
        /* Little endian */
        return (((sum >> 8) & 0xff) | sum << 8) & 0xffff;
    }
}
