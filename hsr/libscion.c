#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#include "libscion.h"

#define UDP_HDRLEN 8

const int ADDR_LENS[] = {0, 4, 16, 2};

unsigned char *get_dstaddr(SCIONCommonHeader *sch) {
    uint8_t src_len;
    uint8_t src_type = (ntohs(sch->versionSrcDst) & 0xfc0) >> 6;

    if (src_type < ADDR_NONE_TYPE || src_type > ADDR_SVC_TYPE)
        return NULL;

    src_len = ADDR_LENS[src_type];
    return (unsigned char *)sch + sizeof(*sch) + SCION_ISD_AD_LEN +
        src_len + SCION_ISD_AD_LEN;
}

uint8_t get_type(SCIONCommonHeader *sch) {

    uint8_t src_type = SRC_TYPE(sch);
    uint8_t dst_type = DST_TYPE(sch);

    if ((src_type == ADDR_IPV4_TYPE || src_type == ADDR_IPV6_TYPE) &&
            (dst_type == ADDR_IPV4_TYPE || dst_type == ADDR_IPV6_TYPE))
        return DATA_PACKET;

    uint8_t payload_class =
        *(uint8_t *)((void *)sch + sch->headerLen + UDP_HDRLEN);

    switch (payload_class) {
        case PCB_CLASS:
            return BEACON_PACKET;
        case IFID_CLASS:
            return IFID_PKT_PACKET;
        case CERT_CLASS:
            return CERT_CHAIN_REQ_PACKET;
        case PATH_CLASS:
            return PATH_MGMT_PACKET;
        default:
            fprintf(stderr, "Unknown packet class\n");
            return PACKET_TYPE_ERROR;
    }
}

uint8_t is_on_up_path(InfoOpaqueField *currOF) {
    // low bit of type field is used for uppath/downpath flag
    if ((currOF->info & 0x1) == 1)
        return 1;
    return 0;
}

uint8_t is_last_path_of(SCIONCommonHeader *sch) {
    uint8_t offset = sch->headerLen -  sizeof(HopOpaqueField);
    //printf("is_last_path_of %d %d\n",sch->currentOF, offset);
    return sch->currentOF == offset;
}

uint8_t is_regular(HopOpaqueField *currOF) {
    if ((currOF->info & (1 << 6)) == 0)
        return 0;
    return 1;
}

uint8_t is_continue(HopOpaqueField *currOF) {
    if ((currOF->info & (1 << 5)) == 0)
        return 0;
    return 1;
}
uint8_t is_xovr(HopOpaqueField *currOF) {
    if ((currOF->info & (1 << 4)) == 0)
        return 0;
    return 1;
}

uint16_t scion_udp_checksum(SCIONCommonHeader *sch)
{
    uint32_t sum = 0;
    int i;
    int src_len = ADDR_LENS[SRC_TYPE(sch)];
    int dst_len = ADDR_LENS[DST_TYPE(sch)];
    uint8_t buf[ntohs(sch->totalLen)]; // UDP packet + pseudoheader < totalLen
    uint8_t *ptr = buf;
    uint16_t payload_len;
    int total;
    SCIONUDPHeader *udp_hdr;

    udp_hdr = (SCIONUDPHeader *)((uint8_t *)sch + sch->headerLen);

    payload_len = ntohs(udp_hdr->len);
    // Length in UDP header includes header size, so subtract it.
    payload_len -= sizeof(SCIONUDPHeader);

    memcpy(ptr, sch + 1, src_len + dst_len + 8);
    ptr += src_len + dst_len + 8;
    *ptr = L4_UDP;
    ptr++;
    memcpy(ptr, (uint8_t *)sch + sch->headerLen, 6);
    ptr += 6;
    memcpy(ptr, (uint8_t *)sch + sch->headerLen + 8, payload_len);
    ptr += payload_len;

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

void update_scion_udp_checksum(SCIONCommonHeader *sch){
    SCIONUDPHeader *scion_udp_hdr =
        (SCIONUDPHeader *)((uint8_t *)sch + sch->headerLen);
    scion_udp_hdr->checksum = htons(scion_udp_checksum(sch));
    //printf("SCION UDP checksum=%x\n",scion_udp_hdr->dgram_cksum);
}

    void
build_cmn_hdr(SCIONCommonHeader *sch, int src_type, int dst_type, int next_hdr)
{
    uint16_t vsd = 0;
    vsd |= src_type << 6;
    vsd |= dst_type;
    sch->versionSrcDst = htons(vsd);
    sch->nextHeader = next_hdr;
    sch->headerLen = sizeof(*sch);
    sch->currentIOF = 0;
    sch->currentOF = 0;
    sch->totalLen = htons(sch->headerLen);
}

void build_addr_hdr(SCIONCommonHeader *sch, SCIONAddr *src, SCIONAddr *dst)
{
    uint8_t src_type = SRC_TYPE(sch);
    int src_len = ADDR_LENS[src_type];
    uint8_t dst_type = DST_TYPE(sch);
    int dst_len = ADDR_LENS[dst_type];
    int pad = (SCION_ADDR_PAD - ((src_len + dst_len) % 8)) % 8;
    uint8_t *ptr = (uint8_t *)sch + sizeof(*sch);
    *(uint32_t *)ptr = htonl(src->isd_ad);
    ptr += 4;
    memcpy(ptr, src->host_addr, src_len);
    ptr += src_len;
    *(uint32_t *)ptr = htonl(dst->isd_ad);
    ptr += 4;
    memcpy(ptr, dst->host_addr, dst_len);
    sch->headerLen += src_len + dst_len + 8 + pad;
    sch->totalLen = htons(sch->headerLen);
}

void build_scion_udp(SCIONCommonHeader *sch, uint16_t payload_len)
{
    uint8_t *ptr = (uint8_t *)sch + sch->headerLen;
    *(uint16_t *)ptr = htons(SCION_UDP_PORT);
    ptr += 2;
    *(uint16_t *)ptr = htons(SCION_UDP_PORT);
    ptr += 2;
    *(uint16_t *)ptr = htons(payload_len);
    ptr += 2;
    *(uint16_t *)ptr = 0; // checksum, calculate later
    ptr += 2;
    return ptr;
}
