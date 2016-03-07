#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

void build_scion_udp(uint8_t *buf, uint16_t payload_len)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *ptr = (uint8_t *)sch + sch->headerLen;
    *(uint16_t *)ptr = htons(SCION_UDP_PORT);
    ptr += 2;
    *(uint16_t *)ptr = htons(SCION_UDP_PORT);
    ptr += 2;
    *(uint16_t *)ptr = htons(payload_len);
    ptr += 2;
    *(uint16_t *)ptr = 0; // checksum, calculate later
    ptr += 2;
}

uint8_t get_payload_class(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return *(uint8_t *)((void *)sch + sch->headerLen + sizeof(SCIONUDPHeader));
}

uint8_t get_payload_type(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return *(uint8_t *)((uint8_t *)sch + sch->headerLen + sizeof(SCIONUDPHeader) + 1);
}

uint16_t scion_udp_checksum(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint32_t sum = 0;
    int i;
    int src_len = get_src_len(buf);
    int dst_len = get_dst_len(buf);
    uint8_t phdr[ntohs(sch->totalLen)]; // UDP packet + pseudoheader < totalLen
    uint8_t *ptr = phdr;
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

    total = ptr - phdr;
    if (total % 2 != 0) {
        *ptr = 0;
        ptr++;
        total++;
    }

    for (i = 0; i < total; i += 2)
        sum += *(uint16_t *)(phdr + i);
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

void update_scion_udp_checksum(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    SCIONUDPHeader *scion_udp_hdr =
        (SCIONUDPHeader *)((uint8_t *)sch + sch->headerLen);
    scion_udp_hdr->checksum = htons(scion_udp_checksum(buf));
    //printf("SCION UDP checksum=%x\n",scion_udp_hdr->dgram_cksum);
}
