#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/* 
 * Initialize SCION UDP header
 * buf: Pointer to start of SCION packet
 * payload_len: Length of payload data
 */
void build_scion_udp(uint8_t *buf, uint16_t payload_len)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *ptr = (uint8_t *)sch + sch->header_len;
    *(uint16_t *)ptr = htons(SCION_UDP_PORT);
    ptr += 2;
    *(uint16_t *)ptr = htons(SCION_UDP_PORT);
    ptr += 2;
    *(uint16_t *)ptr = htons(payload_len);
    ptr += 2;
    *(uint16_t *)ptr = 0; // checksum, calculate later
    ptr += 2;
}

/*
 * Get payload class of SCION UDP packet
 * buf: Pointer to start of SCION packet
 * return value: Payload class, 0xFF on error
 */
uint8_t get_payload_class(uint8_t *buf)
{
    if (!buf)
        return 0xFF;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return *(uint8_t *)((uint8_t *)sch + sch->header_len + sizeof(SCIONUDPHeader));
}

/*
 * Get payload type of SCION UDP packet
 * buf: Pointer to start of SCION packet
 * return value: Payload type, 0xFF on error
 */
uint8_t get_payload_type(uint8_t *buf)
{
    if (!buf)
        return 0xFF;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return *(uint8_t *)((uint8_t *)sch + sch->header_len + sizeof(SCIONUDPHeader) + 1);
}

/*
 * Calculate UDP checksum
 * Same as regular IP/UDP checksum but IP addrs replaced with SCION addrs
 * buf: Pointer to start of SCION packet
 * return value: Checksum value, 0 on error
 */
uint16_t scion_udp_checksum(uint8_t *buf)
{
    if (!buf)
        return 0;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint32_t sum = 0;
    int i;
    int src_len = get_src_len(buf) + ISD_AS_LEN;
    int dst_len = get_dst_len(buf) + ISD_AS_LEN;
    uint16_t payload_len;
    int total;
    SCIONUDPHeader *udp_hdr;

    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    udp_hdr = (SCIONUDPHeader *)l4ptr;

    payload_len = ntohs(udp_hdr->len);
    // Length in UDP header includes header size, so subtract it.
    payload_len -= sizeof(SCIONUDPHeader);

    int phdr_len = src_len + dst_len + 1 + 6 + payload_len;
    if (phdr_len % 2 != 0)
        phdr_len++;
    uint8_t phdr[phdr_len];
    uint8_t *ptr = phdr;

    /* 
     * Build pseudoheader:
     * src SCION addr
     * dst SCION addr
     * protocol number
     * src port, dst port, len of UDP header
     * payload
     */
    memcpy(ptr, sch + 1, src_len + dst_len);
    ptr += src_len + dst_len;
    *ptr = L4_UDP;
    ptr++;
    memcpy(ptr, (uint8_t *)udp_hdr, 6); // src port, dst port, len
    ptr += 6;
    memcpy(ptr, (uint8_t *)udp_hdr + sizeof(SCIONUDPHeader), payload_len);
    ptr += payload_len;

    /* Pad to even bytes */
    total = ptr - phdr;
    if (total % 2 != 0) {
        *ptr = 0;
        ptr++;
        total++;
    }

    /* Calculate checksum */
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

/*
 * Calculate and update checksum field of SCION UDP header
 * buf: Pointer to start of SCION packet
 */
void update_scion_udp_checksum(uint8_t *buf)
{
    if (!buf)
        return;

    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    SCIONUDPHeader *scion_udp_hdr = (SCIONUDPHeader *)l4ptr;
    scion_udp_hdr->checksum = htons(scion_udp_checksum(buf));
}

/*
 * Reverse SCION UDP header
 * l4ptr: Pointer to start of UDP header
 */
void reverse_udp_header(uint8_t *l4ptr)
{
    if (!l4ptr)
        return;

    SCIONUDPHeader *udp = (SCIONUDPHeader *)l4ptr;
    uint16_t src = udp->src_port;
    udp->src_port = udp->dst_port;
    udp->dst_port = src;
}
