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
 * src_port: UDP source port, in network byte order.
 * dst_port: UDP destination port, in network byte order.
 * payload_len: Length of payload data in network byte order.
 */
void build_scion_udp(uint8_t *buf, uint16_t src_port, uint16_t dst_port, uint16_t payload_len)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    SCIONUDPHeader *uhdr = (SCIONUDPHeader *)(buf + sch->header_len);
    uhdr->src_port = src_port;
    uhdr->dst_port = dst_port;
    uhdr->len = payload_len;
    uhdr->checksum = 0;  // calculate later
}

/*
 * Get payload class of SCION UDP packet
 * buf: Pointer to start of SCION packet
 * return value: Payload class
 */
uint8_t get_payload_class(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return *(uint8_t *)((uint8_t *)sch + sch->header_len + sizeof(SCIONUDPHeader));
}

/*
 * Get payload type of SCION UDP packet
 * buf: Pointer to start of SCION packet
 * return value: Payload type
 */
uint8_t get_payload_type(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return *(uint8_t *)((uint8_t *)sch + sch->header_len + sizeof(SCIONUDPHeader) + 1);
}

/*
 * Calculate UDP checksum
 * Same as regular IP/UDP checksum but IP addrs replaced with SCION addrs
 * buf: Pointer to start of SCION packet
 * return value: Checksum value
 */
uint16_t scion_udp_checksum(uint8_t *buf)
{
    uint8_t *ptr = buf + sizeof(SCIONCommonHeader);
    chk_input *input = mk_chk_input(5);
    SCIONUDPHeader *udp_hdr;
    uint8_t l4_type;
    uint16_t payload_len, ret;

    // Src ISD-AS & host address
    ptr = chk_add_chunk(input, 0, ptr, ISD_AS_LEN + get_src_len(buf));
    // Dest ISD-AS & host address
    chk_add_chunk(input, 1, ptr, ISD_AS_LEN + get_dst_len(buf));
    ptr = buf;
    l4_type = get_l4_proto(&ptr);
    udp_hdr = (SCIONUDPHeader *)ptr;
    // L4 protocol type
    chk_add_chunk(input, 2, &l4_type, 1);
    // udp src+dst port and len fields.
    ptr = chk_add_chunk(input, 3, ptr, 6);
    // Skip checksum field
    ptr += 2;
    // Length in UDP header includes header size, so subtract it.
    payload_len = ntohs(udp_hdr->len) - sizeof(SCIONUDPHeader);
    chk_add_chunk(input, 4, ptr, payload_len);

    ret = checksum(input);
    rm_chk_input(input);
    return ret;
}

/*
 * Calculate and update checksum field of SCION UDP header
 * buf: Pointer to start of SCION packet
 */
void update_scion_udp_checksum(uint8_t *buf)
{
    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    SCIONUDPHeader *scion_udp_hdr = (SCIONUDPHeader *)l4ptr;
    scion_udp_hdr->checksum = scion_udp_checksum(buf);
}

/*
 * Reverse SCION UDP header
 * l4ptr: Pointer to start of UDP header
 */
void reverse_udp_header(uint8_t *l4ptr)
{
    SCIONUDPHeader *udp = (SCIONUDPHeader *)l4ptr;
    uint16_t src = udp->src_port;
    udp->src_port = udp->dst_port;
    udp->dst_port = src;
}

/*
 * Print fields in UDP header
 * buf: Pointer to start of SCION packet
 */
void print_udp_header(uint8_t *buf) {
    uint8_t *l4ptr = buf;
    get_l4_proto(&l4ptr);
    SCIONUDPHeader *scion_udp_hdr = (SCIONUDPHeader *)l4ptr;
    fprintf(stderr, "Src port: %d Dst port: %d Length: %d Checksum: %04x\n",
            ntohs(scion_udp_hdr->src_port), ntohs(scion_udp_hdr->dst_port),
            ntohs(scion_udp_hdr->len), scion_udp_hdr->checksum);
}
