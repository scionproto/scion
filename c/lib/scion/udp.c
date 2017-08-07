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
    SCIONUDPHeader *uhdr = (SCIONUDPHeader *)(buf + sch->header_len * LINE_LEN);
    uhdr->src_port = src_port;
    uhdr->dst_port = dst_port;
    uhdr->len = payload_len;
    uhdr->checksum = 0;  // calculate later
}

/*
 * Calculate UDP checksum
 * Same as regular IP/UDP checksum but IP addrs replaced with SCION addrs
 * buf: Pointer to start of SCION packet
 * return value: Checksum value
 */
uint16_t scion_udp_checksum(uint8_t *buf, chk_input *input)
{
    SCIONUDPHeader *udp_hdr;
    uint16_t l4_type;
    uint16_t payload_len, blank_sum = 0;

    // Reset input index to 0, to allow simple re-use by callers.
    input->idx = 0;

    // Address header (without padding)
    chk_add_chunk(input, buf + DST_IA_OFFSET, get_addrs_len(buf));

    uint8_t *ptr = buf;
    // Load LSB of l4_type with protocol number, then put in network order
    l4_type = htons((uint16_t)get_l4_proto(&ptr));
    udp_hdr = (SCIONUDPHeader *)ptr;
    // L4 protocol type
    chk_add_chunk(input, (uint8_t*)&l4_type, 2);
    // udp src+dst port and len fields.
    ptr = chk_add_chunk(input, ptr, 6);
    // Use blank checksum field
    chk_add_chunk(input, (uint8_t *)(&blank_sum), 2);
    ptr += 2;
    // Length in UDP header includes header size, so subtract it.
    payload_len = ntohs(udp_hdr->len) - sizeof(SCIONUDPHeader);
    chk_add_chunk(input, ptr, payload_len);

    return checksum(input);
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
