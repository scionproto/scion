#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

uint8_t L4PROTOCOLS[] = {L4_SCMP, L4_TCP, L4_UDP, L4_SSP};

/*
 * Initialize common header fields
 * buf: Pointer to start of SCION packet
 * src_type: Address type of src host addr
 * dst_type: Address type of dst host addr
 * next_hdr: L4 protocol number or extension type
 */
void build_cmn_hdr(void *buf, int src_type, int dst_type, int next_hdr)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint16_t vsd = 0;
    vsd |= src_type << 6;
    vsd |= dst_type;
    sch->ver_src_dst = htons(vsd);
    sch->next_header = next_hdr;

    int addr_len = padded_addr_len(buf);
    sch->header_len = sizeof(SCIONCommonHeader) + addr_len;
    sch->total_len = htons(sch->header_len);
    /* Set of pointers to start of path (which has not been set yet) */
    sch->current_iof = sch->header_len;
    sch->current_hof = sch->current_iof;
}

/*
 * Initialize address fields
 * buf: Pointer to start of SCION packet
 * src: Src SCION addr
 * dst: Dst SCION addr
 */
void build_addr_hdr(void *buf, SCIONAddr *src, SCIONAddr *dst)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    int src_len = get_src_len(buf);
    int dst_len = get_dst_len(buf);
    uint8_t *ptr = (uint8_t *)(sch + 1);
    *(uint32_t *)ptr = htonl(src->isd_as);
    ptr += ISD_AS_LEN;
    memcpy(ptr, src->host.addr, src_len);
    ptr += src_len;
    *(uint32_t *)ptr = htonl(dst->isd_as);
    ptr += ISD_AS_LEN;
    memcpy(ptr, dst->host.addr, dst_len);
}

/*
 * Get total length of addresses with padding
 * buf: Pointer to start of SCION packet
 * return value: Total padded addr length, -1 on error
 */
int padded_addr_len(void *buf)
{
    if (!buf)
        return -1;
    int addr_len = get_src_len(buf) + get_dst_len(buf) + 2 * ISD_AS_LEN;
    return (addr_len + SCION_ADDR_PAD - 1) & ~(SCION_ADDR_PAD - 1);
}

/*
 * Set SCION path
 * buf: Pointer to start of SCION packet
 * path: Pointer to start of path data to be copied
 */
void set_path(void *buf, uint8_t *path, int len)
{
    if (!buf || len < 0)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    /* pre-condition: header_len points to end of address header */
    memcpy(buf + sch->header_len, path, len);
    sch->header_len += len;
    sch->total_len = htons(sch->header_len);
}

/*
 * Get SCION path
 * buf: Pointer to start of SCION packet
 * return value: Pointer to start of SCION path in packet, NULL on error
 */
uint8_t * get_path(void *buf)
{
    if (!buf)
        return NULL;
    return buf + sizeof(SCIONCommonHeader) + padded_addr_len(buf);
}

/*
 * Get length of SCION path
 * buf: Pointer to start of SCION packet
 * return value: Length of SCION path in packet
 */
int get_path_len(void *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ntohs(sch->header_len) - (get_path(buf) - (uint8_t *)buf);
}

/*
 * Get total length of headers including extensions
 * buf: Pointer to start of SCION packet
 * return value: Length of combined SCION headers, -1 on error
 */
int get_scion_layer_len(void *buf)
{
    if (!buf)
        return -1;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    int ext_len = get_total_ext_len(buf);
    if (ext_len < 0)
        return -1;
    return sch->header_len + ext_len;
}

/*
 * Initialize OF indices (pointers)
 * buf: Pointer to start of SCION packet
 */
void init_of_idx(void *buf)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;

    uint8_t *iof = buf + sch->current_iof;
    uint8_t *hof = buf + sch->current_iof + SCION_OF_LEN;
    if ((*iof & IOF_FLAG_PEER) && (*hof & HOF_FLAG_XOVER))
        sch->current_hof += SCION_OF_LEN;

    inc_hof_idx(buf);
}

/*
 * Increment HOF pointer to next valid HOF
 * buf: Pointer to start of SCION packet
 */
void inc_hof_idx(void *buf)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *iof = buf + sch->current_iof;
    uint8_t *hof = buf + sch->current_hof;
    int hops = *(iof + SCION_OF_LEN - 1);

    while (1) {
        sch->current_hof += SCION_OF_LEN;
        if ((sch->current_hof - sch->current_iof) / SCION_OF_LEN > hops) {
            /* Move to next segment */
            sch->current_iof = sch->current_hof;
            iof = buf + sch->current_iof;
            hops = *(iof + SCION_OF_LEN - 1);
            continue;
        }
        hof = buf + sch->current_hof;
        /* Skip VERIFY_ONLY HOFs */
        if (!(*hof & HOF_FLAG_VERIFY_ONLY))
            break;
    }
}

/*
 * Check if current header is a known L4 protocol
 * type: Current header type
 * return value: 1 if type is known L4 protocol, 0 otherwise
 */
int is_known_proto(uint8_t type)
{
    size_t i;
    for (i = 0; i < sizeof(L4PROTOCOLS); i++) {
        if (L4PROTOCOLS[i] == type)
            return 1;
    }
    return 0;
}

/*
 * Get L4 protocol and start of L4 header
 * l4ptr: Pointer to pointer to start of SCION packet. When the function
 *        returns it will point to the start of the L4 header.
 * return value: L4 protocol of packet, 0 on error
 */
uint8_t get_l4_proto(uint8_t **l4ptr)
{
    if (!l4ptr || !*l4ptr)
        return 0;

    uint8_t *ptr = *l4ptr;
    SCIONCommonHeader *sch = (SCIONCommonHeader *)ptr;
    uint8_t currentHeader = sch->next_header;
    ptr += sch->header_len;
    while (!is_known_proto(currentHeader)) {
        currentHeader = *ptr;
        size_t nextLen = *(ptr + 1);
        nextLen = (nextLen + 1) * 8;
        ptr += nextLen;
    }
    *l4ptr = ptr;
    return currentHeader;
}

/*
 * Reverse the direction of all headers
 * buf: Pointer to start of SCION packet
 */
void reverse_packet(void *buf)
{
    if (!buf)
        return;

    uint8_t *srcptr = buf + sizeof(SCIONCommonHeader);
    int srclen = get_src_len(buf) + ISD_AS_LEN;
    uint8_t *dstptr = srcptr + srclen;
    int dstlen = get_dst_len(buf) + ISD_AS_LEN;
    uint8_t *orig_src = (uint8_t *)malloc(srclen);
    /* reverse src/dst addrs */
    memcpy(orig_src, srcptr, srclen);
    memcpy(srcptr, dstptr, dstlen);
    memcpy(dstptr, orig_src, srclen);
    int pathlen = get_path_len(buf);
    /* Reverse path */
    uint8_t *reverse = (uint8_t *)malloc(pathlen);
    reverse_path(buf, reverse);
    memcpy(get_path(buf), reverse, pathlen);
    /* Reverse L4 header if necessary */
    uint8_t *ptr = buf;
    uint8_t l4 = get_l4_proto(&ptr);
    switch (l4) {
        case L4_UDP:
            reverse_udp_header(ptr);
            break;
        default:
            /* other protocols may be added later as they become necessary */
            break;
    }
}

void print_header(void *buf) {
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    fprintf(stderr, "Version: %d Src type: %d Dest type: %d Total len: %dB\n",
           PROTO_VER(sch), SRC_TYPE(sch), DST_TYPE(sch), ntohs(sch->total_len));
    fprintf(stderr, "IOF offset: %dB HOF offset: %dB Next hdr: %d Header len: %dB\n",
           sch->current_iof, sch->current_hof, sch->next_header, sch->header_len);
}
