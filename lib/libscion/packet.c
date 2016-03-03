#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

uint8_t L4PROTOCOLS[] = {L4_ICMP, L4_TCP, L4_UDP, L4_SSP};

/*
 * Initialize common header fields
 * buf: Pointer to start of SCION packet
 * src_type: Address type of src host addr
 * dst_type: Address type of dst host addr
 * next_hdr: L4 protocol number or extension type
 */
void build_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
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

/*
 * Initialize address fields
 * buf: Pointer to start of SCION packet
 * src: Src SCION addr
 * dst: Dst SCION addr
 */
void build_addr_hdr(uint8_t *buf, uint8_t *src, uint8_t *dst)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    int src_len = get_src_len(buf);
    int dst_len = get_dst_len(buf);
    int pad = (SCION_ADDR_PAD - ((src_len + dst_len) % 8)) % 8;
    uint8_t *ptr = (uint8_t *)(sch + 1);
    SCIONAddr *src_addr = (SCIONAddr *)src;
    SCIONAddr *dst_addr = (SCIONAddr *)dst;
    *(uint32_t *)ptr = htonl(src_addr->isd_ad);
    ptr += 4;
    memcpy(ptr, src->host_addr, src_len);
    ptr += src_len;
    *(uint32_t *)ptr = htonl(dst->isd_ad);
    ptr += 4;
    memcpy(ptr, dst->host_addr, dst_len);
    sch->headerLen += src_len + dst_len + 8 + pad;
    sch->totalLen = htons(sch->headerLen);
}

/*
 * Initialize OF indices (pointers)
 * buf: Pointer to start of SCION packet
 */
void init_of_idx(uint8_t *buf)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    int addr_len = get_src_len(buf) + get_dst_len(buf) + 2 * SCION_ISD_AD_LEN;
    addr_len = (addr_len + SCION_ADDR_PAD - 1) & ~(SCION_ADDR_PAD - 1);
    sch->currentIOF = sizeof(SCIONCommonHeader) + addr_len;
    sch->currentOF = sch->currentIOF;

    uint8_t *iof = buf + sch->currentIOF;
    uint8_t *hof = buf + sch->currentIOF + SCION_OF_LEN;
    if ((*iof & IOF_FLAG_PEER) && (*hof & HOF_FLAG_XOVER))
        sch->currentOF += SCION_OF_LEN;

    inc_hof_idx(buf);
}

/*
 * Increment HOF pointer to next valid HOF
 * buf: Pointer to start of SCION packet
 */
void inc_hof_idx(uint8_t *buf)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *iof = buf + sch->currentIOF;
    uint8_t *hof = buf + sch->currentOF;
    int hops = *(iof + SCION_OF_LEN - 1);

    while (1) {
        sch->currentOF += SCION_OF_LEN;
        if ((sch->currentOF - sch->currentIOF) / SCION_OF_LEN > hops) {
            /* Move to next segment */
            sch->currentIOF = sch->currentOF;
            iof = buf + sch->currentIOF;
            hops = *(iof + SCION_OF_LEN - 1);
            continue;
        }
        hof = buf + sch->currentOF;
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
    uint8_t currentHeader = sch->nextHeader;
    ptr += sch->headerLen;
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
void reverse_packet(uint8_t *buf)
{
    if (!buf)
        return;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *srcptr = buf + sizeof(SCIONCommonHeader);
    int srclen = get_src_len(buf) + SCION_ISD_AD_LEN;
    uint8_t *dstptr = srcptr + srclen;
    int dstlen = get_dst_len(buf) + SCION_ISD_AD_LEN;
    uint8_t *orig_src = (uint8_t *)malloc(srclen);
    /* reverse src/dst addrs */
    memcpy(orig_src, srcptr, srclen);
    memcpy(srcptr, dstptr, dstlen);
    memcpy(dstptr, orig_src, srclen);
    int pathlen = sch->headerLen - srclen - dstlen - sizeof(SCIONCommonHeader);
    /* Account for padding if any */
    int rem = (srclen + dstlen) % SCION_ADDR_PAD;
    if (rem != 0)
        pathlen -= SCION_ADDR_PAD - rem;
    uint8_t *path = buf + sch->headerLen - pathlen;
    /* Reverse path */
    uint8_t *reverse = (uint8_t *)malloc(pathlen);
    reverse_path(buf, path, reverse, pathlen);
    memcpy(path, reverse, pathlen);
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
