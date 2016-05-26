#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

uint8_t L4PROTOCOLS[] = {L4_SCMP, L4_TCP, L4_UDP, L4_SSP};

spkt_t * build_spkt(saddr_t *src, saddr_t *dst, spath_t *path, exts_t *exts, l4_pkt *l4)
{
    spkt_t *spkt = (spkt_t *)malloc(sizeof(spkt_t));
    spkt->sch = (sch_t *)malloc(sizeof(sch_t));
    uint8_t next_header;
    if (exts && exts->count > 0) {
        seh_t *first_ext = exts->extensions;
        next_header = first_ext->ext_class;
    } else {
        next_header = l4->type;
    }
    pack_cmn_hdr((uint8_t *)spkt->sch, src->type, dst->type, next_header);
    spkt->src = src;
    spkt->dst = dst;
    spkt->path = path;
    spkt->exts = exts;
    spkt->l4 = l4;
    return spkt;
}

spkt_t * parse_spkt(uint8_t *buf)
{
    // assumption: buf is not freed or overwritten throughout the lifetime of spkt
    // this is to avoid some potentially large memcpy()s
    spkt_t *spkt = (spkt_t *)malloc(sizeof(spkt_t));
    parse_spkt_cmn_hdr(buf, spkt);
    parse_spkt_addr_hdr(buf, spkt);
    parse_spkt_path(buf, spkt);
    parse_spkt_extensions(buf, spkt);
    parse_spkt_l4(buf, spkt);
    return spkt;
}

void parse_spkt_cmn_hdr(uint8_t *buf, spkt_t *spkt)
{
    sch_t *sch = (sch_t *)malloc(sizeof(sch_t));
    memcpy(sch, buf, sizeof(sch_t));
    spkt->sch = sch;
}

void parse_spkt_addr_hdr(uint8_t *buf, spkt_t *spkt)
{
    saddr_t *src = (saddr_t *)malloc(sizeof(saddr_t));
    src->type = SRC_TYPE(spkt->sch);
    memcpy(src->addr, buf + sizeof(sch_t), ISD_AS_LEN + get_addr_len(src->type));
    spkt->src = src;

    saddr_t *dst = (saddr_t *)malloc(sizeof(saddr_t));
    dst->type = DST_TYPE(spkt->sch);
    memcpy(dst->addr, get_dst_addr(buf) - ISD_AS_LEN, ISD_AS_LEN + get_addr_len(dst->type));
    spkt->dst = dst;
}

void parse_spkt_path(uint8_t *buf, spkt_t *spkt)
{
    spath_t *path = (spath_t *)malloc(sizeof(spath_t));
    memset(path, 0, sizeof(spath_t));
    path->len = get_path_len(buf);
    path->raw_path = get_path(buf);
    spkt->path = path;
}

void parse_spkt_extensions(uint8_t *buf, spkt_t *spkt)
{
    exts_t *exts = (exts_t *)malloc(sizeof(exts_t));
    memset(exts, 0, sizeof(exts_t));
    uint8_t curr = spkt->sch->next_header;
    uint8_t *ptr = buf + spkt->sch->header_len;
    while (!is_known_proto(curr)) {
        seh_t *seh = (seh_t *)malloc(sizeof(seh_t));
        memset(seh, 0, sizeof(seh_t));
        seh->next_header = *ptr;
        seh->len = (*(ptr + 1) + 1) * SCION_EXT_LINE;
        seh->ext_class = curr;
        seh->ext_type = *(ptr + 2);
        seh->payload = ptr + 3;
        curr = seh->next_header;
        ptr += seh->len;
        if (!exts->extensions)
            exts->extensions = seh;
        else
            exts->extensions->next = seh;
        exts->count++;
    }
    spkt->exts = exts;
}

void parse_spkt_l4(uint8_t *buf, spkt_t *spkt)
{
    uint8_t *l4ptr = buf;
    uint8_t l4proto = get_l4_proto(&l4ptr);
    l4_pkt *l4 = (l4_pkt *)malloc(sizeof(l4_pkt));
    l4->type = l4proto;
    l4->len = ntohs(spkt->sch->total_len) - (l4ptr - buf);
    l4->packet = l4ptr;
    spkt->l4 = l4;
}

void pack_spkt(spkt_t *spkt, uint8_t *buf)
{
    uint8_t *ptr = buf;

    ptr = pack_spkt_cmn_hdr(spkt, ptr);
    ptr = pack_spkt_addr_hdr(spkt, ptr);
    if (spkt->path && spkt->path->len > 0)
        ptr = pack_spkt_path(spkt, ptr);

    if (spkt->exts && spkt->exts->count > 0)
        ptr = pack_spkt_extensions(spkt, ptr);

    ptr = pack_spkt_l4(spkt, ptr);
}

uint8_t * pack_spkt_cmn_hdr(spkt_t *spkt, uint8_t *ptr)
{
    size_t len;
    len = sizeof(sch_t);
    memcpy(ptr, spkt->sch, len);
    return ptr + len;
}

uint8_t * pack_spkt_addr_hdr(spkt_t *spkt, uint8_t *ptr)
{
    uint8_t *start = ptr;
    size_t len;
    len = get_addr_len(spkt->src->type) + ISD_AS_LEN;
    memcpy(ptr, spkt->src->addr, len);
    ptr += len;
    len = get_addr_len(spkt->dst->type) + ISD_AS_LEN;
    memcpy(ptr, spkt->dst->addr, len);
    int padded_len = padded_addr_len((uint8_t *)(spkt->sch));
    return start + padded_len;
}

uint8_t * pack_spkt_path(spkt_t *spkt, uint8_t *ptr)
{
    size_t len;
    len = spkt->path->len;
    memcpy(ptr, spkt->path->raw_path, len);
    return ptr + len;
}

uint8_t * pack_spkt_extensions(spkt_t *spkt, uint8_t *ptr)
{
    seh_t *seh = spkt->exts->extensions;
    while (seh) {
        *ptr++ = seh->next_header;
        *ptr++ = seh->len / SCION_EXT_LINE - 1;
        *ptr++ = seh->ext_type;
        memcpy(ptr, seh->payload, seh->len);
        ptr += seh->len;
        seh = seh->next;
    }
    return ptr;
}

uint8_t * pack_spkt_l4(spkt_t *spkt, uint8_t *ptr)
{
    memcpy(ptr, spkt->l4->packet, spkt->l4->len);
    return ptr + spkt->l4->len;
}

void destroy_spkt(spkt_t *spkt, int from_raw)
{
    /*
     * If from_raw is true, original raw packet data is assumed to exist,
     * therefore raw path, extension payload, l4 data are not free'd here.
     * Otherwise those elements are also assumed to have been malloc'ed
     * somewhere and consequently free'd here.
     */
    if (spkt->sch)
        free(spkt->sch);
    if (spkt->src)
        free(spkt->src);
    if (spkt->dst)
        free(spkt->dst);
    if (spkt->path) {
        if (!from_raw)
            free(spkt->path->raw_path);
        free(spkt->path);
    }
    if (spkt->exts) {
        seh_t *ext = spkt->exts->extensions;
        while (ext) {
            seh_t *next = ext->next;
            if (!from_raw)
                free(ext->payload);
            free(ext);
            ext = next;
        }
        free(spkt->exts);
    }
    if (spkt->l4) {
        if (!from_raw)
            free(spkt->l4->packet);
        free(spkt->l4);
    }
    free(spkt);
}

/*
 * Initialize common header fields
 * buf: Pointer to start of SCION packet
 * src_type: Address type of src host addr
 * dst_type: Address type of dst host addr
 * next_hdr: L4 protocol number or extension type
 */
void pack_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr)
{
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
void pack_addr_hdr(uint8_t *buf, SCIONAddr *src, SCIONAddr *dst)
{
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
 * return value: Total padded addr length
 */
int padded_addr_len(uint8_t *buf)
{
    int addr_len = get_src_len(buf) + get_dst_len(buf) + 2 * ISD_AS_LEN;
    return (addr_len + SCION_ADDR_PAD - 1) & ~(SCION_ADDR_PAD - 1);
}

/*
 * Set SCION path
 * buf: Pointer to start of SCION packet
 * path: Pointer to start of path data to be copied
 */
void set_path(uint8_t *buf, uint8_t *path, int len)
{
    if (len < 0)
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
 * return value: Pointer to start of SCION path in packet
 */
uint8_t * get_path(uint8_t *buf)
{
    return buf + sizeof(SCIONCommonHeader) + padded_addr_len(buf);
}

/*
 * Get length of SCION path
 * buf: Pointer to start of SCION packet
 * return value: Length of SCION path in packet
 */
int get_path_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return sch->header_len - sizeof(SCIONCommonHeader) - padded_addr_len(buf);
}

/*
 * Initialize OF indices (pointers)
 * buf: Pointer to start of SCION packet
 */
void init_of_idx(uint8_t *buf)
{
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
void inc_hof_idx(uint8_t *buf)
{
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
 * return value: L4 protocol of packet
 */
uint8_t get_l4_proto(uint8_t **l4ptr)
{
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
void reverse_packet(uint8_t *buf)
{
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

/*
 * Print fields in common header
 * buf: Pointer to start of SCION packet
 */
void print_header(uint8_t *buf) {
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    fprintf(stderr, "Version: %d Src type: %d Dest type: %d Total len: %dB\n",
           PROTO_VER(sch), SRC_TYPE(sch), DST_TYPE(sch), ntohs(sch->total_len));
    fprintf(stderr, "IOF offset: %dB HOF offset: %dB Next hdr: %d Header len: %dB\n",
           sch->current_iof, sch->current_hof, sch->next_header, sch->header_len);
}
