#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

uint8_t L4PROTOCOLS[] = {L4_SCMP, L4_TCP, L4_UDP};

spkt_t * build_spkt(saddr_t *dst, saddr_t *src, spath_t *path, exts_t *exts, l4_pld *l4)
{
    spkt_t *spkt = (spkt_t *)malloc(sizeof(spkt_t));
    spkt->sch = (sch_t *)malloc(sizeof(sch_t));
    uint8_t next_header;
    uint16_t exts_len = 0;
    if (exts && exts->count > 0) {
        next_header = exts->extensions[0].ext_class;
        uint8_t i;
        for (i = 0; i < exts->count; i++)
            exts_len += exts->extensions[i].len;
    }
    else
        next_header = l4->type;
    pack_cmn_hdr((uint8_t *)spkt->sch, dst->type, src->type, next_header,
                 path->len, exts_len, l4->len);
    spkt->dst = dst;
    spkt->src = src;
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
    spkt->sch = (sch_t *)buf;
}

void parse_spkt_addr_hdr(uint8_t *buf, spkt_t *spkt)
{
    saddr_t *dst = (saddr_t *)malloc(sizeof(saddr_t));
    dst->type = DST_TYPE(spkt->sch);
    memcpy(dst->addr, buf + DST_IA_OFFSET, ISD_AS_LEN);
    memcpy(dst->addr + ISD_AS_LEN, get_dst_addr(buf), get_dst_len(buf));
    spkt->dst = dst;

    saddr_t *src = (saddr_t *)malloc(sizeof(saddr_t));
    src->type = SRC_TYPE(spkt->sch);
    memcpy(src->addr, buf + SRC_IA_OFFSET, ISD_AS_LEN);
    memcpy(src->addr + ISD_AS_LEN, get_src_addr(buf), get_src_len(buf));
    spkt->src = src;
}

void parse_spkt_path(uint8_t *buf, spkt_t *spkt)
{
    int path_len = get_path_len(buf);
    if (path_len > 0) {
        spath_t *path = (spath_t *)malloc(sizeof(spath_t));
        memset(path, 0, sizeof(spath_t));
        path->len = path_len;
        path->raw_path = get_path(buf);
        spkt->path = path;
    } else {
        spkt->path = NULL;
    }
}

void parse_spkt_extensions(uint8_t *buf, spkt_t *spkt)
{
    exts_t *exts = (exts_t *)malloc(sizeof(exts_t));
    memset(exts, 0, sizeof(exts_t));
    uint8_t curr = spkt->sch->next_header;
    uint8_t *ptr = buf + spkt->sch->header_len * LINE_LEN;
    while (!is_known_proto(curr)) {
        // first pass to get ext count
        curr = *ptr;
        uint8_t len = (*(ptr + 1)) * SCION_EXT_LINE;
        ptr += len;
        exts->count++;
    }
    size_t size = exts->count * sizeof(seh_t);
    exts->extensions = (seh_t *)malloc(size);
    memset(exts->extensions, 0, size);

    curr = spkt->sch->next_header;
    ptr = buf + spkt->sch->header_len * LINE_LEN;
    seh_t *seh = exts->extensions;
    while (!is_known_proto(curr)) {
        // second pass to populate array
        seh->len = (*(ptr + 1)) * SCION_EXT_LINE;
        seh->ext_class = curr;
        seh->ext_type = *(ptr + 2);
        seh->payload = ptr + 3;
        curr = *ptr;
        ptr += seh->len;
        seh++;
    }
    spkt->exts = exts;
}

void parse_spkt_l4(uint8_t *buf, spkt_t *spkt)
{
    uint8_t *l4ptr = buf;
    uint8_t l4proto = get_l4_proto(&l4ptr);
    l4_pld *l4 = (l4_pld *)malloc(sizeof(l4_pld));
    l4->type = l4proto;
    l4->len = ntohs(spkt->sch->total_len) - (l4ptr - buf);
    l4->payload = l4ptr;
    spkt->l4 = l4;
}

int pack_spkt(spkt_t *spkt, uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;

    if (len < ntohs(spkt->sch->total_len))
        return -1;

    ptr = pack_spkt_cmn_hdr(spkt, ptr);
    ptr = pack_spkt_addr_hdr(spkt, ptr);
    if (spkt->path && spkt->path->len > 0)
        ptr = pack_spkt_path(spkt, ptr);
    if (spkt->exts && spkt->exts->count > 0)
        ptr = pack_spkt_extensions(spkt, ptr);
    ptr = pack_spkt_l4(spkt, ptr);

    return 0;
}

uint8_t * pack_spkt_cmn_hdr(spkt_t *spkt, uint8_t *ptr)
{
    size_t len = sizeof(sch_t);
    memcpy(ptr, spkt->sch, len);
    return ptr + len;
}

uint8_t * pack_spkt_addr_hdr(spkt_t *spkt, uint8_t *ptr)
{
    uint8_t *start = ptr;
    size_t len;
    len = ISD_AS_LEN;
    memcpy(ptr, spkt->dst->addr, len);
    ptr += len;
    memcpy(ptr, spkt->src->addr, len);
    ptr += len;
    len = get_addr_len(spkt->dst->type);
    memcpy(ptr, spkt->dst->addr + ISD_AS_LEN, len);
    ptr += len;
    len = get_addr_len(spkt->src->type);
    memcpy(ptr, spkt->src->addr + ISD_AS_LEN, len);
    int padded_len = padded_addr_len((uint8_t *)(spkt->sch));
    return start + padded_len;
}

uint8_t * pack_spkt_path(spkt_t *spkt, uint8_t *ptr)
{
    size_t len = spkt->path->len;
    memcpy(ptr, spkt->path->raw_path, len);
    return ptr + len;
}

uint8_t * pack_spkt_extensions(spkt_t *spkt, uint8_t *ptr)
{
    int i;
    for (i = 0; i < spkt->exts->count; i++) {
        seh_t *seh = spkt->exts->extensions + i;
        uint8_t next_header;
        if (i == spkt->exts->count - 1)
            next_header = spkt->l4->type;
        else
            next_header = spkt->exts->extensions[i + 1].ext_class;
        *ptr++ = next_header;
        *ptr++ = seh->len / SCION_EXT_LINE;
        *ptr++ = seh->ext_type;
        memcpy(ptr, seh->payload, seh->len - SCION_EXT_SUBHDR);
        ptr += seh->len - SCION_EXT_SUBHDR;
    }
    return ptr;
}

uint8_t * pack_spkt_l4(spkt_t *spkt, uint8_t *ptr)
{
    memcpy(ptr, spkt->l4->payload, spkt->l4->len);
    return ptr + spkt->l4->len;
}

void destroy_spkt(spkt_t *spkt, int from_raw)
{
    /*
     * If from_raw is true, original raw packet data is assumed to exist and
     * sch, raw path, extension payload, and l4 data point into the original
     * buffer, therefore they are not free()'d here.
     * Otherwise those elements are also assumed to have been malloc()'ed
     * somewhere and consequently free()'d here.
     */
    if (!from_raw && spkt->sch)
        free(spkt->sch);
    if (spkt->dst)
        free(spkt->dst);
    if (spkt->src)
        free(spkt->src);
    if (spkt->path) {
        if (!from_raw)
            free(spkt->path->raw_path);
        free(spkt->path);
    }
    if (spkt->exts) {
        if (!from_raw) {
            int i;
            for (i = 0; i < spkt->exts->count; i++)
                free(spkt->exts->extensions[i].payload);
        }
        free(spkt->exts->extensions);
        free(spkt->exts);
    }
    if (spkt->l4) {
        if (!from_raw)
            free(spkt->l4->payload);
        free(spkt->l4);
    }
    free(spkt);
}

/*
 * Initialize common header fields
 * buf: Pointer to start of SCION packet
 * dst_type: Address type of dst host addr
 * src_type: Address type of src host addr
 * next_hdr: L4 protocol number or extension type
 */
void pack_cmn_hdr(uint8_t *buf, int dst_type, int src_type, int next_hdr,
                  int path_len, int exts_len, int l4_len)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint16_t vds = 0;
    vds |= dst_type << 6;
    vds |= src_type;
    sch->ver_dst_src = htons(vds);
    sch->next_header = next_hdr;

    int addr_len = padded_addr_len(buf);
    int header_len = sizeof(SCIONCommonHeader) + addr_len + path_len;
    sch->header_len = header_len/LINE_LEN;
    sch->total_len = htons(header_len + exts_len + l4_len);
    /* Set of pointers to start of path (which has not been set yet) */
    sch->current_iof = (sizeof(SCIONCommonHeader) + addr_len)/LINE_LEN;
    if(path_len < 1)
        sch->current_iof = 0;
    sch->current_hof = sch->current_iof;
}

/*
 * Get total length of addresses with padding
 * buf: Pointer to start of SCION packet
 * return value: Total padded addr length
 */
int padded_addr_len(uint8_t *buf)
{
    int addr_len = 2 * ISD_AS_LEN + get_dst_len(buf) + get_src_len(buf);
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
    memcpy(buf + sch->header_len * LINE_LEN, path, len);
    sch->header_len += len/LINE_LEN;
    sch->total_len = htons(sch->header_len * LINE_LEN);
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
    return sch->header_len * LINE_LEN - sizeof(SCIONCommonHeader) - padded_addr_len(buf);
}

/*
 * Initialize OF indices (pointers)
 * buf: Pointer to start of SCION packet
 */
void init_of_idx(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;

    uint8_t *iof = buf + sch->current_iof * LINE_LEN;
    uint8_t *hof = buf + sch->current_iof * LINE_LEN + SCION_OF_LEN;
    if ((*iof & IOF_FLAG_PEER) && (*hof & HOF_FLAG_XOVER))
        sch->current_hof += SCION_OF_LEN/LINE_LEN;

    inc_hof_idx(buf);
}

/*
 * Increment HOF pointer to next valid HOF
 * buf: Pointer to start of SCION packet
 */
void inc_hof_idx(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *iof = buf + sch->current_iof * LINE_LEN;
    uint8_t *hof = buf + sch->current_hof * LINE_LEN;
    int hops = *(iof + SCION_OF_LEN - 1);

    while (1) {
        sch->current_hof += SCION_OF_LEN/LINE_LEN;
        if (((sch->current_hof - sch->current_iof) * LINE_LEN) / SCION_OF_LEN > hops) {
            /* Move to next segment */
            sch->current_iof = sch->current_hof;
            iof = buf + sch->current_iof * LINE_LEN;
            hops = *(iof + SCION_OF_LEN - 1);
            continue;
        }
        hof = buf + sch->current_hof * LINE_LEN;
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
    ptr += sch->header_len * LINE_LEN;
    while (!is_known_proto(currentHeader)) {
        currentHeader = *ptr;
        size_t nextLen = *(ptr + 1);
        nextLen *= SCION_EXT_LINE;
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
    // Parse addresses into temporary spkt, then swap them and write them back
    // out to the buffer.
    spkt_t spkt;
    saddr_t *tmp;
    parse_spkt_cmn_hdr(buf, &spkt);
    parse_spkt_addr_hdr(buf, &spkt);
    tmp = spkt.dst;
    spkt.dst = spkt.src;
    spkt.src = tmp;
    // Swap SRC and DST Types in the common header
    uint16_t old_vds = ntohs(spkt.sch->ver_dst_src);
    uint16_t vds = (old_vds & 0xf000) | ((old_vds & 0x3f) << 6) | ((old_vds >> 6) & 0x3f);
    spkt.sch->ver_dst_src = htons(vds);
    pack_spkt_addr_hdr(&spkt, buf + DST_IA_OFFSET);

    /* Reverse path */
    int pathlen = get_path_len(buf);
    uint8_t *reverse = (uint8_t *)malloc(pathlen);
    reverse_path(buf, reverse);
    memcpy(get_path(buf), reverse, pathlen);
    free(reverse);

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

struct extn_h {
    uint8_t next_header;
    uint8_t len;
    uint8_t type;
};

void remove_hbh_scmp_extn(uint8_t *buf)
{
    spkt_t spkt;
    parse_spkt_cmn_hdr(buf, &spkt);

    uint8_t nh = spkt.sch->next_header;
    uint16_t total_len = ntohs(spkt.sch->total_len);
    uint16_t hdr_len = spkt.sch->header_len * LINE_LEN;
    if (nh != HOP_BY_HOP || total_len == hdr_len) {
        // No HBH extension
        return;
    }

    uint8_t *extn = buf + hdr_len;
    struct extn_h *e = (struct extn_h *)extn;
    if (e->type != SCMP) {
        return;
    }

    uint16_t extn_len = e->len * LINE_LEN;
    spkt.sch->next_header = e->next_header;
    spkt.sch->total_len = htons(total_len - extn_len);
    memmove(extn, extn + extn_len, total_len - hdr_len - extn_len);
}

/*
 * Print fields in common header
 * buf: Pointer to start of SCION packet
 */
void print_header(uint8_t *buf) {
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    fprintf(stderr, "Version: %d Dest type: %d Src type: %d Total len: %dB\n",
           PROTO_VER(sch), DST_TYPE(sch), SRC_TYPE(sch), ntohs(sch->total_len));
    fprintf(stderr, "Header len: %dB IOF offset: %dB HOF offset: %dB Next hdr: %d\n",
           sch->header_len*LINE_LEN, sch->current_iof*LINE_LEN, sch->current_hof*LINE_LEN, sch->next_header);
}
