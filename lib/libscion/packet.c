#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

void build_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr)
{
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

void build_addr_hdr(uint8_t *buf, SCIONAddr *src, SCIONAddr *dst)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    int src_len = get_src_len(buf);
    int dst_len = get_dst_len(buf);
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
