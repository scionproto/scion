#ifndef _PACKET_H_
#define _PACKET_H_

#pragma pack(push)
#pragma pack(1)

#include <arpa/inet.h>

#include "defines.h"

typedef struct {
    /** Packet Type of the packet (version, srcType, dstType) */
    uint16_t versionSrcDst;
    /** Total Length of the packet */
    uint16_t totalLen;
    /** Index of current Info opaque field*/
    uint8_t currentIOF;
    /** Index of current opaque field*/
    uint8_t currentOF;
    /** next header type, shared with IP protocol number*/
    uint8_t nextHeader;
    /** Header length that includes the path */
    uint8_t headerLen;
} SCIONCommonHeader;

#pragma pack(pop)

#define SRC_TYPE(sch) ((ntohs(sch->versionSrcDst) & 0xfc0) >> 6)
#define DST_TYPE(sch) (ntohs(sch->versionSrcDst) & 0x3f)

void build_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr);
void build_addr_hdr(uint8_t *buf, uint8_t *src, uint8_t *dst);
void init_of_idx(uint8_t *buf);
void inc_hof_idx(uint8_t *buf);
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);

typedef struct SCIONExtension {
    uint8_t nextHeader;
    uint8_t headerLen;
    uint8_t type;
    uint8_t extClass;
    void *data;
    struct SCIONExtension *nextExt;
} SCIONExtension;

typedef struct {
    SCIONCommonHeader commonHeader;
    uint8_t srcAddr[SCION_HOST_ADDR_MAX];
    uint8_t dstAddr[SCION_HOST_ADDR_MAX];
    uint8_t *path;
    size_t pathLen;
    SCIONExtension *extensions;
    size_t numExtensions;
} SCIONHeader;

#endif
