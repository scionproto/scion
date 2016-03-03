#ifndef _PACKET_H_
#define _PACKET_H_

#include <arpa/inet.h>

#include "defines.h"

#pragma pack(push)
#pragma pack(1)

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
