#ifndef _PACKET_H_
#define _PACKET_H_

#pragma pack(push)
#pragma pack(1)

#include <arpa/inet.h>

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

#endif
