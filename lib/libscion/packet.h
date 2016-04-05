#ifndef _PACKET_H_
#define _PACKET_H_

#include <arpa/inet.h>

#pragma pack(push)
#pragma pack(1)

typedef struct {
    /** Packet Type of the packet (version, srcType, dstType) */
    uint16_t ver_src_dst;
    /** Total Length of the packet */
    uint16_t total_len;
    /** Offset of current Info opaque field*/
    uint8_t current_iof;
    /** Offset of current Hop opaque field*/
    uint8_t current_hof;
    /** next header type, shared with IP protocol number*/
    uint8_t next_header;
    /** Header length that includes the path */
    uint8_t header_len;
} SCIONCommonHeader;

#pragma pack(pop)

#define SRC_TYPE(sch) ((ntohs(sch->ver_src_dst) & 0xfc0) >> 6)
#define DST_TYPE(sch) (ntohs(sch->ver_src_dst) & 0x3f)

void build_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr);
void build_addr_hdr(uint8_t *buf, SCIONAddr *src, SCIONAddr *dst);
void set_path(uint8_t *buf, uint8_t *path, int len);
void init_of_idx(uint8_t *buf);
void inc_hof_idx(uint8_t *buf);
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);
void reverse_packet(uint8_t *buf);

#endif
