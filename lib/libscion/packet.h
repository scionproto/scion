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

#define PROTO_VER(sch) ((ntohs(sch->ver_src_dst) >> 12))
#define SRC_TYPE(sch) ((ntohs(sch->ver_src_dst) & 0xfc0) >> 6)
#define DST_TYPE(sch) (ntohs(sch->ver_src_dst) & 0x3f)

void build_cmn_hdr(void *buf, int src_type, int dst_type, int next_hdr);
void build_addr_hdr(void *buf, SCIONAddr *src, SCIONAddr *dst);
int padded_addr_len(void *buf);
void set_path(void *buf, uint8_t *path, int len);
uint8_t * get_path(void *buf);
int get_path_len(void *buf);
int get_total_header_len(void *buf);
void init_of_idx(void *buf);
void inc_hof_idx(void *buf);
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);
void reverse_packet(void *buf);
void print_header(void *buf);

#endif
