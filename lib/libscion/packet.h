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
typedef SCIONCommonHeader sch_t;

#pragma pack(pop)

#define PROTO_VER(sch) ((ntohs(sch->ver_src_dst) >> 12))
#define SRC_TYPE(sch) ((ntohs(sch->ver_src_dst) & 0xfc0) >> 6)
#define DST_TYPE(sch) (ntohs(sch->ver_src_dst) & 0x3f)

typedef struct {
    uint8_t len;
    uint8_t *raw_path;
    struct sockaddr_in first_hop;
} spath_t;

typedef struct scion_ext_hdr {
    uint8_t next_header;
    uint8_t len;
    uint8_t ext_class;
    uint8_t ext_type;
    uint8_t *payload;
    struct scion_ext_hdr *next;
} seh_t;

typedef struct {
    uint8_t count;
    seh_t *extensions;
} exts_t;

typedef struct {
    uint8_t type;
    uint16_t len;
    uint8_t *packet;
} l4_pkt;

typedef struct {
    sch_t *sch;
    saddr_t *src;
    saddr_t *dst;
    spath_t *path;
    exts_t *exts;
    l4_pkt *l4;
} spkt_t;

spkt_t * build_spkt(saddr_t *src, saddr_t *dst, spath_t *path, exts_t *exts, l4_pkt *l4);

spkt_t * parse_spkt(uint8_t *buf);
void parse_spkt_cmn_hdr(uint8_t *buf, spkt_t *spkt);
void parse_spkt_addr_hdr(uint8_t *buf, spkt_t *spkt);
void parse_spkt_path(uint8_t *buf, spkt_t *spkt);
void parse_spkt_extensions(uint8_t *buf, spkt_t *spkt);
void parse_spkt_l4(uint8_t *buf, spkt_t *spkt);

void pack_spkt(spkt_t *spkt, uint8_t *buf);
uint8_t * pack_spkt_cmn_hdr(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_addr_hdr(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_path(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_extensions(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_l4(spkt_t *spkt, uint8_t *ptr);

void pack_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr);
void pack_addr_hdr(uint8_t *buf, SCIONAddr *src, SCIONAddr *dst);
int padded_addr_len(uint8_t *buf);
void set_path(uint8_t *buf, uint8_t *path, int len);
uint8_t * get_path(uint8_t *buf);
int get_path_len(uint8_t *buf);
void init_of_idx(uint8_t *buf);
void inc_hof_idx(uint8_t *buf);
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);
void reverse_packet(uint8_t *buf);
void print_header(uint8_t *buf);

#endif
