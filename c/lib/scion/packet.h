#ifndef _PACKET_H_
#define _PACKET_H_

#include <arpa/inet.h>

#pragma pack(push)
#pragma pack(1)

typedef struct {
    /** Packet Type of the packet (version, dstType, srcType) */
    uint16_t ver_dst_src;
    /** Total Length of the packet */
    uint16_t total_len;
    /** Header length that includes the path */
    uint8_t header_len;
    /** Offset of current Info opaque field*/
    uint8_t current_iof;
    /** Offset of current Hop opaque field*/
    uint8_t current_hof;
    /** next header type, shared with IP protocol number*/
    uint8_t next_header;
} SCIONCommonHeader;
typedef SCIONCommonHeader sch_t;

#pragma pack(pop)

#define PROTO_VER(sch) ((ntohs((sch)->ver_dst_src) >> 12))
#define DST_TYPE(sch) ((ntohs((sch)->ver_dst_src) >> 6) & 0x3f)
#define SRC_TYPE(sch) (ntohs((sch)->ver_dst_src) & 0x3f)

typedef struct {
    uint8_t len;
    uint8_t *raw_path;
    HostAddr first_hop;
} spath_t;

typedef struct {
    uint8_t len;
    uint8_t ext_class;
    uint8_t ext_type;
    uint8_t *payload;
} seh_t;

typedef struct {
    uint8_t count;
    seh_t *extensions; // malloc'ed as count * seh_t
} exts_t;

typedef struct {
    uint8_t type;
    uint16_t len;
    uint8_t *payload;
} l4_pld;

typedef struct {
    sch_t *sch;
    saddr_t *dst;
    saddr_t *src;
    spath_t *path;
    exts_t *exts;
    l4_pld *l4;
} spkt_t;

spkt_t * build_spkt(saddr_t *dst, saddr_t *src, spath_t *path, exts_t *exts, l4_pld *l4);

spkt_t * parse_spkt(uint8_t *buf);
void parse_spkt_cmn_hdr(uint8_t *buf, spkt_t *spkt);
void parse_spkt_addr_hdr(uint8_t *buf, spkt_t *spkt);
void parse_spkt_path(uint8_t *buf, spkt_t *spkt);
void parse_spkt_extensions(uint8_t *buf, spkt_t *spkt);
void parse_spkt_l4(uint8_t *buf, spkt_t *spkt);

int pack_spkt(spkt_t *spkt, uint8_t *buf, size_t len);
uint8_t * pack_spkt_cmn_hdr(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_addr_hdr(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_path(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_extensions(spkt_t *spkt, uint8_t *ptr);
uint8_t * pack_spkt_l4(spkt_t *spkt, uint8_t *ptr);

void destroy_spkt(spkt_t *spkt, int from_raw);

void pack_cmn_hdr(uint8_t *buf, int dst_type, int src_type, int next_hdr,
                  int path_len, int exts_len, int l4_len);
int padded_addr_len(uint8_t *buf);
void set_path(uint8_t *buf, uint8_t *path, int len);
uint8_t * get_path(uint8_t *buf);
int get_path_len(uint8_t *buf);
void init_of_idx(uint8_t *buf);
void inc_hof_idx(uint8_t *buf);
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);
void reverse_packet(uint8_t *buf);
void remove_hbh_scmp_extn(uint8_t *buf);
void print_header(uint8_t *buf);

#endif
