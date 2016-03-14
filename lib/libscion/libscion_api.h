#ifndef _LIB_SCION_API_H_
#define _LIB_SCION_API_H_

#ifdef __cplusplus
extern "C" {
#endif

int reverse_path(uint8_t *buf, uint8_t *original, uint8_t *reverse, int len);
void reverse_packet(uint8_t *buf);

uint8_t * get_src_addr(uint8_t *buf);
uint8_t get_src_len(uint8_t *buf);
void * get_dst_addr(uint8_t *buf);
uint8_t get_dst_len(uint8_t *buf);

void build_cmn_hdr(uint8_t *buf, int src_type, int dst_type, int next_hdr);
void build_addr_hdr(uint8_t *buf, uint8_t *src, uint8_t *dst);
void init_of_idx(uint8_t *buf);
void inc_hof_idx(uint8_t *buf);
int is_known_proto(uint8_t type);
uint8_t get_l4_proto(uint8_t **l4ptr);

#ifdef __cplusplus
}
#endif

#endif
