#ifndef _LIB_SCION_API_H_
#define _LIB_SCION_API_H_

#ifdef __cplusplus
extern "C" {
#endif

int reverse_path(uint8_t *original, uint8_t *reverse, int len);

uint8_t * get_src_addr(uint8_t *buf);
uint8_t get_src_len(uint8_t *buf);
void * get_dst_addr(uint8_t *buf);
uint8_t get_dst_len(uint8_t *buf);

uint8_t * find_extension(uint8_t *buf, uint8_t ext_class, uint8_t ext_type);

#ifdef __cplusplus
}
#endif

#endif
