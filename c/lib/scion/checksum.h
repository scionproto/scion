#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

typedef struct {
    uint8_t idx;
    uint8_t total;
    uint16_t *len;
    uint8_t **ptr;
} chk_input;

uint16_t checksum(chk_input *in);
chk_input *mk_chk_input(int count);
void rm_chk_input(chk_input *in);
uint8_t * chk_add_chunk(chk_input *in, uint8_t *ptr, int len);

#endif
