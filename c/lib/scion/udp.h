#ifndef _UDP_H_
#define _UDP_H_

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} SCIONUDPHeader;

#pragma pack(pop)

#define UDP_CHK_INPUT_SIZE 5

void build_scion_udp(uint8_t *buf, uint16_t src_port, uint16_t dst_port, uint16_t payload_len);
uint16_t scion_udp_checksum(uint8_t *buf, chk_input *input);
void reverse_udp_header(uint8_t *l4ptr);
void print_udp_header(uint8_t *buf);

#endif
