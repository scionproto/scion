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

#endif
