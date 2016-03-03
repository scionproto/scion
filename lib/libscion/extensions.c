#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

int is_l4(uint8_t header)
{
    switch (header) {
        case L4_ICMP:
        case L4_TCP:
        case L4_UDP:
        case L4_SSP:
        case L4_NONE:
        case L4_RESERVED:
            return 1;
        default:
            return 0;
    }
    return 0;
}

uint8_t * find_extension(uint8_t *buf, uint8_t ext_class, uint8_t ext_type)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t next_header = sch->nextHeader;
    uint8_t curr_header = next_header;
    uint8_t header_len = sch->headerLen;
    uint8_t *ptr = buf + header_len;
    uint8_t type = 0;
    while (!is_l4(curr_header)) {
        next_header = *ptr++;
        header_len = *ptr++;
        type = *ptr++;
        if (curr_header == ext_class && type == ext_type)
            return ptr - 3;
        uint8_t real_len = (header_len + 1) * SCION_EXT_LINE;
        curr_header = next_header;
        ptr += real_len - SCION_EXT_SUBHDR;
    }
    return NULL;
}
