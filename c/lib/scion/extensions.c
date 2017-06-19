#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/*
 * Find extension of given class and type
 * buf: Pointer to start of SCION packet
 * ext_class: Class of extension to find (HOP_BY_HOP vs END_TO_END)
 * ext_type: Type of extension to find
 * return value: Pointer to extension, NULL if not found or error
 */
uint8_t * find_extension(uint8_t *buf, uint8_t ext_class, uint8_t ext_type)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t next_header = sch->next_header;
    uint8_t curr_header = next_header;
    int header_len = sch->header_len * LINE_LEN;
    uint8_t *ptr = buf + header_len;
    uint8_t type = 0;
    while (!is_known_proto(curr_header)) {
        next_header = *ptr;
        header_len = *(ptr + 1);
        type = *(ptr + 2);
        if (curr_header == ext_class && type == ext_type)
            return ptr;
        int real_len = header_len * SCION_EXT_LINE;
        curr_header = next_header;
        ptr += real_len;
    }
    return NULL;
}

/*
 * Get total length of all extension headers
 * buf: Pointer to start of SCION packet
 * return value: Total length of all extension headers
 */
int get_total_ext_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *ptr = buf + sch->header_len * LINE_LEN;
    int current_header = sch->next_header;
    int size = 0;
    while (!is_known_proto(current_header)) {
        current_header = *ptr;
        int header_len = *(ptr + 1);
        header_len *= SCION_EXT_LINE;
        ptr += header_len;
        size += header_len;
    }
    return size;
}

/*
 * Create one hop path extensions.
 * ext: Pointer to the extension. Required memory is allocated here.
 */
void build_one_hop_path_ext(seh_t *ext)
{
    ext->ext_class = HOP_BY_HOP;
    ext->ext_type = ONE_HOP_PATH;
    ext->len = SCION_EXT_LINE;
    ext->payload = malloc(ONE_HOP_PATH_PLDLEN);
    memset(ext->payload, 0, ONE_HOP_PATH_PLDLEN);
}
