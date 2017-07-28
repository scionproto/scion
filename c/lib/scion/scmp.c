#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

uint16_t scmp_checksum(uint8_t *buf)
{
    chk_input *input = mk_chk_input(6);
    SCMPL4Header *scmp_l4;
    uint16_t l4_type;
    uint16_t payload_len, ret, blank_sum = 0;

    // Address header (without padding)
    chk_add_chunk(input, buf + DST_IA_OFFSET, get_addrs_len(buf));

    uint8_t *ptr = buf;
    // Load LSB of l4_type with protocol number
    l4_type = htons((uint16_t)get_l4_proto(&ptr));
    scmp_l4 = (SCMPL4Header *)ptr;
    // L4 protocol type
    chk_add_chunk(input, (uint8_t*)&l4_type, 2);
    // SCMP class, type & length
    ptr = chk_add_chunk(input, ptr, 6);
    // Use blank checksum field
    chk_add_chunk(input, (uint8_t *)(&blank_sum), 2);
    ptr += 2;
    // SCMP Timestamp
    ptr = chk_add_chunk(input, ptr, 8);
    // Length in SCMP header includes header size, so subtract it.
    payload_len = ntohs(scmp_l4->len) - sizeof(SCMPL4Header);
    chk_add_chunk(input, ptr, payload_len);

    ret = checksum(input);
    rm_chk_input(input);
    return ret;
}

void update_scmp_checksum(uint8_t *buf)
{
    SCMPL4Header *scmp_hdr = (SCMPL4Header *)buf;
    get_l4_proto((uint8_t **)&scmp_hdr);
    scmp_hdr->checksum = scmp_checksum(buf);
}


/*
 * Parse the scmp payload.
 * scmp_hdr: Pointer to the start of the SCMP L4 header in the packet.
 * return value: a newly allocated SCMPPayload structure, with all fields
 *               either pointing to the relevant part of the packet, or NULL if
 *               not present.
 */
SCMPPayload *scmp_parse_payload(SCMPL4Header *scmp_hdr) {
    SCMPPayload *pld = (SCMPPayload *)malloc(sizeof(SCMPPayload));
    void *ptr = scmp_hdr + 1;
    pld->meta = (SCMPMetaHeader *)ptr;
    ptr = pld->meta + 1;
    pld->info = pld->meta->info_len ? ptr : NULL;
    ptr += pld->meta->info_len * LINE_LEN;
    pld->cmnhdr = pld->meta->cmnhdr_len ? ptr : NULL;
    ptr += pld->meta->cmnhdr_len * LINE_LEN;
    pld->addr = pld->meta->addr_len ? ptr : NULL;
    ptr += pld->meta->addr_len * LINE_LEN;
    pld->path = pld->meta->path_len ? ptr : NULL;
    ptr += pld->meta->path_len * LINE_LEN;
    pld->exts = pld->meta->exts_len ? ptr : NULL;
    ptr += pld->meta->exts_len * LINE_LEN;
    pld->l4hdr = pld->meta->l4_len ? ptr : NULL;
    return pld;
}
