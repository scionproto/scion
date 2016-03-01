#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

const int ADDR_LENS[] = {0, 4, 16, 2};

uint8_t * get_src_addr(SCIONCommonHeader *sch)
{
    return (uint8_t *)sch + sizeof(*sch) + SCION_ISD_AD_LEN;
}

uint8_t get_src_len(SCIONCommonHeader *sch)
{
    return ADDR_LENS[SRC_TYPE(sch)];
}

void * get_dst_addr(SCIONCommonHeader *sch)
{
    uint8_t src_len;
    uint8_t src_type = SRC_TYPE(sch);

    if (src_type < ADDR_NONE_TYPE || src_type > ADDR_SVC_TYPE) {
        printf("invalid src addr type: %d\n", src_type);
        return NULL;
    }

    src_len = ADDR_LENS[src_type];
    void *ret = (uint8_t *)sch + sizeof(*sch) + SCION_ISD_AD_LEN +
        src_len + SCION_ISD_AD_LEN;
    return ret;
}

uint8_t get_dst_len(SCIONCommonHeader *sch)
{
    return ADDR_LENS[DST_TYPE(sch)];
}
