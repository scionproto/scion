#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/* Host addr lengths by type */
const int ADDR_LENS[] = {0, 4, 16, 2};

/* 
 * Get src host addr
 * buf: Pointer to start of SCION packet
 * return value: pointer to start of src host addr, NULL on error
 * */
uint8_t * get_src_addr(uint8_t *buf)
{
    if (!buf)
        return NULL;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return (uint8_t *)(sch + 1) + SCION_ISD_AD_LEN;
}

/* 
 * Get length of src host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of src host addr, 0 on error
 * */
uint8_t get_src_len(uint8_t *buf)
{
    if (!buf)
        return 0;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ADDR_LENS[SRC_TYPE(sch)];
}

/* 
 * Get dst host addr
 * buf: Pointer to start of SCION packet
 * return value: Pointer to start of dst host addr, NULL on error
 * */
uint8_t * get_dst_addr(uint8_t *buf)
{
    if (!buf)
        return NULL;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t src_len;
    uint8_t src_type = SRC_TYPE(sch);

    if (src_type < ADDR_NONE_TYPE || src_type > ADDR_SVC_TYPE) {
        printf("invalid src addr type: %d\n", src_type);
        return NULL;
    }

    src_len = ADDR_LENS[src_type];
    void *ret = (uint8_t *)(sch + 1) + SCION_ISD_AD_LEN +
        src_len + SCION_ISD_AD_LEN;
    return ret;
}

/* 
 * Get length of dst host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of dst host addr, 0 on error
 * */
uint8_t get_dst_len(uint8_t *buf)
{
    if (!buf)
        return 0;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ADDR_LENS[DST_TYPE(sch)];
}
