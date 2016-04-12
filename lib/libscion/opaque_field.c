#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/*
 * Get current IOF
 * buf: Pointer to start of SCION packet
 * return value: Pointer to current IOF, NULL on error
 */
uint8_t * get_current_iof(void *buf)
{
    if (!buf)
        return NULL;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return buf + sch->current_iof;
}

/*
 * Get current HOF
 * buf: Pointer to start of SCION packet
 * return value: Pointer to current HOF, NULL on error
 */
uint8_t * get_current_hof(void *buf)
{
    if (!buf)
        return NULL;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return buf + sch->current_hof;
}

/*
 * Get forwarding interface
 * buf: Pointer to start of SCION packet
 * return value: IFID of next hop interface, 0 on error
 */
uint16_t get_fwd_if(void *buf)
{
    if (!buf)
        return 0;

    uint8_t *iof = get_current_iof(buf);
    uint8_t *hof = get_current_hof(buf);
    if (*iof & IOF_FLAG_UPDOWN)
        return get_ingress_if(hof);
    return get_egress_if(hof);
}

/*
 * Get ingress/egress IFIDs from HOF
 * hof: Pointer to HOF
 * return value: Combined ingress/egress IFIDs in hof, 0 on error
 */
uint32_t get_ingress_egress(uint8_t *hof)
{
    if (!hof)
        return 0;

    uint8_t in_eg_bytes[4];
    int i;
    for (i = 0; i < 3; i++)
        in_eg_bytes[1 + i] = *(hof + 2 + i);
    in_eg_bytes[0] = 0;
    return ntohl(*(uint32_t *)(in_eg_bytes));
}

/*
 * Get ingress IFID from HOF
 * hof: Pointer to HOF
 * return value: Ingress IFID in hof, 0 on error
 */
uint16_t get_ingress_if(uint8_t *hof)
{
    if (!hof)
        return 0;
    return get_ingress_egress(hof) >> 12;
}

/*
 * Get egress IFID from HOF
 * hof: Pointer to HOF
 * return value: Egress IFID in hof, 0 on error
 */
uint16_t get_egress_if(uint8_t *hof)
{
    if (!hof)
        return 0;
    return get_ingress_egress(hof) & 0xfff;
}
