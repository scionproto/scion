#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

uint8_t is_on_up_path(InfoOpaqueField *currOF)
{
    // low bit of type field is used for uppath/downpath flag
    if ((currOF->info & 0x1) == 1)
        return 1;
    return 0;
}

uint8_t is_last_path_of(SCIONCommonHeader *sch)
{
    uint8_t offset = sch->headerLen -  sizeof(HopOpaqueField);
    //printf("is_last_path_of %d %d\n",sch->currentOF, offset);
    return sch->currentOF == offset;
}

uint8_t is_regular(HopOpaqueField *currOF)
{
    if ((currOF->info & (1 << 6)) == 0)
        return 0;
    return 1;
}

uint8_t is_continue(HopOpaqueField *currOF)
{
    if ((currOF->info & (1 << 5)) == 0)
        return 0;
    return 1;
}

uint8_t is_xovr(HopOpaqueField *currOF)
{
    if ((currOF->info & (1 << 4)) == 0)
        return 0;
    return 1;
}

uint8_t * get_current_iof(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return buf + sch->currentIOF;
}

uint8_t * get_current_hof(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return buf + sch->currentOF;
}

uint32_t get_fwd_if(uint8_t *buf)
{
    uint8_t *iof = get_current_iof(buf);
    uint8_t *hof = get_current_hof(buf);
    if (*iof & IOF_FLAG_UPDOWN)
        return get_ingress_if(hof);
    return get_egress_if(hof);
}

uint32_t get_ingress_egress(uint8_t *hof)
{
    uint8_t in_eg_bytes[4];
    int i;
    for (i = 0; i < 3; i++)
        in_eg_bytes[1 + i] = *(hof + 2 + i);
    in_eg_bytes[0] = 0;
    return ntohl(*(uint32_t *)(in_eg_bytes));
}

uint16_t get_ingress_if(uint8_t *hof)
{
    return get_ingress_egress(hof) >> 12;
}

uint16_t get_egress_if(uint8_t *hof)
{
    return get_ingress_egress(hof) & 0xfff;
}
