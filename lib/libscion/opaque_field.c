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
