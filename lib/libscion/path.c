#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

int reverse_path(uint8_t *buf, uint8_t *original, uint8_t *reverse, int len)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t *iof[] = {NULL, NULL, NULL};
    uint8_t hops[] = {0, 0, 0};
    uint8_t *ptr = original;
    int i, j;
    int segments;

    if (len == 0)
        return 0;

    for (i = 0; i < 3; i++) {
        segments = i + 1;
        iof[i] = ptr;
        hops[i] = *(uint8_t *)(ptr + SCION_OF_LEN - 1);
        ptr = iof[i] + ((hops[i] + 1) * SCION_OF_LEN);
        if (ptr - original >= len)
            break;
    }

    ptr = reverse;
    for (i = segments - 1; i >= 0; i--) {
        *(uint64_t *)ptr = *(uint64_t *)iof[i];
        *ptr ^= IOF_FLAG_UPDOWN;
        ptr += SCION_OF_LEN;
        for (j = hops[i]; j >= 1; j--) {
            *(uint64_t *)ptr = *(uint64_t *)(iof[i] + (SCION_OF_LEN * j));
            ptr += SCION_OF_LEN;
        }
    }

    int of_offset = sizeof(SCIONCommonHeader);
    uint8_t *current_iof = sch->currentIOF + of_offset + buf;
    if (current_iof == iof[0])
        sch->currentIOF = iof[segments - 1] - buf + of_offset;
    else if (current_iof == iof[segments - 1])
        sch->currentIOF = iof[0] - buf + of_offset;

    int of_count = segments;
    for (i = 0; i < segments; i++)
        of_count += hops[i];
    int hof_index = (sch->currentOF + of_offset + buf - original) / SCION_OF_LEN;
    hof_index = of_count - hof_index;
    sch->currentOF = original + hof_index * SCION_OF_LEN - buf - of_offset;

    return 0;
}
