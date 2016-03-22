#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/*
 * Reverse path
 * buf: Pointer to start of SCION packet
 * original: Pointer to start of path in SCION packet
 * reverse: Buffer to store reversed path
 * len: Length of SCION Packet
 * return value: 0 on success, -1 on failure
 */
int reverse_path(uint8_t *buf, uint8_t *original, uint8_t *reverse, int len)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    /* Pointers to IOF fields in original path */
    uint8_t *iof[] = {NULL, NULL, NULL};
    /* Number of hops in each segment of original path */
    uint8_t hops[] = {0, 0, 0};
    uint8_t *ptr = original;
    int i, j;
    /* Number of segments in original path */
    int segments;

    if (!buf || !original || !reverse || len <= 0)
        return -1;

    /* Scan the original path */
    for (i = 0; i < 3; i++) {
        segments = i + 1;
        iof[i] = ptr;
        hops[i] = *(ptr + SCION_OF_LEN - 1);
        ptr = iof[i] + ((hops[i] + 1) * SCION_OF_LEN);
        if (ptr - original >= len)
            break;
    }

    ptr = reverse;
    /* Fill in the reversed path, last segment first */
    for (i = segments - 1; i >= 0; i--) {
        /* Copy IOF */
        *(uint64_t *)ptr = *(uint64_t *)iof[i];
        /* Reverse up flag */
        *ptr ^= IOF_FLAG_UPDOWN;
        ptr += SCION_OF_LEN;
        /* Copy HOFs in reverse order */
        for (j = hops[i]; j >= 1; j--) {
            *(uint64_t *)ptr = *(uint64_t *)(iof[i] + (SCION_OF_LEN * j));
            ptr += SCION_OF_LEN;
        }
    }

    /* Update currentIOF pointer to reversed location */
    uint8_t *current_iof = sch->currentIOF + buf;
    /* Original currentIOF pointer was at first IOF -> set to last */
    if (current_iof == iof[0])
        sch->currentIOF = iof[segments - 1] - buf;
    /* Original currentIOF pointer was at last IOF -> set to first */
    else if (current_iof == iof[segments - 1])
        sch->currentIOF = iof[0] - buf;

    int of_count = segments;
    for (i = 0; i < segments; i++)
        of_count += hops[i];
    /* Get index of current HOF in OF list */
    int hof_index = (sch->currentOF + buf - original) / SCION_OF_LEN;
    hof_index = of_count - hof_index;
    /* Update currentOF pointer to reversed location */
    sch->currentOF = original + hof_index * SCION_OF_LEN - buf;

    return 0;
}

/*
 * Get HOF used to verify current HOF
 * buf: Pointer to start of SCION packet
 * ingress: True if packet is from neighbor AS
 * return value: Pointer to HOF used to verify current HOF, NULL on error
 */
uint8_t * get_hof_ver(uint8_t *buf, int ingress)
{
    if (!buf)
        return NULL;

    uint8_t *iof = get_current_iof(buf);
    uint8_t *hof = get_current_hof(buf);

    if (!(*hof & HOF_FLAG_XOVER))
        return get_hof_ver_normal(buf);

    uint8_t ingress_up[2][2];
    memset(ingress_up, 0, sizeof(ingress_up));

    if (IOF_PEER(iof)) {
        ingress_up[1][1] = 2;
        ingress_up[1][0] = 1;
        ingress_up[0][1] = -1;
        ingress_up[0][0] = -2;
    } else {
        ingress_up[1][1] = 0;
        ingress_up[1][0] = -1;
        ingress_up[0][1] = 1;
        ingress_up[0][0] = 0;
    }

    int offset = ingress_up[ingress][IOF_UP(iof)];
    if (offset == 0)
        return 0;
    return hof + offset * SCION_OF_LEN;
}

/*
 * Get HOF used to verify current HOF in non-crossover case
 * buf: Pointer to start of SCION packet
 * return value: Pointer to HOF used to verify current HOF, NULL on error
 */
uint8_t * get_hof_ver_normal(uint8_t *buf)
{
    if (!buf)
        return NULL;

    uint8_t *iof = get_current_iof(buf);
    uint8_t *hof = get_current_hof(buf);

    if ((IOF_UP(iof) && (hof == iof + IOF_HOPS(iof) * SCION_OF_LEN)) ||
            (!IOF_UP(iof) && (hof == iof + SCION_OF_LEN)))
        return NULL;

    int offset = IOF_UP(iof) ? 1 : -1;
    return hof + offset * SCION_OF_LEN;
}
