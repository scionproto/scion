#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

int reverse_core_path(uint8_t *original, uint8_t *reverse, int len)
{
    int i;
    int offset = 0;
    uint8_t *up_iof = original;
    uint8_t up_hops = *(up_iof + 7);
    uint8_t *core_iof = up_iof + (up_hops + 1) * 8;
    uint8_t core_hops = *(core_iof + 7);
    uint8_t *down_iof = core_iof + (core_hops + 1) * 8;
    uint8_t down_hops = *(down_iof + 7);

    if (down_iof >= original + len) {
        down_iof = core_iof;
        down_hops = core_hops;
        core_iof = NULL;
        core_hops = 0;
        if (down_iof >= original + len) {
            // still out of bounds, only one segment in path
            down_iof = NULL;
            down_hops = 0;
        }
    } else {
        down_hops = *(down_iof + 7);
    }

    // up segment = reversed down segment
    uint8_t *iof = down_iof;
    if (!iof)
        iof = up_iof;
    int hops = down_hops;
    if (!hops)
        hops = up_hops;
    *(uint64_t *)reverse = *(uint64_t *)iof;
    *reverse ^= 1;
    offset = 8;
    for (i = hops; i > 0; i--) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(iof + i * 8);
        offset += 8;
    }

    // reverse core hops
    if (core_hops > 0) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)core_iof;
        *(reverse + offset) ^= 1;
        offset += 8;
        for (i = core_hops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(core_iof + i * 8);
            offset += 8;
        }
    }

    // down segment = reversed up segment
    if (down_hops > 0) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)up_iof;
        *(reverse + offset) ^= 1;
        offset += 8;
        for (i = up_hops; i > 0; i--) {
            *(uint64_t *)(reverse + offset) = *(uint64_t *)(up_iof + i * 8);
            offset += 8;
        }
    }
    return offset;
}

int reverse_crossover_path(uint8_t *original, uint8_t *reverse, int len)
{
    int i;
    int offset = 0;
    uint8_t *up_iof = original;
    uint8_t up_hops = *(up_iof + 7);
    uint8_t *down_iof = up_iof + (up_hops + 2) * 8;
    uint8_t down_hops = *(down_iof + 7);

    // up segment = reversed down segment
    *(uint64_t *)reverse = *(uint64_t *)down_iof;
    *reverse ^= 1;
    offset = 8;
    for (i = down_hops + 1; i > 1; i--) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(down_iof + i * 8);
        offset += 8;
    }
    *(uint64_t *)(reverse + offset) = *(uint64_t *)(down_iof + 8);
    offset += 8;

    // down segment = reversed up segment
    *(uint64_t *)(reverse + offset) = *(uint64_t *)up_iof;
    *(reverse + offset) ^= 1;
    offset += 8;
    *(uint64_t *)(reverse + offset) = *(uint64_t *)(up_iof + (up_hops + 1) * 8);
    offset += 8;
    for (i = up_hops; i > 0; i--) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(up_iof + i * 8);
        offset += 8;
    }
    return offset;
}

int reverse_peer_path(uint8_t *original, uint8_t *reverse, int len)
{
    int i;
    int offset = 0;
    uint8_t *up_iof = original;
    uint8_t up_hops = *(up_iof + 7);
    uint8_t *down_iof = up_iof + (up_hops + 3) * 8;
    uint8_t down_hops = *(down_iof + 7);

    // up segment = reversed down segment
    *(uint64_t *)reverse = *(uint64_t *)down_iof;
    *reverse ^= 1;
    offset = 8;
    for (i = down_hops + 2; i > 2; i--) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(down_iof + i * 8);
        offset += 8;
    }
    *(uint64_t *)(reverse + offset) = *(uint64_t *)(down_iof + 16);
    offset += 8;
    *(uint64_t *)(reverse + offset) = *(uint64_t *)(down_iof + 8);
    offset += 8;

    // down segment = reversed up segment
    *(uint64_t *)(reverse + offset) = *(uint64_t *)up_iof;
    *(reverse + offset) ^= 1;
    offset += 8;
    *(uint64_t *)(reverse + offset) = *(uint64_t *)(up_iof + (up_hops + 2) * 8);
    offset += 8;
    *(uint64_t *)(reverse + offset) = *(uint64_t *)(up_iof + (up_hops + 1) * 8);
    offset += 8;
    for (i = up_hops; i > 0; i--) {
        *(uint64_t *)(reverse + offset) = *(uint64_t *)(up_iof + i * 8);
        offset += 8;
    }
    return offset;
}

int reverse_path(uint8_t *original, uint8_t *reverse, int len)
{
    if (len == 0)
        return 0;

    if (IS_HOP_OF(*original)) {
        //printf("No leading Info OF in path (%#x)\n", *original);
        return -1;
    }


    int offset = 0;
    uint8_t type = *original >> 1;
    if (type == OFT_CORE)
        offset = reverse_core_path(original, reverse, len);
    else if (type == OFT_SHORTCUT)
        offset = reverse_crossover_path(original, reverse, len);
    else
        offset = reverse_peer_path(original, reverse, len);

    if (offset != len) {
        //printf("Size mismatch reversing core path\n");
        return -1;
    }

    return 0;
}

