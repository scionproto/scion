#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include "checksum.h"

void _add_sum(uint32_t *sum, uint16_t val);

/*
 * Calculate RFC1071 checksum of supplied data chunks. The use of a gather
 * mechanism means there's 0 copies required to calculate the checksum.
 * in: a struct containing the number of chunks, for every chunk a length and a
 *     pointer to its start.
 */
uint16_t checksum(chk_input *in) {
    int i;
    uint32_t sum = 0;
    uint8_t *carry = NULL;

    // Iterate over the chunks
    for (i=0; i < in->total; i++){
        int j = 0;
        int len = in->len[i];
        uint8_t *ptr = in->ptr[i];
        if (len == 0) {
            continue;
        }
        // Handle a carry byte from the previous chunk.
        if (carry) {
            _add_sum(&sum, *carry << 8 | ptr[0]);
            j = 1;
        }
        for (; j < len - 1; j+=2) {
            _add_sum(&sum, ntohs(*((uint16_t *)(ptr + j))));
        }
        // If there's an odd number of bytes, save last one.
        carry = j == len ? NULL : ptr + j;
    }
    if (carry) {
        // Total number of bytes is odd, so pad with trailing 0.
        _add_sum(&sum, *carry << 8);
    }
    // Return 16bit ones-complement.
    return ~sum & 0xFFFF;
}

/*
 * Handle bit-carry operation during addition.
 */
void _add_sum(uint32_t *sum, uint16_t val) {
    *sum += val;
    if (*sum > 0xFFFF)
        *sum -= 0xFFFF;
}

/*
 * Helper function to allocate a chk_input struct for checksum.
 * total: number of input chunks.
 */
chk_input *mk_chk_input(int total){
    chk_input *input;
    input = (chk_input *)malloc(sizeof(chk_input));
    input->idx = 0;
    input->total = total;
    input->len = (uint16_t *)malloc(sizeof(uint16_t) * input->total);
    input->ptr = (uint8_t **)malloc(sizeof(uint8_t *) * input->total);
    return input;
}

/*
 * Helper function to deallocate a chk_input struct.
 */
void rm_chk_input(chk_input *in) {
    free(in->ptr);
    free(in->len);
    free(in);
}

/*
 * Helper function to populate a chk_input struct for checksum.
 * in: Pointer to the chk_input struct.
 * idx: Index of the current chunk.
 * ptr: Pointer to start of data chunk.
 * len: Length of data chunk.
 * return value: a pointer to the data following the current chunk.
 */
uint8_t * chk_add_chunk(chk_input *in, uint8_t *ptr, int len) {
    if (in->idx >= in->total) {
        fprintf(stderr, "ERROR chk_add_chunk: in->idx (%d) >= in->total (%d)\n", in->idx, in->total);
        exit(1);
    }
    in->len[in->idx] = len;
    in->ptr[in->idx] = ptr;
    in->idx++;
    return ptr + len;
}
