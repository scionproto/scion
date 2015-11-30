#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>

#include "aesni.h"


#if (INT_MAX != 0x7fffffff)
#error -- Assumes 4-byte int
#endif


void *malloc_aligned(size_t alignment, size_t bytes)
{
    const size_t total_size = bytes + (2 * alignment) + sizeof(size_t);

    // use malloc to allocate the memory.
    char *data = malloc(sizeof(char) * total_size);

    if (data)
    {
        // store the original start of the malloc'd data.
        const void * const data_start = data;

        // dedicate enough space to the book-keeping.
        data += sizeof(size_t);

        // find a memory location with correct alignment.  the alignment minus 
        // the remainder of this mod operation is how many bytes forward we need 
        // to move to find an aligned byte.
        const size_t offset = alignment - (((size_t)data) % alignment);

        // set data to the aligned memory.
        data += offset;

        // write the book-keeping.
        size_t *book_keeping = (size_t*)(data - sizeof(size_t));
        *book_keeping = (size_t)data_start;
    }

    return data;
}

void free_aligned(void *raw_data)
{
    if (raw_data)
    {
        char *data = raw_data;

        // we have to assume this memory was allocated with malloc_aligned.  
        // this means the sizeof(size_t) bytes before data are the book-keeping 
        // which points to the location we need to pass to free.
        data -= sizeof(size_t);

        // set data to the location stored in book-keeping.
        data = (char*)(*((size_t*)data));

        // free the memory.
        free(data);
    }
}

unsigned char* aes_assembly_init(void *enc_key)
{
    if (enc_key != NULL) {
    	unsigned char* roundkey = (unsigned char*)malloc_aligned(16, 10*16*sizeof(char));
    	memset(roundkey, 0, sizeof(10*16*sizeof(char)));
    	ExpandKey128(enc_key, roundkey);
    	return roundkey;
	}
}

/*
int main()
{
	unsigned long long start, end;
	int i, j;
	struct keystruct rk;
	unsigned char key[] = "0123456789abcdef";
	rk.roundkey = aes_assembly_init(key);
	
	for(i=0;i<10;i++)
	{
		printf("roundkey[%d]:", i);
		for(j=0;j<16;j++)
			printf("%2x", rk.roundkey[i*16+j]);
		printf("\n");
	}
	
	unsigned char input[16];
	unsigned char mac[8*16];
	rk.iv = malloc(16*sizeof(char));
	
	for(i=0;i<100000;i++)CBCMAC1BLK(rk.roundkey, rk.iv, input, mac);
	
	start = _do_rdtsc();
	for(i=0;i<100000;i++)CBCMAC1BLK(rk.roundkey, rk.iv, input, mac);
	end = _do_rdtsc();

	printf("Average spend %f cycles.\n", (double)(end-start)/100000);
	//printf("mac:");
	//for(j=0;j<16;j++)
	//	printf("%2x", mac[j]);
	//printf("\n");
	
	//for(i=0;i<8;i++)
	//{
	//	CBCMAC1MULTI(&rk, i, input, mac+i*16);
	//	printf("mac[%d]:", i);
	//	for(j=0;j<16;j++)
	//		printf("%2x", mac[j+i*16]);
	//	printf("\n");
	//}
	
	free_aligned(rk.roundkey);
	free(rk.iv);
	return 0;
}

*/
