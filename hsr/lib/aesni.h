#ifndef __AESNI__H
#define __AESNI__H

#ifndef AES_KEY_BITLEN
#define AES_KEY_BITLEN   128  /* Must be 128, 192, 256 */
#endif

#if ((AES_KEY_BITLEN != 128) && \
     (AES_KEY_BITLEN != 192) && \
     (AES_KEY_BITLEN != 256))
#error Bad -- AES_KEY_BITLEN must be one of 128, 192 or 256!!
#endif

typedef struct keystruct {
	unsigned char* iv;				/* iv vector		*/
    unsigned char* roundkey; 		/* AES round keys	*/
}keystruct; 

// assembly functions

// ExpandKey128(unsigned char* enckey, void* roundkey)
// enckey: 16-byte key string input
// roundkey: 10*16-byte round key ouput buffer
#define ExpandKey128 ExpandKey128
// CBCMAC1BLK(void* rk, unsigned char* iv, unsigned char* plain, unsigned char* mac)
// rk: 16*10-byte round key input buffer
// iv: initial vector for AES-CBC MAC
// plain: 16-byte buffer input plaintext
// mac: 16-byte buffer for ouput AES-CBC MAC
#define CBCMAC1BLK CBCMAC1BLK
// CBCMAC1MULTI(int core_id, keystruct rk, plain, mac)
// rk: keystruct to store roundkey and iv
// core_id: multi-core thread identifier
// plain: unsigned char*, 16-byte buffer input plaintext
// mac: unsigned char*, 16-byte buffer for computed MAC
#define CBCMAC1MULTI CBCMAC1MULTI
#define _do_rdtsc _do_rdtsc

void *malloc_aligned(size_t alignment, size_t bytes);
void free_aligned(void *raw_data);
unsigned char* aes_assembly_init(void *enc_key);


#endif /* __AESNI__H */
