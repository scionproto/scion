#include <string.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t u8;

int curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);

void LinkTest(void);
