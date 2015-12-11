#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE (1024 * 200)

int main(int argc, char **argv)
{
    system("dd if=/dev/urandom of=randomfile bs=1024 count=1024");

    uint8_t hash[20];
    CSHA1 sha;
    sha.HashFile("randomfile");
    sha.Final();
    sha.GetHash(hash);

    SCIONAddr addrs[1];
    SCIONAddr saddr;
    int isd, ad;
    char str[20];
    if (argc == 3) {
        isd = atoi(argv[1]);
        ad = atoi(argv[2]);
    } else {
        isd = 2;
        ad = 26;
    }
    saddr.isd_ad = ISD_AD(isd, ad);
    saddr.host.addrLen = 4;
    sprintf(str, "127.%d.%d.254", isd, ad);
    printf("connect to (%d, %d):%s\n", isd, ad, str);
    in_addr_t in = inet_addr(str);
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = saddr;
    SCIONSocket s(SCION_PROTO_SSP, addrs, 1, 0, 8080);
    s.send((uint8_t *)hash, 20);
    printf("hash sent: ");
    for (int i = 0; i < 20; i++)
        printf("%x", hash[i]);
    printf("\n");
    FILE *fp = fopen("randomfile", "rb");
    char fbuf[BUFSIZE];
    memset(fbuf, 0, BUFSIZE);
    int len = 0;
    while ((len = fread(fbuf, 1, BUFSIZE, fp)) > 0)
        s.send((uint8_t *)fbuf, len);
    printf("done sending file\n");
    s.recv((uint8_t *)fbuf, BUFSIZE, NULL);
    fclose(fp);
    exit(0);
}
