#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE 1024

int main()
{
    system("dd if=/dev/urandom of=randomfile bs=1024 count=10240");

    uint8_t hash[20];
    CSHA1 sha;
    sha.HashFile("randomfile");
    sha.Final();
    sha.GetHash(hash);

    SCIONAddr *addrs[1];
    SCIONAddr saddr;
    saddr = ISD_AD(2, 26);
    saddr.host.addrLen = 4;
    in_addr_t in = inet_addr("127.2.26.254");
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = &saddr;
    SCIONSocket s(SCION_PROTO_SDAMP, addrs, 1, 0, 8080);
    s.send((uint8_t *)hash, 20);
    printf("hash sent\n");
    FILE *fp = fopen("randomfile", "rb");
    char fbuf[BUFSIZE];
    int len = 0;
    while ((len = fread(fbuf, 1, BUFSIZE, fp)) > 0)
        s.send((uint8_t *)fbuf, len);
    printf("done sending file\n");
    s.recv((uint8_t *)fbuf, BUFSIZE, NULL);
    fclose(fp);
    exit(0);
}
