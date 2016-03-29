#include <arpa/inet.h>

#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE (1024 * 200)

int main(int argc, char **argv)
{
    SCIONAddr saddr;
    int isd, as;
    char str[20];
    if (argc == 3) {
        isd = atoi(argv[1]);
        as = atoi(argv[2]);
    } else {
        isd = 2;
        as = 26;
    }
    saddr.isd_as = ISD_AS(isd, as);
    saddr.host.addr_len = 4;
    sprintf(str, "127.%d.%d.254", isd, as);
    printf("connect to (%d, %d):%s\n", isd, as, str);
    in_addr_t in = inet_addr(str);
    memcpy(saddr.host.addr, &in, 4);
    SCIONSocket s(L4_SSP);
    s.connect(saddr);

    char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);

    uint8_t recvdhash[20];
    memset(recvdhash, 0, 20);
    int ret = s.recv((uint8_t *)recvdhash, 20, NULL);
    printf("recvd %d bytes\n", ret);
    FILE *fp = fopen("recvdfile", "wb");
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    int recvlen;
    while ((recvlen = s.recv((uint8_t *)buf, BUFSIZE, NULL)) > 0) {
        gettimeofday(&end, NULL);
        fwrite(buf, 1, recvlen, fp);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        printf("%d bytes: %f bps\n", size, (double)size / us * 1000000);
    }
    printf("received total %d bytes\n", size);
    s.shutdown();
    while (s.recv((uint8_t *)buf, BUFSIZE, NULL) > 0);
    //s.send((uint8_t *)buf, 1);
    fclose(fp);

    CSHA1 sha;
    sha.HashFile("recvdfile");
    sha.Final();
    uint8_t hash[20];
    sha.GetHash(hash);
    printf("received hash: ");
    for (int i = 0; i < 20; i++)
        printf("%x", recvdhash[i]);
    printf("\n");
    printf("computed hash: ");
    for (int i = 0; i < 20; i++)
        printf("%x", hash[i]);
    printf("\n");

    bool success = true;
    for (int i = 0; i < 20; i++) {
        if (hash[i] != recvdhash[i]) {
            printf("failed\n");
            success = false;
            break;
        }
    }
    if (success) {
        printf("success\n");
    }

    return 0;
}
