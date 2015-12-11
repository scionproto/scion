#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE (1024 * 200)

int main()
{
    SCIONSocket s(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    SCIONSocket &newSocket = s.accept();
    printf("got new socket\n");
    char buf[BUFSIZE];
    uint8_t recvdhash[20];
    memset(recvdhash, 0, 20);
    int ret = newSocket.recv((uint8_t *)recvdhash, 20, NULL);
    printf("recvd %d bytes\n", ret);
    FILE *fp = fopen("recvdfile", "wb");
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (size < 1 * 1024 * 1024) {
        memset(buf, 0, BUFSIZE);
        int recvlen = newSocket.recv((uint8_t *)buf, BUFSIZE, NULL);
        gettimeofday(&end, NULL);
        fwrite(buf, 1, recvlen, fp);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        printf("%d bytes: %f bps\n", size, (double)size / us * 1000000);
    }
    printf("received total %d bytes\n", size);
    newSocket.send((uint8_t *)buf, 1);
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

    exit(0);
}
