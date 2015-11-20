#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "SCIONWrapper.h"

#define BUFSIZE 1024

int main()
{
    int sock = newSCIONSocket(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    int newSocket = SCIONAccept(sock);
    char buf[BUFSIZE];
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int recvlen = SCIONRecv(newSocket, (uint8_t *)buf, BUFSIZE, NULL);
        gettimeofday(&end, NULL);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        fprintf(stderr, "%d bytes: %f bps\n", size, (double)size / us * 1000000);
    }
    exit(0);
}
