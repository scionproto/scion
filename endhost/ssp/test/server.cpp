#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"

#define BUFSIZE 1024

int main()
{
    SCIONSocket s(SCION_PROTO_UDP, NULL, 0, 8080, 0);
    //SCIONSocket &newSocket = s.accept();
    char buf[BUFSIZE];
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int recvlen = s.recv((uint8_t *)buf, BUFSIZE, NULL);
        printf("received message: %s", buf);
        gettimeofday(&end, NULL);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        fprintf(stderr, "%d bytes: %f bps\n", size, (double)size / us * 1000000);
    }
    exit(0);
}
