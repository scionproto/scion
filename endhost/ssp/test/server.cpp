#include "SCIONSocket.h"

#define BUFSIZE 102400

int main()
{
    SCIONSocket s(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    SCIONSocket *newSocket = s.accept();
    char buf[BUFSIZE];
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int recvlen = newSocket->recv((uint8_t *)buf, BUFSIZE, NULL);
        //int recvlen = s.recv((uint8_t *)buf, BUFSIZE, NULL);
        //printf("received message: %s", buf);
        gettimeofday(&end, NULL);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        fprintf(stderr, "%d bytes: %f Mbps\n", size, (double)size / us * 1000000 / 1024 / 1024 * 8);
    }
    exit(0);
}
