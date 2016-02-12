#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "SCIONWrapper.h"

#define BUFSIZE 10240

int main()
{
    int sock = newSCIONSocket(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    char buf[BUFSIZE];
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    fd_set readfds;
    int max = sock;
    int newsock = -1;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        if (newsock > 0)
            FD_SET(newsock, &readfds);
        int sel = SCIONSelect(max + 1, &readfds, NULL, NULL);
        if (sel > 0) {
            if (FD_ISSET(sock, &readfds)) {
                newsock = SCIONAccept(sock);
                if (newsock > max)
                    max = newsock;
                printf("accepted socket %d\n", newsock);
            }
            if (newsock > 0 && FD_ISSET(newsock, &readfds)) {
                memset(buf, 0, BUFSIZE);
                int recvlen = SCIONRecv(newsock, (uint8_t *)buf, BUFSIZE, NULL);
                gettimeofday(&end, NULL);
                size += recvlen;
                long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
                fprintf(stderr, "%d bytes: %f bps\n", size, (double)size / us * 1000000);
            }
        }
    }

    return 0;
}
