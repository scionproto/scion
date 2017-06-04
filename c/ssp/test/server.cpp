#include "SCIONSocket.h"

#define BUFSIZE 1024000

int main(int argc, char **argv)
{
    uint16_t isd;
    uint32_t as;
    char str[40];
    if (argc == 2) {
        isd = atoi(strtok(argv[1], "-"));
        as = atoi(strtok(NULL, "-"));
    } else {
        isd = 2;
        as = 26;
    }

    sprintf(str, "/run/shm/sciond/%d-%d.sock", isd, as);
#ifdef MPUDP
    SCIONSocket s(L4_UDP, str);
#else
    SCIONSocket s(L4_SSP, str);
#endif

    SCIONAddr addr;
    memset(&addr, 0, sizeof(addr));
    addr.isd_as = ISD_AS(isd, as);
    addr.host.port = 8080;
    addr.host.addr_type = ADDR_IPV4_TYPE;
    sprintf(str, "127.%d.%d.254", isd, as);
    in_addr_t in = inet_addr(str);
    memcpy(addr.host.addr, &in, 4);
    s.bind(addr);

#ifndef MPUDP
    s.listen();
    SCIONSocket *newSocket = s.accept();
#endif

    char buf[BUFSIZE];
    int size = 0;
    int count = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
#ifdef MPUDP
        int recvlen = s.recv((uint8_t *)buf, BUFSIZE, NULL);
#else
        int recvlen = newSocket->recv((uint8_t *)buf, BUFSIZE, NULL);
#endif
        if (recvlen < 1) {
            fprintf(stderr, "Connection closed (%d)\n", recvlen);
            break;
        }
        size += recvlen;
        count++;
        if (count > 1000) {
            count = 0;
            gettimeofday(&end, NULL);
            long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
            fprintf(stderr, "%d bytes: %f Mbps\n", size, (double)size / us * 1000000 / 1024 / 1024 * 8);
        }
    }
    exit(0);
}
