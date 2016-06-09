#include "SCIONSocket.h"

#define BUFSIZE 102400

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
    SCIONSocket s(L4_SSP, str);


    SCIONAddr addr;
    memset(&addr, 0, sizeof(addr));
    addr.isd_as = ISD_AS(isd, as);
    addr.host.port = 8080;
    sprintf(str, "127.%d.%d.254", isd, as);
    *(in_addr_t *)addr.host.addr = inet_addr(str);
    addr.host.addr_len = 4;
    s.bind(addr);

    s.listen();
    SCIONSocket *newSocket = s.accept();

    char buf[BUFSIZE];
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int recvlen = newSocket->recv((uint8_t *)buf, BUFSIZE, NULL);
        //int recvlen = s.recv((uint8_t *)buf, BUFSIZE, NULL);
        printf("received message: %s", buf);
        gettimeofday(&end, NULL);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        fprintf(stderr, "%d bytes: %f Mbps\n", size, (double)size / us * 1000000 / 1024 / 1024 * 8);
    }
    exit(0);
}
