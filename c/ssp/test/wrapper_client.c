#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "SCIONWrapper.h"

#define BUFSIZE 1024

int main(int argc, char **argv)
{
    uint16_t src_isd, dst_isd;
    uint32_t src_as, dst_as;
    char str[40];
    if (argc >= 2) {
        src_isd = atoi(strtok(argv[1], "-"));
        src_as = atoi(strtok(NULL, "-"));
    } else {
        src_isd = 1;
        src_as = 19;
    }
    if (argc == 3) {
        dst_isd = atoi(strtok(argv[2], "-"));
        dst_as = atoi(strtok(NULL, "-"));
    } else {
        dst_isd = 2;
        dst_as = 26;
    }

    sprintf(str, "/run/shm/sciond/%d-%d.sock", src_isd, src_as);
    int sock = newSCIONSocket(L4_SSP, str);

    SCIONAddr saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.isd_as = ISD_AS(dst_isd, dst_as);
    saddr.host.addr_type = ADDR_IPV4_TYPE;
    saddr.host.port = 8080;
    sprintf(str, "127.%d.%d.254", dst_isd, dst_as);
    in_addr_t in = inet_addr(str);
    memcpy(saddr.host.addr, &in, 4);

    SCIONConnect(sock, saddr);

    int count = 0;
    char buf[BUFSIZE];
    while (1) {
        count++;
        sprintf(buf, "This is message %d\n", count);
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        SCIONSelect(sock + 1, NULL, &writefds, NULL);
        SCIONSend(sock, (uint8_t *)buf, BUFSIZE, NULL);
    }

    return 0;
}
