#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "SCIONWrapper.h"

#define BUFSIZE 1024

int main()
{
    SCIONAddr addr;
    addr.isd_as = ISD_AS(2, 26);
    addr.host.addr_len = 4;
    addr.host.port = 8080;
    in_addr_t in = inet_addr("127.2.26.254");
    memcpy(addr.host.addr, &in, 4);
    int sock = newSCIONSocket(L4_SSP);
    SCIONConnect(sock, addr);
    int count = 0;
    char buf[BUFSIZE];
    while (1) {
        count++;
        sprintf(buf, "This is message %d\n", count);
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        SCIONSelect(sock + 1, NULL, &writefds, NULL);
        SCIONSend(sock, (uint8_t *)buf, BUFSIZE);
    }

    return 0;
}
