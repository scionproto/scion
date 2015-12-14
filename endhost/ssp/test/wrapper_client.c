#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "SCIONWrapper.h"

#define BUFSIZE 1024

int main()
{
    SCIONAddr addrs[1];
    SCIONAddr saddr;
    saddr.isd_ad = ISD_AD(2, 26);
    saddr.host.addrLen = 4;
    in_addr_t in = inet_addr("127.2.26.254");
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = saddr;
    int sock = newSCIONSocket(SCION_PROTO_SSP, addrs, 1, 0, 8080);
    int count = 0;
    char buf[BUFSIZE];
    while (1) {
        count++;
        sprintf(buf, "This is message %d\n", count);
        SCIONSend(sock, (uint8_t *)buf, BUFSIZE);
        //usleep(50000);
    }
    exit(0);
}
