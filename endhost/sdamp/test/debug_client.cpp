#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ncurses.h>
#include <signal.h>
#include <Python.h>
#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE 1024

int main()
{
    SCIONAddr *addrs[1];
    SCIONAddr saddr;
    saddr.ISD_AD(1, 5);
    saddr.host.addrLen = 4;
    in_addr_t in = inet_addr("192.33.93.195");
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = &saddr;
    SCIONSocket s(SCION_PROTO_SDAMP, addrs, 1, 0, 8080);
    int count = 0;
    char buf[BUFSIZE];
    while (1) {
        count++;
        sprintf(buf, "This is message %d\n", count);
        s.send((uint8_t *)buf, BUFSIZE);
    }
    exit(0);
}
