#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"

int main()
{
    SCIONAddr *addrs[1];
    SCIONAddr saddr;
    saddr.isd = 2;
    saddr.ad = 26;
    saddr.host.addrLen = 4;
    in_addr_t in = inet_addr("127.2.26.254");
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = &saddr;
    SCIONSocket s(SCION_PROTO_SDAMP, addrs, 1, 80);
    while (1) {
        char buf[1024];
        memset(buf, 0, 1024);
        *(int *)buf = 1024;
        for (int i = 4; i < 512; i++)
            buf[i] = 'a';
        for (int i = 512; i < 1022; i++)
            buf[i] = 'b';
        buf[1022] = '\n';
        s.send((uint8_t *)buf, 1024, SCION_PROFILE_DEFAULT);
        memset(buf, 0, sizeof(buf));
        int total = s.recv((uint8_t *)buf, 1024, NULL);
        int expected = *(int *)buf;
        printf("got %d of %d bytes\n", total, expected);
        while (total < expected) {
            total += s.recv((uint8_t *)(buf + total), 1024 - total, NULL);
            printf("got %d of %d bytes\n", total, expected);
        }
        printf("server returned %d byte message: %s\n", total, buf + 4);
        getchar();
    }
    return 0;
}
