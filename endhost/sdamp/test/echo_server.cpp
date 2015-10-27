#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "SCIONSocket.h"

int main()
{
    SCIONSocket s(SCION_PROTO_SDAMP, NULL, 0, 80);
    SCIONSocket newSocket = s.accept();
    printf("got new socket\n");
    uint8_t buf[1024];
    SCIONAddr addr;
    while (1) {
        memset(buf, 0, 1024);
        int total = newSocket.recv(buf, 1024, &addr);
        int expected = *(int *)buf;
        printf("expecting %d byte message\n", expected);
        while (total < expected)
            total += newSocket.recv(buf + total, 1024 - total, &addr);
        printf("received %d byte message: %s\n", total, (char *)(buf + 4));
        newSocket.send(buf, total);
    }
    return 0;
}
