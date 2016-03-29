#include <arpa/inet.h>
#include <unistd.h>

#include "SCIONSocket.h"

#define BUFSIZE 1024

int main(int argc, char **argv)
{
    SCIONAddr saddr;
    memset(&saddr, 0, sizeof(saddr));

    SCIONSocket s(L4_UDP);
    s.bind(saddr);

    uint16_t isd;
    uint32_t as;
    char str[20];
    if (argc == 3) {
        isd = atoi(argv[1]);
        as = atoi(argv[2]);
    } else {
        isd = 2;
        as = 26;
    }
    saddr.isd_as = ISD_AS(isd, as);
    saddr.host.addr_len = 4;
    saddr.host.port = 8080;
    sprintf(str, "127.%d.%d.254", isd, as);
    printf("connect to (%d, %d):%s\n", isd, as, str);
    in_addr_t in = inet_addr(str);
    memcpy(saddr.host.addr, &in, 4);

    s.connect(saddr);

    /*
    SCIONOption option;
    memset(&option, 0, sizeof(option));
    option.type = SCION_OPTION_ISD_WLIST;
    option.val = 0;
    option.len = 4;
    *(uint16_t *)(option.data) = 1;
    *(uint16_t *)(option.data + 2) = 3;
    s.setSocketOption(&option);
    */

    int count = 0;
    char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    while (1) {
        count++;
        sprintf(buf, "This is message %d\n", count);
        //s.send((uint8_t *)buf, BUFSIZE);
        s.send((uint8_t *)buf, BUFSIZE, &saddr);
        usleep(500000);
    }
    exit(0);
}
